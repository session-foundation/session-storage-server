#include "service_node.h"

#include "serialization.h"
#include "sn_test.h"
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <oxenmq/connections.h>
#include <oxen/quic/format.hpp>
#include <oxenss/version.h>
#include <oxenss/common/mainnet.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/base.h>
#include <oxenss/server/omq.h>
#include <oxenss/logging/oxen_logger.h>
#include <iterator>
#include <numeric>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/random.hpp>

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <oxenmq/oxenmq.h>

#include <algorithm>
#include <tuple>
#include <utility>

using json = nlohmann::json;

namespace oxenss::snode {

static auto logcat = log::Cat("snode");

// Threshold of missing data records at which we start warning and consult bootstrap nodes
// (mainly so that we don't bother producing warning spam or going to the bootstrap just for a
// few new nodes that will often have missing info for a few minutes).
using MISSING_PUBKEY_THRESHOLD = std::ratio<3, 100>;

/// TODO: there should be config.h to store constants like these
constexpr auto OXEND_PING_INTERVAL = 30s;

// How often to trigger 'check_new_members' which checks for 'data ready' handshakes from
// swarm members and propagate a DB dump if necessary.
constexpr auto NEW_SWARM_MEMBER_INTERVAL = 10s;

// How often to look for stored swarm requests that are due to be retried.  This bounds how late a
// retry can go out past its Database::RETRY_INITIAL_DELAY / RETRY_INTERVAL schedule.
constexpr auto RETRY_REQUEST_CHECK_INTERVAL = 5s;

// How long to wait for a reply to a retried swarm request.  This is longer than the timeout on the
// original request since the peer has already failed to answer within that once.
constexpr auto RETRY_REQUEST_TIMEOUT = 10s;

// Dumps of swarm messages to another node go out in batches of about this many bytes, with at most
// DUMP_WINDOW batches unacknowledged at once.  Together these bound how much of the connection to
// that node a dump occupies (everything else sent to it, onion requests included, queues behind
// the batches in flight) while still filling a 100Mbit link at a few hundred ms of latency.
constexpr size_t DUMP_BATCH_BYTES = 1'000'000;
constexpr int DUMP_WINDOW = 5;
// A batch is acknowledged only once the receiver has committed it, and on a busy node (several
// dumps arriving at once, a slow disk) that can lag well behind receipt with nothing wrong.  A
// dead peer is caught by the connection's idle timeout, which fails every pending request, so this
// only bounds a batch that was lost outright; make it long so that a merely slow peer is not sent
// the same window again.
constexpr auto DUMP_REQUEST_TIMEOUT = 5min;
// How long a dump pauses after a batch fails or when the node is not contactable.
constexpr auto DUMP_RETRY_DELAY = 15s;

// Our version as the single integer MMmmpp (e.g. 21204 for 2.12.4) that the data_ready handshake
// carries in each direction.
static uint32_t handshake_version() {
    const auto& [major, minor, patch] = STORAGE_SERVER_VERSION;
    return major * 10000 + minor * 100 + patch;
}

static std::string format_handshake_version(uint32_t v) {
    return "{}.{}.{}"_format(v / 10000, v / 100 % 100, v % 100);
}
// How often to look for dumps that are due to start or resume; once running they are driven by the
// acknowledgements.
constexpr auto DUMP_CHECK_INTERVAL = 5s;

ServiceNode::ServiceNode(
        const crypto::legacy_keypair& keys,
        const contact& contact,
        server::OMQ& omq_server,
        const std::filesystem::path& db_location,
        bool force_start,
        bool skip_bootstrap) :
        force_start_{force_start},
        skip_bootstrap_{skip_bootstrap},
        db{std::make_unique<Database>(db_location)},
        our_keys_{keys},
        our_contact_{contact},
        network_{*omq_server},
        swarm_{network_, our_keys_.pub, *db},
        omq_server_{omq_server},
        all_stats_{*omq_server} {
    mq_servers_.push_back(&omq_server);

    // Lets the first swarm update tell whether our swarm dissolved while we were down.
    if (auto id = db->get_current_swarm())
        swarm_.cur_swarm_id_ = *id;

    omq_server->add_timer([this] { db->clean_expired(); }, Database::CLEANUP_PERIOD);

    omq_server->add_timer([this] { check_new_members(); }, NEW_SWARM_MEMBER_INTERVAL);

    // We really want to make sure nodes don't get stuck in "syncing" mode,
    // so if we are still "syncing" after a long time, activate SN regardless
    auto delay_timer = std::make_shared<oxenmq::TimerID>();
    auto& dtimer = *delay_timer;  // Get reference before we move away the shared_ptr
    omq_server_->add_timer(
            dtimer,
            [this, timer = std::move(delay_timer)] {
                omq_server_->cancel_timer(*timer);
                std::lock_guard lock{sn_mutex_};
                if (!syncing_)
                    return;
                log::warning(logcat, "Block syncing is taking too long, activating SS regardless");
                syncing_ = false;
            },
            1h);

    omq_server_->add_timer([this] { check_retry_requests(); }, RETRY_REQUEST_CHECK_INTERVAL);
    omq_server_->add_timer([this] { check_dumps(); }, DUMP_CHECK_INTERVAL);
}

void ServiceNode::on_oxend_connected(const std::function<bool()>& keep_going) {
    // This should be the first time we ever trigger a block update from Oxen, i.e. the initial
    // call to `update_swarms` should not early out which would cause a deadlock on the promise.
    assert(!updating_swarms_.load());
    auto started = std::chrono::steady_clock::now();

    // Whether oxend's node list can be used as-is is a question of whether oxend is synced, and
    // the age of its top block answers that directly.  This has to be settled before the list
    // arrives: process_snodes_update() drops the list of an oxend that is still syncing.
    {
        auto block_age = omq_server_.oxend_top_block_age(keep_going);
        std::lock_guard lock{sn_mutex_};
        syncing_ = block_age > MAX_SYNCED_BLOCK_AGE;
        if (syncing_)
            log::warning(
                    logcat,
                    "oxend's top block is {} old; treating oxend as still syncing",
                    util::friendly_duration(block_age));
    }

    while (true) {
        auto prom = std::make_shared<std::promise<bool>>();
        auto fut = prom->get_future();
        update_swarms(prom);
        if (await_startup(fut, keep_going, "the initial block update from oxend"))
            break;
        std::this_thread::sleep_for(1s);
    }

    log::info(
            logcat,
            "Got initial block update from oxend in {} (height {}/{} HF {}.{})",
            util::short_duration(std::chrono::steady_clock::now() - started),
            block_height_,
            block_hash_,
            hardfork_.first,
            hardfork_.second);

    oxend_ping();
    omq_server_->add_timer([this] { oxend_ping(); }, OXEND_PING_INTERVAL);
    omq_server_->add_timer([this] { ping_peers(); }, reachability_testing::TESTING_TIMER_INTERVAL);
}

template <typename T>
static T get_or(const json& j, std::string_view key, std::common_type_t<T> default_val) {
    if (auto it = j.find(key); it != j.end())
        return it->get<T>();
    return default_val;
}

static std::optional<block_update> parse_swarm_update(
        std::string_view response_body, const crypto::legacy_pubkey& our_pk) {
    if (response_body.empty()) {
        log::critical(logcat, "Bad oxend rpc response: no response body");
        throw std::runtime_error("Failed to parse swarm update");
    }

    std::optional<block_update> maybe_bu;

    log::trace(logcat, "swarm response: <{}>", response_body);

    try {
        json result = json::parse(response_body, nullptr, true);
        if (result.value<bool>("unchanged", false))
            return maybe_bu;  // nullopt

        auto& bu = maybe_bu.emplace();

        bu.height = result.at("height").get<uint64_t>();
        bu.block_hash = result.at("block_hash").get<std::string>();
        bu.hardfork = result.at("hardfork").get<int>();
        bu.snode_revision = result.value<int>("snode_revision", 0);

        const json service_node_states = result.at("service_node_states");

        int missing_contacts = 0, total = 0;

        for (const auto& sn_json : service_node_states) {
            total++;
            const auto& pk_hex = sn_json.at("service_node_pubkey").get_ref<const std::string&>();

            const auto pk_x25519_hex = sn_json.value<std::string_view>("pubkey_x25519", ""sv);
            const auto pk_ed25519_hex = sn_json.value<std::string_view>("pubkey_ed25519", ""sv);

            auto pk = crypto::legacy_pubkey::from_hex(pk_hex);
            auto& c = bu.contacts[pk];
            c = contact{
                    ipv4{sn_json.value<std::string>("public_ip", "0.0.0.0")},
                    sn_json.value<uint16_t>("storage_port", 0),
                    sn_json.value<uint16_t>("storage_lmq_port", 0),
                    sn_json.value<std::array<uint16_t, 3>>("storage_server_version", {0, 0, 0}),
                    pk_ed25519_hex.empty() ? crypto::ed25519_pubkey{}
                                           : crypto::ed25519_pubkey::from_hex(pk_ed25519_hex),
                    pk_x25519_hex.empty() ? crypto::x25519_pubkey{}
                                          : crypto::x25519_pubkey::from_hex(pk_x25519_hex)};

            if (!c) {
                // oxend hasn't yet received an uptime proof from this node
                missing_contacts++;
                log::debug(logcat, "contact info is missing from service node info {}", pk_hex);
            }

            const swarm_id_t swarm_id = sn_json.at("swarm_id").get<swarm_id_t>();

            if (swarm_id != INVALID_SWARM_ID)
                bu.swarms[swarm_id].insert(pk);
            else if (pk == our_pk)
                bu.decommed = true;
        }

        if (missing_contacts >
            MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den) {
            log::warning(
                    logcat,
                    "Missing contact info for {}/{} service nodes; "
                    "oxend may be out of sync with the network",
                    missing_contacts,
                    total);
        }
    } catch (const std::exception& e) {
        log::critical(logcat, "Bad oxend rpc response: invalid json ({})", e.what());
        throw std::runtime_error("Failed to parse swarm update");
    }

    return maybe_bu;
}

void ServiceNode::register_mq_server(server::MQBase* server) {
    if (quic_server_)
        throw std::logic_error{"register_mq_server called more than once"};
    mq_servers_.push_back(server);
    quic_server_ = server;
}

void ServiceNode::bootstrap_fallback() {
    std::lock_guard guard(sn_mutex_);

    log::trace(logcat, "Bootstrapping peer data");

    // TODO: once all bootstraps are on 11.x releases, we can change the fields value to be an array
    // of field names rather than this dict of {"field": true, "field2": true, ...} pairs.
    std::string params = json{
            {"fields",
             {
                     {"service_node_pubkey", true},
                     {"swarm_id", true},
                     {"storage_port", true},
                     {"public_ip", true},
                     {"height", true},
                     {"block_hash", true},
                     {"hardfork", true},
                     {"snode_revision", true},
                     {"pubkey_x25519", true},
                     {"pubkey_ed25519", true},
                     {"storage_lmq_port", true},
                     {"storage_server_version", true},
             }}}.dump();

    std::vector<oxenmq::address> seed_nodes;
    if (oxenss::is_mainnet) {
        seed_nodes.emplace_back(
                "curve://storage.seed1.loki.network:22027/"
                "63089194d7ed97c9bb9c1112501b09be1b4b8ff026ceeb339532ce240da03178");
        seed_nodes.emplace_back(
                "curve://public-eu.optf.ngo:22027/"
                "3c157ed3c675f56280dc5d8b2f00b327b5865c127bf2c6c42becc3ca73d9132b");
        seed_nodes.emplace_back(
                "curve://imaginary.stream:22027/"
                "c0cab39382531e5b6c6325c0f980e9ffb79b20a4c82bb96571f1ffdc3ee76d58");
    } else {
        seed_nodes.emplace_back(
                "curve://storage.seed2.loki.network:38161/"
                "9c5201e30957cd44e3dcc8ad7f94f48e6914deef77390f77a439a2d7e7f4cb5c");
    }

    auto req_counter = std::make_shared<std::atomic<int>>(0);

    for (const auto& addr : seed_nodes) {
        auto connid = omq_server_->connect_remote(
                addr,
                [addr](oxenmq::ConnectionID) {
                    log::debug(logcat, "Connected to bootstrap node {}", addr.full_address());
                },
                [addr](oxenmq::ConnectionID, auto reason) {
                    log::debug(
                            logcat,
                            "Failed to connect to bootstrap node {}: {}",
                            addr.full_address(),
                            reason);
                },
                oxenmq::connect_option::ephemeral_routing_id{true},
                oxenmq::connect_option::timeout{BOOTSTRAP_TIMEOUT});
        omq_server_->request(
                connid,
                "rpc.get_service_nodes",
                [this, connid, addr, req_counter, node_count = (int)seed_nodes.size()](
                        bool success, std::vector<std::string> data) {
                    if (!success)
                        log::error(
                                logcat,
                                "Failed to contact bootstrap node {}: request timed out",
                                addr.full_address());
                    else if (data.empty())
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "no "
                                "data",
                                addr.full_address());
                    else if (data[0] != "200")
                        log::error(
                                logcat,
                                "Failed to request bootstrap node data from {}: request returned "
                                "failure status {}",
                                addr.full_address(),
                                data[0]);
                    else {
                        log::info(
                                logcat,
                                "Parsing response from bootstrap node {}",
                                addr.full_address());
                        try {
                            std::lock_guard lock{sn_mutex_};
                            if (auto update = parse_swarm_update(data[1], our_keys_.pub))
                                on_bootstrap_update(std::move(*update));
                            log::info(logcat, "Bootstrapped from {}", addr.full_address());
                        } catch (const std::exception& e) {
                            log::error(
                                    logcat,
                                    "Exception caught while bootstrapping from {}: {}",
                                    addr.full_address(),
                                    e.what());
                        }
                    }

                    omq_server_->disconnect(connid);

                    if (++(*req_counter) == node_count) {
                        log::info(logcat, "Bootstrapping done");
                        if (target_height_ == 0) {
                            // No seed answered, so nothing can tell us whether our oxend is
                            // behind; assume it is not, or we would never leave the syncing
                            // state.
                            log::warning(
                                    logcat,
                                    "Could not contact any bootstrap nodes to get target "
                                    "height. Assuming our local height is correct.");
                            syncing_ = false;
                        }
                        // The initial oxend response was discarded as "still syncing", so ask
                        // again now rather than knowing no service nodes until the next block.
                        update_swarms();
                    }
                },
                params,
                oxenmq::send_option::request_timeout{BOOTSTRAP_TIMEOUT});
    }
}

void ServiceNode::shutdown() {
    shutting_down_ = true;
}

bool ServiceNode::snode_ready(std::string* reason) {
    if (shutting_down()) {
        if (reason)
            *reason = "shutting down";
        return false;
    }

    std::lock_guard guard(sn_mutex_);

    std::vector<std::string> problems;

    if (!hf_at_least(STORAGE_SERVER_HARDFORK))
        problems.push_back(fmt::format(
                "not yet on hardfork {}.{}",
                STORAGE_SERVER_HARDFORK.first,
                STORAGE_SERVER_HARDFORK.second));
    if (syncing_)
        problems.push_back("not done syncing");

    if (reason && !problems.empty())
        *reason = "{}"_format(fmt::join(problems, "; "));

    return problems.empty() || force_start_;
}

void ServiceNode::send_onion_to_sn(
        const contact& ct,
        std::string_view payload,
        rpc::OnionRequestMetadata&& data,
        std::function<void(bool success, std::vector<std::string> data)> cb) {
    // Since HF18 we bencode everything (which is a bit more compact than sending the eph_key in
    // hex, plus flexible enough to allow other metadata such as the hop number and the
    // encryption type).
    data.hop_no++;
    sn_request(
            ct,
            "onion_request",
            {server::OMQ::encode_onion_data(payload, data)},
            std::move(cb),
            30s);
}

void ServiceNode::record_proxy_request() {
    all_stats_.bump_proxy_requests();
}

void ServiceNode::record_onion_request() {
    all_stats_.bump_onion_requests();
}

void ServiceNode::record_retrieve_request() {
    all_stats_.bump_retrieve_requests();
}

void ServiceNode::check_new_members() {
    for (const auto& pk : swarm_.extract_contact_pending_members()) {
        auto c = network_.contacts.find(pk);
        if (!c || !*c) {
            // We don't have contact info, so don't do anything right now and this will get
            // triggered again later.
            log::debug(
                    logcat,
                    "Leaving {} as pending: node {}",
                    pk,
                    c ? "has missing contact info" : "is unknown");
            continue;
        }

        if (c->version < NEW_SWARM_MEMBER_HANDSHAKE_VERSION) {
            log::debug(
                    logcat,
                    "Skipping handshake with new swarm member {}: v{}+ required, remote is v{}",
                    pk,
                    fmt::join(NEW_SWARM_MEMBER_HANDSHAKE_VERSION, "."),
                    fmt::join(c->version, "."));

            std::lock_guard network_lock{network().mut_};
            if (SwarmMemberState* member = swarm_.is_member_locked(pk); member)
                member->status = SwarmMemberStatus::Ready;
            continue;
        }

        auto on_sn_data_ready_response = [this, pk](bool success, std::vector<std::string> data) {
            if (data.empty()) {
                success = false;
                data.push_back("Empty reply"s);
            } else if (data[0] != "OK"sv) {
                success = false;
            }

            // A 2.12+ node answers with its version after the "OK" (see data_ready_handshake); a
            // pre-2.12 one answers with the "OK" alone.
            const bool legacy = success && data.size() < 2;
            if (success) {
                std::string version;
                if (!legacy)
                    try {
                        version = format_handshake_version(
                                oxenc::bt_dict_consumer{data[1]}.require<uint32_t>("#"));
                    } catch (const std::exception& e) {
                        version = "?"s;
                    }
                log::debug(
                        logcat,
                        "Successful contact made with swarm member {} (v{}), marking as ready",
                        pk,
                        legacy ? "<2.12" : version);
            } else {
                log::info(
                        logcat,
                        "Failed to connect to remote SS {} to initiate new "
                        "data transfer ({}); will retry soon",
                        pk,
                        fmt::join(data, ", "));
            }

            // The 'pk' member might not be in the swarm anymore if the request elapsed over a
            // period of time where the swarm composition changed.
            bool push = false;
            {
                std::lock_guard network_lock{network().mut_};
                if (SwarmMemberState* member = swarm_.is_member_locked(pk); member) {
                    // Update the requested DB dump state machine if necessary.
                    SwarmRequestedDBDump& status = member->our_ss_requested_db_dump;
                    if (status == SwarmRequestedDBDump::RequestUnderway)
                        status = success ? SwarmRequestedDBDump::Nil
                                         : SwarmRequestedDBDump::NeedsToRequest;

                    if (success) {
                        member->status = SwarmMemberStatus::Ready;
                        // A node that joined our swarm needs its messages.  A 2.12+ one asks for
                        // them in its own handshake with us; a pre-2.12 one never asks, and
                        // expects them to follow this handshake, as 2.11.x sends them.
                        if (member->joined_our_swarm) {
                            member->joined_our_swarm = false;
                            push = legacy;
                        }
                    }
                }
            }
            // Outside the lock: queueing the dump starts it, which reads the swarm list.
            if (push) {
                log::info(logcat, "Pushing swarm messages to pre-2.12 swarm member {}", pk);
                queue_swarm_dump(pk);
            }
        };

        bool needs_db_dump{false};
        {
            std::lock_guard network_lock{network().mut_};
            if (SwarmMemberState* member = swarm_.is_member_locked(pk); member) {
                SwarmRequestedDBDump& status = member->our_ss_requested_db_dump;
                if (status == SwarmRequestedDBDump::NeedsToRequest) {
                    status = SwarmRequestedDBDump::RequestUnderway;
                    needs_db_dump = true;
                }
            }
        }

        // Request payload: "#" is our version, so that the receiver can gate on it without going
        // through oxend's lagging view; "t" is whether we want the peer to send us its copy of the
        // swarm's messages.  It goes to every peer: a pre-2.12 one ignores it.
        oxenc::bt_dict_producer d;
        d.append("#", handshake_version());
        d.append("t", needs_db_dump);
        log::debug(
                logcat,
                "Initiating contact with new swarm member {}{}",
                pk,
                needs_db_dump ? " (requesting DB dump)" : "");
        sn_request(*c, "data_ready", {std::move(d).str()}, on_sn_data_ready_response, 15s);
    }
}

static void write_metadata(
        oxenc::bt_dict_producer& d, std::string_view pubkey, const message& msg) {
    d.append("@", pubkey);
    d.append("h", msg.hash);
    d.append("n", to_int(msg.msg_namespace));
    d.append("t", to_epoch_ms(msg.timestamp));
    d.append("z", to_epoch_ms(msg.expiry));
}

void ServiceNode::send_notifies(message msg) {
    auto pubkey = msg.pubkey.prefixed_raw();
    std::vector<server::connection_id> relay_to, relay_to_with_data;

    for (auto* s : mq_servers_)
        s->get_notifiers(msg, relay_to, relay_to_with_data);

    if (relay_to.empty() && relay_to_with_data.empty())
        return;

    // We output a dict with keys (in order):
    // - @ pubkey
    // - h msg hash
    // - n msg namespace
    // - t msg timestamp
    // - z msg expiry
    // - ~ msg data (optional)
    constexpr size_t metadata_size = 2       // d...e
                                   + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                   + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                   + 3 + 8   // 1:n and i-32768e
                                   + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                   + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                   + 10;     // safety margin

    oxenc::bt_dict_producer d;
    d.reserve(
            relay_to_with_data.empty() ? metadata_size
                                       : metadata_size  // all the metadata above
                                                 + 3    // 1:~
                                                 + 8    // 76800: plus a couple bytes to grow
                                                 + msg.data.size());

    write_metadata(d, pubkey, msg);

    if (!relay_to.empty())
        for (auto* s : mq_servers_)
            s->notify(relay_to, d.view());

    if (!relay_to_with_data.empty()) {
        d.append("~", msg.data);
        for (auto* s : mq_servers_)
            s->notify(relay_to_with_data, d.view());
    }
}

bool ServiceNode::process_store(
        message msg, bool* new_msg, std::chrono::system_clock::time_point* expiry) {
    // No sn_mutex_ here: nothing below needs it (the swarm, stats, and notification lookups lock
    // internally, and the database has its own connection pool), and holding it across the store
    // would make everything else that takes it wait on sqlite's write lock.

    /// only accept a message if we are in a swarm
    if (!swarm_.is_valid()) {
        // This should never be printed now that we have "snode_ready"
        log::error(logcat, "error: my swarm in not initialized");
        return false;
    }

    all_stats_.bump_store_requests();

    /// store in the database (if not already present)
    const auto result = db->store(msg, expiry);
    if (new_msg)
        *new_msg = result == StoreResult::New;

    if (result == StoreResult::New)
        send_notifies(std::move(msg));

    return result != StoreResult::Full;
}

bool ServiceNode::save_bulk(std::span<const message> msgs) {
    try {
        db->bulk_store(msgs);
    } catch (const std::exception& e) {
        log::error(logcat, "failed to save batch to the database: {}", e.what());
        return false;
    }

    log::trace(logcat, "saved messages count: {}", msgs.size());
    return true;
}

void ServiceNode::on_bootstrap_update(block_update&& bu) {
    swarm_.update_swarms(bu.height, std::move(bu.swarms), bu.contacts);
    target_height_ = std::max(target_height_, bu.height);
}

void ServiceNode::on_snodes_update(block_update&& bu) {
    hf_revision net_ver{bu.hardfork, bu.snode_revision};
    if (hardfork_ != net_ver) {
        log::info(logcat, "New hardfork: {}.{}", net_ver.first, net_ver.second);
        hardfork_ = net_ver;
    }

    if (syncing_ && target_height_ != 0) {
        syncing_ = bu.height < target_height_;
    }

    /// We don't have anything to do until we have synced
    if (syncing_) {
        log::debug(logcat, "Still syncing: {}/{}", bu.height, target_height_);
        // Note that because we are still syncing, we won't update our swarm id
        return;
    }

    if (bu.block_hash != block_hash_) {
        log::debug(logcat, "new block, height: {}, hash: {}", bu.height, bu.block_hash);

        block_height_ = bu.height;
        block_hash_ = bu.block_hash;
    } else {
        log::trace(logcat, "already seen this block");
        return;
    }

    bool ready;
    if (std::string reason; !(ready = snode_ready(&reason)))
        log::warning(logcat, "Storage server is still not ready: {}", reason);
    else if (!active_) {
        // NOTE: because we never reset `active_` after we get decommissioned, this code won't run
        // when the node comes back again
        log::info(logcat, "Storage server is now active!");
        active_ = true;
    }

    auto events = swarm_.update_swarms(bu.height, std::move(bu.swarms), bu.contacts);

    // The new swarm state is in effect as of the call above, so any monitor subscription for an
    // account we would now answer with a 421 has to be terminated.  This must not be skipped when
    // we are not `ready` (e.g. we just got decommissioned): those are exactly the cases where the
    // subscription has become useless.
    for (auto* s : mq_servers_) {
        s->drop_foreign_monitors();
        s->sweep_sn_connections();
    }

    if (const SnodeStatus status = events.our_swarm_id != INVALID_SWARM_ID ? SnodeStatus::ACTIVE
                                 : bu.decommed ? SnodeStatus::DECOMMISSIONED
                                               : SnodeStatus::UNSTAKED;
        status != status_) {

        log::info(logcat, "Node status updated: {}", status);
        status_ = status;
    }

    if (!ready)
        return;

    if (!events.new_swarms.empty())
        bootstrap_swarms(events.new_swarms);

    if (events.dissolved)
        /// Go through all our PK and push them accordingly
        bootstrap_swarms();
}

void ServiceNode::update_swarms(std::shared_ptr<std::promise<bool>> on_finish) {
    if (updating_swarms_.exchange(true)) {
        log::debug(logcat, "Swarm update already in progress, not sending another update request");
        return;
    }

    std::lock_guard lock{sn_mutex_};

    log::debug(logcat, "Swarm update triggered");

    json params{
            {"fields",
             {
                     "block_hash",
                     "hardfork",
                     "height",
                     "pubkey_ed25519",
                     "pubkey_x25519",
                     "public_ip",
                     "service_node_pubkey",
                     "snode_revision",
                     "storage_lmq_port",
                     "storage_port",
                     "storage_server_version",
                     "swarm_id",
             }},
            {"active_only", false}};
    if (got_first_response_ && !block_hash_.empty())
        params["poll_block_hash"] = block_hash_;

    omq_server_.oxend_request(
            "rpc.get_service_nodes",
            [this, on_finish](bool success, std::vector<std::string> data) {
                updating_swarms_ = false;
                if (!success || data.size() < 2 || data[0] != "200") {
                    log::critical(
                            logcat,
                            "Failed to retrieve snode list from oxend: {}",
                            fmt::join(data, " "));
                    if (on_finish)
                        on_finish->set_value(false);
                    return;
                }

                try {
                    process_snodes_update(data[1]);
                } catch (const std::exception& e) {
                    log::error(logcat, "Exception caught on swarm update: {}", e.what());
                    if (on_finish)
                        on_finish->set_value(false);
                    return;
                }

                if (on_finish)
                    on_finish->set_value(true);
            },
            params.dump());
}

void ServiceNode::sn_request(
        const contact& ct,
        std::string_view cmd,
        std::vector<std::string> parts,
        std::function<void(bool success, std::vector<std::string> parts)> cb,
        std::chrono::milliseconds timeout) {
    auto via_omq = [this, ct, cmd = std::string{cmd}, cb, timeout](std::vector<std::string> parts) {
        omq_server_.sn_request(ct, cmd, std::move(parts), cb, timeout, nullptr);
    };
    if (quic_server_)
        quic_server_->sn_request(
                ct, cmd, std::move(parts), std::move(cb), timeout, std::move(via_omq));
    else
        via_omq(std::move(parts));
}

bool ServiceNode::peer_is_current(const contact& ct) {
    if (ct.version >= SN_QUIC_VERSION)
        return true;
    for (auto* s : mq_servers_)
        if (s->sn_connected(ct))
            return true;
    return false;
}

std::vector<std::string> ServiceNode::data_ready_handshake(
        const crypto::legacy_pubkey& pk, std::string_view payload) {
    if (!swarm_.is_member(pk))
        return {"Swarm mismatch"s};

    // Storage servers before 2.12 send a bare request: they are just checking that we are
    // reachable before pushing their messages to us, and never ask for ours.  (One that joined our
    // swarm gets our copy of its messages after our own handshake with it; see
    // check_new_members.)
    bool needs_db_dump = false;
    if (!payload.empty()) {
        try {
            oxenc::bt_dict_consumer d{payload};
            // Nothing is gated on the sender's version yet, but it is required so that it is
            // there to gate on.
            auto version = d.require<uint32_t>("#");
            needs_db_dump = d.require<bool>("t");
            log::debug(
                    logcat, "data_ready from {} (v{})", pk, format_handshake_version(version));
        } catch (const std::exception& e) {
            log::info(logcat, "Malformed data_ready request from {}: {}", pk, e.what());
            return {"Request payload malformed"s};
        }
    }

    if (needs_db_dump)
        queue_swarm_dump(pk);

    log::debug(logcat, "data_ready from {} processed (needs db dump: {})", pk, needs_db_dump);

    // The sender tells a pre-2.12 node, which replies with the "OK" alone, from us by this second
    // part, so it must be present whatever else it may carry someday.
    oxenc::bt_dict_producer info;
    info.append("#", handshake_version());
    return {"OK"s, std::move(info).str()};
}

void ServiceNode::queue_swarm_dump(const crypto::legacy_pubkey& pk) {
    auto swarm = swarm_.our_swarm_id();
    if (swarm == INVALID_SWARM_ID)
        return;
    queue_dump(pk, swarm);
}

void ServiceNode::queue_dump(const crypto::legacy_pubkey& pk, swarm_id_t swarm) {
    // Anything stored after this point reaches the node through the normal store relay, so the
    // dump stops here.
    auto end_id = db->max_message_id();

    std::lock_guard lock{dumps_mutex_};
    db->queue_dump(pk, swarm, end_id);
    dump_windows_.erase({pk, swarm});
    log::info(logcat, "Queued dump of swarm {:x} messages (ids up to {}) to {}", swarm, end_id, pk);
    check_dumps_locked();
}

void ServiceNode::check_dumps() {
    std::lock_guard lock{dumps_mutex_};
    check_dumps_locked();
    check_deliveries_locked();
    db->clean_pending_recipients();
}

void ServiceNode::queue_delivery(const crypto::legacy_pubkey& pk, const std::string& hash) {
    db->queue_delivery(pk, hash);
    std::lock_guard lock{dumps_mutex_};
    send_deliveries(pk);
}

void ServiceNode::check_deliveries_locked() {
    for (const auto& pk : db->delivery_peers())
        send_deliveries(pk);
}

void ServiceNode::send_deliveries(const crypto::legacy_pubkey& pk) {
    if (deliveries_in_flight_.count(pk))
        return;

    auto now = std::chrono::system_clock::now();
    if (auto it = delivery_retry_after_.find(pk); it != delivery_retry_after_.end()) {
        if (it->second > now)
            return;
        delivery_retry_after_.erase(it);
    }

    if (!swarm_.is_member(pk)) {
        log::debug(logcat, "Dropping pending deliveries to {}: no longer in our swarm", pk);
        db->remove_deliveries(pk);
        return;
    }

    auto ct = network_.contacts.find(pk);
    if (!ct || !*ct) {
        delivery_retry_after_[pk] = now + DUMP_RETRY_DELAY;
        return;
    }

    auto [msgs, ids] = db->next_delivery_batch(pk, DUMP_BATCH_BYTES);
    if (msgs.empty())
        return;

    auto parts = serialize_messages(msgs, SERIALIZATION_VERSION_BT);
    log::debug(logcat, "Delivering {} messages whose store forward failed to {}", msgs.size(), pk);
    deliveries_in_flight_[pk] = {static_cast<int>(parts.size()), false};
    for (auto& part : parts)
        sn_request(
                *ct,
                "data",
                {std::move(part)},
                [this, pk, ids](bool success, std::vector<std::string> data) {
                    // Pre-2.12 nodes acknowledge with an empty reply.
                    on_delivery_reply(pk, ids, success && (data.empty() || data[0] == "OK"sv));
                },
                DUMP_REQUEST_TIMEOUT);
}

void ServiceNode::on_delivery_reply(
        const crypto::legacy_pubkey& pk, std::span<const int64_t> ids, bool ok) {
    std::lock_guard lock{dumps_mutex_};
    auto it = deliveries_in_flight_.find(pk);
    if (it == deliveries_in_flight_.end())
        return;
    auto& [parts, failed] = it->second;
    failed = failed || !ok;
    if (--parts > 0)
        return;
    const bool delivered = !failed;
    deliveries_in_flight_.erase(it);

    if (delivered) {
        db->remove_deliveries(pk, ids);
        send_deliveries(pk);
    } else {
        log::info(
                logcat,
                "Delivery of {} messages to {} failed; retrying in {}",
                ids.size(),
                pk,
                DUMP_RETRY_DELAY);
        delivery_retry_after_[pk] = std::chrono::system_clock::now() + DUMP_RETRY_DELAY;
    }
}

void ServiceNode::check_dumps_locked() {
    auto now = std::chrono::system_clock::now();
    for (const auto& d : db->pending_dumps()) {
        dump_key key{d.pubkey, d.swarm};
        auto it = dump_windows_.find(key);
        if (it == dump_windows_.end()) {
            if (d.next_attempt > now)
                continue;
            it = dump_windows_
                         .emplace(
                                 key,
                                 dump_window{
                                         .next_id = d.next_id,
                                         .end_id = d.end_id,
                                         .sent_next_id = d.next_id,
                                         .generation = ++dump_generation_})
                         .first;
        }
        advance_dump(it->first, it->second);
    }
}

void ServiceNode::advance_dump(const dump_key& key_ref, dump_window& w) {
    // Copies: erasing the window below invalidates the references.
    const auto key = key_ref;
    const auto& [pk, swarm] = key;

    auto finish = [&] {
        log::info(
                logcat,
                "Finished dump of {} swarm {:x} messages to {}",
                w.sent_messages,
                swarm,
                pk);
        db->remove_dump(pk, swarm);
        dump_windows_.erase(key);
    };

    auto members = network_.get_swarm(swarm);
    if (!members || !members->count(pk)) {
        log::info(logcat, "Dropping dump to {}: no longer a member of swarm {:x}", pk, swarm);
        db->remove_dump(pk, swarm);
        dump_windows_.erase(key);
        return;
    }

    if (w.exhausted) {
        if (w.in_flight == 0)
            finish();
        return;
    }
    if (w.in_flight >= DUMP_WINDOW)
        return;

    auto ct = network_.contacts.find(pk);
    if (!ct || !*ct) {
        log::debug(logcat, "Pausing dump to {}: node is not currently contactable", pk);
        db->update_dump(pk, swarm, w.next_id, std::chrono::system_clock::now() + DUMP_RETRY_DELAY);
        dump_windows_.erase(key);
        return;
    }

    std::pair<uint64_t, uint64_t> bounds;
    try {
        bounds = network_.get_swarm_boundaries(swarm);
    } catch (const std::logic_error&) {
        // The swarm list changed between the membership check above and here; the next check will
        // sort out whether the dump still applies.
        return;
    }

    while (w.in_flight < DUMP_WINDOW) {
        auto [msgs, last_id] = db->next_dump_batch(
                w.sent_next_id, w.end_id, bounds.first, bounds.second, DUMP_BATCH_BYTES);
        if (msgs.empty()) {
            w.exhausted = true;
            if (w.in_flight == 0)
                finish();
            return;
        }

        auto parts = serialize_messages(msgs, SERIALIZATION_VERSION_BT);
        w.batches[last_id] = parts.size();
        w.in_flight++;
        w.sent_next_id = last_id + 1;
        w.sent_messages += msgs.size();
        log::debug(
                logcat,
                "Sending {} messages (through id {}) of swarm {:x} dump to {}",
                msgs.size(),
                last_id,
                swarm,
                pk);

        for (auto& part : parts)
            sn_request(
                    *ct,
                    "data",
                    {std::move(part)},
                    [this, key, last_id, generation = w.generation](
                            bool success, std::vector<std::string> data) {
                        // Pre-2.12 nodes acknowledge with an empty reply.
                        on_dump_batch_reply(
                                key,
                                last_id,
                                generation,
                                success && (data.empty() || data[0] == "OK"sv));
                    },
                    DUMP_REQUEST_TIMEOUT);
    }
}

void ServiceNode::on_dump_batch_reply(
        const dump_key& key, int64_t last_id, uint64_t generation, bool ok) {
    std::lock_guard lock{dumps_mutex_};
    auto it = dump_windows_.find(key);
    if (it == dump_windows_.end() || it->second.generation != generation)
        return;
    auto& w = it->second;
    const auto& [pk, swarm] = key;

    if (!ok) {
        log::info(
                logcat,
                "Dump batch to {} failed; resuming from message id {} in {}",
                pk,
                w.next_id,
                DUMP_RETRY_DELAY);
        db->update_dump(pk, swarm, w.next_id, std::chrono::system_clock::now() + DUMP_RETRY_DELAY);
        dump_windows_.erase(it);
        return;
    }

    auto b = w.batches.find(last_id);
    if (b == w.batches.end() || --b->second > 0)
        return;
    w.in_flight--;

    while (!w.batches.empty() && w.batches.begin()->second == 0) {
        w.next_id = w.batches.begin()->first + 1;
        w.batches.erase(w.batches.begin());
    }
    db->update_dump(pk, swarm, w.next_id, {});

    advance_dump(it->first, w);
}

void ServiceNode::process_snodes_update(std::string_view data) {
    auto maybe_bu = parse_swarm_update(data, our_keys_.pub);

    std::lock_guard lock{sn_mutex_};

    if (maybe_bu && !got_first_response_.exchange(true)) {
        log::info(logcat, "Got initial swarm information from local Oxend");
        const int total = maybe_bu->contacts.size();
        const int contactable = std::ranges::count_if(
                maybe_bu->contacts, [](const auto& c) { return c.second.contactable(); });
        const int missing = total - contactable;

        if (syncing_) {
            if (skip_bootstrap_) {
                log::warning(
                        logcat,
                        "oxend looks behind but bootstrap nodes are disabled; assuming its data "
                        "is current");
                syncing_ = false;
            } else {
                log::info(
                        logcat,
                        "oxend is still syncing; asking bootstrap nodes for the network's height "
                        "and node data");
                bootstrap_fallback();
            }
        } else if (
                !skip_bootstrap_ &&
                (total < (oxenss::is_mainnet ? 100 : 10) ||
                 missing > MISSING_PUBKEY_THRESHOLD::num * total / MISSING_PUBKEY_THRESHOLD::den)) {
            // A synced oxend can still have hardly any contact details: it learns IPs, ports and
            // pubkeys from uptime proofs, which take up to an hour to reach a fresh oxend.  The
            // list is used as it is, and the bootstrap nodes fill in what it lacks.
            log::info(
                    logcat,
                    "Initialized from oxend, but only {}/{} service nodes are contactable; asking "
                    "bootstrap nodes for contact info",
                    contactable,
                    total);
            bootstrap_fallback();
        } else
            log::info(
                    logcat,
                    "Initialized from oxend with {}/{} contactable service nodes",
                    contactable,
                    total);
    }

    if (maybe_bu) {
        log::debug(logcat, "Blockchain updated, rebuilding swarm list");
        on_snodes_update(std::move(*maybe_bu));
    }
}

void ServiceNode::update_last_ping(ReachType type) {
    reach_records_.incoming_ping(type);
}

void ServiceNode::ping_peers() {
    std::lock_guard lock{sn_mutex_};

    // TODO: Don't do anything until we are fully funded

    if (status_ == SnodeStatus::UNSTAKED || status_ == SnodeStatus::UNKNOWN) {
        log::trace(logcat, "Skipping peer testing (unstaked)");
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // Check if we've been tested (reached) recently ourselves.  Only nodes older than
    // SN_QUIC_VERSION test oxenmq ports (see test_reachability), so once none are left an oxenmq
    // ping is not expected.
    reach_records_.check_incoming_tests(now, network_.min_peer_version() < SN_QUIC_VERSION);

    if (status_ == SnodeStatus::DECOMMISSIONED) {
        log::trace(logcat, "Skipping peer testing (decommissioned)");
        return;
    }

    /// We always test nodes due to be tested plus one general, non-failing node.

    auto to_test = reach_records_.get_failing(now);
    for (int i = 0; i < reachability_testing::RANDOM_TESTS_PER_TICK; i++) {
        auto rando = reach_records_.next_random(swarm_, now);
        if (!rando)
            break;
        to_test.emplace_back(std::move(*rando), 0);
    }

    if (to_test.empty())
        log::trace(logcat, "no nodes to test this tick");
    else
        log::debug(logcat, "{} nodes to test", to_test.size());
    for (const auto& [sn, prev_fails] : to_test)
        test_reachability(sn, prev_fails);
}

void ServiceNode::test_reachability(const crypto::legacy_pubkey& sn, int previous_failures) {
    log::debug(
            logcat,
            "Testing {} SN {} for reachability",
            previous_failures > 0 ? "previously failing" : "random",
            sn);

    auto http = http_.lock();
    if (!http) {
        log::debug(logcat, "Skipping reachability test during shutdown");
        return;
    }

    auto c = network_.contacts.find(sn);
    if (!c || !*c) {
        // oxend won't accept uncontactable info in an uptime proof, which means if we get here the
        // node hasn't sent an uptime proof; we could treat it as a failure, but that seems
        // unnecessary since oxend will already fail the service node for not sending uptime proofs.
        log::debug(logcat, "Not testing {}: node is uncontactable", sn);
        reach_records_.remove_node_from_failing(sn);
        return;
    }

    // From SN_QUIC_VERSION a node is reached over HTTPS and QUIC only: clients use nothing else,
    // and node-to-node traffic with it goes over QUIC.  Its oxenmq listener stays up for older
    // peers but is not tested, so that it can go away once every node is at that version.
    const bool test_omq = !peer_is_current(*c);

    auto test = std::make_shared<sn_test>(
            sn,
            1 + mq_servers_.size() - (test_omq ? 0 : 1),
            [this, previous_failures](const crypto::legacy_pubkey& sn, bool passed) {
                report_reachability(sn, passed, previous_failures);
            });

    for (auto* mq : mq_servers_)
        if (test_omq || mq != &omq_server_)
            mq->reachability_test(test);

    auto url = fmt::format("https://{}:{}/ping_test/v1", c->ip, c->https_port);
    std::optional<std::string> host;
    host = "{}.snode"_format(oxenc::to_base32z(sn.view()));

    log::debug(logcat, "Sending HTTPS ping to {} @ {}", sn, url);
    http->post(
            [test](cpr::Response r) {
                const auto& pk = test->pubkey;
                bool success = false;
                if (r.error.code != cpr::ErrorCode::OK) {
                    log::debug(logcat, "FAILED HTTPS ping test of {}: {}", pk, r.error.message);
                } else if (r.status_code != 200) {
                    log::debug(
                            logcat,
                            "FAILED HTTPS ping test of {}: received non-200 status {} {}",
                            pk,
                            r.status_code,
                            r.status_line);
                } else {
                    if (auto it = r.header.find(http::SNODE_PUBKEY_HEADER); it == r.header.end())
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: {} response header missing",
                                pk,
                                http::SNODE_PUBKEY_HEADER);
                    else if (auto remote_pk = crypto::parse_legacy_pubkey(it->second);
                             remote_pk != pk)
                        log::debug(
                                logcat,
                                "FAILED HTTPS ping test of {}: reply has wrong pubkey {}",
                                pk,
                                remote_pk);
                    else
                        success = true;
                }
                if (success)
                    log::debug(logcat, "Successful HTTPS ping test of {}", pk);

                test->add_result(success);
            },
            std::move(url),
            ""s /*body*/,
            SN_PING_TIMEOUT,
            std::move(host),
            true /*disable https validation*/);
}

void ServiceNode::oxend_ping() {
    std::lock_guard guard(sn_mutex_);

    json oxend_params{
            {"version", STORAGE_SERVER_VERSION},
            {"pubkey_ed25519", our_contact_.pubkey_ed25519.hex()},
            {"https_port", our_contact_.https_port},
            {"omq_port", our_contact_.omq_quic_port}};

    omq_server_.oxend_request(
            "admin.storage_server_ping",
            [this](bool success, std::vector<std::string> data) {
                if (!success)
                    log::critical(
                            logcat, "Could not ping oxend: Request failed ({})", data.front());
                else if (data.size() < 2 || data[1].empty())
                    log::critical(logcat, "Could not ping oxend: Empty body on reply");
                else
                    try {
                        if (const auto status =
                                    json::parse(data[1]).at("status").get<std::string>();
                            status == "OK") {
                            auto good_pings = ++oxend_pings_;
                            if (good_pings == 1)  // First ping after startup or after ping failure
                                log::info(logcat, "Successfully pinged oxend");
                            else if (good_pings % (1h / OXEND_PING_INTERVAL) == 0)  // Once an hour
                                log::info(logcat, "{} successful oxend pings", good_pings);
                            else
                                log::debug(
                                        logcat,
                                        "Successfully pinged Oxend ({} consecutive times)",
                                        good_pings);
                        } else {
                            log::critical(logcat, "Could not ping oxend: {}", status);
                            oxend_pings_ = 0;
                        }
                    } catch (...) {
                        log::critical(logcat, "Could not ping oxend: bad json in response");
                    }
            },
            oxend_params.dump());

    // Also re-subscribe (or subscribe, in case oxend restarted) to block and snode address
    // subscriptions.  This makes oxend start firing notify.block/notify.snode_addr messages at as
    // whenever new blocks or contact-changing proofs arrive, but we have to renew the subscriptions
    // within 30min to keep them alive, so do it here (it doesn't hurt anything for it to be much
    // faster than 30min).
    omq_server_.oxend_request("sub.block", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to oxend block notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to oxend new block notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed oxend new block notification subscription");
    });

    omq_server_.oxend_request("sub.snode_addr", [](bool success, auto&& result) {
        if (!success || result.empty())
            log::critical(
                    logcat,
                    "Failed to subscribe to oxend address notifications: {}",
                    result.empty() ? "response is empty" : result.front());
        else if (result.front() == "OK")
            log::info(logcat, "Subscribed to oxend address change notifications");
        else if (result.front() == "ALREADY")
            log::debug(logcat, "Renewed oxend address change notification subscription");
    });
}

void ServiceNode::report_reachability(
        const crypto::legacy_pubkey& sn_pk, bool reachable, int previous_failures) {
    auto cb = [sn_pk, reachable](bool success, std::vector<std::string> data) {
        if (!success) {
            log::warning(
                    logcat,
                    "Could not report node status: {}",
                    data.empty() ? "unknown reason" : data[0]);
            return;
        }

        if (data.size() < 2 || data[1].empty()) {
            log::warning(logcat, "Empty body on Oxend report node status");
            return;
        }

        try {
            const auto status = json::parse(data[1]).at("status").get<std::string>();

            if (status == "OK") {
                log::debug(
                        logcat,
                        "Successfully reported {} node: {}",
                        reachable ? "reachable" : "UNREACHABLE",
                        sn_pk);
            } else {
                log::warning(logcat, "Could not report node: {}", status);
            }
        } catch (...) {
            log::error(logcat, "Could not report node status: bad json in response");
        }
    };

    json params{{"type", "storage"}, {"pubkey", sn_pk.hex()}, {"passed", reachable}};

    omq_server_.oxend_request("admin.report_peer_status", std::move(cb), params.dump());

    if (!reachable || previous_failures > 0) {
        std::lock_guard guard(sn_mutex_);
        if (!reachable)
            reach_records_.add_failing_node(sn_pk, previous_failures);
        else
            reach_records_.remove_node_from_failing(sn_pk);
    }
}

void ServiceNode::bootstrap_swarms(const std::set<swarm_id_t>& swarms) {
    std::lock_guard guard(sn_mutex_);

    auto targets = swarms.empty() ? network_.get_all_swarm_ids() : swarms;
    if (swarms.empty())
        log::info(logcat, "Bootstrapping all swarms");
    else if (logcat->level() <= log::Level::info)
        log::info(logcat, "Bootstrapping swarms: [{}]", fmt::join(swarms, ", "));

    for (const auto& swarm_id : targets) {
        auto members = network_.get_swarm(swarm_id);
        if (!members)
            continue;
        auto [lower, upper] = network_.get_swarm_boundaries(swarm_id);
        if (!db->has_owners_in_range(lower, upper))
            continue;
        for (const auto& pk : *members)
            if (pk != our_keys_.pub)
                queue_dump(pk, swarm_id);
    }
}

void to_json(nlohmann::json& j, const test_result& val) {
    j["timestamp"] = std::chrono::duration<double>(val.timestamp.time_since_epoch()).count();
    j["result"] = to_str(val.result);
}

static nlohmann::json to_json(const all_stats& stats) {
    json peers;
    for (const auto& [pk, stats] : stats.peer_report()) {
        auto& p = peers[pk.hex()];

        p["requests_failed"] = stats.requests_failed;
        p["pushes_failed"] = stats.requests_failed;
    }

    auto [window, recent] = stats.get_recent_requests();
    return json{
            {"total_store_requests", stats.get_total_store_requests()},
            {"total_retrieve_requests", stats.get_total_retrieve_requests()},
            {"total_onion_requests", stats.get_total_onion_requests()},
            {"total_proxy_requests", stats.get_total_proxy_requests()},

            {"recent_timespan", std::chrono::duration<double>(window).count()},
            {"recent_store_requests", recent.client_store_requests},
            {"recent_retrieve_requests", recent.client_retrieve_requests},
            {"recent_onion_requests", recent.onion_requests},
            {"recent_proxy_requests", recent.proxy_requests},

            {"peers", std::move(peers)}};
}

std::string ServiceNode::get_stats_for_session_client() const {
    return json{{"version", STORAGE_SERVER_VERSION_STRING}}.dump();
}

std::string ServiceNode::get_stats() const {
    auto val = to_json(all_stats_);

    val["version"] = STORAGE_SERVER_VERSION_STRING;
    val["height"] = block_height_;
    val["target_height"] = target_height_;

    std::vector<int> counts = db->get_message_counts();
    int64_t total = std::accumulate(counts.begin(), counts.end(), int64_t{0});

    counts.erase(
            std::remove_if(counts.begin(), counts.end(), [](int c) { return c < 2; }),
            counts.end());

    // If less than 5 our iterators below could end up at the same position, so just require at
    // least 5 rather than worrying about that case:
    if (counts.size() >= 5) {
        // We're going to calculate a few numbers here from the list of stored account sizes:
        // - minimum
        // - 5th percentile
        // - 25th percentile
        // - median (i.e. 50th percentile)
        // - 75th percentile
        // - 95th percentile
        // - maximum
        // - total
        // - mean
        //
        // To get a percentile we partially sort the data via nth_element; we don't muck around with
        // averaging the middle two elements or anything like that (because that's of limited actual
        // real world use) and instead just use the upper value by rounding up.  These look a little
        // weird as `size-1+n` values but that's because we to divide the top index, not the size.
        auto pct_5th = std::next(counts.begin(), (counts.size() - 1 + 19) / 20 - 1);
        auto pct_25th = std::next(counts.begin(), (counts.size() - 1 + 3) / 4 - 1);
        auto pct_50th = std::next(counts.begin(), (counts.size() - 1) / 2 - 1);
        auto pct_75th = std::next(counts.begin(), (3 * counts.size() - 1 + 3) / 4 - 1);
        auto pct_95th = std::next(counts.begin(), (19 * counts.size() - 1 + 19) / 20);
        std::nth_element(counts.begin(), pct_5th, counts.end());
        std::nth_element(std::next(pct_5th), pct_25th, counts.end());
        std::nth_element(std::next(pct_25th), pct_50th, counts.end());
        std::nth_element(std::next(pct_50th), pct_75th, counts.end());
        std::nth_element(std::next(pct_75th), pct_95th, counts.end());

        val["account_msg_count_min"] = *std::min_element(counts.begin(), pct_5th);
        val["account_msg_count_max"] = *std::max_element(pct_95th, counts.end());
        val["account_msg_count_5th"] = *pct_5th;
        val["account_msg_count_25th"] = *pct_25th;
        val["account_msg_count_median"] = *pct_50th;
        val["account_msg_count_75th"] = *pct_75th;
        val["account_msg_count_95th"] = *pct_95th;
    }

    val["accounts"] = counts.size();
    val["total_stored"] = total;
    if (counts.size() > 0)
        val["account_msg_mean"] = total / (double)counts.size();

    auto& ns_stats = (val["namespace_messages"] = nlohmann::json::object());
    for (auto& [ns, count] : db->get_namespace_counts())
        ns_stats[fmt::format("{}", ns)] = count;

    val["db_used"] = db->get_used_bytes();
    val["db_total"] = db->get_total_bytes();
    val["db_max"] = Database::SIZE_LIMIT;

    return val.dump();
}

std::string ServiceNode::get_status_line() const {
    // This produces a short, single-line status string, used when running as a
    // systemd Type=notify service to update the service Status line.  The
    // status message has to be fairly short: has to fit on one line, and if
    // it's too long systemd just truncates it when displaying it.

    // syncing_ is all that needs sn_mutex_: the swarm and stats accessors lock internally, and the
    // database has its own connection pool.
    bool syncing;
    {
        std::lock_guard guard(sn_mutex_);
        syncing = syncing_;
    }

    std::string swarm_disp;
    if (auto our_swid = swarm_.our_swarm_id(); our_swid == INVALID_SWARM_ID)
        swarm_disp = "NONE";
    else {
        std::string swarm_hex = "{:016x}"_format(our_swid);
        std::string_view sw{swarm_hex};
        swarm_disp = "{}…{}(n={})"_format(sw.substr(0, 4), sw.substr(sw.size() - 3), swarm_.size());
    }
    auto [window, stats] = all_stats_.get_recent_requests();

    // v2.3.4; sw=abcd…789(n=7); 1234 msgs (47.3 MB) for 567 users; reqs(S/R/O/P):
    // 123/456/789/1011 (last 62.3min)
    return "v{}{}{}; {} msgs ({}) for {} accts; reqs(S/R/O/P): {}/{}/{}/{} (last {})"_format(
            STORAGE_SERVER_VERSION_STRING,
            oxenss::is_mainnet ? "" : " (TESTNET)",
            syncing ? "; SYNCING" : "",
            db->get_message_count(),
            util::get_human_readable_bytes(db->get_used_bytes()),
            db->get_owner_count(),
            stats.client_store_requests,
            stats.client_retrieve_requests,
            stats.onion_requests,
            stats.proxy_requests,
            util::short_duration(window));
}

bool ServiceNode::process_push_batch(std::string_view blob, std::string_view sender) {
    if (blob.empty())
        return true;

    std::vector<message> items;
    try {
        items = deserialize_messages(blob);
    } catch (const std::exception& e) {
        log::warning(
                logcat,
                "Failed to deserialize incoming message batch from {}: {}",
                sender,
                e.what());
        return false;
    }

    log::debug(logcat, "Got {} messages from peers, size: {}", items.size(), blob.size());

    return save_bulk(items);
}

void ServiceNode::check_retry_requests() {
    db->remove_expired_retry_requests();

    db->foreach_ready_retry_request([this](const crypto::legacy_pubkey& key,
                                           const std::string& cmd,
                                           const std::string& payload,
                                           int64_t req_id) {
        // A node that has left our swarm no longer owns the messages the request is about
        if (!swarm_.is_member(key)) {
            db->remove_node_retry_request(req_id);
            return false;
        }

        auto ct = contacts().find(key);
        if (!ct || !*ct)
            return false;

        auto on_request_done = [this, req_id](bool success, std::vector<std::string> parts) {
            // We cleanup the request in all situations except timeout (timeout
            // indicating that the node was non-responsive, maybe offline). In an error
            // state we don't know what state the recipient's storage server is in and
            // we default to deleting it and ending the retry attempts.
            rpc::SNStorageCCResult store_result =
                    rpc::interpret_sn_storage_cc_response_parts(success, parts);
            if (store_result.status != rpc::SNStorageCCResultStatus::Timeout) {
                db->remove_node_retry_request(req_id);
            }
        };
        sn_request(*ct, "storage_cc", {cmd, payload}, on_request_done, RETRY_REQUEST_TIMEOUT);
        return true;
    });
}

}  // namespace oxenss::snode
