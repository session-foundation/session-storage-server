#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <oxenss/crypto/keys.h>
#include <oxenss/common/message.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/storage/database.hpp>
#include "network.h"
#include "swarm.h"
#include "reachability_testing.h"
#include "stats.h"
#include "contacts.h"

namespace oxenss::server {
class OMQ;
class QUIC;
class MQBase;
}  // namespace oxenss::server

namespace oxenss::rpc {
struct OnionRequestMetadata;
}

namespace oxenss::http {
class Client;
}

namespace oxenss::snode {

inline constexpr size_t BLOCK_HASH_CACHE_SIZE = 30;

// How long we wait for a HTTPS or OMQ ping response from another SN when ping testing
inline constexpr auto SN_PING_TIMEOUT = 5s;

// Timeout for bootstrap node OMQ requests
inline constexpr auto BOOTSTRAP_TIMEOUT = 10s;

// At startup our oxend is taken to be synced if its top block is at most this old.  Only an oxend
// that is behind sends us to the bootstrap nodes to find out how far behind it is.
inline constexpr auto MAX_SYNCED_BLOCK_AGE = 1h;

// Thrown out of startup when the daemon is asked to stop (SIGINT/SIGTERM) before it is up.
struct startup_aborted : std::exception {
    const char* what() const noexcept override { return "startup aborted"; }
};

// Waits for the result of a startup step, checking `keep_going` every quarter second and throwing
// startup_aborted when it says to stop, with a warning every few seconds while still waiting.  The
// step's callback may fire after an abort, so it must own its promise (see the shared_ptr
// promises in the callers) rather than point at the waiter's stack.
template <typename T>
T await_startup(
        std::future<T>& fut,
        const std::function<bool()>& keep_going,
        std::string_view waiting_for) {
    for (int ticks = 1;; ticks++) {
        if (fut.wait_for(250ms) == std::future_status::ready)
            return fut.get();
        if (!keep_going())
            throw startup_aborted{};
        if (ticks % 20 == 0)
            log::warning(log::Cat("snode"), "Still waiting for {}...", waiting_for);
    }
}

/// We test based on the height a few blocks back to minimise discrepancies between nodes (we
/// could also use checkpoints, but that is still not bulletproof: swarms are calculated based
/// on the latest block, so they might be still different and thus derive different pairs)
inline constexpr uint64_t TEST_BLOCKS_BUFFER = 4;

// We use the network hardfork and snode revision from oxend to version-gate upgrade features.
using hf_revision = std::pair<int, int>;

// The earliest hardfork *this* version of storage server will work on:
inline constexpr hf_revision STORAGE_SERVER_HARDFORK = {19, 6};

// The storage server version at which initial handshaking is supported before attempting a swarm
// message transfer.
inline constexpr std::array<uint16_t, 3> NEW_SWARM_MEMBER_HANDSHAKE_VERSION = {2, 10, 0};
// The storage server version at which the sn.data_ready handshake carries a request payload (which
// lets the new member ask us for a copy of the swarm's messages).  Older versions ignore any
// payload, and send none.
inline constexpr std::array<uint16_t, 3> SN_DATA_READY_WITH_REQUEST_VERSION = {2, 12, 0};

// The storage server version from which node-to-node traffic goes over a held QUIC connection
// (negotiated with server::SN_ALPN) rather than oxenmq.  Older versions only accept the client
// ALPN and only the commands a client may send.
inline constexpr std::array<uint16_t, 3> SN_QUIC_VERSION = {2, 12, 0};

constexpr std::string_view to_string(SnodeStatus status) {
    switch (status) {
        case SnodeStatus::UNSTAKED: return "Unstaked"sv;
        case SnodeStatus::DECOMMISSIONED: return "Decommissioned"sv;
        case SnodeStatus::ACTIVE: return "Active"sv;
        case SnodeStatus::UNKNOWN: return "Unknown"sv;
    }
    return "Unknown"sv;
}

/// All service node logic that is not network-specific
class ServiceNode {
    bool syncing_ = true;
    bool active_ = false;
    std::atomic<bool> got_first_response_ = false;
    bool force_start_ = false;
    bool skip_bootstrap_ = false;
    std::atomic<bool> shutting_down_ = false;
    hf_revision hardfork_ = {0, 0};
    uint64_t block_height_ = 0;
    uint64_t target_height_ = 0;
    std::string block_hash_;
    std::weak_ptr<http::Client> http_;

  public:
    // bit messy, but Swarm needs db startup version, so db has to init before Swarm
    std::unique_ptr<Database> db;

  private:
    SnodeStatus status_ = SnodeStatus::UNKNOWN;

    const crypto::legacy_keypair our_keys_;
    const contact our_contact_;

    Network network_;

    Swarm swarm_;

    server::OMQ& omq_server_;
    std::vector<server::MQBase*> mq_servers_;
    // The QUIC server, once registered: node-to-node requests go to it first, and it hands back
    // those for nodes that do not speak QUIC to be sent over oxenmq (see sn_request).
    server::MQBase* quic_server_ = nullptr;

    std::atomic<int> oxend_pings_ =
            0;  // Consecutive successful pings, used for batching logs about it

    // Will be set to true while we have an outstanding update_swarms() call so that we squelch
    // other update_swarms() until it finishes (or fails), to avoid spamming oxend (particularly
    // when syncing when we get tons of block notifications quickly).
    std::atomic<bool> updating_swarms_ = false;

    reachability_testing reach_records_;

    mutable all_stats all_stats_;

    mutable std::recursive_mutex sn_mutex_;

    void send_notifies(message m);

    // Save multiple messages to the database at once (i.e. in a single transaction).  Returns
    // false if they could not be saved.
    bool save_bulk(const std::vector<message>& msgs);

    void process_snodes_update(std::string_view data);

    void on_bootstrap_update(block_update&& bu);

    void on_snodes_update(block_update&& bu);

    // Called periodically to handshake with new swarm members (asking them for a dump of the
    // swarm's messages if we need one).
    void check_new_members();

    // Asks the bootstrap nodes for their view of the network: the height they are at (which tells
    // us when our own oxend has caught up) and their contact info for the nodes.  Used at startup
    // when our oxend is behind, or has a full node list but hardly any contact details (a fresh
    // oxend receives those over the network for up to an hour).
    void bootstrap_fallback();

    // Queues dumps of the messages we hold for each of the given swarms (all swarms, if empty) to
    // that swarm's members.  Used when a new swarm appears next to ours, and when our own swarm
    // dissolves.
    void bootstrap_swarms(const std::set<swarm_id_t>& swarms = {});

    // Dumps of our messages to other nodes.  Each dump is a database row holding the persisted
    // cursor (see Database::pending_dump) plus, while it is being sent, one of these tracking the
    // batches in flight.  Batches are acknowledged individually and possibly out of order, so the
    // persisted cursor advances only across the contiguous prefix of acknowledged batches.
    struct dump_window {
        int64_t next_id;                 // first id not yet acknowledged; mirrors the database row
        int64_t end_id;                  // last id the dump covers
        int64_t sent_next_id;            // first id not yet sent
        std::map<int64_t, int> batches;  // last id of each sent batch -> parts awaiting an ack
        int in_flight = 0;               // batches with parts awaiting an ack
        bool exhausted = false;          // nothing left to send before end_id
        uint64_t generation;             // tells acks for a discarded window from a restarted one
        int64_t sent_messages = 0;
    };
    using dump_key = std::pair<crypto::legacy_pubkey, swarm_id_t>;
    std::mutex dumps_mutex_;
    std::map<dump_key, dump_window> dump_windows_;
    uint64_t dump_generation_ = 0;

    void queue_dump(const crypto::legacy_pubkey& pk, swarm_id_t swarm);
    // Periodic: starts or resumes any dump or delivery that is due.
    void check_dumps();
    // The following require dumps_mutex_ to be held.
    void check_dumps_locked();
    // Sends batches of the dump until the window is full or the dump is finished.  `key` and `w`
    // may be invalidated (the window erased) by this call.
    void advance_dump(const dump_key& key, dump_window& w);
    void on_dump_batch_reply(const dump_key& key, int64_t last_id, uint64_t generation, bool ok);

    // Pending deliveries (Database::queue_delivery) go out over sn.data with one batch in flight
    // per node, sharing the dump batch size, timeout and retry delay.  The in-flight entry counts
    // the batch's parts still awaiting a reply and whether any failed.
    std::map<crypto::legacy_pubkey, std::pair<int, bool>> deliveries_in_flight_;
    std::map<crypto::legacy_pubkey, std::chrono::system_clock::time_point> delivery_retry_after_;
    // These require dumps_mutex_ to be held.
    void check_deliveries_locked();
    void send_deliveries(const crypto::legacy_pubkey& pk);
    void on_delivery_reply(
            const crypto::legacy_pubkey& pk, const std::vector<int64_t>& ids, bool ok);

    // Conducts any ping peer tests that are due; (this is designed to be called frequently and
    // does nothing if there are no tests currently due).
    void ping_peers();

    /// Pings oxend (as required for uptime proofs)
    void oxend_ping();

    // Initiate node ping tests
    void test_reachability(const crypto::legacy_pubkey& sn, int previous_failures);

    // Reports node reachability result to oxend and, if a failure, queues the node for
    // retesting.
    void report_reachability(
            const crypto::legacy_pubkey& sn, bool reachable, int previous_failures);

  public:
    ServiceNode(
            const crypto::legacy_keypair& keys,
            const contact& contact,
            server::OMQ& omq_server,
            const std::filesystem::path& db_location,
            bool force_start,
            bool skip_bootstrap);

    const Network& network() { return network_; }

    const Swarm& swarm() { return swarm_; }

    Contacts& contacts() { return network_.contacts; }

    const Contacts& contacts() const { return network_.contacts; }

    const contact& own_address() { return our_contact_; }

    // Adds a MQ server, i.e. QUIC.  The OMQ server is added automatically during construction and
    // should not be added.
    void register_mq_server(server::MQBase* server);

    // Sets the http client needed to perform HTTPS reachability tests
    void set_http_client(std::weak_ptr<http::Client> client) { http_ = std::move(client); }

    // Return info about this node as it is advertised to other nodes
    const crypto::legacy_pubkey& own_pubkey() const { return our_keys_.pub; }

    // Record the time of our last being tested over omq/https
    void update_last_ping(ReachType type);

    // These three are only needed because we store stats in Service Node,
    // might move it out later
    void record_proxy_request();
    void record_onion_request();
    void record_retrieve_request();

    /// Sends an onion request to the next SS
    void send_onion_to_sn(
            const contact& ct,
            std::string_view payload,
            rpc::OnionRequestMetadata&& data,
            std::function<void(bool success, std::vector<std::string> data)> cb);

    const hf_revision& hf() const { return hardfork_; }

    const uint64_t& blockheight() const { return block_height_; }

    bool hf_at_least(hf_revision version) const { return hardfork_ >= version; }

    // Return true if the service node is ready to handle requests, which means the storage
    // server is fully initialized (and not trying to shut down), the service node is active and
    // assigned to a swarm and is not syncing.
    //
    // Returns false and, if `reason` is non-nullptr, sets a reason string during initialization and
    // while shutting down.
    //
    // If this ServiceNode was created with force_start enabled then this function always
    // returns true (except when shutting down); the reason string is still set (when non-null)
    // when errors would have occurred without force_start.
    bool snode_ready(std::string* reason = nullptr);

    // Puts the storage server into shutdown mode; this operation is irreversible and should
    // only be used during storage server shutdown.
    void shutdown();

    // Returns true if the storage server is currently shutting down.
    bool shutting_down() const { return shutting_down_; }

    /// Process message received from a client, return false if not in a swarm.  If new_msg is not
    /// nullptr, sets it to true if we stored as a new message, false if we already had it.  If
    /// `expiry` is non-null it will be set to the message's expiry: for a new message this is the
    /// given expiry; for existing messages this is the message's new expiry (which might have been
    /// extended to match the one in `msg`, if later).
    bool process_store(
            message msg,
            bool* new_msg = nullptr,
            std::chrono::system_clock::time_point* expiry = nullptr);

    /// Process incoming blob of messages: add to DB if new.  Returns false if the blob could not be
    /// decoded or the messages could not be stored.
    bool process_push_batch(std::string_view blob, std::string_view sender);

    // Stats for session clients that want to know the version number
    std::string get_stats_for_session_client() const;

    std::string get_stats() const;

    std::string get_status_line() const;

    // Called once we have established the initial connection to our local oxend to set up
    // initial data and timers that rely on an oxend connection.  This blocks until we know whether
    // oxend is synced (see MAX_SYNCED_BLOCK_AGE) and have its service node list; when it is
    // synced, that list is in effect by the time this returns, so listeners started afterwards
    // recognize the network from their first request.  Throws startup_aborted if `keep_going`
    // returns false while waiting on oxend.
    void on_oxend_connected(const std::function<bool()>& keep_going);

    // Called when oxend notifies us of a new block to update swarm info.  `on_completion`, if
    // given, is set to whether the update succeeded once oxend has answered.
    void update_swarms(std::shared_ptr<std::promise<bool>> on_completion = nullptr);

    // Queues a dump to `pk` of all the messages we currently hold for our swarm.  Called when a
    // swarm member asks for one in its sn.data_ready handshake.  Does nothing if we are not in a
    // swarm.
    void queue_swarm_dump(const crypto::legacy_pubkey& pk);

    // Handles a data_ready handshake from swarm member `pk` (see check_new_members).  `payload`
    // is the request payload, empty from pre-2.12 nodes.  Returns the reply to send: "OK", or a
    // reason the handshake was refused.
    std::string data_ready_handshake(const crypto::legacy_pubkey& pk, std::string_view payload);

    // Sends a node-to-node request to `ct` (see server::MQBase::sn_request): over QUIC for a node
    // that speaks it, over oxenmq for the rest.
    void sn_request(
            const contact& ct,
            std::string_view cmd,
            std::vector<std::string> parts,
            std::function<void(bool success, std::vector<std::string> parts)> cb,
            std::chrono::milliseconds timeout);

    // True if the node runs SN_QUIC_VERSION or later: it reports so, or it holds a node-to-node
    // QUIC connection with us, which only such a version makes.  (The reported version lags an
    // upgrade by up to an hour.)
    bool peer_is_current(const contact& ct);

    // Called when a connection with another storage server is established: starts or resumes any
    // dump or delivery that was waiting on the node being reachable.
    void resume_transfers() { check_dumps(); }

    // Delivers our stored message with the given hash to swarm peer `pk` over sn.data, retrying
    // until it arrives or the message is gone.  Used when forwarding a client's store to `pk`
    // failed: replaying the store request instead would be refused by the peer once the client's
    // signature timestamp is more than a minute old.
    void queue_delivery(const crypto::legacy_pubkey& pk, const std::string& hash);

    server::OMQ& omq_server() { return omq_server_; }

    void check_retry_requests();
};

}  // namespace oxenss::snode

template <>
inline constexpr bool oxenss::to_string_formattable<oxenss::snode::SnodeStatus> = true;
