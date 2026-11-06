#include "monitors.h"

#include <sodium/crypto_sign.h>

#include <algorithm>
#include <cassert>
#include <cstring>

#include <fmt/ranges.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include "../common/message.h"
#include "../crypto/subaccount.h"
#include "../snode/service_node.h"
#include "../snode/swarm.h"
#include "../utils/time.hpp"

namespace oxenss::server {

static auto logcat = log::Cat("server");

snode::swarm_membership Monitors::swarm_for(const user_pubkey& pk) const {
    return service_node_->network().get_swarm_for(pk);
}

snode::swarm_id_t Monitors::our_swarm_id() const {
    return service_node_->swarm().our_swarm_id();
}

const snode::Contacts& Monitors::contacts() const {
    return std::as_const(*service_node_).contacts();
}

void Monitors::handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<subscription>& subs) {

    // Values we receive, in bt-dict order:
    std::string_view ed_pk;                         // P (ed25519 pubkey only for session ids)
    std::optional<signed_subaccount_token> subacc;  // S (token signature), T (token)
    bool want_data = false;                         // d (given and true if data is desired)
    using namespace_int = std::underlying_type_t<namespace_id>;
    std::vector<namespace_id> namespaces;  // n (ordered list of numeric namespaces)
    std::string pubkey;                    // p (network id + ed25519 pubkey; not a session id)
    std::string_view signature;            // s (signature, by subacc.token.pubkey() or pubkey)
    std::chrono::seconds timestamp;        // t

    try {
        // Ed25519 pubkey for a Session ID (required if `p` is not present)
        if (d.skip_until("P")) {
            ed_pk = d.consume_string_view();
            if (ed_pk.size() != 32)
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided P= Session Ed25519 pubkey must be 32 bytes");
        }

        // Subaccount signature & token
        if (d.skip_until("S")) {
            subacc.emplace();
            if (auto sig = d.consume_string_view(); sig.size() == subacc->signature.size())
                std::memcpy(subacc->signature.data(), sig.data(), sig.size());
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided S subaccount signature must be {} bytes"_format(
                                subacc->signature.size()));

            if (auto token = d.require<std::string_view>("T");
                token.size() == SUBACCOUNT_TOKEN_LENGTH)
                std::memcpy(subacc->token.token.data(), token.data(), token.size());
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_PUBKEY,
                        "Provided T subaccount token must be {} bytes"_format(
                                SUBACCOUNT_TOKEN_LENGTH));
        }

        // Flag to send full message data as part of the pushed notifications (optional)
        if (d.skip_until("d"))
            want_data = d.consume_integer<bool>();

        // List of namespaces to monitor (required)
        auto ns = d.require<oxenc::bt_list_consumer>("n");
        namespaces.push_back(static_cast<namespace_id>(ns.consume_integer<namespace_int>()));
        while (!ns.is_finished()) {
            auto nsi = static_cast<namespace_id>(ns.consume_integer<namespace_int>());
            if (nsi > namespaces.back())
                namespaces.push_back(nsi);
            else
                return monitor_error(
                        out,
                        MonitorResponse::BAD_NS,
                        "Invalid n= namespace list: namespaces must be ascending");
        }

        // Account ID (i.e. network prefix followed by an Ed25519 pubkey).  *Not* for Session
        // IDs, which must use P instead (because Session IDs are X25519 pubkeys).
        if (d.skip_until("p")) {
            if (!ed_pk.empty())
                throw std::runtime_error{"Cannot provide both p= and P= pubkey values"};
            pubkey = d.consume_string();
            if (pubkey.size() != 33)
                return monitor_error(
                        out, MonitorResponse::BAD_PUBKEY, "Provided p= pubkey must be 33 bytes");
        } else if (ed_pk.empty()) {
            throw std::runtime_error{"Either p= or P= must be given"};
        }

        signature = d.require<std::string_view>("s");
        if (signature.size() != 64)
            return monitor_error(
                    out, MonitorResponse::BAD_SIG, "Provided s= signature must be 64 bytes");

        if (!d.skip_until("t"))
            throw std::runtime_error{"required signature timestamp is missing"};
        timestamp = std::chrono::seconds{d.consume_integer<int64_t>()};

    } catch (const std::exception& ex) {
        return monitor_error(out, MonitorResponse::BAD_ARGS, "Invalid arguments: "s + ex.what());
    }

    // Make sure the sig timestamp isn't too old or too new
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::time_point(timestamp);
    if (bool too_old = ts < now - 14 * 24h; too_old || ts > now + 24h) {
        return monitor_error(
                out,
                MonitorResponse::BAD_TS,
                "Invalid t= signature timestamp: timestamp is "s +
                        (too_old ? "too old" : "in the future"));
    }

    // If given an Ed25519 pubkey for a Session ID, derive the Session ID
    if (!ed_pk.empty()) {
        pubkey.resize(33);
        pubkey[0] = 0x05;
        if (auto rc = crypto_sign_ed25519_pk_to_curve25519(
                    reinterpret_cast<unsigned char*>(pubkey.data() + 1),
                    reinterpret_cast<const unsigned char*>(ed_pk.data()));
            rc != 0)
            return monitor_error(out, MonitorResponse::BAD_PUBKEY, "Invalid P= ed25519 public key");
    } else {
        // No Session Ed25519, so assume the pubkey (without prefix byte) is Ed25519
        ed_pk = pubkey;
        ed_pk.remove_prefix(1);
    }

    std::string_view verify_key = ed_pk;
    if (subacc) {
        try {
            subacc->verify(
                    pubkey[0],
                    reinterpret_cast<const unsigned char*>(ed_pk.data()),
                    subaccount_access::Read);
        } catch (const std::exception& ex) {
            auto m = "Subaccount verification failed: {}"_format(ex.what());
            log::warning(logcat, "{}", m);
            return monitor_error(out, MonitorResponse::BAD_SIG, m);
        }
        auto sub_pk = subacc->token.pubkey();
        verify_key = std::string_view{reinterpret_cast<const char*>(sub_pk.data()), sub_pk.size()};
    }
    assert(verify_key.size() == 32);

    auto pubkey_hex = oxenc::to_hex(pubkey);

    auto sig_msg = fmt::format(
            "MONITOR{:s}{:d}{:d}{}",
            pubkey_hex,
            timestamp.count(),
            want_data,
            fmt::join(namespaces, ","));

    if (0 != crypto_sign_verify_detached(
                     reinterpret_cast<const unsigned char*>(signature.data()),
                     reinterpret_cast<const unsigned char*>(sig_msg.data()),
                     sig_msg.size(),
                     reinterpret_cast<const unsigned char*>(verify_key.data()))) {
        log::debug(logcat, "monitor signature verification failed");
        return monitor_error(out, MonitorResponse::BAD_SIG, "Signature verification failed");
    }

    user_pubkey account;
    if (!account.load(pubkey))
        return monitor_error(
                out, MonitorResponse::BAD_PUBKEY, "Provided p= pubkey is not a valid account");

    // Knowing no swarms at all is not the same as knowing the account is someone else's: we have
    // no swarm to redirect the subscriber to, and this is most likely a transient gap in our oxend
    // data, so say so rather than claiming a wrong swarm.  `drop_foreign_monitors` holds onto
    // existing subscriptions in this same state.
    auto swarm = swarm_for(account);
    if (!swarm) {
        log::debug(logcat, "monitor: no swarms known, cannot place {}", pubkey_hex);
        return monitor_error(
                out,
                MonitorResponse::NO_SWARM_INFO,
                "Service node does not currently know the swarm list");
    }

    // A subscription to an account we do not store can never deliver anything, so refuse it and
    // hand back the swarm that does store it (the same information a 421 would carry).
    if (swarm->first != our_swarm_id()) {
        log::debug(logcat, "monitor: {} is not stored by this swarm", pubkey_hex);
        monitor_error(
                out,
                MonitorResponse::WRONG_SWARM,
                "Account is not stored by this service node's swarm");
        snode::swarm_to_bt(out, swarm, contacts());
        return;
    }

    subs.emplace_back(std::move(pubkey), std::move(pubkey_hex), std::move(namespaces), want_data);
    out.append("success", 1);
}

void Monitors::handle_monitor_message_single(
        oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<subscription>& subs) {
    handle_monitor_message_single(d, out, subs);
}

std::string Monitors::handle_monitor(std::string_view request, const connection_id& conn) {
    if (request.size() < 2 || !(request.front() == 'd' || request.front() == 'l') ||
        request.back() != 'e')
        return oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error",
                 "Invalid arguments: monitor request takes a single bencoded dict or list "
                 "parameter"}});

    std::string result;
    std::vector<subscription> subs;
    try {
        if (request.front() == 'd') {
            oxenc::bt_dict_producer out;
            handle_monitor_message_single(oxenc::bt_dict_consumer{request}, out, subs);
            result = std::move(out).str();
        } else {
            oxenc::bt_list_producer out;
            oxenc::bt_list_consumer l{request};
            while (!l.is_finished())
                handle_monitor_message_single(l.consume_dict_consumer(), out.append_dict(), subs);
            result = std::move(out).str();
        }
    } catch (const std::exception& e) {
        return oxenc::bt_serialize(oxenc::bt_dict{
                {"errcode", static_cast<int>(MonitorResponse::BAD_ARGS)},
                {"error", "Invalid arguments: Failed to parse monitor data value"}});
    }

    if (!subs.empty())
        update_monitors(subs, conn);

    return result;
}

void Monitors::update_monitors(std::vector<subscription>& subs, const connection_id& conn) {
    std::unique_lock lock{monitoring_mutex_};
    for (auto& sub : subs) {
        auto& [pubkey, pubkey_hex, namespaces, want_data] = sub;
        if (auto* mon_data = find_monitor(sub, conn)) {
            log::debug(
                    logcat,
                    "sub renewed for {} monitoring namespace(s) {}",
                    pubkey_hex,
                    fmt::join(mon_data->namespaces, ", "));
            mon_data->reset_expiry();
            continue;
        }
        log::debug(
                logcat,
                "new subscription for {} monitoring namespace(s) {}",
                pubkey_hex,
                fmt::join(namespaces, ", "));
        monitoring_conns_[conn].insert(pubkey);
        monitoring_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(std::move(pubkey)),
                std::forward_as_tuple(std::move(namespaces), want_data, conn));
    }
}

MonitorData* Monitors::find_monitor(const subscription& sub, const connection_id& conn) {
    for (auto [it, end] = monitoring_.equal_range(sub.pubkey); it != end; ++it) {
        auto& mon = it->second;
        if (mon.conn == conn && mon.namespaces == sub.namespaces && mon.want_data == sub.want_data)
            return &mon;
    }
    return nullptr;
}

bool Monitors::has_monitor(const std::string& account, const connection_id& conn) {
    for (auto [it, end] = monitoring_.equal_range(account); it != end; ++it)
        if (it->second.conn == conn)
            return true;
    return false;
}

std::unordered_multimap<std::string, MonitorData>::iterator Monitors::erase_monitor(
        std::unordered_multimap<std::string, MonitorData>::iterator it) {
    // Copied: both outlive the erase, which the account only leaves its connection's index after,
    // and then only if that was the connection's last monitor of it.
    auto account = it->first;
    auto conn = it->second.conn;
    auto next = monitoring_.erase(it);

    if (!has_monitor(account, conn))
        if (auto cit = monitoring_conns_.find(conn); cit != monitoring_conns_.end()) {
            cit->second.erase(account);
            if (cit->second.empty())
                monitoring_conns_.erase(cit);
        }
    return next;
}

void Monitors::remove_monitors_for(const connection_id& conn) {
    std::unique_lock lock{monitoring_mutex_};

    auto conn_it = monitoring_conns_.find(conn);
    if (conn_it == monitoring_conns_.end())
        return;

    log::debug(
            logcat,
            "dropping {} monitor subscription(s) of a closed connection",
            conn_it->second.size());

    for (const auto& account : conn_it->second) {
        auto [it, end] = monitoring_.equal_range(account);
        while (it != end) {
            if (it->second.conn == conn)
                it = monitoring_.erase(it);
            else
                ++it;
        }
    }

    monitoring_conns_.erase(conn_it);
}

void Monitors::remove_expired() {
    std::unique_lock lock{monitoring_mutex_};
    auto now = std::chrono::steady_clock::now();

    size_t expired = 0;
    for (auto it = monitoring_.begin(); it != monitoring_.end();) {
        if (it->second.expiry < now) {
            it = erase_monitor(it);
            ++expired;
        } else
            ++it;
    }

    if (expired)
        log::debug(logcat, "removed {} expired monitor(s)", expired);
}

std::vector<std::pair<user_pubkey, std::vector<connection_id>>> Monitors::extract_foreign_monitors(
        const std::function<bool(const user_pubkey&)>& still_ours) {

    std::vector<std::string> accounts;
    {
        std::shared_lock lock{monitoring_mutex_};
        accounts.reserve(monitoring_.size());
        // Entries with equal keys are adjacent in an unordered_multimap, so this collects each
        // monitored account exactly once.
        for (const auto& [account, _mon] : monitoring_)
            if (accounts.empty() || accounts.back() != account)
                accounts.push_back(account);
    }

    std::vector<std::pair<std::string, user_pubkey>> foreign;
    for (auto& account : accounts) {
        user_pubkey pk;
        if (!pk.load(account)) {
            log::warning(logcat, "Ignoring unparseable pubkey in the monitoring table");
            continue;
        }
        if (!still_ours(pk))
            foreign.emplace_back(std::move(account), std::move(pk));
    }

    std::vector<std::pair<user_pubkey, std::vector<connection_id>>> dropped;
    if (foreign.empty())
        return dropped;

    dropped.reserve(foreign.size());
    {
        std::unique_lock lock{monitoring_mutex_};
        for (auto& [account, pk] : foreign) {
            std::vector<connection_id> conns;
            auto [it, end] = monitoring_.equal_range(account);
            while (it != end) {
                conns.push_back(it->second.conn);
                it = erase_monitor(it);
            }
            // A connection with several monitors of the account is told once.
            std::ranges::sort(conns);
            conns.erase(std::unique(conns.begin(), conns.end()), conns.end());
            if (!conns.empty())
                dropped.emplace_back(std::move(pk), std::move(conns));
        }
    }

    return dropped;
}

std::string Monitors::monitor_ended_payload(
        const user_pubkey& pubkey, MonitorResponse reason, std::string_view message) {
    oxenc::bt_dict_producer d;
    d.append("@", pubkey.prefixed_raw());
    monitor_error(d, reason, std::string{message});
    snode::swarm_to_bt(d, swarm_for(pubkey), contacts());
    return std::move(d).str();
}

void Monitors::drop_foreign_monitors() {
    const auto our_swarm = our_swarm_id();

    auto dropped = extract_foreign_monitors([&](const user_pubkey& pk) {
        auto swarm = swarm_for(pk);
        // Knowing no swarms at all means we answer requests with a 500 rather than a 421, and we
        // would have no replacement swarm to offer, so hold onto the subscription instead of
        // terminating it on what is most likely a transient gap in our oxend data.
        return !swarm || swarm->first == our_swarm;
    });

    for (auto& [pk, conns] : dropped) {
        log::debug(
                logcat,
                "terminating {} monitor subscription(s) for {}: no longer in our swarm",
                conns.size(),
                pk.prefixed_hex());
        auto payload = monitor_ended_payload(
                pk,
                MonitorResponse::WRONG_SWARM,
                "Account is no longer stored by this service node's swarm");
        send(conns, "monitor_ended", payload);
    }
}

void Monitors::notify_message(const message& m) {
    auto pubkey = m.pubkey.prefixed_raw();
    // Each connection gets one notification however many of its monitors match: with data if any
    // of them wants it.
    std::map<connection_id, bool> to_conns;
    {
        auto now = std::chrono::steady_clock::now();
        std::shared_lock lock{monitoring_mutex_};

        for (auto [it, end] = monitoring_.equal_range(pubkey); it != end; ++it) {
            const auto& mon_data = it->second;
            if (mon_data.expiry >= now &&
                std::binary_search(
                        mon_data.namespaces.begin(), mon_data.namespaces.end(), m.msg_namespace))
                to_conns[mon_data.conn] |= mon_data.want_data;
        }
    }

    std::vector<connection_id> relay_to, relay_to_with_data;
    for (const auto& [conn, want_data] : to_conns)
        (want_data ? relay_to_with_data : relay_to).push_back(conn);

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
                                                 + m.data.size());

    d.append("@", pubkey);
    d.append("h", m.hash);
    d.append("n", to_int(m.msg_namespace));
    d.append("t", to_epoch_ms(m.timestamp));
    d.append("z", to_epoch_ms(m.expiry));

    if (!relay_to.empty())
        send(relay_to, "notify", d.view());

    if (!relay_to_with_data.empty()) {
        d.append("~", m.data);
        send(relay_to_with_data, "notify", d.view());
    }
}

}  // namespace oxenss::server
