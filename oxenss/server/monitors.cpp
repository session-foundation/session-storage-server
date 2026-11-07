#include "monitors.h"

#include <sodium/crypto_sign.h>
#include <sodium/randombytes.h>

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

std::unordered_set<std::string> default_privileged_keys(bool mainnet) {
    if (!mainnet)
        return {};
    return {oxenc::from_hex(MAINNET_PUSH_SERVER_KEY)};
}

Monitors::Monitors(snode::ServiceNode* sn, std::unordered_set<std::string> privileged_keys) :
        privileged_keys_{std::move(privileged_keys)}, service_node_{sn} {}

snode::swarm_membership Monitors::swarm_for(const user_pubkey& pk) const {
    return service_node_->network().get_swarm_for(pk);
}

snode::swarm_id_t Monitors::our_swarm_id() const {
    return service_node_->swarm().our_swarm_id();
}

const snode::Contacts& Monitors::contacts() const {
    return std::as_const(*service_node_).contacts();
}

std::vector<connection_id> Monitors::gone_connections(std::vector<connection_id>) {
    return {};
}

std::vector<std::pair<int64_t, message>> Monitors::retrieve_from_id(
        const user_pubkey& pubkey,
        namespace_id ns,
        int64_t from_id,
        size_t limit,
        bool newest_first) {
    return service_node_->db->retrieve_from_id(pubkey, ns, from_id, limit, newest_first);
}

int64_t Monitors::count_id_range(
        const user_pubkey& pubkey, namespace_id ns, int64_t from_id, int64_t before_id) {
    return service_node_->db->count_id_range(pubkey, ns, from_id, before_id);
}

void Monitors::run_later(std::function<void()> f) {
    f();
}

void body_limit::merge(const body_limit& other) {
    if (!other.data)
        return;
    if (!data)
        *this = other;
    else if (!max || !other.max)
        max.reset();
    else
        max = std::max(*max, *other.max);
}

body_limit body_limit::applied(size_t size) const {
    if (!data)
        return {};
    if (!max || (*max > 0 && size <= *max))
        return {true, std::nullopt};
    return *this;
}

namespace {
    // The encoded reply dict for a monitor subscription that failed.
    std::string error_reply(MonitorResponse r, std::string message) {
        oxenc::bt_dict_producer out;
        monitor_error(out, r, std::move(message));
        return std::move(out).str();
    }
}  // namespace

std::variant<subscription, std::string> Monitors::parse_subscription(oxenc::bt_dict_consumer d) {

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
                return error_reply(
                        MonitorResponse::BAD_PUBKEY,
                        "Provided P= Session Ed25519 pubkey must be 32 bytes");
        }

        // Subaccount signature & token
        if (d.skip_until("S")) {
            subacc.emplace();
            if (auto sig = d.consume_string_view(); sig.size() == subacc->signature.size())
                std::memcpy(subacc->signature.data(), sig.data(), sig.size());
            else
                return error_reply(
                        MonitorResponse::BAD_PUBKEY,
                        "Provided S subaccount signature must be {} bytes"_format(
                                subacc->signature.size()));

            if (auto token = d.require<std::string_view>("T");
                token.size() == SUBACCOUNT_TOKEN_LENGTH)
                std::memcpy(subacc->token.token.data(), token.data(), token.size());
            else
                return error_reply(
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
                return error_reply(
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
                return error_reply(
                        MonitorResponse::BAD_PUBKEY, "Provided p= pubkey must be 33 bytes");
        } else if (ed_pk.empty()) {
            throw std::runtime_error{"Either p= or P= must be given"};
        }

        signature = d.require<std::string_view>("s");
        if (signature.size() != 64)
            return error_reply(MonitorResponse::BAD_SIG, "Provided s= signature must be 64 bytes");

        if (!d.skip_until("t"))
            throw std::runtime_error{"required signature timestamp is missing"};
        timestamp = std::chrono::seconds{d.consume_integer<int64_t>()};

    } catch (const std::exception& ex) {
        return error_reply(MonitorResponse::BAD_ARGS, "Invalid arguments: "s + ex.what());
    }

    // Make sure the sig timestamp isn't too old or too new
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::system_clock::time_point(timestamp);
    if (bool too_old = ts < now - 14 * 24h; too_old || ts > now + 24h) {
        return error_reply(
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
            return error_reply(MonitorResponse::BAD_PUBKEY, "Invalid P= ed25519 public key");
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
            return error_reply(MonitorResponse::BAD_SIG, m);
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
        return error_reply(MonitorResponse::BAD_SIG, "Signature verification failed");
    }

    user_pubkey account;
    if (!account.load(pubkey))
        return error_reply(
                MonitorResponse::BAD_PUBKEY, "Provided p= pubkey is not a valid account");

    // Knowing no swarms at all is not the same as knowing the account is someone else's: we have
    // no swarm to redirect the subscriber to, and this is most likely a transient gap in our oxend
    // data, so say so rather than claiming a wrong swarm.  `drop_foreign_monitors` holds onto
    // existing subscriptions in this same state.
    auto swarm = swarm_for(account);
    if (!swarm) {
        log::debug(logcat, "monitor: no swarms known, cannot place {}", pubkey_hex);
        return error_reply(
                MonitorResponse::NO_SWARM_INFO,
                "Service node does not currently know the swarm list");
    }

    // A subscription to an account we do not store can never deliver anything, so refuse it and
    // hand back the swarm that does store it (the same information a 421 would carry).
    if (swarm->first != our_swarm_id()) {
        log::debug(logcat, "monitor: {} is not stored by this swarm", pubkey_hex);
        oxenc::bt_dict_producer out;
        monitor_error(
                out,
                MonitorResponse::WRONG_SWARM,
                "Account is not stored by this service node's swarm");
        snode::swarm_to_bt(out, swarm, contacts());
        return std::move(out).str();
    }

    return subscription{std::move(pubkey), std::move(pubkey_hex), std::move(namespaces), want_data};
}

std::string Monitors::handle_monitor(std::string_view request, const connection_id& conn) {
    if (request.size() < 2 || !(request.front() == 'd' || request.front() == 'l') ||
        request.back() != 'e')
        return error_reply(
                MonitorResponse::BAD_ARGS,
                "Invalid arguments: monitor request takes a single bencoded dict or list "
                "parameter");

    // For each subscription in the request, in order: its error reply if it failed, otherwise its
    // index in `subs`.
    std::vector<std::variant<std::string, size_t>> results;
    std::vector<subscription> subs;
    const bool single = request.front() == 'd';
    try {
        auto parse = [&](oxenc::bt_dict_consumer d) {
            auto parsed = parse_subscription(std::move(d));
            if (auto* sub = std::get_if<subscription>(&parsed)) {
                results.emplace_back(subs.size());
                subs.push_back(std::move(*sub));
            } else
                results.emplace_back(std::move(std::get<std::string>(parsed)));
        };
        if (single)
            parse(oxenc::bt_dict_consumer{request});
        else
            for (oxenc::bt_list_consumer l{request}; !l.is_finished();)
                parse(l.consume_dict_consumer());
    } catch (const std::exception& e) {
        return error_reply(
                MonitorResponse::BAD_ARGS, "Invalid arguments: Failed to parse monitor data value");
    }

    std::vector<std::optional<std::chrono::seconds>> expiries;
    if (!subs.empty())
        expiries = update_monitors(subs, conn);

    auto reply = [&](std::variant<std::string, size_t>& result) {
        if (auto* err = std::get_if<std::string>(&result))
            return std::move(*err);
        auto& expiry = expiries[std::get<size_t>(result)];
        if (!expiry)
            return error_reply(
                    MonitorResponse::TOO_MANY_MONITORS,
                    "Too many monitors in this session (at most {})"_format(
                            limits_.unprivileged_monitors));
        oxenc::bt_dict_producer out;
        out.append("success", 1);
        out.append("x", expiry->count());
        return std::move(out).str();
    };

    if (single)
        return reply(results.front());
    oxenc::bt_list_producer out;
    for (auto& result : results)
        out.append_encoded(reply(result));
    return std::move(out).str();
}

namespace {
    // The bt-encoded body of a `notify` for `m`, for a subscriber with body limit `limit`, which
    // is a dict with keys (in order):
    // - @ pubkey
    // - L full size of the msg data (only if `~` is cut short or left out because of the limit)
    // - h msg hash
    // - n msg namespace
    // - t msg timestamp
    // - z msg expiry
    // - ~ msg data (if wanted, and only as much of it as wanted)
    std::string notify_body(const message& m, const body_limit& limit) {
        auto body = limit.applied(m.data.size());
        // A limit that survives being applied is one the body exceeds.
        const bool cut = body.max.has_value();
        const bool with_data = body.data && body.max != 0;
        std::string_view data{m.data};
        if (cut)
            data = data.substr(0, *body.max);

        constexpr size_t metadata_size = 2       // d...e
                                       + 3 + 36  // 1:@ and 33:[33-byte pubkey]
                                       + 3 + 46  // 1:h and 43:[43-byte base64 unpadded hash]
                                       + 3 + 8   // 1:n and i-32768e
                                       + 3 + 16  // 1:t and i1658784776010e plus a byte to grow
                                       + 3 + 16  // 1:z and i1658784776010e plus a byte to grow
                                       + 10;     // safety margin

        oxenc::bt_dict_producer d;
        d.reserve(
                metadata_size + (cut ? 3 + 10 : 0)         // 1:L and i76800e plus bytes to grow
                + (with_data ? 3 + 8 + data.size() : 0));  // 1:~ and 76800: plus bytes to grow

        d.append("@", m.pubkey.prefixed_raw());
        if (cut)
            d.append("L", m.data.size());
        d.append("h", m.hash);
        d.append("n", to_int(m.msg_namespace));
        d.append("t", to_epoch_ms(m.timestamp));
        d.append("z", to_epoch_ms(m.expiry));
        if (with_data)
            d.append("~", data);
        return std::move(d).str();
    }

    // The body limit of a monitor's owner: a session's `b`; a connection has none.
    std::optional<uint64_t> body_max_of(const monitor_owner& owner) {
        if (auto* s = std::get_if<MonitorSession*>(&owner))
            return (*s)->body_max;
        return std::nullopt;
    }

}  // namespace

std::vector<std::optional<std::chrono::seconds>> Monitors::update_monitors(
        std::vector<subscription>& subs, const connection_id& conn) {
    std::vector<std::optional<std::chrono::seconds>> expiries;
    expiries.reserve(subs.size());
    std::unique_lock lock{monitoring_mutex_};
    // Taken before any expiry is set, so that a freshly renewed monitor counts as the whole
    // MONITOR_EXPIRY_TIME rather than a second short of it.
    const auto now = std::chrono::steady_clock::now();
    auto until = [&now](const MonitorData& mon) {
        return std::chrono::duration_cast<std::chrono::seconds>(mon.expiry - now);
    };

    if (closed_conns_.contains(conn)) {
        log::debug(logcat, "ignoring monitor request from a connection that has since closed");
        expiries.resize(subs.size(), std::chrono::seconds{0});
        return expiries;
    }

    monitor_owner owner = conn;
    MonitorSession* session = nullptr;
    if (auto it = session_conns_.find(conn); it != session_conns_.end())
        owner = session = it->second;

    for (auto& sub : subs) {
        auto& [pubkey, pubkey_hex, namespaces, want_data] = sub;
        if (auto* mon_data = find_monitor(sub, owner)) {
            log::debug(
                    logcat,
                    "sub renewed for {} monitoring namespace(s) {}",
                    pubkey_hex,
                    fmt::join(mon_data->namespaces, ", "));
            mon_data->reset_expiry();
            expiries.push_back(until(*mon_data));
            continue;
        }
        if (session && !session->privileged &&
            session->monitor_count >= limits_.unprivileged_monitors) {
            expiries.emplace_back();
            continue;
        }
        log::debug(
                logcat,
                "new {}subscription for {} monitoring namespace(s) {}",
                session ? "session " : "",
                pubkey_hex,
                fmt::join(namespaces, ", "));
        if (session) {
            session->accounts.insert(pubkey);
            ++session->monitor_count;
        } else
            monitoring_conns_[conn].insert(pubkey);
        auto it = monitoring_.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(std::move(pubkey)),
                std::forward_as_tuple(std::move(namespaces), want_data, owner));
        expiries.push_back(until(it->second));
    }
    return expiries;
}

MonitorData* Monitors::find_monitor(const subscription& sub, const monitor_owner& owner) {
    for (auto [it, end] = monitoring_.equal_range(sub.pubkey); it != end; ++it) {
        auto& mon = it->second;
        if (mon.owner == owner && mon.namespaces == sub.namespaces &&
            mon.want_data == sub.want_data)
            return &mon;
    }
    return nullptr;
}

bool Monitors::has_monitor(const std::string& account, const monitor_owner& owner) {
    for (auto [it, end] = monitoring_.equal_range(account); it != end; ++it)
        if (it->second.owner == owner)
            return true;
    return false;
}

std::unordered_multimap<std::string, MonitorData>::iterator Monitors::erase_monitor(
        std::unordered_multimap<std::string, MonitorData>::iterator it) {
    // Copied: both outlive the erase, which the account only leaves its owner's index after, and
    // then only if that was the owner's last monitor of it.
    auto account = it->first;
    auto owner = it->second.owner;
    auto next = monitoring_.erase(it);

    if (auto* s = std::get_if<MonitorSession*>(&owner)) {
        --(*s)->monitor_count;
        if (!(*s)->privileged && (*s)->detached_since) {
            std::lock_guard lock{missed_mutex_};
            --detached_monitors_;
        }
        if (!has_monitor(account, owner))
            (*s)->accounts.erase(account);
    } else if (!has_monitor(account, owner)) {
        auto& conn = std::get<connection_id>(owner);
        if (auto cit = monitoring_conns_.find(conn); cit != monitoring_conns_.end()) {
            cit->second.erase(account);
            if (cit->second.empty())
                monitoring_conns_.erase(cit);
        }
    }
    return next;
}

void Monitors::detach(MonitorSession& s, std::chrono::steady_clock::time_point now) {
    if (s.conn) {
        // Only if still its: the connection may already be bound to the session replacing it.
        if (auto it = session_conns_.find(*s.conn); it != session_conns_.end() && it->second == &s)
            session_conns_.erase(it);
        s.conn.reset();
    }
    s.detached_since = now;
    {
        std::lock_guard lock{missed_mutex_};
        fold_recent(s);
        detached_[s.privileged].emplace(now, &s);
        if (s.privileged)
            return;
        detached_monitors_ += s.monitor_count;
    }
    while (true) {
        MonitorSession* victim;
        {
            std::lock_guard lock{missed_mutex_};
            if (detached_monitors_ <= limits_.detached_monitors || detached_[false].empty())
                return;
            victim = detached_[false].begin()->second;
        }
        log::debug(
                logcat,
                "Removing a detached monitor session ({} monitors) to keep within {}",
                victim->monitor_count,
                limits_.detached_monitors);
        remove_session(*victim);
    }
}

void Monitors::bind(MonitorSession& s, const connection_id& conn) {
    {
        std::lock_guard lock{missed_mutex_};
        if (s.detached_since) {
            detached_[s.privileged].erase({*s.detached_since, &s});
            if (!s.privileged)
                detached_monitors_ -= s.monitor_count;
            s.detached_since.reset();
        } else if (s.conn && *s.conn != conn) {
            log::debug(logcat, "monitor session moved off a connection still open");
            if (auto it = session_conns_.find(*s.conn);
                it != session_conns_.end() && it->second == &s)
                session_conns_.erase(it);
            fold_recent(s);
        }
    }
    s.conn = conn;
    session_conns_[conn] = &s;
}

bool Monitors::session_live(const MonitorSession& s, std::chrono::steady_clock::time_point now) {
    return s.conn || !s.detached_since || now < *s.detached_since + SESSION_DETACHED_LIFETIME;
}

void Monitors::remove_session(MonitorSession& s) {
    log::debug(logcat, "removing monitor session with {} monitor(s)", s.monitor_count);
    // Copied, because erasing the monitors removes them from `accounts`.
    auto accounts = s.accounts;
    for (const auto& account : accounts) {
        auto [it, end] = monitoring_.equal_range(account);
        while (it != end)
            it = it->second.owner == monitor_owner{&s} ? erase_monitor(it) : std::next(it);
    }
    if (s.conn)
        if (auto it = session_conns_.find(*s.conn); it != session_conns_.end() && it->second == &s)
            session_conns_.erase(it);
    if (!s.ip.empty())
        if (auto it = sessions_by_ip_.find(s.ip); it != sessions_by_ip_.end()) {
            std::erase(it->second, &s);
            if (it->second.empty())
                sessions_by_ip_.erase(it);
        }
    if (s.detached_since) {
        std::lock_guard lock{missed_mutex_};
        detached_[s.privileged].erase({*s.detached_since, &s});
    }
    // Last, as this may destroy `s` (so by iterator: erasing by key would use `s.token` as it
    // goes).
    sessions_.erase(sessions_.find(s.token));
}

void Monitors::rotate_token(MonitorSession& s) {
    std::string token(MonitorSession::TOKEN_SIZE, '\0');
    do {
        randombytes_buf(token.data(), token.size());
    } while (sessions_.contains(token));

    auto node = sessions_.extract(s.token);
    s.token = token;
    if (node) {
        node.key() = std::move(token);
        sessions_.insert(std::move(node));
    }
}

void Monitors::handle_monitor_session(
        std::string_view request,
        const connection_id& conn,
        const std::function<void(std::string)>& reply,
        std::string_view remote_key,
        std::string_view remote_ip) {
    std::optional<uint64_t> body_max, account_limit;
    bool list_live = true;
    std::optional<std::string> token;
    try {
        oxenc::bt_dict_consumer d{request};
        if (d.skip_until("b"))
            body_max = d.consume_integer<uint64_t>();
        if (d.skip_until("l"))
            list_live = d.consume_integer<bool>();
        if (d.skip_until("m"))
            if (account_limit = d.consume_integer<uint64_t>(); *account_limit < 1)
                throw std::invalid_argument{"m must be at least 1"};
        if (d.skip_until("t"))
            token = d.consume_string();
    } catch (const std::exception& e) {
        oxenc::bt_dict_producer out;
        monitor_error(
                out,
                MonitorResponse::BAD_ARGS,
                "Invalid arguments: monitor_session takes a single bencoded dict parameter, with "
                "optional integers b (0 or more), l (0 or 1) and m (1 or more) and string t");
        return reply(std::move(out).str());
    }

    // Everything that changes the session, at once: nothing changes (and the token given still
    // resumes the session) unless the connection is still open.  Nothing here walks the session's
    // monitors or accounts, so a resume costs the same under the lock however big the session.
    std::shared_ptr<MonitorSession> session;
    bool resumed = false;
    std::string issued;
    std::set<std::string> ended;
    uint64_t replay_id = 0;
    {
        std::unique_lock lock{monitoring_mutex_};
        auto now = std::chrono::steady_clock::now();

        if (closed_conns_.contains(conn)) {
            log::debug(logcat, "ignoring monitor_session from a connection that has since closed");
            return;
        }

        if (token)
            if (auto it = sessions_.find(*token);
                it != sessions_.end() && session_live(*it->second, now))
                session = it->second;

        // A connection is bound to at most one session, so starting or resuming another
        // detaches whatever this one had.
        MonitorSession* previous = nullptr;
        if (auto it = session_conns_.find(conn);
            it != session_conns_.end() && it->second != session.get())
            previous = it->second;

        resumed = session != nullptr;
        // A client has no need to start more than one fresh session on a connection; refusing it
        // makes each one cost at least a new connection.
        if (!resumed && started_session_.contains(conn)) {
            lock.unlock();
            log::debug(logcat, "refusing a second new monitor session on one connection");
            return reply(error_reply(
                    MonitorResponse::SESSION_ALREADY_STARTED,
                    "This connection has already started a monitor session: resume a session with "
                    "its token, or start a new one on a new connection"));
        }
        const bool privileged = !resumed && privileged_keys_.contains(std::string{remote_key});
        const std::string ip = resumed || privileged ? "" : std::string{remote_ip};
        // Make room among the IP's sessions, by its own longest detached, or refuse.
        while (!ip.empty()) {
            auto it = sessions_by_ip_.find(ip);
            if (it == sessions_by_ip_.end() || it->second.size() < limits_.sessions_per_ip)
                break;
            MonitorSession* oldest = nullptr;
            for (auto* s : it->second)
                if (s->detached_since && (!oldest || *s->detached_since < *oldest->detached_since))
                    oldest = s;
            if (!oldest) {
                lock.unlock();
                log::debug(logcat, "refusing a monitor session: too many from {}", ip);
                return reply(error_reply(
                        MonitorResponse::TOO_MANY_SESSIONS,
                        "Too many monitor sessions from this address (at most {}), and none of "
                        "them without a connection to make room"_format(limits_.sessions_per_ip)));
            }
            log::debug(logcat, "removing a monitor session of {} to make room for another", ip);
            remove_session(*oldest);
        }

        if (resumed) {
            // Bound before `previous` is detached, which can remove the sessions detached the
            // longest: this one is then no longer among them.
            bind(*session, conn);
            ended = std::exchange(session->ended, {});
        }
        if (previous)
            detach(*previous, now);
        if (!resumed) {
            session = std::make_shared<MonitorSession>();
            session->privileged = privileged;
            session->ip = ip;
            if (!ip.empty())
                sessions_by_ip_[ip].push_back(session.get());
            started_session_.insert(conn);
        }
        rotate_token(*session);
        if (!resumed)
            sessions_.emplace(session->token, session);
        session->body_max = body_max;
        bind(*session, conn);
        issued = session->token;
        if (resumed) {
            replay_id = next_replay_id_++;
            std::lock_guard mlock{missed_mutex_};
            session->replay_id = replay_id;
        }
    }

    // What the request's per-account limit cuts from the replay, worked out before the reply,
    // which reports it, and the replay that follows it.
    std::map<std::string, std::map<namespace_id, int64_t>> cut;
    if (resumed && account_limit)
        cut = limit_replay(*session, *account_limit);

    // The live monitors to list, gathered a batch at a time under a shared lock (which holds up
    // other requests, but not notifications) from a snapshot of the session's accounts.
    struct listed {
        std::string account;
        std::chrono::seconds expires_in;
        bool want_data;
        std::vector<namespace_id> namespaces;
    };
    std::vector<listed> live;
    if (resumed && list_live) {
        std::vector<std::string> accounts;
        {
            std::shared_lock lock{monitoring_mutex_};
            accounts.assign(session->accounts.begin(), session->accounts.end());
        }
        const monitor_owner owner{session.get()};
        for (size_t start = 0; start < accounts.size(); start += PASS_BATCH) {
            std::shared_lock lock{monitoring_mutex_};
            auto now = std::chrono::steady_clock::now();
            for (size_t i = start; i < std::min(start + PASS_BATCH, accounts.size()); i++)
                for (auto [it, end] = monitoring_.equal_range(accounts[i]); it != end; ++it)
                    if (const auto& mon = it->second; mon.owner == owner && mon.expiry >= now)
                        live.push_back(
                                {accounts[i],
                                 std::chrono::duration_cast<std::chrono::seconds>(mon.expiry - now),
                                 mon.want_data,
                                 mon.namespaces});
        }
    }

    log::debug(
            logcat,
            "{} monitor session; {} ended monitor account(s), {} account(s) cut by its limit",
            resumed ? "resumed" : "started",
            ended.size(),
            cut.size());

    oxenc::bt_dict_producer out;
    {
        auto by_account = out.append_dict("m");
        for (const auto& [account, by_ns] : cut) {
            auto list = by_account.append_list(account);
            for (const auto& [ns, count] : by_ns) {
                auto entry = list.append_dict();
                entry.append("n", to_int(ns));
                entry.append("o", count);
            }
        }
    }
    out.append("r", resumed ? 1 : 0);
    {
        auto list = out.append_list("s");
        for (const auto& account : ended) {
            user_pubkey pk;
            if (!pk.load(account))
                continue;
            auto entry = list.append_dict();
            entry.append("@", account);
            monitor_error(
                    entry,
                    MonitorResponse::WRONG_SWARM,
                    "Account is no longer stored by this service node's swarm");
            snode::swarm_to_bt(entry, swarm_for(pk), contacts());
        }
        for (const auto& m : live) {
            auto entry = list.append_dict();
            entry.append("@", m.account);
            entry.append("d", m.want_data ? 1 : 0);
            {
                auto ns = entry.append_list("n");
                for (auto n : m.namespaces)
                    ns.append(to_int(n));
            }
            entry.append("x", m.expires_in.count());
        }
    }
    out.append("t", issued);
    reply(std::move(out).str());

    if (resumed)
        replay(conn, std::move(session), replay_id);
}

uint32_t Monitors::account_index(MonitorSession& s, const std::string& account) {
    auto [it, inserted] =
            s.account_index.try_emplace(account, static_cast<uint32_t>(s.account_keys.size()));
    if (inserted)
        s.account_keys.push_back(account);
    return it->second;
}

void Monitors::note_missed(
        MonitorSession& s, uint32_t account, namespace_id ns, int64_t id, bool want_data) {
    auto [it, inserted] = s.missed.try_emplace({account, ns}, missed_from{id, want_data});
    if (!inserted) {
        it->second.id = std::min(it->second.id, id);
        it->second.want_data |= want_data;
    }
}

void Monitors::fold_recent(MonitorSession& s) {
    for (const auto& r : s.recent)
        note_missed(s, r.account, r.ns, r.id, r.want_data);
    s.recent.clear();
}

void Monitors::prune_recent(MonitorSession& s, std::chrono::steady_clock::time_point now) {
    while (!s.recent.empty() && s.recent.front().sent + RECENT_WINDOW < now)
        s.recent.pop_front();
}

std::map<std::string, std::map<namespace_id, int64_t>> Monitors::limit_replay(
        MonitorSession& s, uint64_t limit) {
    // The pairs to replay, by account.
    std::map<std::string, std::vector<std::pair<namespace_id, int64_t>>> by_account;
    {
        std::lock_guard lock{missed_mutex_};
        for (const auto& [key, from] : s.missed)
            by_account[s.account_keys[key.first]].emplace_back(key.second, from.id);
    }

    std::map<std::string, std::map<namespace_id, int64_t>> cut;
    std::map<std::pair<std::string, namespace_id>, int64_t> new_start;
    for (const auto& [account, pairs] : by_account) {
        user_pubkey pk;
        if (!pk.load(account))
            continue;
        try {
            // The account's newest `limit` across its namespaces are among each namespace's newest
            // `limit`; one more from each tells whether there is anything to cut.
            std::vector<int64_t> newest;
            for (const auto& [ns, from] : pairs)
                for (const auto& [id, m] : retrieve_from_id(pk, ns, from, limit + 1, true))
                    newest.push_back(id);
            if (newest.size() <= limit)
                continue;
            std::ranges::sort(newest, std::greater<>{});
            const int64_t cutoff = newest[limit - 1];
            for (const auto& [ns, from] : pairs) {
                if (from >= cutoff)
                    continue;
                if (auto n = count_id_range(pk, ns, from, cutoff); n > 0)
                    cut[account][ns] = n;
                new_start[{account, ns}] = cutoff;
            }
        } catch (const std::exception& e) {
            // Replaying more than asked for is better than losing any.
            log::warning(logcat, "Unable to apply a monitor session's replay limit: {}", e.what());
        }
    }

    std::lock_guard lock{missed_mutex_};
    for (const auto& [key, start] : new_start)
        if (auto idx = s.account_index.find(key.first); idx != s.account_index.end())
            if (auto it = s.missed.find({idx->second, key.second}); it != s.missed.end())
                it->second.id = std::max(it->second.id, start);
    return cut;
}

struct Monitors::replay_state {
    connection_id conn;
    uint64_t id;
    std::shared_ptr<MonitorSession> session;
    size_t sent = 0;
};

void Monitors::replay(const connection_id& conn, std::shared_ptr<MonitorSession> s, uint64_t id) {
    replay_chunk(std::make_shared<replay_state>(conn, id, std::move(s)));
}

void Monitors::replay_chunk(std::shared_ptr<replay_state> state) {
    auto& s = *state->session;
    // Whether this replay may still act for the session.  Called with both locks held.
    auto current = [&] { return s.conn == state->conn && s.replay_id == state->id; };
    auto stop = [&](std::string_view why) {
        log::debug(
                logcat, "Ending a missed notification replay after {} sent: {}", state->sent, why);
        send_paced(state->conn, state->id, {}, nullptr);
    };

    // Pairs with nothing (left) to send are passed straight over.
    while (true) {
        std::pair<uint32_t, namespace_id> key;
        missed_from from;
        std::string account;
        {
            std::shared_lock lock{monitoring_mutex_};
            std::lock_guard mlock{missed_mutex_};
            if (!current())
                return stop("the session has moved on");
            if (s.missed.empty())
                return stop("all sent");
            std::tie(key, from) = *s.missed.begin();
            account = s.account_keys[key.first];
        }

        user_pubkey pk;
        std::vector<std::pair<int64_t, message>> rows;
        if (pk.load(account)) {
            try {
                rows = retrieve_from_id(pk, key.second, from.id, REPLAY_CHUNK, false);
            } catch (const std::exception& e) {
                // The session keeps what is left, for its next resume.
                log::error(logcat, "Missed notification replay lookup failed: {}", e.what());
                return stop("message lookup failed");
            }
        }

        std::vector<std::string> bodies;
        {
            std::shared_lock lock{monitoring_mutex_};
            std::lock_guard mlock{missed_mutex_};
            if (!current())
                return stop("the session has moved on");
            auto it = s.missed.find(key);
            if (it == s.missed.end())
                continue;
            // Whatever is taken from `missed` here goes into `recent` in the same step, so that if
            // the connection turns out to be dead it is noted as missed again on detaching.
            const auto now = std::chrono::steady_clock::now();
            for (auto& [id, m] : rows) {
                if (id < it->second.id)
                    continue;
                bodies.push_back(notify_body(
                        m, {from.want_data, from.want_data ? s.body_max : std::nullopt}));
                s.recent.push_back({now, id, key.first, key.second, from.want_data});
            }
            if (rows.size() < REPLAY_CHUNK)
                s.missed.erase(it);
            else
                it->second.id = rows.back().first + 1;
        }
        if (bodies.empty())
            continue;

        state->sent += bodies.size();
        return send_paced(
                state->conn, state->id, std::move(bodies), [this, state] { replay_chunk(state); });
    }
}

void Monitors::connection_closed(const connection_id& conn) {
    std::unique_lock lock{monitoring_mutex_};

    closed_conns_.emplace(conn, std::chrono::steady_clock::now());
    started_session_.erase(conn);

    if (auto it = session_conns_.find(conn); it != session_conns_.end())
        detach(*it->second, std::chrono::steady_clock::now());

    auto conn_it = monitoring_conns_.find(conn);
    if (conn_it == monitoring_conns_.end())
        return;

    log::debug(
            logcat,
            "dropping {} monitor subscription(s) of a closed connection",
            conn_it->second.size());

    const monitor_owner owner{conn};
    for (const auto& account : conn_it->second) {
        auto [it, end] = monitoring_.equal_range(account);
        while (it != end) {
            if (it->second.owner == owner)
                it = monitoring_.erase(it);
            else
                ++it;
        }
    }

    monitoring_conns_.erase(conn_it);
}

struct Monitors::sweep_state {
    // Sessions found ended, to remove.
    std::vector<std::shared_ptr<MonitorSession>> ended;
    size_t next_ended = 0;
    // The walk over the table's buckets for expired monitors.
    size_t bucket = 0, bucket_count = 0;
    size_t expired = 0;
};

void Monitors::remove_expired() {
    if (sweeping_.exchange(true))
        return;

    // First connections gone without our being told: their sessions are detached, and so fold in
    // their recent logs, before anything is pruned from those.
    std::vector<connection_id> conns;
    {
        std::shared_lock lock{monitoring_mutex_};
        for (const auto& [conn, s] : session_conns_)
            conns.push_back(conn);
        for (const auto& [conn, accounts] : monitoring_conns_)
            conns.push_back(conn);
    }
    std::ranges::sort(conns);
    conns.erase(std::unique(conns.begin(), conns.end()), conns.end());
    // Asked without the lock held, as the transport has its own thread to ask.
    for (const auto& conn : gone_connections(std::move(conns))) {
        log::debug(logcat, "Treating a connection that no longer exists as closed");
        connection_closed(conn);
    }

    auto state = std::make_shared<sweep_state>();
    {
        std::unique_lock lock{monitoring_mutex_};
        auto now = std::chrono::steady_clock::now();
        std::erase_if(closed_conns_, [&now](const auto& c) {
            return c.second + CLOSED_CONN_MEMORY < now;
        });
        std::lock_guard mlock{missed_mutex_};
        for (auto& [token, s] : sessions_) {
            if (!session_live(*s, now))
                state->ended.push_back(s);
            else if (s->conn)
                prune_recent(*s, now);
        }
    }
    sweep_step(std::move(state));
}

void Monitors::sweep_step(std::shared_ptr<sweep_state> state) {
    bool done = false;
    {
        std::unique_lock lock{monitoring_mutex_};
        auto now = std::chrono::steady_clock::now();
        if (state->next_ended < state->ended.size()) {
            // Sessions until about a batch's worth of monitors has gone with them.
            size_t removed_monitors = 0;
            while (state->next_ended < state->ended.size() && removed_monitors < PASS_BATCH) {
                auto& s = *state->ended[state->next_ended++];
                // Resumed since it was found ended, or already removed (to make room)?
                if (session_live(s, now) || !sessions_.contains(s.token) ||
                    sessions_.at(s.token).get() != &s)
                    continue;
                removed_monitors += s.monitor_count + 1;
                remove_session(s);
            }
        } else {
            for (const auto& account : accounts_in_buckets(state->bucket, state->bucket_count)) {
                auto [it, end] = monitoring_.equal_range(account);
                while (it != end) {
                    const auto& mon = it->second;
                    // A monitor of a session without a connection lasts as long as the session.
                    if (mon.expiry < now && mon.destination()) {
                        it = erase_monitor(it);
                        ++state->expired;
                    } else
                        ++it;
                }
            }
            done = state->bucket >= monitoring_.bucket_count();
        }
    }

    if (!done)
        return run_later(
                [this, state = std::move(state)]() mutable { sweep_step(std::move(state)); });

    if (state->expired || !state->ended.empty())
        log::debug(
                logcat,
                "removed {} expired monitor(s) and {} monitor session(s)",
                state->expired,
                state->ended.size());
    sweeping_ = false;
}

std::vector<std::string> Monitors::accounts_in_buckets(size_t& bucket, size_t& bucket_count) const {
    if (bucket_count != monitoring_.bucket_count()) {
        bucket_count = monitoring_.bucket_count();
        bucket = 0;
    }
    std::vector<std::string> accounts;
    const size_t end = std::min(bucket + PASS_BATCH, bucket_count);
    for (; bucket < end; bucket++)
        // Entries with equal keys are adjacent, and in the same bucket.
        for (auto it = monitoring_.begin(bucket); it != monitoring_.end(bucket); ++it)
            if (accounts.empty() || accounts.back() != it->first)
                accounts.push_back(it->first);
    return accounts;
}

std::vector<std::pair<user_pubkey, std::vector<connection_id>>> Monitors::extract_foreign_monitors(
        const std::function<bool(const user_pubkey&)>& still_ours) {

    // Accounts found more than once (the table having been rehashed meanwhile) are tested once.
    std::unordered_set<std::string> accounts;
    {
        size_t bucket = 0, bucket_count = 0;
        bool more = true;
        while (more) {
            std::shared_lock lock{monitoring_mutex_};
            for (auto& account : accounts_in_buckets(bucket, bucket_count))
                accounts.insert(std::move(account));
            more = bucket < monitoring_.bucket_count();
        }
    }

    std::vector<std::pair<std::string, user_pubkey>> foreign;
    for (const auto& account : accounts) {
        user_pubkey pk;
        if (!pk.load(account)) {
            log::warning(logcat, "Ignoring unparseable pubkey in the monitoring table");
            continue;
        }
        if (!still_ours(pk))
            foreign.emplace_back(account, std::move(pk));
    }

    std::vector<std::pair<user_pubkey, std::vector<connection_id>>> dropped;
    dropped.reserve(foreign.size());
    for (size_t start = 0; start < foreign.size(); start += PASS_BATCH) {
        std::unique_lock lock{monitoring_mutex_};
        for (size_t i = start; i < std::min(start + PASS_BATCH, foreign.size()); i++) {
            auto& [account, pk] = foreign[i];
            std::vector<connection_id> conns;
            auto [it, end] = monitoring_.equal_range(account);
            while (it != end) {
                if (auto* to = it->second.destination())
                    conns.push_back(*to);
                else
                    // A session with nobody to tell hears of it when next resumed.
                    std::get<MonitorSession*>(it->second.owner)->ended.insert(account);
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

void Monitors::notify_message(const message& m, int64_t id) {
    // Each destination gets one notification however many of its monitors match: with data if any
    // of them wants it, limited by the `b` of the session they belong to.  (A connection bound to a
    // session can also have monitors of its own, which have no limit and so lift it.)
    std::map<connection_id, body_limit> to_conns;
    {
        auto now = std::chrono::steady_clock::now();
        std::shared_lock lock{monitoring_mutex_};

        // The sessions it is for, and whether any of their matching monitors wants data: one with
        // a connection is sent it and remembers having been; one without notes it as missed.
        std::map<MonitorSession*, bool> to_sessions;
        const auto account = m.pubkey.prefixed_raw();
        for (auto [it, end] = monitoring_.equal_range(account); it != end; ++it) {
            const auto& mon_data = it->second;
            auto* to = mon_data.destination();
            // A monitor of a session without a connection lasts as long as the session: its
            // subscriber cannot renew it while away.
            if ((to && mon_data.expiry < now) ||
                !std::binary_search(
                        mon_data.namespaces.begin(), mon_data.namespaces.end(), m.msg_namespace))
                continue;
            if (to)
                to_conns[*to].merge(
                        {mon_data.want_data,
                         mon_data.want_data ? body_max_of(mon_data.owner) : std::nullopt});
            if (auto* s = std::get_if<MonitorSession*>(&mon_data.owner))
                to_sessions[*s] |= mon_data.want_data;
        }
        if (!to_sessions.empty()) {
            std::lock_guard mlock{missed_mutex_};
            for (auto& [s, want_data] : to_sessions) {
                auto idx = account_index(*s, account);
                if (s->conn)
                    s->recent.push_back({now, id, idx, m.msg_namespace, want_data});
                else
                    note_missed(*s, idx, m.msg_namespace, id, want_data);
            }
        }
    }

    // Grouped by what of the body they get, so that each distinct notification is built only once.
    std::map<body_limit, std::vector<connection_id>> relay_to;
    for (const auto& [conn, body] : to_conns)
        relay_to[body.applied(m.data.size())].push_back(conn);

    for (const auto& [body, conns] : relay_to)
        send(conns, "notify", notify_body(m, body));
}

}  // namespace oxenss::server
