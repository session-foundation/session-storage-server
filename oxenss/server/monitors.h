#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <oxen/quic/connection_ids.hpp>
#include <oxenc/bt_producer.h>

#include "../common/message.h"
#include "../common/namespace.h"
#include "../common/pubkey.h"
#include "../snode/swarm.h"
#include "utils.h"

namespace oxenss::snode {
class ServiceNode;
class Contacts;
}  // namespace oxenss::snode

namespace oxenss::server {

using namespace std::literals;

// A QUIC connection, as {endpoint index, connection reference id}: monitors are only carried over
// QUIC.
using connection_id = std::pair<size_t, oxen::quic::ConnectionID>;

// How much of a message's body goes in a notification to one destination: whether any of its
// matching monitors want data (`d` of a `monitor` subscription), and the body limit of whatever
// those monitors belong to (`b` of a session; connections have none).
struct body_limit {
    // Whether any of the body is wanted; if not, `max` is ignored (and should be nullopt).
    bool data = false;
    // The most body bytes wanted, or nullopt for the whole body however big.
    std::optional<uint64_t> max;

    // Combines this with another monitor's, for a destination that both match a message for: data
    // if either wants it, and then the larger limit, where no limit at all beats any.
    void merge(const body_limit& other);

    // What applies to a message of `size` bytes, normalized so that equal results produce
    // identical notifications: no data; data with no limit, when the body fits; or the limit, when
    // the body is cut (or, for a limit of 0, left out) because of it.
    body_limit applied(size_t size) const;

    auto operator<=>(const body_limit&) const = default;
};

// One validated subscription from a `monitor` request.
struct subscription {
    std::string pubkey;                    // the account, in bytes (33)
    std::string pubkey_hex;                // the same, hex-encoded, for logging
    std::vector<namespace_id> namespaces;  // sorted, without duplicates
    bool want_data;
};

struct MonitorSession;

// Whom a monitor's notifications go to: the connection it arrived on, or the session it was
// attached to (and through that whichever connection is bound to the session, if any).
using monitor_owner = std::variant<connection_id, MonitorSession*>;

struct MonitorData {
    static constexpr auto MONITOR_EXPIRY_TIME = 65min;

    std::chrono::steady_clock::time_point expiry;  // When this notify reg expires
    std::vector<namespace_id> namespaces;          // sorted namespace_ids
    monitor_owner owner;
    bool want_data;  // true if the subscriber wants msg data

    MonitorData(
            std::vector<namespace_id> namespaces,
            bool data,
            monitor_owner owner,
            std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) :
            expiry{std::chrono::steady_clock::now() + ttl},
            namespaces{std::move(namespaces)},
            owner{owner},
            want_data{data} {}

    void reset_expiry(std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) {
        expiry = std::chrono::steady_clock::now() + ttl;
    }

    // The connection this monitor's notifications currently go to; nullptr for a monitor of a
    // session with no connection bound.
    const connection_id* destination() const;
};

// A notification recently sent through a session's connection, kept for a while in case the
// connection had already died without our knowing (see Monitors::RECENT_WINDOW).
struct recent_send {
    std::chrono::steady_clock::time_point sent;
    int64_t id;        // the message's database row id
    uint32_t account;  // index into MonitorSession::account_keys
    namespace_id ns;
    bool want_data;
};

// Where a session's replay of one of its (account, namespace) pairs starts: the lowest row id the
// subscriber may not have been sent, and whether any of the monitors that matched wanted data.
struct missed_from {
    int64_t id;
    bool want_data;
};

// A bulk subscriber's monitors, kept across its connections; see QUIC::handle_monitor_session.
struct MonitorSession {
    static constexpr size_t TOKEN_SIZE = 32;

    // The current token, which is also this session's key in `Monitors::sessions_`.
    std::string token;

    // Whether the session was created by a connection with a privileged key, which is exempt from
    // the limits on ordinary sessions (see Monitors::session_limits).
    bool privileged = false;

    // The IP the (unprivileged) session was created from, which it counts against; see
    // Monitors::session_limits::sessions_per_ip.
    std::string ip;

    // The connection the session's notifications go to, if any; and if none, since when.
    std::optional<connection_id> conn;
    std::optional<std::chrono::steady_clock::time_point> detached_since;

    // The accounts the session has a monitor for: its reverse index into `Monitors::monitoring_`.
    std::unordered_set<std::string> accounts;
    // How many monitors it has, as there can be several per account.
    size_t monitor_count = 0;

    // The most body bytes to send in any notification through the session (its `b`, set by the
    // request that started or last resumed it), or nullopt for no limit.
    std::optional<uint64_t> body_max;

    // Accounts whose monitors ended, by moving to another swarm, while the session had no
    // connection: reported, and forgotten, by the next resume.
    std::set<std::string> ended;

    // The rest are guarded by `Monitors::missed_mutex_`, not `monitoring_mutex_`, as they are added
    // to while delivering notifications under a shared lock of the latter.

    // The accounts `recent` and `missed` refer to, each kept once and referred to by its index.
    std::vector<std::string> account_keys;
    std::unordered_map<std::string, uint32_t> account_index;

    // While bound: the notifications sent through the connection lately, oldest first.  Folded into
    // `missed` when the session loses its connection.
    std::deque<recent_send> recent;

    // The (account index, namespace) pairs with notifications the subscriber may not have been
    // sent, and where each one's replay starts; an entry goes once replayed.  Added to while the
    // session has no connection, and from `recent` as it loses one.
    std::map<std::pair<uint32_t, namespace_id>, missed_from> missed;

    // The replay allowed to advance `missed`: the one started by the latest resume.
    uint64_t replay_id = 0;
};

inline const connection_id* MonitorData::destination() const {
    if (auto* s = std::get_if<MonitorSession*>(&owner))
        return (*s)->conn ? &*(*s)->conn : nullptr;
    return &std::get<connection_id>(owner);
}

// The Ed25519 pubkey (hex) of the production push server, privileged on mainnet without needing
// configuring; see default_privileged_keys.
inline constexpr std::string_view MAINNET_PUSH_SERVER_KEY =
        "87a324b8a9472fbd397f14973b6443fb0902ee0b663595806bd601aa1a156496";

// The Ed25519 pubkeys (32 bytes each) whose monitor sessions are privileged on every node of the
// network: on mainnet, MAINNET_PUSH_SERVER_KEY; on testnet, none.
std::unordered_set<std::string> default_privileged_keys(bool mainnet);

/// The monitor subscriptions held by this node, and the notifications pushed to them.  The QUIC
/// server owns the one instance and supplies the transport by implementing `send`.
///
/// Everything public is thread-safe.
class Monitors {
  public:
    // `sn` supplies the swarm state that the default environment hooks below consult.  It may be
    // null only for a subclass that overrides every one of them.
    // `privileged_keys` are the Ed25519 pubkeys (32 bytes each) whose sessions are privileged.
    explicit Monitors(snode::ServiceNode* sn, std::unordered_set<std::string> privileged_keys = {});

    virtual ~Monitors() = default;

    // Handles a `monitor` request arriving on `conn`, returning the reply body.  See
    // QUIC::handle_monitor_message for the request and reply formats.
    //
    // `conn` identifies the connection: a subscription identical to one it already has renews that
    // monitor, and any other adds one.
    //
    // If `conn` is bound to a session then the monitors are attached to the session instead.
    std::string handle_monitor(std::string_view request, const connection_id& conn);

    // Handles a `monitor_session` request arriving on `conn`, whose QUIC remote pubkey is
    // `remote_key` (empty if it presented none) and remote IP `remote_ip`; see
    // QUIC::handle_monitor_session for the request and reply formats.  The session is changed
    // (started or resumed, bound to `conn` and its token rotated) all at once: if `conn` has
    // already closed by then nothing is changed and `reply` is not invoked, so the token given
    // still resumes the session.  Otherwise `reply` is invoked with the reply body, before any
    // replayed notification is sent and before this returns.
    void handle_monitor_session(
            std::string_view request,
            const connection_id& conn,
            const std::function<void(std::string)>& reply,
            std::string_view remote_key = {},
            std::string_view remote_ip = {});

    // Called when `conn` has closed: its connection-bound monitors are removed, and any session
    // bound to it is detached, keeping its monitors.
    void connection_closed(const connection_id& conn);

    // How many missed notifications a replay looks up and sends at a time: few enough that a
    // replay holds little in memory and does not monopolise a worker or the connection, as each
    // chunk waits for the one before to be sent on.
    static constexpr size_t REPLAY_CHUNK = 64;

    // How long a notification sent through a session's connection is kept in its `recent` log: a
    // connection can have died up to an idle timeout (MAX_IDLE_TIMEOUT, 63s at most) before we
    // learn of it, and whatever was sent in that time never arrived, so it is replayed along with
    // what was missed.  Pruning comes only after the sweep has detached sessions from connections
    // that are gone, so nothing sent since a connection died is pruned before it is folded in.
    static constexpr auto RECENT_WINDOW = 90s;

    // How much of the monitoring table one step of a paced pass over it (the sweep, a swarm
    // change) covers while holding the lock, before letting other work in.
    static constexpr size_t PASS_BATCH = 4096;

    // How often `remove_expired` should be called.
    static constexpr auto EXPIRY_SWEEP_INTERVAL = 1min;

    // How long a session with no connection bound lasts, whatever its monitors' expiries: long
    // enough to ride out a short disconnect (and a bulk subscriber's restart).
    static constexpr auto SESSION_DETACHED_LIFETIME = 10min;

    // Treats as closed the connections with sessions or monitors that no longer exist (see
    // gone_connections); prunes sessions' recent logs; removes sessions detached for
    // SESSION_DETACHED_LIFETIME; and removes expired monitors, but not those of sessions without a
    // connection, whose subscribers cannot renew them while away.  The removals are paced: done a
    // batch at a time, continuing through `run_later`, with the lock released in between.  A sweep
    // started while one is still in progress does nothing.
    void remove_expired();

    // The limits on ordinary (unprivileged) sessions.  A session is privileged if the connection
    // that created it had one of the privileged keys (meant for a push server: one bulk
    // subscriber with tens of thousands of monitors per node), and then none of these apply.
    //
    // An unprivileged session can have at most `unprivileged_monitors` monitors.
    //
    // The monitors of unprivileged sessions without a connection are bounded too, as anyone can
    // make sessions (filling each with 64 monitors, replaying the same signed subscriptions into
    // one after another) and leave them for SESSION_DETACHED_LIFETIME.  A bound session is bounded
    // by its connection, and an empty one costs little, so it is the monitors of detached sessions
    // that are counted: at about 340 bytes a monitor, `detached_monitors` is a bound of some 340MB
    // against an attacker, far beyond legitimate use.  (What a detached session has missed is an
    // entry per account and namespace that had a message, so is bounded by its monitors too.)
    // Detaching a session is the only way the count rises; when it passes the limit, the
    // unprivileged sessions detached the longest are removed whole until it does not.
    //
    // And as a monitoring connection's remote address is its client's own (directly, or the unique
    // address of its tunnel), each IP can have at most `sessions_per_ip` unprivileged sessions,
    // bound or not: enough for a client's one per node, and some reconnects that start afresh
    // instead of resuming.  Beyond it the IP's own session detached the longest is removed whole;
    // with none of its sessions detached, the new one is refused.  This is no bound against
    // deliberate abuse (a new tunnel address is cheap), which `detached_monitors` is; it keeps a
    // client that starts fresh sessions by mistake from displacing anyone's but its own.
    struct session_limits {
        size_t unprivileged_monitors = 64;
        size_t detached_monitors = 1'000'000;
        size_t sessions_per_ip = 8;
    };

    // Pushes a `notify` for the newly stored message `m`, whose database row id is `id`, to each
    // subscriber monitoring its account and namespace.
    void notify_message(const message& m, int64_t id);

    /// Terminates every monitor subscription for an account this node no longer serves, pushing a
    /// `monitor_ended` notification to each affected subscriber.
    ///
    /// A subscription is only useful for as long as we would not answer a request for the account
    /// with a 421, so this must be called after a swarm update has taken effect.  Without it a
    /// client that has stopped polling cannot tell "the swarm moved" from "no messages arrived".
    void drop_foreign_monitors();

  protected:
    // Fire-and-forget push of `command` with `body` to each of `conns`.
    virtual void send(
            const std::vector<connection_id>& conns,
            std::string_view command,
            std::string_view body) = 0;

    // Pushes `notify` with each of `bodies` to `conn` for replay `replay` (ids increase with each
    // replay started), then, once the connection has sent them on (rather than just queued them),
    // invokes `on_drained` on a worker thread.  A null `on_drained` means nothing more will follow.
    // Nothing is sent or invoked if `conn` is gone.  If a newer replay has started on it the
    // bodies are still sent (the replay counted them as sent when it took them), but `on_drained`
    // is not invoked and the newer replay's pacing is left alone.
    virtual void send_paced(
            const connection_id& conn,
            uint64_t replay,
            std::vector<std::string> bodies,
            std::function<void()> on_drained) = 0;

    // Environment hooks: the swarm state that decides which accounts we store, and the contact
    // details used to describe a swarm to a subscriber.  The defaults ask the service node.
    virtual snode::swarm_membership swarm_for(const user_pubkey& pk) const;
    virtual snode::swarm_id_t our_swarm_id() const;
    virtual const snode::Contacts& contacts() const;

    // Which of `conns` no longer exist.  A request is handled on a worker some time after it
    // arrives, so a session can be bound to (or monitors made on) a connection that has closed in
    // the meantime, too long before for `closed_conns_` to remember; the sweep uses this to treat
    // such connections as closed.  The default knows of no connections, so reports none gone.
    virtual std::vector<connection_id> gone_connections(std::vector<connection_id> conns);

    // Looks up stored messages for a replay; see Database::retrieve_from_id and
    // Database::count_id_range.
    virtual std::vector<std::pair<int64_t, message>> retrieve_from_id(
            const user_pubkey& pubkey,
            namespace_id ns,
            int64_t from_id,
            size_t limit,
            bool newest_first);
    virtual int64_t count_id_range(
            const user_pubkey& pubkey, namespace_id ns, int64_t from_id, int64_t before_id);

    // Runs `f` later, on a worker thread: the next step of a paced pass.  The default runs it at
    // once.
    virtual void run_later(std::function<void()> f);

    // Adds or renews a monitor for each of `subs`, returning how long each one now has until it
    // expires, or nullopt for one refused because its session already has as many monitors as it
    // may.
    std::vector<std::optional<std::chrono::seconds>> update_monitors(
            std::vector<subscription>& subs, const connection_id& conn);

    // Removes every monitor subscription whose account `still_ours` rejects, returning the dropped
    // accounts along with the connections that had been subscribed to each.
    //
    // A monitor of a session that has no connection bound has nobody to tell, so its account is
    // added to the session's `ended`, for the next resume to report (see handle_monitor_session).
    //
    // `still_ours` is called without `monitoring_mutex_` held, because it takes network locks of
    // its own; the table is therefore sampled, tested, and then modified in separate steps, each
    // sampling and modifying step a PASS_BATCH at a time with the lock released in between.
    std::vector<std::pair<user_pubkey, std::vector<connection_id>>> extract_foreign_monitors(
            const std::function<bool(const user_pubkey&)>& still_ours);

    // Builds the bt-encoded body of a monitor-terminated notification for `pubkey`: the account,
    // the reason it ended, and the swarm that now holds the account so that the subscriber can
    // resubscribe without first asking us where to go.
    std::string monitor_ended_payload(
            const user_pubkey& pubkey, MonitorResponse reason, std::string_view message);

    // Tracks accounts we are monitoring for push notification messages
    std::unordered_multimap<std::string, MonitorData> monitoring_;

    // Reverse index of `monitoring_`, listing the accounts subscribed to by each connection (for
    // monitors not attached to a session) so that a connection going away doesn't require a scan
    // of the whole table.
    std::map<connection_id, std::unordered_set<std::string>> monitoring_conns_;

    // Sessions, by current token.
    std::unordered_map<std::string, std::shared_ptr<MonitorSession>> sessions_;

    // The Ed25519 pubkeys (32 bytes each) whose sessions are privileged.
    std::unordered_set<std::string> privileged_keys_;

    // The unprivileged sessions created from each IP.
    std::unordered_map<std::string, std::vector<MonitorSession*>> sessions_by_ip_;

    // The session bound to each connection that has one.
    std::map<connection_id, MonitorSession*> session_conns_;

    // The connections that have started a new session, which may not start another.
    std::set<connection_id> started_session_;

    // Connections that have closed, and when.  A request is handled on a worker thread after the
    // QUIC loop hands it over, so its connection may close first; this keeps such a request from
    // binding anything to a connection that will never be closed again.  Kept for a while, then
    // swept (connection reference ids are never reused, so no id is ever wrongly refused).
    std::map<connection_id, std::chrono::steady_clock::time_point> closed_conns_;
    static constexpr auto CLOSED_CONN_MEMORY = 1min;

    // Guards all of the above together, so that the indices cannot drift apart from the table.
    mutable std::shared_mutex monitoring_mutex_;

    session_limits limits_;

    // Guards each session's recent and missed notifications, and the detached sessions' index and
    // count.  Always taken after `monitoring_mutex_` (in either mode) when both are needed.
    std::mutex missed_mutex_;
    // The id of the next replay to start.
    std::atomic<uint64_t> next_replay_id_{1};
    // Set while a sweep is in progress.
    std::atomic<bool> sweeping_{false};

    // The sessions with no connection bound, of each kind, longest detached first.
    std::array<std::set<std::pair<std::chrono::steady_clock::time_point, MonitorSession*>>, 2>
            detached_;
    // The monitors held by unprivileged sessions in `detached_` (see
    // session_limits::detached_monitors).
    size_t detached_monitors_ = 0;

  private:
    snode::ServiceNode* service_node_;

    // These four must be called with `missed_mutex_` held.

    // The index of `account` in the session's account table, adding it if need be.
    static uint32_t account_index(MonitorSession& s, const std::string& account);

    // Notes that the subscriber may not have been sent the message with row id `id` for the
    // session's account `account` (an index) in namespace `ns`: the pair's replay then starts at
    // `id` at the latest.
    static void note_missed(
            MonitorSession& s, uint32_t account, namespace_id ns, int64_t id, bool want_data);

    // Notes everything in the session's recent log as possibly missed, and empties the log: for a
    // session losing its connection, which may have died before we knew.
    static void fold_recent(MonitorSession& s);

    // Drops the entries of the session's recent log older than RECENT_WINDOW.
    static void prune_recent(MonitorSession& s, std::chrono::steady_clock::time_point now);

    // Cuts what each of the session's accounts has to replay to its newest `limit` (across the
    // account's namespaces), returning how many each account's namespaces had cut, by account and
    // then namespace.  Looks messages up without any lock held.
    std::map<std::string, std::map<namespace_id, int64_t>> limit_replay(
            MonitorSession& s, uint64_t limit);

    struct replay_state;

    // Replays to `conn` what the session's `missed` lists, a chunk at a time (see replay_chunk).
    void replay(const connection_id& conn, std::shared_ptr<MonitorSession> s, uint64_t id);

    // Looks up and sends the next REPLAY_CHUNK messages of the first (account, namespace) pair in
    // the session's `missed`, advancing the pair's start past them (or removing it once it has
    // no more), and arranges for the chunk after to follow once the connection has sent them on.
    // Gives up, changing nothing, once the session is no longer bound to the replay's connection
    // or a newer resume has started a replay of its own.
    void replay_chunk(std::shared_ptr<replay_state> state);

    struct sweep_state;

    // The steps of a paced sweep (see remove_expired): removing the sessions found ended, then the
    // expired monitors, a batch at a time.
    void sweep_step(std::shared_ptr<sweep_state> state);

    // Collects the monitoring table's accounts from up to PASS_BATCH of its buckets, from bucket
    // `bucket` on, advancing `bucket`; starts again from the first bucket (so possibly repeating
    // accounts) if the table has been rehashed since `bucket_count`.  Must be called with
    // `monitoring_mutex_` held (in either mode).
    std::vector<std::string> accounts_in_buckets(size_t& bucket, size_t& bucket_count) const;

    // The remaining private methods must all be called with `monitoring_mutex_` held for writing.

    // Erases a monitor from `monitoring_`, keeping its owner's reverse index (and a session's
    // monitor count) up to date; returns the iterator following it.
    std::unordered_multimap<std::string, MonitorData>::iterator erase_monitor(
            std::unordered_multimap<std::string, MonitorData>::iterator it);

    // The monitor that `sub` renews for `owner`, if any: the one with the same account, owner,
    // namespaces and data flag.
    MonitorData* find_monitor(const subscription& sub, const monitor_owner& owner);

    // True if `owner` has any monitor of `account`.
    bool has_monitor(const std::string& account, const monitor_owner& owner);

    // Unbinds the session from its connection, starting its SESSION_DETACHED_LIFETIME and noting
    // what was sent through the connection lately as possibly missed; then, if that puts detached
    // unprivileged sessions' monitors over session_limits::detached_monitors, removes the ones
    // detached the longest, whole, until it does not.
    void detach(MonitorSession& s, std::chrono::steady_clock::time_point now);

    // Binds (or rebinds) the session to `conn`, ending any detachment.  A session moving off
    // another connection notes what was sent through that one lately as possibly missed, as the
    // subscriber reconnecting suggests it may have died.
    void bind(MonitorSession& s, const connection_id& conn);

    // True if the session can still be resumed: bound, or detached for less than
    // SESSION_DETACHED_LIFETIME.
    static bool session_live(const MonitorSession& s, std::chrono::steady_clock::time_point now);

    // Removes the session along with all of its monitors, missed notifications and token.
    void remove_session(MonitorSession& s);

    // Gives the session a fresh token, invalidating the old one.
    void rotate_token(MonitorSession& s);

    // Validates one subscription dict of a `monitor` request, returning either the subscription or
    // the encoded reply dict saying why it failed.
    std::variant<subscription, std::string> parse_subscription(oxenc::bt_dict_consumer d);
};

}  // namespace oxenss::server
