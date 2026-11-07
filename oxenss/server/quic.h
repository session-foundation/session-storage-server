#pragma once

#include "utils.h"
#include "monitors.h"
#include "mqbase.h"
#include "replay_owners.h"
#include "serial_runs.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/snode/service_node.h>

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

#include <atomic>
#include <unordered_map>

namespace oxenss::rpc {
class RequestHandler;
}  // namespace oxenss::rpc

namespace oxenss::server {

namespace quic = oxen::quic;
using namespace quic::literals;

using Address = quic::Address;

// ALPN for connections from clients, allowing access to client commands (store, retrieve, expire,
// etc.).
static constexpr auto ALPN = "oxenstorage";

// ALPN for connections between storage servers (SN_QUIC_VERSION and later).  Node-to-node commands
// are accepted only on connections negotiated with it, and the listener requires and verifies the
// peer's ed25519 key on them.  The plain client ALPN carries neither requirement.
inline constexpr auto SN_ALPN = "oxenstorage-sn";

// Two storage servers can race to connect to each other, ending up with a connection in each
// direction.  Both are kept for this long after the second one is established, so that anything
// already sent on the one that loses has time to complete, then the loser is closed.  Both sides
// pick the same loser: the connection initiated by the node with the lower ed25519 key wins.
inline constexpr auto SN_CONN_REDUNDANT_LINGER = 20s;

// Keep-alive and idle timeouts, after session-router's.  Connections to other storage servers are
// held open indefinitely, with the connecting side pinging every SN_CONN_KEEP_ALIVE; the idle
// timeout is two pings plus a little, so a little more than two consecutive pings have to go
// unanswered before the connection dies.
//
// QUIC negotiates the lower of the two sides' idle timeouts, so the listener advertises a longer
// value than the SN one: a connection between storage servers gets the SN value from the
// connecting side, while a client gets whatever it asks for, up to MAX_IDLE_TIMEOUT.  What a
// client asks for, and how it keeps its connection alive, is its business.
inline constexpr auto SN_CONN_KEEP_ALIVE = 15s;
inline constexpr auto SN_CONN_IDLE_TIMEOUT = 33s;
inline constexpr auto MAX_IDLE_TIMEOUT = 63s;

// On each connection with another storage server we open a fixed set of streams and send each
// kind of traffic on its own, so that none waits behind another (a QUIC stream delivers in order
// and has its own flow-control window; separate streams do not):
// - command: handshakes and pings -- small and latency-sensitive;
// - forward: client commands forwarded to the rest of the swarm;
// - data: message batches (dumps and deliveries) -- bulk;
// - onion: onion request hops, spread over several so that a large payload in transit holds up
//   only the hops sharing its stream.
// The peer opens its own set for what it sends us; our handler treats every incoming stream alike.
inline constexpr size_t SN_ONION_STREAMS = 4;

// Onion hops are queued on the stream without bound, so a client pushing a lot of data through a
// path whose next hop is slow would have us buffer all of it.  A hop goes on the peer's
// least-loaded onion stream; if even that one has this much unsent, every stream to the peer does
// (so at least SN_ONION_STREAMS times this is queued) and the hop is refused with a 503 so that the
// client reroutes rather than waits.  Generous: a healthy 100Mbit link clears this in seconds.
inline constexpr size_t SN_ONION_STREAM_MAX_BACKLOG = 50_Mi;

// Every store we receive is forwarded to each swarm member, so a member draining more slowly than
// stores arrive would have us buffer them without bound.  Once a peer's forward stream has this
// much unsent, forwards to it are refused with MQBase::SN_STREAM_FULL until it has drained to half
// this, which diverts them to what a timed-out forward is replaced with: a delivery or retry
// request, held in the database and paced by the peer's acknowledgements.  (A stream watermark
// tracks this; see watch_forward_backlog.)  Only data yet to be sent counts; what is in flight is
// bounded separately by the peer's stream flow control window (at most 16MiB by default), so a
// forward stream holds at most about twice this.  Forwards only go to the members of our own
// swarm, so this is held for a handful of peers at most, which lets it be generous.
inline constexpr size_t SN_FORWARD_STREAM_MAX_BACKLOG = 16_Mi;

enum class sn_stream_kind { command, forward, data, onion };

class QUIC : public MQBase {
  public:
    struct transport_options {
        // Every other storage server sends to us over the one socket, in bursts, so the OS default
        // buffers (about 200kB on Linux) overflow and drop packets whenever the QUIC loop falls
        // briefly behind.  Linux caps these at the net.core.rmem_max/wmem_max sysctls, which the
        // libquic-common package raises to allow them.
        quic::opt::socket_buffers socket_buffers{.recv = 8_Mi, .send = 1_Mi};
        // UDP offloads to use on the endpoints' sockets, where the OS supports them.
        bool gro = true;
        bool gso = true;
        // Applies to what we send, on both incoming and outgoing connections.
        quic::opt::congestion_control congestion_control = quic::opt::congestion_control::cubic;
    };

    QUIC(snode::ServiceNode& snode,
         rpc::RequestHandler& rh,
         rpc::RateLimiter& rl,
         std::span<const Address> bind,
         const crypto::ed25519_seckey& sk,
         const transport_options& opts);

    void startup_endpoint();

    // Destroys the endpoints, closing every connection, and drops the SN connection registry.
    // Afterwards nothing arrives from the network and the loop hands nothing more to oxenmq, so
    // oxenmq can be torn down next while this object, which its queued jobs use, still exists.
    // Anything asked of this object after this is dropped, without a reply or fallback.
    void shutdown();

    void notify_message(const message& m, int64_t id) override;

    void drop_foreign_monitors() override;

    void reachability_test(std::shared_ptr<snode::sn_test> test) override;

    void sweep_sn_connections() override;

    // Sends over the held connection when the node speaks QUIC (see sn_quic_capable),
    // establishing the connection first if needed; the request is passed to `fallback` for a node
    // that does not.  A single part is the request body as-is, several are sent as a bt list (see
    // handle_sn_storage_cc).  Replies are delivered off the QUIC loop, via an oxenmq task.
    void sn_request(
            const snode::contact& ct,
            std::string_view cmd,
            std::vector<std::string> parts,
            sn_reply_callback cb,
            std::chrono::milliseconds timeout,
            sn_fallback fallback) override;

    quic::Loop loop{};

  private:
    // Pushes `notify` with each of `bodies` to `conn` for replay `replay`, then posts `on_drained`
    // (if given) to a worker once the stream has written them all into packets: it waits on the
    // stream's unsent buffer watermarks, which this alone uses on a client stream (and switches off
    // when given no `on_drained`).  Nothing is sent or posted if the connection is gone, or a
    // newer replay has started on it (see replay_owners).
    void send_paced(
            const connection_id& conn,
            uint64_t replay,
            std::vector<std::string> bodies,
            std::function<void()> on_drained);

    // Which of `conns` no longer exist, asked of the loop (so not to be called on it).
    std::vector<connection_id> gone_connections(std::vector<connection_id> conns);

    // Fire-and-forget push of `notification` to each quic connection in `conns`, as a `command`
    // on the connection's stream 0.
    void send_notification(
            const std::vector<connection_id>& conns,
            std::string command,
            std::string_view notification);

    std::shared_ptr<quic::TLSCreds> tls_creds;
    std::vector<std::shared_ptr<quic::Endpoint>> endpoints;
    quic::Endpoint* reach_ep = nullptr;
    size_t reach_ep_idx = 0;
    quic::opt::congestion_control congestion_control;

    rpc::RequestHandler& request_handler;

    class QUICMonitors final : public Monitors {
        QUIC& quic_;

        void send(
                const std::vector<connection_id>& conns,
                std::string_view command,
                std::string_view body) override {
            quic_.send_notification(conns, std::string{command}, body);
        }

        void send_paced(
                const connection_id& conn,
                uint64_t replay,
                std::vector<std::string> bodies,
                std::function<void()> on_drained) override {
            quic_.send_paced(conn, replay, std::move(bodies), std::move(on_drained));
        }

        std::vector<connection_id> gone_connections(std::vector<connection_id> conns) override {
            return quic_.gone_connections(std::move(conns));
        }

        void run_later(std::function<void()> f) override;

      public:
        QUICMonitors(QUIC& quic, snode::ServiceNode& sn) : Monitors{&sn}, quic_{quic} {}
    };

    QUICMonitors monitors_;

    // Close codes for connections we close deliberately, so that the closed callback can tell them
    // from failures.
    static constexpr uint64_t CONN_CLOSE_REDUNDANT = 6;
    static constexpr uint64_t CONN_CLOSE_NOT_SN = 7;

    // Our connections with one other storage server, in either or both directions (see
    // SN_CONN_REDUNDANT_LINGER).
    struct sn_conn {
        bool inbound_wins;
        std::shared_ptr<quic::Connection> inbound{}, outbound{};

        // The connection to use: the winner when we have both, else whichever we have.
        std::shared_ptr<quic::Connection> preferred() const;
        // Stores a new connection in the given direction, returning any it replaces for the
        // caller to close.
        std::shared_ptr<quic::Connection> set(std::shared_ptr<quic::Connection> c, bool is_inbound);
        // Drops and returns the connection in the given direction (nullptr if none).
        std::shared_ptr<quic::Connection> take(bool is_inbound);
        bool empty() const { return !inbound && !outbound; }
    };

    struct sn_streams {
        std::shared_ptr<quic::BTRequestStream> command, forward, data;
        std::array<std::shared_ptr<quic::BTRequestStream>, SN_ONION_STREAMS> onion;
    };

    using sn_conn_callback = std::function<void(std::shared_ptr<quic::Connection>)>;

    // The SN connection registry.  Everything from here to the end of the private section is
    // owned by the QUIC loop: it is only touched from loop callbacks, timers and jobs, so no lock
    // is involved; other threads reach it through loop.call() / loop.call_get().
    std::unordered_map<crypto::ed25519_pubkey, sn_conn> sn_conns_;
    // The streams we opened on each SN connection, by connection.
    std::unordered_map<quic::ConnectionID, sn_streams> sn_streams_;
    // Peers we have connections in both directions with, and when the second one arrived.
    std::unordered_map<crypto::ed25519_pubkey, std::chrono::steady_clock::time_point> sn_bidir_;
    // Outbound connections being established, with the callbacks waiting for them.
    std::unordered_map<crypto::ed25519_pubkey, std::vector<sn_conn_callback>> pending_sn_conns_;

    // Each connection's monitor_session requests, and the monitor ones arriving behind them, run
    // one at a time in arrival order; see handle_request.
    serial_runs<connection_id, quic::message> session_runs_;

    // Which replay paces each client connection's notifications; see send_paced.
    replay_owners<connection_id> replay_owners_;

    // Session request jobs queued but not yet started, across all connections, and the most there
    // may be: oxenmq jobs are never dropped, so beyond this requests are answered with an error
    // instead of queueing without bound.  (Each connection can also have at most
    // serial_runs::MAX_WAITING waiting behind the one it has queued.)
    std::atomic<size_t> session_jobs_{0};
    static constexpr size_t MAX_SESSION_JOBS = 10'000;

    // Hands `msgs`, monitor and monitor_session requests of `conn`, to a worker to handle in order,
    // then carries on with any that have arrived on it meanwhile.
    void run_session_requests(const connection_id& conn, std::deque<quic::message> reqs);

    bool has_sn_conn(const crypto::ed25519_pubkey& pk) const;

    // True if node-to-node traffic with this node goes over QUIC.  An SN_ALPN connection we
    // currently hold with it settles that on its own (only a QUIC-capable node makes one, and
    // the version oxend reports lags a node's upgrade by up to an hour); only without one does
    // the reported version decide what to establish.
    bool sn_quic_capable(const snode::contact& ct) const;

    // Invokes `cb` with our connection to the given storage server, establishing one first if we
    // have none; `cb` gets nullptr if a connection could not be established.  It is invoked
    // immediately when already connected, otherwise once the connection attempt resolves.
    void sn_connect(const snode::contact& ct, sn_conn_callback cb);

    // The stream to send the given kind of traffic on, on the given SN connection.  For onion
    // requests this is whichever onion stream currently has the least data outstanding, or nullptr
    // when even that one has SN_ONION_STREAM_MAX_BACKLOG unsent; for forwards it is nullptr while
    // the forward stream is backlogged (see SN_FORWARD_STREAM_MAX_BACKLOG).  Also nullptr if the
    // connection has no stream set (it is not an established SN connection).
    std::shared_ptr<quic::BTRequestStream> sn_stream(
            const quic::Connection& c, sn_stream_kind kind) const;

    void on_conn_established(quic::Connection& c);
    void on_conn_closed(quic::Connection& c, uint64_t ec, size_t ep_idx);
    void close_redundant_sn_conns();

    void handle_request(quic::message msg, size_t ep_idx);

    // Node-to-node commands, accepted only on SN_ALPN connections (see handle_request).
    void handle_sn_data(quic::message msg);
    void handle_sn_data_ready(quic::message msg, const crypto::ed25519_pubkey& peer);
    void handle_sn_storage_cc(quic::message msg);
    void handle_sn_onion_request(quic::message msg);

    void handle_onion_request(quic::message msg);

    /// Handles a subscription request to monitor new messages (the `monitor` command).  The request
    /// body must be bt-encoded, and can be either a dict, or a list of dicts, containing the
    /// following keys.  Note that keys are case-sensitive and, for proper bt-encoding, must be
    /// in ascii-sorted order (rather than the order described here).
    ///
    /// The list of dicts mode is primarily intended to batch multiple subscription requests
    /// together
    ///
    /// Keys are:
    /// - exactly one of:
    ///   - p -- the account public key, prefixed with the netid, in bytes (33 bytes).  This should
    ///     be used for pubkeys that are ed keys (but not 05 session ids, see the next entry)
    ///   - P -- an ed25519 pubkey underlying a session ID, in bytes (32 bytes).  The account
    ///     will be derived by converting to an x25519 pubkey and prepending the 0x05 byte.  The
    ///     signature uses *this* key, not the derived x25519 key.
    /// - S, T -- (optional) - subaccount signature (S) and token (T) for subaccount authentication:
    ///   T is the 36-byte subaccount token, and S is the 64-byte main account signature authorizing
    ///   that token.  See the subaccount description in the "store" RPC endpoint documentation for
    ///   more details.  Both keys must be given when doing subaccount auth, neither key otherwise.
    /// - n -- list of namespace ids to monitor for new messages; the ids must be valid (i.e. -32768
    ///   through 32767), must be sorted in numeric order, and must contain no duplicates.
    /// - d -- set to 1 if the caller wants the full message data, 0 (or omitted) will omit the data
    ///   from notifications.
    /// - t -- signature timestamp, in integer unix seconds (*not* milliseconds), associated with
    ///   the signature.  This timestamp must be within the last 2 weeks (and no more than 1 day in
    ///   the future) for this request to be valid.
    /// - s -- the signature associated with this message.  This is an Ed25519 signature of the
    ///   value:
    ///       ( "MONITOR" || ACCOUNT || TS || D || NS[0] || "," || ... || "," || NS[n] )
    ///   signed by the account Ed25519 key or subaccount key (if using subaccount auth):
    ///   - ACCOUNT is the full account ID, expressed in hex (e.g. "0512345...").
    ///   - TS is the signature timestamp value, expressed as a base-10 string
    ///   - D is "0" or "1" depending on whether data is wanted (i.e. the "d" request parameter)
    ///   - NS[i] are the namespace values from the request expressed as base-10 strings
    ///
    /// If the request validates then the connection is subscribed (for 65 minutes) to new incoming
    /// messages in the given namespace(s).  A caller should renew subscriptions periodically by
    /// re-submitting the subscription request (with at most 1h between re-subscriptions).  The
    /// subscription ends when the connection closes, unless the connection is bound to a session
    /// (see `handle_monitor_session`), in which case it is attached to the session instead: it then
    /// outlives the connection, and its notifications go to whichever connection the session is
    /// bound to.
    ///
    /// The reply to the subscription request is either a bencoded dict or list of dicts containing
    /// the following keys.  In the case of a list of subscriptions in the request, the returned
    /// list will be the same length with the ith element corresponding to the ith element of the
    /// input.
    /// - success -- included on successful subscription and set to the integer 1
    /// - x -- included on successful subscription: the number of seconds until the subscription
    ///   (as renewed by this request) expires, so that the subscriber need not assume the 65
    ///   minutes.
    /// - errcode -- a numeric error value indicating the failure.  Currently implemented are:
    ///   - 1 -- invalid arguments -- called for invalid data (e.g. wrong encoding, wrong value
    ///     type, or a missing required parameter)
    ///   - 2 -- invalid pubkey -- the given pubkey/session id is not a valid pubkey.
    ///   - 3 -- invalid namespace -- the namespaces provided are invalid (e.g. invalid value, not
    ///     sorted, or contains duplicates).
    ///   - 4 -- invalid timestamp -- the timestamp is not a valid integral timestamp, is too old,
    ///     or is in the future.
    ///   - 5 -- signature failed -- the signature failed to validate.
    ///   - 6 -- wrong swarm -- the given pubkey is not stored by this service node's swarm.
    ///   - 7 -- no swarm info -- this service node does not currently know of any swarms, and so
    ///     cannot tell whether the account is one it stores.  This is a temporary condition and
    ///     the request can be retried.
    /// - error -- included whenever `errcode` is, this contains an English description of the
    ///   error.
    /// - snodes, swarm -- included with errcode 6, and describing the swarm that *does* store the
    ///   account, in the same form as the body of a 421 response (see `get_swarm`).  This lets a
    ///   client redirect itself without a further request.
    ///
    /// Each time a message is received the service node sends a `notify` command on the
    /// connection's first stream (stream id 0) with a body containing the bt-encoded message
    /// details in a dict with keys:
    ///
    /// - @ -- the account pubkey, in bytes (33).  This is the actual account value, regardless of
    ///   which of `p`/`P`/`S` was used in the request.  (The dict key is a symbol so that it sorts
    ///   first in the encoded data).
    /// - L -- the full size of the message data, in bytes; included only when `~` was cut short or
    ///   left out because of a session's `b` limit (see `handle_monitor_session`), so its presence
    ///   signals that `~` is not the whole message.  When the data fits the notification is the
    ///   same as without a limit.
    /// - h -- the message hash
    /// - n -- the message namespace (-32768 to 32767)
    /// - t -- the message timestamp (milliseconds since unix epoch), as provided by the client who
    ///   deposited the message.
    /// - z -- the expiry (milliseconds since unix epoch) of the message.
    /// - ~ -- the message data, if requested (and as much of it as a session's `b` allows).
    ///
    /// Each subscription is a monitor of its own, identified by its account, the connection (or
    /// session) it belongs to, its namespace list and its data flag (`d`).  A subscription
    /// identical in all four to an existing monitor renews it, resetting its expiry.  Any other
    /// subscription creates a new monitor alongside the existing ones.  Monitors are never
    /// merged: one whose namespace list has been superseded by a later subscription keeps its own
    /// namespaces and expiry, and simply expires if not renewed.  All pubkey/subaccount/ed25519
    /// pubkeys that access the same account count as the same account.
    ///
    /// A message is delivered once per connection (or session), however many of its monitors match
    /// it (that is, are for the message's account and include its namespace).  The notification
    /// carries data (`~`) if any of the matching monitors wants data: in full to a connection, and
    /// limited by the session's `b` (see `handle_monitor_session`) through a session.  A `b` key in
    /// a subscription is ignored, like any other key not listed above.  Thus any code that is
    /// managing subscriptions for multiple end clients should take care to check the namespace/data
    /// values and only pass it on if actually desired by a client.
    ///
    /// A subscription can also be terminated by the service node before it expires, which happens
    /// when the account stops being one that this node stores (because this node moved swarm, or
    /// because the swarm boundaries moved around the account).  The subscriber is sent a
    /// `monitor_ended` command, on the same stream as `notify`, with a body containing a bt-encoded
    /// dict with keys:
    ///
    /// - @ -- the account pubkey, in bytes (33), whose subscription has ended.
    /// - errcode -- why it ended, using the same codes as the subscription response above;
    ///   currently always 6 (wrong swarm).
    /// - error -- an English description of the reason.
    /// - snodes, swarm -- the swarm that now stores the account, in the same form as the body of a
    ///   421 response.  A client that has stopped polling can reconnect to one of these nodes and
    ///   resubscribe immediately, without having to ask where the account went.
    ///
    /// No notification is sent for a subscription that simply expires, nor when this node no
    /// longer knows of any swarms at all (in which case it has nowhere to redirect the client).
    /// A session subscription that ends while no connection is bound to the session is not
    /// notified either: it is kept, and reported as ended when the session is next resumed (unless
    /// it has expired by then, in which case it is simply gone).
    ///
    /// Note that the client should accept (and ignore) unknown keys, to allow for future expansion.
    void handle_monitor_message(quic::message msg, size_t ep_idx);

    /// Handles a `monitor_session` request, which starts or resumes a monitor session.  A session
    /// is for a bulk subscriber that wants its monitors kept across connections: it holds monitors
    /// (attached by `monitor` requests on a connection bound to it) that outlive any one
    /// connection, so that a subscriber whose connection drops can reconnect and resume the session
    /// rather than resubscribing to every account.  A subscriber wanting a session calls this
    /// before its first `monitor` on each connection, but need not wait for the reply: a
    /// `monitor_session`, and every `monitor` or `monitor_session` arriving on the connection while
    /// one is being handled, are handled one at a time in the order they arrive, so a `monitor`
    /// sent after it on the same stream is attached to the session.  Requests on different streams
    /// are not ordered with respect to each other (they need not arrive in the order sent), so a
    /// `monitor` sent on another stream must wait for the reply.  At most 64 such requests can wait
    /// behind one being handled; any more get an error response, as do requests arriving while
    /// the node has 10,000 connections' worth of them queued.  It should be sent on the
    /// connection's first stream, the one notifications arrive on, as only there is the reply
    /// ordered ahead of the replayed notifications that follow it.
    ///
    /// The request body is a bt-encoded dict with keys:
    /// - b -- (optional) the most bytes of message data to send in any notification through this
    ///   session (for monitors that want data at all).  A message whose data is larger has it cut
    ///   to its first `b` bytes, or left out entirely when `b` is 0, and its notification then also
    ///   carries `L`.  Without it there is no limit.  Like `m`, each request sets it afresh: a
    ///   resume without `b` lifts the limit.
    /// - l -- (optional) 1 (the default) to list the session's live monitors in the reply, 0 to
    ///   list only the ones that have ended.  A bulk subscriber that keeps its own record of what
    ///   it subscribed to, and when it last renewed each, can get everything else it needs from
    ///   that and save the listing's 100 or so bytes per monitor.
    /// - m -- (optional) the most missed notifications (see below) to replay for any one account,
    ///   at least 1: on a resume, only each account's newest `m` (across all of its namespaces) are
    ///   replayed, and the rest reported in the reply's `m`.  It applies only to the request that
    ///   gives it; without it everything missed is replayed.
    /// - t -- (optional) a session token previously issued by this node.
    ///
    /// If `t` names a live session, the session is resumed: the token is the only credential, so
    /// this works from any connection, whatever QUIC key (if any) it presents.  Any other
    /// connection still bound to it is unbound from it (it stays open, but no longer receives the
    /// session's notifications), and this one is bound to it. Otherwise a new session with no
    /// monitors is created and bound to this connection; omitting `t` is how a subscriber
    /// deliberately starts clean.  In either case any
    /// other session that was bound to this connection is unbound from it, as a connection is bound
    /// to at most one session.  Every reply issues a new token: the one given in `t` is no longer
    /// valid.
    ///
    /// The reply is a bt-encoded dict with keys:
    /// - t -- the session's new 32-byte token.
    /// - r -- 1 if an existing session was resumed, 0 if a new one was created.
    /// - s -- a list (empty when `r` is 0) of the accounts whose monitors ended while the session
    ///   had no connection, followed, unless `l` was 0, by the session's live monitors, as one dict
    ///   each:
    ///   - for an account whose monitors ended because the account is no longer stored by this
    ///     node (listed once, however many monitors it had): `@`, the account, in bytes (33), and
    ///     `errcode`, `error`, `snodes` and `swarm`, as in a `monitor_ended` notification.  It is
    ///     forgotten once reported.
    ///   - for each live monitor (so an account with several appears several times): `@`, and
    ///     - x -- seconds until the monitor expires.  Resuming does not extend it: monitors are
    ///       only renewed by `monitor` requests.
    ///     - d, n -- the monitor's data flag (0 or 1) and namespace list, as subscribed.
    /// - m -- a dict of the accounts for which the request's `m` cut missed notifications from the
    ///   replay, keyed by account (in bytes, so in byte order), each holding a list of one dict per
    ///   namespace that had any cut, in namespace order, with keys `n` (the namespace) and `o` (how
    ///   many were cut there).  Always present; empty when nothing was cut.
    ///
    /// A request that cannot be met gets a dict with `errcode` and `error` instead (as `monitor`
    /// does for a subscription), and changes nothing:
    /// - 1 -- the request is malformed (anything other than a bt-encoded dict of the keys above).
    ///
    /// A reply too large for a single response frame (a session of more than about 100,000
    /// monitors, listed with `l` 1) is replaced by an error response; the session is resumed (and
    /// its token rotated) all the same.
    ///
    /// The session is changed (started or resumed, bound to this connection and its token rotated)
    /// all at once.  If the connection has closed by the time the request is handled, nothing is
    /// changed and no reply is sent, so the token given still resumes the session.  A reply lost in
    /// transit after that (the connection failing just then) orphans the session: the
    /// subscriber's token is no longer valid, and it treats the node as it would a new session.
    ///
    /// While no connection is bound to a session, each message that would have been notified to it
    /// is noted instead, as where the replay of its account's namespace has to start: the session
    /// keeps, for each (account, namespace) with a missed message, the lowest place in this node's
    /// database to replay from, so what it holds does not grow with the number of messages.  And
    /// as a connection can die some time before this node notices (at most an idle timeout, 63
    /// seconds), the notifications sent through it in the 90 seconds before the session lost it
    /// are noted the same way, as possibly never received; likewise when a session is resumed on
    /// another connection while still bound to the old one.  So a resume can repeat notifications
    /// that did arrive, but never leaves out one that might not have: subscribers should expect
    /// duplicates, and recognise them by message hash.
    ///
    /// After the reply to a resume, the messages from those places on that are still stored are
    /// sent, each account's namespace in turn and oldest first (the order across them is
    /// unspecified), as ordinary `notify` commands as they would have been sent live: with data if
    /// the session's monitors matching the message wanted it, and limited by the `b` given in the
    /// resuming request.  This includes messages that arrived after the subscriber went, and
    /// messages of accounts reported as ended in the reply.  Messages that have since expired or
    /// been deleted are not sent, nor counted in `m`. The replay goes 64 messages at a time, each
    /// batch only once the connection has sent the one before on, so a long replay does not crowd
    /// out the connection.  What it has sent counts as sent through the connection (so is replayed
    /// again if the connection turns out to have died), and what it has yet to send stays with the
    /// session: if the connection closes, or the session is resumed again, the next resume carries
    /// on from there. The session is bound to the connection as the reply is composed, so
    /// notifications for messages arriving from then on are sent as they arrive, and may be
    /// delivered before the reply as well as before replayed ones; likewise a `monitor_ended` for
    /// one of the session's monitors, which is then not listed in `s`.
    ///
    /// A session lives while it is bound to a connection, and for 10 minutes after
    /// (SESSION_DETACHED_LIFETIME) once it is not: a session that has had no connection for that
    /// long is removed whole (its monitors, what it missed, and its token).  Its monitors do not
    /// expire while it has no connection, as its subscriber cannot renew them while away; while it
    /// is bound they expire as any do, unless renewed, and the session lives on without them.
    void handle_monitor_session(quic::message msg, size_t ep_idx);

    void handle_ping(quic::message msg);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace oxenss::server
