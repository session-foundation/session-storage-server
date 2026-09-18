#pragma once

#include "utils.h"
#include "mqbase.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/snode/service_node.h>

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

#include <unordered_map>

namespace oxenss::rpc {
class RequestHandler;
}  // namespace oxenss::rpc

namespace oxenss::server {

namespace quic = oxen::quic;

using quic_callback = std::function<void(quic::message)>;
using Address = quic::Address;

struct PendingRequest {
    std::optional<std::string> name = std::nullopt;
    std::string body;
    quic_callback func = nullptr;

    // Constructor
    PendingRequest(std::string name, std::string body, quic_callback func) :
            name{std::move(name)}, body{std::move(body)}, func{std::move(func)} {}
    PendingRequest(std::string_view name, std::string_view body, quic_callback func) :
            name{name}, body{body}, func{std::move(func)} {}
};

using RequestQueue = std::deque<PendingRequest>;

// ALPN for connections between storage servers (SN_QUIC_VERSION and later).  Node-to-node commands
// are accepted only on connections negotiated with it, and the listener requires and verifies the
// peer's ed25519 key on them.  The plain client ALPN carries neither requirement.
inline constexpr auto SN_ALPN = "oxenstorage-sn";

// Two storage servers can race to connect to each other, ending up with a connection in each
// direction.  Both are kept for this long after the second one is established, so that anything
// already sent on the one that loses has time to complete, then the loser is closed.  Both sides
// pick the same loser: the connection initiated by the node with the lower ed25519 key wins.
inline constexpr auto SN_CONN_REDUNDANT_LINGER = 20s;

// Keep-alive and idle timeout for connections to other storage servers.  The connection is held
// open indefinitely; the pings keep it from idling out and detect a dead peer.
inline constexpr auto SN_CONN_KEEP_ALIVE = 15s;
inline constexpr auto SN_CONN_IDLE_TIMEOUT = 60s;

// On each connection with another storage server we open a fixed set of streams and send each
// kind of traffic on its own, so that none waits behind another (a QUIC stream delivers in order
// and has its own flow-control window; separate streams do not):
// - command: forwarded client commands, handshakes and pings -- small and latency-sensitive;
// - data: message batches (dumps and deliveries) -- bulk;
// - onion: onion request hops, spread over several so that a large payload in transit holds up
//   only the hops sharing its stream.
// The peer opens its own set for what it sends us; our handler treats every incoming stream alike.
inline constexpr size_t SN_ONION_STREAMS = 4;

enum class sn_stream_kind { command, data, onion };

class QUIC : public MQBase {
  public:
    QUIC(snode::ServiceNode& snode,
         rpc::RequestHandler& rh,
         rpc::RateLimiter& rl,
         std::span<const Address> bind,
         const crypto::ed25519_seckey& sk);

    void startup_endpoint();

    void notify(std::vector<connection_id>&, std::string_view notification) override;

    void notify_monitor_ended(std::vector<connection_id>&, std::string_view notification) override;

    void reachability_test(std::shared_ptr<snode::sn_test> test) override;

    void sweep_sn_connections() override;

    bool sn_connected(const snode::contact& ct) override;

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
    // Fire-and-forget push of `notification` to each quic connection in `conns`, as a `command`
    // on the connection's stream 0.
    void send_notification(
            std::vector<connection_id>& conns, std::string command, std::string_view notification);

    std::shared_ptr<quic::TLSCreds> tls_creds;
    std::vector<std::shared_ptr<quic::Endpoint>> endpoints;
    quic::Endpoint* reach_ep = nullptr;
    size_t reach_ep_idx = 0;

    rpc::RequestHandler& request_handler;

    // Close codes for connections we close deliberately, so that the closed callback can tell them
    // from failures.
    static constexpr uint64_t CONN_CLOSE_REDUNDANT = 6;
    static constexpr uint64_t CONN_CLOSE_NOT_SN = 7;

    // Our connections with one other storage server, in either or both directions (see
    // SN_CONN_REDUNDANT_LINGER).
    struct sn_conn {
        bool inbound_wins;
        std::shared_ptr<quic::Connection> inbound, outbound;

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
        std::shared_ptr<quic::BTRequestStream> command, data;
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
    // requests this is whichever onion stream currently has the least data outstanding.  Returns
    // nullptr if the connection has no stream set (it is not an established SN connection).
    std::shared_ptr<quic::BTRequestStream> sn_stream(
            const quic::Connection& c, sn_stream_kind kind) const;

    void on_conn_established(quic::Connection& c);
    void on_conn_closed(quic::Connection& c, uint64_t ec, size_t ep_idx);
    void close_redundant_sn_conns();

    std::shared_ptr<quic::Endpoint> create_endpoint();

    void handle_request(quic::message msg, size_t ep_idx);

    // Node-to-node commands, accepted only on SN_ALPN connections (see handle_request).
    void handle_sn_data(quic::message msg);
    void handle_sn_data_ready(quic::message msg, const crypto::ed25519_pubkey& peer);
    void handle_sn_storage_cc(quic::message msg);
    void handle_sn_onion_request(quic::message msg);

    void handle_onion_request(quic::message msg);

    void handle_monitor_message(quic::message msg, size_t ep_idx);

    void handle_ping(quic::message msg);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace oxenss::server
