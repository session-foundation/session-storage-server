#pragma once

#include "utils.h"
#include "mqbase.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/snode/service_node.h>

#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

#include <mutex>
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

    using sn_conn_callback = std::function<void(std::shared_ptr<quic::Connection>)>;

    // True if node-to-node traffic with this node goes over QUIC.  An SN_ALPN connection we
    // currently hold with it settles that on its own (only a QUIC-capable node makes one, and
    // the version oxend reports lags a node's upgrade by up to an hour); only without one does
    // the reported version decide what to establish.
    bool sn_quic_capable(const snode::contact& ct);

    // Invokes `cb` with our connection to the given storage server, establishing one first if we
    // have none.  `cb` gets nullptr if a connection could not be established.  It may be invoked
    // before this returns (when already connected) or later from the QUIC event loop.
    void sn_connect(const snode::contact& ct, sn_conn_callback cb);

    // The request stream to use for commands to the peer on the given connection.
    std::shared_ptr<quic::BTRequestStream> sn_stream(quic::Connection& c);

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
        // Stores a new connection in the given direction, returning any it replaces (which the
        // caller closes once it no longer holds the registry mutex).
        std::shared_ptr<quic::Connection> set(std::shared_ptr<quic::Connection> c, bool is_inbound);
        // Drops and returns the connection in the given direction (nullptr if none).
        std::shared_ptr<quic::Connection> take(bool is_inbound);
        bool empty() const { return !inbound && !outbound; }
    };

    // Guards the three maps below.  Never hold it across a call into libquic that may run a
    // connection callback or wait on the QUIC loop (close_connection, connect, open_stream, ...):
    // the callbacks take it too.
    std::mutex sn_conns_mutex_;
    std::unordered_map<crypto::ed25519_pubkey, sn_conn> sn_conns_;
    // Peers we have connections in both directions with, and when the second one arrived.
    std::unordered_map<crypto::ed25519_pubkey, std::chrono::steady_clock::time_point> sn_bidir_;
    // Outbound connections being established, with the callbacks waiting for them.
    std::unordered_map<crypto::ed25519_pubkey, std::vector<sn_conn_callback>> pending_sn_conns_;

    void on_conn_established(quic::Connection& c);
    void on_conn_closed(quic::Connection& c, uint64_t ec, size_t ep_idx);
    void close_redundant_sn_conns();

    std::shared_ptr<quic::Endpoint> create_endpoint();

    void handle_request(quic::message msg, size_t ep_idx);

    void handle_onion_request(quic::message msg);

    void handle_monitor_message(quic::message msg, size_t ep_idx);

    void handle_ping(quic::message msg);

    nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status,
            nlohmann::json response) const override;
};

}  // namespace oxenss::server
