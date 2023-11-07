#pragma once

#include "utils.h"

#include <oxenss/crypto/keys.h>
#include <oxenss/logging/oxen_logger.h>

#include <quic.hpp>

namespace oxenss::rpc {
class RequestHandler;
}  // namespace oxenss::rpc

namespace oxenss::server {
class OMQ;
}

namespace oxenss::quic {

static auto logcat = log::Cat("quic");

struct Endpoint;

using quic_callback = std::function<void(oxen::quic::message)>;
using Address = oxen::quic::Address;

enum class message_type { REQUEST = 0, DATAGRAM = 1 };

struct PendingMessage {
    std::optional<std::string> name = std::nullopt;
    std::string body;
    message_type type;
    quic_callback func = nullptr;

    // Constructors for datagrams
    PendingMessage(std::string _b) : body{std::move(_b)}, type{message_type::DATAGRAM} {}
    PendingMessage(std::string_view _b) : body{_b}, type{message_type::DATAGRAM} {}

    // Constructors for requests
    PendingMessage(std::string _n, std::string _b, quic_callback _f) :
            name{std::move(_n)},
            body{std::move(_b)},
            type{message_type::REQUEST},
            func{std::move(_f)} {}
    PendingMessage(std::string_view _n, std::string_view _b, quic_callback _f) :
            name{_n}, body{_b}, type{message_type::REQUEST}, func{std::move(_f)} {}
};

using MessageQueue = std::deque<PendingMessage>;

struct Connection {
    friend struct Endpoint;

    Connection(
            std::shared_ptr<oxen::quic::connection_interface>& c,
            std::shared_ptr<oxen::quic::BTRequestStream>& s);

    void send(std::string method, std::string body, quic_callback f = nullptr);

  private:
    std::shared_ptr<oxen::quic::connection_interface> conn;
    std::shared_ptr<oxen::quic::BTRequestStream> control_stream;

  public:
    //
};

struct Endpoint {

    static std::shared_ptr<Endpoint> make(
            rpc::RequestHandler& rh,
            server::OMQ& q,
            const Address& bind,
            const crypto::ed25519_seckey& sk);

    bool send(
            oxen::quic::ConnectionID cid,
            std::string method,
            std::string body,
            quic_callback func = nullptr);  // may not need this default values

    std::shared_ptr<quic::Connection> get_conn(const oxen::quic::ConnectionID& cid) {
        if (auto itr = conns.find(cid); itr != conns.end())
            return itr->second;

        return nullptr;
    }

    void startup_endpoint();

  private:
    Endpoint(
            rpc::RequestHandler& rh,
            server::OMQ& q,
            const Address& bind,
            const crypto::ed25519_seckey& sk);

    const Address local;
    std::unique_ptr<oxen::quic::Network> network;
    std::shared_ptr<oxen::quic::GNUTLSCreds> tls_creds;
    std::shared_ptr<oxen::quic::Endpoint> ep;

    rpc::RequestHandler& request_handler;
    server::OMQ& omq;

    // Holds all connections currently being managed by the quic endpoint
    std::unordered_map<oxen::quic::ConnectionID, std::shared_ptr<quic::Connection>> conns;

    std::shared_ptr<oxen::quic::Endpoint> create_endpoint();

    void on_conn_closed(oxen::quic::connection_interface& ci, uint64_t ec);

    void register_commands(std::shared_ptr<oxen::quic::BTRequestStream>& s);

    void handle_request(std::string name, oxen::quic::message m, bool forwarded = false);

    void handle_monitor_message(oxen::quic::message m);

  public:
    template <typename... Opt>
    bool establish_connection(const Address& addr, Opt&&... opts) {
        try {
            auto conn_interface = ep->connect(addr, tls_creds, std::forward<Opt>(opts)...);

            // emplace immediately for connection open callback to find scid
            auto [itr, b] = conns.emplace(conn_interface->scid(), nullptr);

            auto control_stream =
                    conn_interface->template get_new_stream<oxen::quic::BTRequestStream>();
            itr->second = std::make_shared<quic::Connection>(conn_interface, control_stream);

            return true;
        } catch (...) {
            log::error(logcat, "Error: failed to establish connection to {}", addr);
            return false;
        }
    }
};

}  // namespace oxenss::quic
