#pragma once

#include <oxenss/common/formattable.h>
#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/version.h>
#include "utils.h"

#include <oxen/quic/address.hpp>

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace oxenmq {
class OxenMQ;
}

namespace oxenss::server {
using namespace std::literals;

// Maximum incoming HTTPS request size, in bytes.
inline constexpr uint64_t MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024;

// The library implementing the HTTPS listener.  Which of these are available is decided at build
// time (see the HTTPS_BACKEND_* cmake options); which one is used is decided at startup.
enum class HttpsBackend {
    uwebsockets,
    microhttpd,
};

std::string_view to_string(HttpsBackend b);
std::optional<HttpsBackend> parse_https_backend(std::string_view name);

// The backends compiled into this binary.
std::span<const HttpsBackend> available_https_backends();

// A request as seen by the backend-independent core: the backend fills in everything except
// `body` when the request line and headers have arrived, then appends to `body` as it streams
// in.
struct HttpsRequest {
    std::string method;
    std::string uri;
    http::headers headers;
    // The remote address formatted for logging, e.g. `1.2.3.4` or `[2001:db8::1]`.
    std::string remote_addr;
    // The remote address as an IPv6 address (IPv4-mapped if the client connected over IPv4), for
    // rate limiting.  Unset if the backend gave us something that is neither 4 nor 16 bytes.
    std::optional<oxen::quic::ipv6> remote_ip;
    std::string body;

    // Sets `remote_addr` and `remote_ip` from a raw network-order address of 4 (IPv4) or 16
    // (IPv6) bytes.
    void set_remote(std::span<const uint8_t> raw);
};

class HTTPS;

// Per-request state shared between the core and a backend.  A backend creates one (of its own
// subclass) once it has decided the request needs its body read, hands it to HTTPS::dispatch()
// when the body is complete, and receives the eventual response through `send()`.
//
// Ownership is shared between whatever the backend needs to keep it alive and the OMQ job that
// processes it; if that job is dropped without ever replying (OMQ overloaded) the destructor is
// the only hook left, and the backend's destructor is responsible for sending
// HTTPS::busy_response() so that the client gets an error instead of a hung connection.
struct HttpsCall : std::enable_shared_from_this<HttpsCall> {
    HTTPS& https;
    HttpsRequest request;
    // Set by the backend if the client went away; once set the response is never sent.
    std::atomic<bool> aborted{false};
    // Set (once) when a response has been handed to the backend.
    std::atomic<bool> replied{false};

    explicit HttpsCall(HTTPS& https) : https{https} {}
    virtual ~HttpsCall() = default;

    HttpsCall(const HttpsCall&) = delete;
    HttpsCall(HttpsCall&&) = delete;
    HttpsCall& operator=(const HttpsCall&) = delete;
    HttpsCall& operator=(HttpsCall&&) = delete;

    // Sends the response for this request, exactly once; later calls are ignored.  May be
    // called from any thread.
    void reply(rpc::Response response, bool force_close = false);

  protected:
    // Backend implementation of reply(): deliver `response` to the client, closing the
    // connection afterwards if `force_close` or if the server is shutting down.  Must be safe to
    // call from any thread; will be called at most once.
    virtual void send(rpc::Response response, bool force_close) = 0;
};

// A response ready to be written by a backend: the status, the complete header list (including
// the Server header and a Content-Type defaulted from the body type when the response did not
// supply one), and the body.  `body` may refer into the rpc::Response it was rendered from, so
// that must outlive this.
struct RenderedResponse {
    http::response_code status;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body_storage;
    std::string_view body;
};

// HTTPS listener.  The backend-independent parts of handling a request -- routing, body size
// limits, rate limiting, handing work to OMQ, and turning an rpc::Response into status, headers
// and body -- live here; talking to the network lives in a subclass, one per HttpsBackend.
class HTTPS {
  public:
    virtual ~HTTPS() = default;

    /// Starts the server: binds and begins accepting requests.  Core must have been initialized
    /// and OxenMQ started.  Throws if binding fails.
    virtual void start() = 0;

    /// Closes the http server connection.  Can safely be called multiple times, or to abort a
    /// startup if called before start().
    ///
    /// \param join - if true, wait for the server thread to exit.  If false then joining will
    /// occur during destruction.
    virtual void shutdown(bool join = false) = 0;

    virtual HttpsBackend backend() const = 0;

    // Backend entry point once the request line and headers are in (`req.body` is still empty).
    // Returns a response to send immediately, in which case the backend must not read the body
    // and must send the response (closing afterwards if `force_close`); or nullopt, in which
    // case the backend reads the body into an HttpsCall and calls dispatch() when it is complete.
    struct Immediate {
        rpc::Response response;
        bool force_close = false;
    };
    std::optional<Immediate> on_headers(HttpsRequest& req);

    // Backend entry point once the request body is complete.  Takes over the call: the response
    // is delivered through `call->reply()`, possibly much later and from another thread.
    void dispatch(std::shared_ptr<HttpsCall> call);

    // Turns a response into what the backend has to put on the wire.
    RenderedResponse render(const rpc::Response& res) const;

    // The response a backend sends for a call that was dropped without being processed.
    static rpc::Response busy_response();

    // Builds the response for a plain error: text/plain with `body`, or the status reason if no
    // body is given.
    static rpc::Response error_response(
            http::response_code code, std::optional<std::string_view> body = std::nullopt);

    const std::string& server_header() const { return server_header_; }

    // True once shutdown has begun; responses sent after this close the connection.
    bool closing() const { return closing_.load(std::memory_order_relaxed); }

    snode::ServiceNode& service_node() { return service_node_; }

  protected:
    HTTPS(snode::ServiceNode& sn,
          rpc::RequestHandler& rh,
          rpc::RateLimiter& rl,
          crypto::legacy_keypair legacy_keys);

    void set_closing() { closing_.store(true, std::memory_order_relaxed); }

    // Cached string we send for the Server header
    std::string server_header_ =
            "Oxen Storage Server/" + std::string{STORAGE_SERVER_VERSION_STRING};
    // Our owning service node
    snode::ServiceNode& service_node_;
    // OMQ reference (from service_node_)
    oxenmq::OxenMQ& omq_;
    // Request handler
    rpc::RequestHandler& request_handler_;
    // Rate limiter for direct client requests
    rpc::RateLimiter& rate_limiter_;
    // Keys for signing responses
    crypto::legacy_keypair legacy_keys_;

  private:
    // Checks whether the snode is ready; if not, returns the 503 to send.
    std::optional<rpc::Response> check_ready();

    /// handles cors headers by adding any needed headers to the request's header map
    void handle_cors(HttpsRequest& req);

    void process_storage_rpc_req(std::shared_ptr<HttpsCall> call);
    void process_onion_req_v2(std::shared_ptr<HttpsCall> call);

    // Access-Control-Allow-Origin header values; if one of these match the incoming Origin
    // header we return it in the ACAO header; otherwise (or if this is empty) we omit the
    // header entirely.
    std::unordered_set<std::string> cors_;
    // If true then always reply with 'Access-Control-Allow-Origin: *' to allow anything.
    bool cors_any_ = false;
    std::atomic<bool> closing_{false};
};

// Constructs the HTTPS server for the given backend, listening on one or more addresses.
//
// \param bind {address,port,required} tuples to bind to.  If `required` is set then start() will
// throw if binding fails, if not then startup will succeed as long as at least one bind address
// works.
//
// Throws std::invalid_argument if `backend` was not compiled in.
std::unique_ptr<HTTPS> make_https(
        HttpsBackend backend,
        snode::ServiceNode& sn,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::vector<std::tuple<std::string, uint16_t, bool>> bind,
        const std::filesystem::path& ssl_cert,
        const std::filesystem::path& ssl_key,
        crypto::legacy_keypair legacy_keys);

}  // namespace oxenss::server

template <>
inline constexpr bool oxenss::to_string_formattable<oxenss::server::HttpsBackend> = true;
