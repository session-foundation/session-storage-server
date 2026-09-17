#include "https_mhd.h"

#include <oxenss/logging/oxen_logger.h>

#include <fmt/format.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <optional>
#include <thread>

extern "C" {
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
}

namespace oxenss::server {

static auto logcat = log::Cat("server");

namespace detail {

    // The connection-side half of a request.  Shared between libmicrohttpd's per-request context
    // (which lives exactly as long as the request) and the HttpsCall (which can outlive it, if the
    // client goes away while a worker is still busy), so that whichever side finishes second can
    // tell that the other is gone.
    struct MhdConn {
        MHD_Connection* const conn;
        std::mutex mutex;
        // Set (on the daemon thread) when the connection is taken out of the event loop to wait
        // for a response; cleared by whoever resumes it.
        bool suspended = false;
        // Set when libmicrohttpd reports the request finished, after which `conn` is dead.
        bool completed = false;
        // A response waiting to be queued the next time libmicrohttpd calls us for `conn`.
        std::optional<HTTPS::Immediate> pending;

        explicit MhdConn(MHD_Connection* c) : conn{c} {}

        // Hands over the response and, if the connection is parked waiting for it, wakes it up.
        // Safe from any thread; anything after the first delivery (or after the connection has
        // gone) is dropped.
        void deliver(rpc::Response response, bool force_close) {
            std::lock_guard lock{mutex};
            if (completed || pending)
                return;
            pending.emplace(HTTPS::Immediate{std::move(response), force_close});
            if (suspended) {
                suspended = false;
                MHD_resume_connection(conn);
            }
        }
    };

}  // namespace detail

namespace {

    using detail::MhdConn;

    struct mhd_call : HttpsCall {
        std::shared_ptr<MhdConn> conn;
        // Set when the body outgrew MAX_REQUEST_BODY_SIZE mid-stream: we can't reply until the
        // upload callbacks stop, so we just stop accumulating and reject at the end.
        bool too_large = false;

        mhd_call(HTTPS& https, std::shared_ptr<MhdConn> conn) :
                HttpsCall{https}, conn{std::move(conn)} {}

        // Dropped without a reply (OMQ overloaded): make sure the client gets an error rather than
        // a connection parked forever.
        ~mhd_call() override {
            if (replied || aborted)
                return;
            conn->deliver(HTTPS::busy_response(), false);
        }

      protected:
        void send(rpc::Response response, bool force_close) override {
            conn->deliver(std::move(response), force_close);
        }
    };

    // What we keep in libmicrohttpd's per-request `req_cls` slot.  `call` is only owned here
    // until the body is complete; from then on the OMQ job owns it.
    struct req_ctx {
        std::shared_ptr<MhdConn> conn;
        std::shared_ptr<mhd_call> call;
    };

    // Chosen to match the uWebSockets backend's policy (see https_uws.cpp): TLS 1.2/1.3 only,
    // ECDHE-ECDSA with our P-256 certificate, AES-128-GCM or ChaCha20-Poly1305 at the client's
    // preference, and only the two universally supported key-exchange groups.  Unlike OpenSSL's
    // cipher list this governs TLS 1.3 as well.  Session tickets are off because a client that
    // can't verify our certificate gains nothing from resuming.
    constexpr const char* tls_priorities =
            "SECURE128:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"
            ":-CIPHER-ALL:+AES-128-GCM:+CHACHA20-POLY1305"
            ":-KX-ALL:+ECDHE-ECDSA"
            ":-SIGN-ALL:+SIGN-ECDSA-SECP256R1-SHA256"
            ":-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1"
            ":%NO_TICKETS";

    // Idle keep-alive connections are dropped after this, matching uWebSockets' default.
    constexpr unsigned connection_timeout_s = 10;
    // Per-connection pool for headers and the upload buffer.  Bigger than the 32k default so that a
    // typical onion request arrives in one or two callbacks rather than several.
    constexpr size_t connection_memory_limit = 128 * 1024;

    std::string slurp(const std::filesystem::path& p) {
        std::ifstream f{p, std::ios::binary};
        f.exceptions(std::ios::failbit | std::ios::badbit);
        return {std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{}};
    }

    MHD_Result header_iterator(
            void* cls,
            MHD_ValueKind /*kind*/,
            const char* key,
            size_t key_size,
            const char* value,
            size_t value_size) {
        auto& headers = *static_cast<http::headers*>(cls);
        headers[std::string{key, key_size}] = value ? std::string{value, value_size} : ""s;
        return MHD_YES;
    }

    void set_remote(HttpsRequest& req, MHD_Connection* conn) {
        const auto* info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        const sockaddr* sa = info ? info->client_addr : nullptr;
        if (sa && sa->sa_family == AF_INET) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
            req.set_remote({reinterpret_cast<const uint8_t*>(&in->sin_addr), 4});
        } else if (sa && sa->sa_family == AF_INET6) {
            const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
            std::span<const uint8_t> addr{reinterpret_cast<const uint8_t*>(&in6->sin6_addr), 16};
            // On a dual-stack socket IPv4 clients show up as ::ffff:a.b.c.d; report them as the
            // IPv4 address they are, as uWebSockets does.
            if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
                addr = addr.subspan(12);
            req.set_remote(addr);
        } else {
            req.set_remote({});
        }
    }

    // libmicrohttpd's option-array callback entries want the function pointer smuggled through an
    // intptr_t.
    template <typename F>
    intptr_t fn_ptr(F* f) {
        return reinterpret_cast<intptr_t>(f);
    }

}  // namespace

HTTPS_MHD::HTTPS_MHD(
        snode::ServiceNode& sn,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::vector<std::tuple<std::string, uint16_t, bool>> bind,
        const std::filesystem::path& ssl_cert,
        const std::filesystem::path& ssl_key,
        crypto::legacy_keypair legacy_keys) :
        HTTPS{sn, rh, rl, std::move(legacy_keys)},
        bind_{std::move(bind)},
        cert_pem_{slurp(ssl_cert)},
        key_pem_{slurp(ssl_key)} {}

HTTPS_MHD::~HTTPS_MHD() {
    shutdown(true);
}

namespace {
    // Owns a response for as long as libmicrohttpd is sending it, so that the body can be handed
    // over as a view rather than copied: `rendered.body` points into either `rendered` (json) or
    // `response` (string, or a span pinned by response.keepalive).  Freed from MHD's callback
    // once the response object's last reference is gone.
    struct held_response {
        rpc::Response response;
        RenderedResponse rendered;
    };
}  // namespace

MHD_Result HTTPS_MHD::queue(MHD_Connection* conn, rpc::Response response, bool force_close) {
    auto held = std::make_unique<held_response>(std::move(response), RenderedResponse{});
    held->rendered = render(held->response);
    const auto& rendered = held->rendered;
    auto* r = MHD_create_response_from_buffer_with_free_callback_cls(
            rendered.body.size(),
            rendered.body.data(),
            [](void* cls) { delete static_cast<held_response*>(cls); },
            held.get());
    if (!r) {
        log::error(logcat, "Failed to allocate HTTP response");
        return MHD_NO;
    }
    // MHD's callback owns it from here.
    (void)held.release();
    for (const auto& [h, v] : rendered.headers)
        MHD_add_response_header(r, h.c_str(), v.c_str());
    if (force_close || closing())
        MHD_add_response_header(r, "Connection", "close");
    auto ret = MHD_queue_response(conn, rendered.status.first, r);
    MHD_destroy_response(r);
    return ret;
}

MHD_Result HTTPS_MHD::on_request(
        MHD_Connection* conn,
        const char* url,
        const char* method,
        const char* upload_data,
        size_t* upload_data_size,
        void** req_cls) {
    auto* ctx = static_cast<req_ctx*>(*req_cls);

    if (!ctx) {
        // First call for this request: the request line and headers are in, the body is not.
        HttpsRequest req;
        req.method = method;
        req.uri = url;
        MHD_get_connection_values_n(conn, MHD_HEADER_KIND, header_iterator, &req.headers);
        set_remote(req, conn);

        auto immediate = on_headers(req);

        // Replying from this first call is legal, but if the request has any body still to come
        // MHD then closes the connection after the reply rather than reuse one whose request it
        // never finished reading.  That is exactly what we want for the deliberate rejections
        // (bad or over-size Content-Length: don't read the body, drop the client), and exactly
        // what we don't want for everything else, so ordinary immediate replies are held until
        // MHD's final call for the request, once it has read (and here, discarded) the body.
        if (immediate && immediate->force_close)
            return queue(conn, std::move(immediate->response), true);

        auto mconn = std::make_shared<MhdConn>(conn);
        {
            std::lock_guard lock{conns_mutex_};
            conns_.insert(mconn);
        }
        ctx = new req_ctx{mconn, nullptr};
        if (immediate) {
            mconn->pending = std::move(immediate);
        } else {
            ctx->call = std::make_shared<mhd_call>(*this, mconn);
            ctx->call->request = std::move(req);
        }
        *req_cls = ctx;
        return MHD_YES;
    }

    if (*upload_data_size > 0) {
        // Body chunk.  We are not allowed to queue a response from here, so an over-size body is
        // just noted and rejected once the upload ends.  (With no `call` the reply is already
        // decided and the body is simply discarded.)
        if (ctx->call && !ctx->call->too_large) {
            auto& body = ctx->call->request.body;
            if (body.size() + *upload_data_size > MAX_REQUEST_BODY_SIZE) {
                log::warning(
                        logcat,
                        "Received HTTPS request from {} with too-large body (> {}), dropping",
                        ctx->call->request.remote_addr,
                        MAX_REQUEST_BODY_SIZE);
                ctx->call->too_large = true;
                body.clear();
                body.shrink_to_fit();
            } else {
                body.append(upload_data, *upload_data_size);
            }
        }
        *upload_data_size = 0;
        return MHD_YES;
    }

    if (auto call = std::move(ctx->call)) {
        // Body complete.  Park the connection and hand the request off; the response comes back
        // through MhdConn::deliver(), which resumes us and we land in the block below.
        if (call->too_large) {
            call->reply(rpc::Response{http::PAYLOAD_TOO_LARGE, "Request body too large"sv}, true);
        } else {
            MHD_suspend_connection(conn);
            {
                std::lock_guard lock{ctx->conn->mutex};
                ctx->conn->suspended = true;
            }
            dispatch(std::move(call));
            return MHD_YES;
        }
    }

    // MHD's final call for the request, with a response waiting: one held back from the first
    // call, the too-large rejection from just above, or a worker's reply that resumed us.
    std::optional<Immediate> pending;
    {
        std::lock_guard lock{ctx->conn->mutex};
        pending.swap(ctx->conn->pending);
    }
    if (!pending) {
        // Nothing should be able to wake a parked connection without leaving a response, so
        // this is a bug; fail the request rather than spin.
        log::error(logcat, "HTTPS connection resumed with no response pending");
        return queue(conn, error_response(http::INTERNAL_SERVER_ERROR), true);
    }
    return queue(conn, std::move(pending->response), pending->force_close);
}

void HTTPS_MHD::on_completed(void** req_cls, MHD_RequestTerminationCode code) {
    auto* ctx = static_cast<req_ctx*>(*req_cls);
    if (!ctx)
        return;
    {
        std::lock_guard lock{ctx->conn->mutex};
        ctx->conn->completed = true;
    }
    if (ctx->call) {
        // Still reading the body when the request ended: the client went away (or timed out).
        log::debug(
                logcat,
                "HTTPS request from {} terminated before completion (code {})",
                ctx->call->request.remote_addr,
                static_cast<int>(code));
        ctx->call->aborted = true;
    }
    {
        std::lock_guard lock{conns_mutex_};
        conns_.erase(ctx->conn);
    }
    delete ctx;
    *req_cls = nullptr;
}

void HTTPS_MHD::on_log(const char* fmt, va_list ap) {
    char buf[1024];
    int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0)
        return;
    std::string_view msg{buf, std::min<size_t>(n, sizeof(buf) - 1)};
    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
        msg.remove_suffix(1);
    log::warning(logcat, "libmicrohttpd: {}", msg);
}

MHD_Daemon* HTTPS_MHD::start_daemon(const std::string& addr, uint16_t port, bool dual_stack) {
    sockaddr_storage ss{};
    bool v6 = addr.find(':') != std::string::npos;
    if (v6) {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(&ss);
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, addr.c_str(), &in6->sin6_addr) != 1)
            throw std::runtime_error{"invalid IPv6 address '" + addr + "'"};
    } else {
        auto* in = reinterpret_cast<sockaddr_in*>(&ss);
        in->sin_family = AF_INET;
        in->sin_port = htons(port);
        if (inet_pton(AF_INET, addr.c_str(), &in->sin_addr) != 1)
            throw std::runtime_error{"invalid IPv4 address '" + addr + "'"};
    }

    // MHD_USE_AUTO picks epoll on Linux (poll elsewhere); ITC is what lets a resume from a worker
    // thread wake the polling thread up.
    unsigned flags = MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_TLS | MHD_ALLOW_SUSPEND_RESUME |
                     MHD_USE_ITC | MHD_USE_ERROR_LOG;
    if (v6)
        flags |= dual_stack ? MHD_USE_DUAL_STACK : MHD_USE_IPv6;

    auto access_handler = [](void* cls,
                             MHD_Connection* conn,
                             const char* url,
                             const char* method,
                             const char* /*version*/,
                             const char* upload_data,
                             size_t* upload_data_size,
                             void** req_cls) -> MHD_Result {
        return static_cast<HTTPS_MHD*>(cls)->on_request(
                conn, url, method, upload_data, upload_data_size, req_cls);
    };
    auto completed = [](void* cls,
                        MHD_Connection* /*conn*/,
                        void** req_cls,
                        MHD_RequestTerminationCode code) {
        static_cast<HTTPS_MHD*>(cls)->on_completed(req_cls, code);
    };
    auto logger = [](void* cls, const char* fmt, va_list ap) {
        static_cast<HTTPS_MHD*>(cls)->on_log(fmt, ap);
    };

    MHD_OptionItem opts[] = {
            // First, so that complaints about any of the options below reach our log too.
            {MHD_OPTION_EXTERNAL_LOGGER, fn_ptr(+logger), this},
            {MHD_OPTION_SOCK_ADDR, 0, &ss},
            {MHD_OPTION_NOTIFY_COMPLETED, fn_ptr(+completed), this},
            {MHD_OPTION_CONNECTION_TIMEOUT, connection_timeout_s, nullptr},
            {MHD_OPTION_CONNECTION_MEMORY_LIMIT,
             static_cast<intptr_t>(connection_memory_limit),
             nullptr},
            {MHD_OPTION_HTTPS_MEM_KEY, 0, const_cast<char*>(key_pem_.c_str())},
            {MHD_OPTION_HTTPS_MEM_CERT, 0, const_cast<char*>(cert_pem_.c_str())},
            {MHD_OPTION_HTTPS_PRIORITIES, 0, const_cast<char*>(tls_priorities)},
            {MHD_OPTION_END, 0, nullptr},
    };

    auto* d = MHD_start_daemon(
            flags,
            port,
            nullptr,
            nullptr,
            +access_handler,
            this,
            MHD_OPTION_ARRAY,
            opts,
            MHD_OPTION_END);
    if (!d)
        // The reason will have gone through on_log() already.
        throw std::runtime_error{"MHD_start_daemon failed"};
    return d;
}

void HTTPS_MHD::start() {
    if (started_)
        throw std::logic_error{"Cannot call HTTPS::start() more than once"};
    started_ = true;

    // A "::" listener only gets to take IPv4 as well if nothing else is binding the IPv4 side.
    bool have_v4 = false;
    for (const auto& [addr, port, required] : bind_)
        have_v4 |= addr.find(':') == std::string::npos;

    std::string failures;
    for (const auto& [addr, port, required] : bind_) {
        try {
            daemons_.push_back(start_daemon(addr, port, /*dual_stack=*/!have_v4));
            log::info(logcat, "HTTPS server listening at {}:{}", addr, port);
        } catch (const std::exception& e) {
            if (required) {
                log::critical(
                        logcat,
                        "HTTPS server failed to bind to required address {}:{}: {}",
                        addr,
                        port,
                        e.what());
                fmt::format_to(std::back_inserter(failures), " {}:{}", addr, port);
            } else {
                log::warning(
                        logcat,
                        "HTTPS server failed to bind to (non-required) address {}:{}: {}",
                        addr,
                        port,
                        e.what());
            }
        }
    }

    if (daemons_.empty() || !failures.empty()) {
        std::string error = "RPC HTTP server failed to bind{}; tried to bind to: "_format(
                daemons_.empty() ? "; no valid bind address(es) given" : "");
        for (const auto& [addr, port, required] : bind_)
            fmt::format_to(std::back_inserter(error), " {}:{}", addr, port);
        shutdown();
        throw std::runtime_error{error};
    }
}

std::vector<uint16_t> HTTPS_MHD::listening_ports() const {
    std::vector<uint16_t> ports;
    for (auto* d : daemons_)
        if (const auto* info = MHD_get_daemon_info(d, MHD_DAEMON_INFO_BIND_PORT))
            ports.push_back(info->port);
    return ports;
}

bool HTTPS_MHD::any_suspended() {
    std::lock_guard lock{conns_mutex_};
    for (const auto& c : conns_) {
        std::lock_guard clock{c->mutex};
        if (c->suspended)
            return true;
    }
    return false;
}

void HTTPS_MHD::shutdown(bool /*join*/) {
    if (stopped_)
        return;
    stopped_ = true;
    if (daemons_.empty())
        return;

    log::trace(logcat, "initiating shutdown");
    // Stop accepting first; whatever is already in flight gets to finish (with Connection: close).
    for (auto* d : daemons_) {
        auto fd = MHD_quiesce_daemon(d);
        if (fd != MHD_INVALID_SOCKET)
            close(fd);
    }
    set_closing();

    // libmicrohttpd requires every suspended connection be resumed before the daemon is stopped.
    // In-flight requests resume themselves when their worker replies; give them a moment, then
    // fail anything still parked.
    using namespace std::chrono;
    auto deadline = steady_clock::now() + 5s;
    while (any_suspended() && steady_clock::now() < deadline)
        std::this_thread::sleep_for(10ms);

    std::vector<std::shared_ptr<MhdConn>> stragglers;
    {
        std::lock_guard lock{conns_mutex_};
        stragglers.assign(conns_.begin(), conns_.end());
    }
    for (auto& c : stragglers)
        c->deliver(error_response(http::SERVICE_UNAVAILABLE, "Server shutting down"sv), true);

    for (auto* d : daemons_)
        MHD_stop_daemon(d);
    daemons_.clear();
    log::trace(logcat, "done shutdown");
}

}  // namespace oxenss::server
