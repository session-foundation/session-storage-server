#include "https_uws.h"

#include <oxenss/logging/oxen_logger.h>

#include <fmt/format.h>
#include <iterator>

namespace oxenss::server {

static auto logcat = log::Cat("server");

namespace {

    struct uws_call : HttpsCall {
        HTTPS_uWS& backend;
        HTTPS_uWS::HttpResponse& res;

        uws_call(HTTPS_uWS& backend, HTTPS_uWS::HttpResponse& res, HttpsRequest request) :
                HttpsCall{backend}, backend{backend}, res{res} {
            this->request = std::move(request);
        }

        // If we have to drop the request because we are overloaded we want to reply with an
        // error (so that we close the connection instead of leaking it and leaving it hanging).
        // We don't do this, of course, if the request got aborted and replied to.
        ~uws_call() override {
            if (replied || aborted)
                return;
            backend.run_on_loop(
                    [&b = backend, &r = res] { b.write(r, HTTPS::busy_response(), false); });
        }

      protected:
        void send(rpc::Response response, bool force_close) override {
            backend.run_on_loop(
                    [self = shared_from_this(), response = std::move(response), force_close] {
                        auto& call = static_cast<uws_call&>(*self);
                        if (call.aborted)
                            return;
                        call.backend.write(call.res, response, force_close);
                    });
        }
    };

}  // namespace

HTTPS_uWS::HTTPS_uWS(
        snode::ServiceNode& sn,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::vector<std::tuple<std::string, uint16_t, bool>> bind,
        const std::filesystem::path& ssl_cert,
        const std::filesystem::path& ssl_key,
        crypto::legacy_keypair legacy_keys) :
        HTTPS{sn, rh, rl, std::move(legacy_keys)} {
    // uWS is designed to work from a single thread, which is good (we pull off the requests and
    // then stick them into the LMQ job queue to be scheduled along with other jobs).  But as a
    // consequence, we need to create everything inside that thread.  We *also* need to get the
    // (thread local) event loop pointer back from the thread so that we can shut it down later
    // (injecting a callback into it is one of the few thread-safe things we can do across
    // threads).
    //
    // Things we need in the owning thread, fulfilled from the http thread:

    // - the uWS::Loop* for the event loop thread (which is thread_local).  We can get this
    // during
    //   thread startup, after the thread does basic initialization.
    std::promise<uWS::Loop*> loop_promise;
    auto loop_future = loop_promise.get_future();

    // - the us_listen_socket_t* on which the server is listening.  We can't get this until we
    //   actually start listening, so wait until `start()` for it.  (We also double-purpose it
    //   to send back an exception if one fires during startup).
    std::promise<std::vector<us_listen_socket_t*>> startup_success_promise;
    startup_success_ = startup_success_promise.get_future();

    // Things we need to send from the owning thread to the event loop thread:
    // - a signal when the thread should bind to the port and start the event loop (when we call
    //   start()).
    // startup_promise_

    // This list is chosen for speed, not strength: the client cannot verify our certificate, so
    // the TLS layer protects nothing that the payload's own encryption to our X25519 key does not
    // already cover.  It only constrains TLS 1.2 -- TLS 1.3 suites come from
    // SSL_CTX_set_ciphersuites, which uSockets never calls.
    //
    // AES-256 is omitted as it is ~7% slower than AES-128 here for strength we have no use for.
    // Both AES-128-GCM and ChaCha20 are offered because neither is faster in general: ChaCha20
    // wins on small payloads and on clients without AES hardware, AES on larger ones.  uSockets
    // sets no SSL_OP_CIPHER_SERVER_PREFERENCE, so the client picks -- which is what we want, since
    // it is the side that knows whether it has AES acceleration.
    static constexpr auto ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305";

    uWS::SocketContextOptions https_opts{
            .key_file_name = ssl_key.c_str(),
            .cert_file_name = ssl_cert.c_str(),
            .ssl_ciphers = ciphers};

    server_thread_ = std::thread{
            [this, bind = std::move(bind), &https_opts](
                    std::promise<uWS::Loop*> loop_promise,
                    std::future<bool> startup_future,
                    std::promise<std::vector<us_listen_socket_t*>> startup_success) {
                uWS::SSLApp https{https_opts};
                try {
                    // Routing is done by HTTPS::on_headers(), so everything goes through the one
                    // handler.
                    https.any("/*", [this](HttpResponse* res, uWS::HttpRequest* req) {
                        handle(res, req);
                    });
                } catch (...) {
                    loop_promise.set_exception(std::current_exception());
                    return;
                }
                // We've initialized, signal the calling thread
                loop_promise.set_value(uWS::Loop::get());
                // Now wait until we get the signal to go (sent when the caller calls start() call).
                if (!startup_future.get())
                    // False means cancel, i.e. we got destroyed/shutdown without start() being
                    // called
                    return;

                std::vector<us_listen_socket_t*> listening;
                try {
                    bool required_bind_failed = false;
                    for (const auto& [addr, port, required] : bind)
                        https.listen(
                                addr,
                                port,
                                LIBUS_LISTEN_EXCLUSIVE_PORT,
                                [&listening,
                                 req = required,
                                 &required_bind_failed,
                                 addr = fmt::format("{}:{}", addr, port)](
                                        us_listen_socket_t* sock) {
                                    if (sock) {
                                        log::info(logcat, "HTTPS server listening at {}", addr);
                                        listening.push_back(sock);
                                    } else if (req) {
                                        required_bind_failed = true;
                                        log::critical(
                                                logcat,
                                                "HTTPS server failed to bind to required address "
                                                "{}",
                                                addr);
                                    } else {
                                        log::warning(
                                                logcat,
                                                "HTTPS server failed to bind to (non-required) "
                                                "address {}",
                                                addr);
                                    }
                                });

                    if (listening.empty() || required_bind_failed) {
                        std::string error =
                                "RPC HTTP server failed to bind{}; tried to bind to: "_format(
                                        listening.empty() ? "; no valid bind address(es) given"
                                                          : "");
                        for (const auto& [addr, port, required] : bind)
                            fmt::format_to(std::back_inserter(error), " {}:{}", addr, port);
                        throw std::runtime_error{error};
                    }
                } catch (...) {
                    startup_success.set_exception(std::current_exception());
                    return;
                }
                startup_success.set_value(std::move(listening));

                https.run();
            },
            std::move(loop_promise),
            startup_promise_.get_future(),
            std::move(startup_success_promise)};

    loop_ = loop_future.get();
}

void HTTPS_uWS::write(HttpResponse& r, const rpc::Response& response, bool force_close) {
    auto rendered = render(response);
    r.cork([&] {
        r.writeStatus(fmt::format("{} {}", rendered.status.first, rendered.status.second));
        for (const auto& [h, v] : rendered.headers)
            r.writeHeader(h, v);
        r.end(rendered.body, force_close || closing());
    });
}

void HTTPS_uWS::handle(HttpResponse* res, uWS::HttpRequest* req) {
    HttpsRequest request;
    request.method = req->getCaseSensitiveMethod();
    request.uri = req->getUrl();
    for (const auto& [header, value] : *req)
        request.headers[std::string{header}] = value;
    // Either 4 (ipv4) or 16 (ipv6) bytes in network order.  uWS offers a
    // getRemoteAddressAsText(), but it doesn't format IPv6 addresses nicely so we format it
    // ourselves.
    auto addr = res->getRemoteAddress();
    request.set_remote({reinterpret_cast<const uint8_t*>(addr.data()), addr.size()});

    if (auto immediate = on_headers(request)) {
        write(*res, immediate->response, immediate->force_close);
        return;
    }

    auto call = std::make_shared<uws_call>(*this, *res, std::move(request));
    res->onAborted([call] { call->aborted = true; });
    res->onData([call = std::move(call)](std::string_view d, bool done) mutable {
        call->request.body += d;
        if (done)
            call->https.dispatch(std::move(call));
    });
}

void HTTPS_uWS::start() {
    if (sent_startup_)
        throw std::logic_error{"Cannot call HTTPS::start() more than once"};

    startup_promise_.set_value(true);
    sent_startup_ = true;
    listen_socks_ = startup_success_.get();
}

void HTTPS_uWS::shutdown(bool join) {
    if (!server_thread_.joinable())
        return;

    if (!sent_shutdown_) {
        log::trace(logcat, "initiating shutdown");
        if (!sent_startup_) {
            startup_promise_.set_value(false);
            sent_startup_ = true;
        } else if (!listen_socks_.empty()) {
            loop_->defer([this] {
                log::trace(logcat, "closing {} listening sockets", listen_socks_.size());
                for (auto* s : listen_socks_)
                    us_listen_socket_close(/*ssl=*/true, s);
                listen_socks_.clear();

                set_closing();
            });
        }
        sent_shutdown_ = true;
    }

    log::trace(logcat, "joining https server thread");
    if (join)
        server_thread_.join();
    log::trace(logcat, "done shutdown");
}

HTTPS_uWS::~HTTPS_uWS() {
    shutdown(true);
}

}  // namespace oxenss::server
