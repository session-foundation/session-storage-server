#pragma once

#include "https.h"

#include <future>
#include <thread>

#include <uWebSockets/App.h>

namespace oxenss::server {

// HTTPS listener implemented on uWebSockets.
class HTTPS_uWS : public HTTPS {
  public:
    using HttpResponse = uWS::HttpResponse<true /*SSL*/>;

    HTTPS_uWS(
            snode::ServiceNode& sn,
            rpc::RequestHandler& rh,
            rpc::RateLimiter& rl,
            std::vector<std::tuple<std::string, uint16_t, bool>> bind,
            const std::filesystem::path& ssl_cert,
            const std::filesystem::path& ssl_key,
            crypto::legacy_keypair legacy_keys);

    ~HTTPS_uWS() override;

    void start() override;
    void shutdown(bool join = false) override;
    HttpsBackend backend() const override { return HttpsBackend::uwebsockets; }
    std::vector<uint16_t> listening_ports() const override;

    // Writes a response to `res` and finalizes it.  Must be called from the server thread.
    void write(HttpResponse& res, const rpc::Response& response, bool force_close);

    // Runs `f` on the server thread: immediately if already on it, otherwise deferred into the
    // event loop (all writes have to happen on that thread).
    template <typename Func>
    void run_on_loop(Func&& f) {
        if (std::this_thread::get_id() == server_thread_.get_id())
            f();
        else
            loop_->defer(std::forward<Func>(f));
    }

  private:
    void handle(HttpResponse* res, uWS::HttpRequest* req);

    // A promise we send from outside into the event loop thread to signal it to start.  We sent
    // "true" to go ahead with binding + starting the event loop, or false to abort.
    std::promise<bool> startup_promise_;
    // A future (promise held by the thread) that delivers us the listening uSockets sockets so
    // that, when we want to shut down, we can tell uWebSockets to close them (which will then
    // run off the end of the event loop).  This also doubles to propagate listen exceptions
    // back to us.
    std::future<std::vector<us_listen_socket_t*>> startup_success_;
    // Whether we have sent the startup/shutdown signals
    bool sent_startup_{false}, sent_shutdown_{false};

    // The uWebSockets event loop pointer (so that we can inject a callback to shut it down)
    uWS::Loop* loop_{nullptr};
    // The socket(s) we are listening on
    std::vector<us_listen_socket_t*> listen_socks_;
    // The thread in which the uWebSockets event listener is running
    std::thread server_thread_;
};

}  // namespace oxenss::server
