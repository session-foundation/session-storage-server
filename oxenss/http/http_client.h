#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <cpr/response.h>
#include <cpr/session.h>
#include <curl/curl.h>
#include <oxen/quic/network.hpp>

namespace oxenss::http {

/// Async client for making outbound storage server HTTP post requests.
class Client {
  public:
    using response_callback = std::function<void(cpr::Response r)>;

    // Starts a new client, attaching itself to the event loop and ready for requests.
    explicit Client(oxen::quic::Network* loop);

    // Non-copyable, non-movable
    Client(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

    // Kills all current requests and shuts down.  Callbacks on pending requests are *not* invoked.
    ~Client();

    // Initiates a new POST request.  When the request complete (or times out) `cb` will be invoked
    // with the cpr::Response object.  Note that cb is invoked inside the event loop context, so it
    // should try to be fast and definitely not do anything blocking.
    void post(
            response_callback cb,
            std::string url,
            std::string payload,
            std::chrono::milliseconds timeout,
            std::optional<std::string> host_override = std::nullopt,
            bool https_disable_validation = false);

  private:
    // FIXME: in future (dev, as of writing) versions of libquic we should a shared_ptr<Loop>
    // instead of this raw Network pointer, but currently Network doesn't give us a public interface
    // to accessing its Loop, so we whole the bigger Network here instead.  (It is still named
    // "loop", though, because we really only want a loop and Network has proxy functions for all
    // the Loop functions we use that should work fine without needing other changes when this gets
    // fixed in the future).
    oxen::quic::Network* loop;
    event* ev_timeout;
    std::shared_ptr<const bool> alive = std::make_shared<bool>(true);
    CURLM* curl_multi;
    std::unordered_map<std::shared_ptr<cpr::Session>, response_callback> active_reqs;

    friend struct curl_context;

    static void curl_perform_c(int fd, short event, void* cctx);
    static void on_timeout_c(evutil_socket_t fd, short events, void* arg);
    static int start_timeout_c(CURLM* multi, long timeout_ms, void* userp);
    static int handle_socket_c(CURL* easy, curl_socket_t s, int action, void* self, void* socketp);

    void check_multi_info();
};

}  // namespace oxenss::http
