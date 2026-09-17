#pragma once

#include "https.h"

#include <microhttpd.h>

#include <cstdarg>
#include <memory>
#include <mutex>
#include <unordered_set>

namespace oxenss::server {

namespace detail {
    struct MhdConn;
}

// HTTPS listener implemented on libmicrohttpd.
//
// libmicrohttpd runs its own polling thread per daemon and calls back into us from it; a response
// can only be queued from inside that callback.  Since our responses arrive later from OMQ worker
// threads, each request's connection is suspended (taken out of the event loop) once its body is
// in, and resumed -- which is legal from any thread -- when the response is ready, at which point
// libmicrohttpd calls us again and we queue it.
class HTTPS_MHD : public HTTPS {
  public:
    HTTPS_MHD(
            snode::ServiceNode& sn,
            rpc::RequestHandler& rh,
            rpc::RateLimiter& rl,
            std::vector<std::tuple<std::string, uint16_t, bool>> bind,
            const std::filesystem::path& ssl_cert,
            const std::filesystem::path& ssl_key,
            crypto::legacy_keypair legacy_keys);

    ~HTTPS_MHD() override;

    void start() override;
    void shutdown(bool join = false) override;
    HttpsBackend backend() const override { return HttpsBackend::microhttpd; }

    // The ports we ended up listening on, one per daemon started; only meaningful after
    // start().  (Mainly useful when binding to port 0.)
    std::vector<uint16_t> listening_ports() const;

  private:
    MHD_Result on_request(
            MHD_Connection* conn,
            const char* url,
            const char* method,
            const char* upload_data,
            size_t* upload_data_size,
            void** req_cls);
    void on_completed(void** req_cls, MHD_RequestTerminationCode code);
    void on_log(const char* fmt, va_list ap);

    // Sends `response` on `conn`; must be called from inside a libmicrohttpd callback.
    MHD_Result queue(MHD_Connection* conn, const rpc::Response& response, bool force_close);

    MHD_Daemon* start_daemon(const std::string& addr, uint16_t port, bool dual_stack);

    bool any_suspended();

    std::vector<std::tuple<std::string, uint16_t, bool>> bind_;
    std::string cert_pem_, key_pem_;
    std::vector<MHD_Daemon*> daemons_;
    bool started_ = false, stopped_ = false;

    // Every connection currently between "body complete" and "request completed", so that
    // shutdown can resume anything still suspended (libmicrohttpd requires that before stopping).
    std::mutex conns_mutex_;
    std::unordered_set<std::shared_ptr<detail::MhdConn>> conns_;
};

}  // namespace oxenss::server
