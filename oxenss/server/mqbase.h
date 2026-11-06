#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <oxen/quic/connection.hpp>

#include "utils.h"

namespace oxenss {

namespace rpc {
    class RequestHandler;
    class RateLimiter;
}  // namespace rpc

namespace snode {
    class ServiceNode;
    struct sn_test;
    struct contact;
}  // namespace snode

struct message;

}  // namespace oxenss

namespace oxenss::server {

using namespace std::literals;

/// Base method for common functionality for message-queue request classes, that is, OxenMQ and
/// BTRequestStream.

class MQBase {
  protected:
    snode::ServiceNode* service_node_ = nullptr;
    rpc::RequestHandler* request_handler_ = nullptr;
    rpc::RateLimiter* rate_limiter_ = nullptr;

    // Attempts to handle the given request, by name.  Returns true if the name was found (in which
    // case the response is handled), false if not found.
    bool handle_client_rpc(
            std::string_view name,
            std::string_view params,
            std::optional<oxen::quic::ipv6> remote_addr,
            std::function<void(http::response_code status, std::string_view body)> reply,
            bool forwarded = false);

    // Subclasses may override this to extend a json or bt response with a status code.  The default
    // returns the given response as-is.  This is primarily aimed at the QUIC implementation which
    // combines status code + body into a list (the OMQ version does not, but rather sends them as
    // two separate frames of the response for errors).
    virtual nlohmann::json wrap_response(
            [[maybe_unused]] const http::response_code& status, nlohmann::json response) const {
        return response;
    }

  public:
    /// Pushes a notification for the newly stored message `m` to the subscribers monitoring its
    /// account.  The default does nothing: only the QUIC server carries monitors.
    virtual void notify_message(const message&) {}

    /// Terminates every monitor subscription for an account this node no longer serves; see
    /// Monitors::drop_foreign_monitors.  Must be called after a swarm update has taken effect.  The
    /// default does nothing, as for `notify_message`.
    virtual void drop_foreign_monitors() {}

    virtual void reachability_test(std::shared_ptr<snode::sn_test> test) = 0;

    // Called after each service node list update so that connections held open to nodes that are
    // no longer service nodes can be closed.  The default does nothing.
    virtual void sweep_sn_connections() {}

    using sn_reply_callback = std::function<void(bool success, std::vector<std::string> parts)>;
    using sn_fallback = std::function<void(std::vector<std::string> parts)>;

    // The failure part of a request refused without being sent because too much is already queued
    // for the node; see sn_request.
    static constexpr std::string_view SN_STREAM_FULL = "STREAMFULL";

    // Sends node-to-node request `cmd` ("data", "data_ready", "storage_cc" or "onion_request")
    // with the given message parts to `ct` over this transport, if this transport carries
    // node-to-node traffic with that node; otherwise hands the parts to `fallback`, which tries
    // the next transport (the default does only that: no such traffic).  The decision, and so
    // `fallback`, may happen later on another thread.  Whatever the transport, the reply reaches
    // `cb` in oxenmq's shape: `success` is false on failure, with parts {"TIMEOUT"} for a timeout
    // or {SN_STREAM_FULL} for a request refused for the node's backlog; otherwise the parts are the
    // reply body, or [code, reason] for a refused storage_cc or a hop reply.
    virtual void sn_request(
            const snode::contact&,
            std::string_view,
            std::vector<std::string> parts,
            sn_reply_callback,
            std::chrono::milliseconds,
            sn_fallback fallback) {
        fallback(std::move(parts));
    }

    virtual ~MQBase() = default;
};

}  // namespace oxenss::server
