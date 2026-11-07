#include "mqbase.h"
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "utils.h"
#include <oxen/quic/format.hpp>

namespace oxenss::server {

static auto logcat = log::Cat("server");

bool MQBase::handle_client_rpc(
        std::string_view name,
        std::string_view params,
        std::optional<oxen::quic::ipv6> remote_ip,
        std::function<void(http::response_code, std::string_view)> reply,
        bool forwarded) {
    // Check client rpc endpoints
    auto it = rpc::RequestHandler::client_rpc_endpoints.find(name);
    if (it == rpc::RequestHandler::client_rpc_endpoints.end())
        return false;

    auto& handler = it->second.mq;

    if (!forwarded && (!remote_ip || rate_limiter_->should_rate_limit_client(*remote_ip))) {
        if (remote_ip)
            log::debug(logcat, "Rate limiting client request from {}", *remote_ip);
        reply(http::TOO_MANY_REQUESTS, "Too many requests, try again later"sv);
        return true;
    }

    try {
        handler(*request_handler_,
                params,
                forwarded,
                [this, reply, bt_encoded = !params.empty() && params.front() == 'd'](
                        rpc::Response res) mutable {
                    std::string_view body;
                    std::string dump;

                    if (auto* j = std::get_if<nlohmann::json>(&res.body)) {
                        nlohmann::json resp = wrap_response(res.status, std::move(*j));
                        if (bt_encoded)
                            dump = bt_serialize(json_to_bt(std::move(resp)));
                        else
                            dump = resp.dump();
                        body = dump;
                    } else if (auto* b = std::get_if<std::span<const std::byte>>(&res.body))
                        body = {reinterpret_cast<const char*>(b->data()), b->size()};
                    else
                        body = view_body(res);

                    log::debug(
                            logcat,
                            "RPC request {} ({}), returning {}-byte {} response",
                            res.status == http::OK ? "successful" : "failed",
                            res.status.first,
                            body.size(),
                            dump.empty() ? "raw"
                            : bt_encoded ? "bt-encoded"
                                         : "json");

                    reply(res.status, body);
                });
    } catch (const rpc::parse_error& e) {
        // These exceptions carry a failure message to send back to the client
        log::debug(logcat, "Invalid request: {}", e.what());
        reply(http::BAD_REQUEST, "invalid request: "s + e.what());
    } catch (const std::exception& e) {
        // Other exceptions might contain something sensitive or irrelevant so warn about it and
        // send back a generic message.
        log::warning(logcat, "Client request raised an exception: {}", e.what());
        reply(http::INTERNAL_SERVER_ERROR, "request failed");
    }
    return true;
}

}  // namespace oxenss::server
