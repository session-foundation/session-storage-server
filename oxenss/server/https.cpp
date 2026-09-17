#include "https.h"

#include "omq.h"
#include "utils.h"
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/utils/string_utils.hpp>

#include <chrono>
#include <fmt/ranges.h>
#include <nlohmann/json.hpp>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <oxen/quic/format.hpp>
#include <oxenmq/oxenmq.h>
#include <variant>

#ifdef OXENSS_HTTPS_UWEBSOCKETS
#include "https_uws.h"
#endif

namespace oxenss::server {

static auto logcat = log::Cat("server");

using nlohmann::json;

namespace {
    const std::vector<HttpsBackend> backends{
#ifdef OXENSS_HTTPS_UWEBSOCKETS
            HttpsBackend::uwebsockets,
#endif
    };
}  // namespace

std::string_view to_string(HttpsBackend b) {
    switch (b) {
        case HttpsBackend::uwebsockets: return "uwebsockets"sv;
    }
    return "unknown"sv;
}

std::optional<HttpsBackend> parse_https_backend(std::string_view name) {
    if (name == "uwebsockets"sv || name == "uws"sv)
        return HttpsBackend::uwebsockets;
    return std::nullopt;
}

std::span<const HttpsBackend> available_https_backends() {
    return backends;
}

void HttpsRequest::set_remote(std::span<const uint8_t> raw) {
    remote_ip.reset();
    if (raw.size() == 4) {
        remote_addr = oxen::quic::ipv4{raw.first<4>()}.to_string();
        // IPv4: convert to ipv4-mapped-ipv6:
        remote_ip = oxen::quic::ipv6{
                0,
                0,
                0,
                0,
                0,
                0xffff,
                oxenc::load_big_to_host<uint16_t>(raw.data()),
                oxenc::load_big_to_host<uint16_t>(raw.data() + 2)};
    } else if (raw.size() == 16) {
        remote_ip = oxen::quic::ipv6{raw.first<16>()};
        remote_addr = "[{}]"_format(remote_ip->to_string());
    } else {
        remote_addr = "{{unknown:{}}}"_format(oxenc::to_hex(raw));
    }
}

void HttpsCall::reply(rpc::Response response, bool force_close) {
    if (replied.exchange(true))
        return;
    send(std::move(response), force_close);
}

HTTPS::HTTPS(
        snode::ServiceNode& sn,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        crypto::legacy_keypair legacy_keys) :
        service_node_{sn},
        omq_{*service_node_.omq_server()},
        request_handler_{rh},
        rate_limiter_{rl},
        legacy_keys_{std::move(legacy_keys)} {
    // Add a category for handling incoming https requests
    omq_.add_category(
            "https",
            oxenmq::AuthLevel::basic,
            2,    // minimum # of threads reserved threads for this category
            1000  // max queued requests
    );
}

rpc::Response HTTPS::error_response(
        http::response_code code, std::optional<std::string_view> body) {
    rpc::Response res{code};
    res.headers.emplace_back("Content-Type", "text/plain");
    if (body)
        res.body = std::string{*body};
    else
        res.body = std::string{code.second} + "\n";
    return res;
}

rpc::Response HTTPS::busy_response() {
    return error_response(http::SERVICE_UNAVAILABLE, "Server busy, try again later"sv);
}

RenderedResponse HTTPS::render(const rpc::Response& res) const {
    RenderedResponse out;
    out.status = res.status;
    out.headers.reserve(res.headers.size() + 2);
    out.headers.emplace_back("Server", server_header());

    const auto* json = std::get_if<nlohmann::json>(&res.body);
    const auto* binary = std::get_if<std::span<const std::byte>>(&res.body);
    if (std::none_of(begin(res.headers), end(res.headers), [](const auto& h) {
            return util::string_iequal(h.first, "content-type");
        }))
        out.headers.emplace_back(
                "Content-Type",
                json     ? "application/json"
                : binary ? "application/octet-stream"
                         : "text/plain");
    for (const auto& h : res.headers)
        out.headers.push_back(h);

    // NB: if the dump() here throws then it means we messed up and put some invalid data
    // (probably binary) into a json value.
    if (json) {
        out.body_storage = json->dump();
        out.body = out.body_storage;
    } else if (binary) {
        out.body = {reinterpret_cast<const char*>(binary->data()), binary->size()};
    } else {
        out.body = rpc::view_body(res);
    }
    return out;
}

std::optional<rpc::Response> HTTPS::check_ready() {
    if (std::string reason; !service_node_.snode_ready(&reason)) {
        log::debug(logcat, "Storage server not ready ({}), replying with 503", reason);
        return error_response(
                http::SERVICE_UNAVAILABLE, "Service node is not ready: " + reason + "\n");
    }
    return std::nullopt;
}

void HTTPS::handle_cors(HttpsRequest& req) {
    if (cors_any_)
        req.headers.emplace("Access-Control-Allow-Origin", "*");
    else if (!cors_.empty()) {
        if (auto it = req.headers.find("origin");
            it != req.headers.end() && cors_.count(it->second)) {
            req.headers.emplace("Access-Control-Allow-Origin", "*");
            req.headers.emplace("Vary", "Origin");
        }
    }
}

std::optional<HTTPS::Immediate> HTTPS::on_headers(HttpsRequest& req) {
    const bool post = req.method == "POST"sv;

    if (post && req.uri == "/ping_test/v1"sv) {
        log::trace(logcat, "Received https ping_test");
        service_node_.update_last_ping(snode::ReachType::HTTPS);
        rpc::Response resp{http::OK};
        resp.headers.emplace_back(
                http::SNODE_PUBKEY_HEADER, oxenc::to_base64(legacy_keys_.pub.view()));
        return Immediate{std::move(resp)};
    }

    if (post && req.uri == "/storage_rpc/v1"sv) {
        if (auto not_ready = check_ready())
            return Immediate{std::move(*not_ready)};
        log::trace(logcat, "POST /storage_rpc/v1");

        if (!req.remote_ip) {
            log::warning(
                    logcat,
                    "Invalid incoming request IP: '{}'; rejecting request",
                    req.remote_addr);
            return Immediate{error_response(http::BAD_REQUEST)};
        }
        if (rate_limiter_.should_rate_limit_client(*req.remote_ip)) {
            log::debug(logcat, "Rate limiting client request from {}", *req.remote_ip);
            return Immediate{error_response(http::TOO_MANY_REQUESTS)};
        }
        if (auto it = req.headers.find("x-loki-long-poll");
            it != req.headers.end() && !it->second.empty()) {
            // Obsolete header, return an error code
            return Immediate{error_response(
                    http::GONE, "long polling is no longer supported, client upgrade required")};
        }
    } else if (post && req.uri == "/onion_req/v2"sv) {
        if (auto not_ready = check_ready())
            return Immediate{std::move(*not_ready)};
        log::trace(logcat, "POST /onion_req/v2");
    } else if (req.method == "GET"sv && req.uri == "/get_stats/v1"sv) {
        // Deprecated; use /storage_rpc/v1 with method=info instead
        return Immediate{rpc::Response{http::OK, json{{"version", STORAGE_SERVER_VERSION_STRING}}}};
    } else {
        log::info(
                logcat,
                "Invalid HTTP request for {} {} from {}",
                req.method,
                req.uri,
                req.remote_addr);
        return Immediate{error_response(
                http::NOT_FOUND, fmt::format("{} {} Not Found", req.method, req.uri))};
    }

    // Everything from here on is a request whose body we need.

    if (auto it = req.headers.find("content-length"); it != req.headers.end()) {
        if (uint64_t length; !util::parse_int(it->second, length)) {
            log::warning(
                    logcat,
                    "Received HTTPS request from {} with invalid Content-Length, dropping",
                    req.remote_addr);
            return Immediate{
                    rpc::Response{http::BAD_REQUEST, "invalid Content-Length"sv},
                    /*force_close=*/true};
        } else if (length > MAX_REQUEST_BODY_SIZE) {
            log::warning(
                    logcat,
                    "Received HTTPS request from {} with too-large body ({} > {}), dropping",
                    req.remote_addr,
                    length,
                    MAX_REQUEST_BODY_SIZE);
            return Immediate{
                    rpc::Response{http::PAYLOAD_TOO_LARGE, "Request body too large"sv},
                    /*force_close=*/true};
        }
    }

    handle_cors(req);
    log::debug(logcat, "Received {} {} request from {}", req.method, req.uri, req.remote_addr);

    return std::nullopt;
}

void HTTPS::dispatch(std::shared_ptr<HttpsCall> call) {
    if (call->request.uri == "/storage_rpc/v1"sv)
        process_storage_rpc_req(std::move(call));
    else if (call->request.uri == "/onion_req/v2"sv)
        process_onion_req_v2(std::move(call));
    else
        // on_headers() only lets the two routes above through to body reading; anything else
        // here is a backend bug.
        call->reply(error_response(http::INTERNAL_SERVER_ERROR), true);
}

void HTTPS::process_storage_rpc_req(std::shared_ptr<HttpsCall> call) {
    auto& request = call->request;
    omq_.inject_task(
            "https",
            "https:" + request.uri,
            request.remote_addr,
            [this, call = std::move(call), started = std::chrono::steady_clock::now()]() mutable {
                if (call->replied || call->aborted)
                    return;

                try {
                    request_handler_.process_client_req(
                            call->request.body, [call, started](rpc::Response response) mutable {
                                log::debug(
                                        logcat,
                                        "Responding to a client request after {}",
                                        util::friendly_duration(
                                                std::chrono::steady_clock::now() - started));
                                call->reply(std::move(response));
                            });
                } catch (const std::exception& e) {
                    auto error = "Exception caught with processing client request: "s + e.what();
                    log::critical(logcat, "{}", error);
                    call->reply({http::INTERNAL_SERVER_ERROR, error});
                }
            });
}

void HTTPS::process_onion_req_v2(std::shared_ptr<HttpsCall> call) {
    auto& request = call->request;
    omq_.inject_task(
            "https",
            "https:" + request.uri,
            request.remote_addr,
            [this, call = std::move(call), started = std::chrono::steady_clock::now()]() mutable {
                if (call->replied || call->aborted)
                    return;

                rpc::OnionRequestMetadata onion{
                        crypto::x25519_pubkey{},
                        [call, started](rpc::Response res) {
                            log::debug(
                                    logcat,
                                    "Got an onion response ({} {}) as edge node (after {})",
                                    res.status.first,
                                    res.status.second,
                                    util::friendly_duration(
                                            std::chrono::steady_clock::now() - started));
                            call->reply(std::move(res));
                        },
                        0,  // hopno
                        crypto::EncryptType::aes_gcm,
                };

                try {
                    auto [ciphertext, json_req] = rpc::parse_combined_payload(call->request.body);

                    onion.ephem_key = rpc::extract_x25519_from_hex(
                            json_req.at("ephemeral_key").get_ref<const std::string&>());

                    if (auto it = json_req.find("enc_type"); it != json_req.end())
                        onion.enc_type = crypto::parse_enc_type(it->get_ref<const std::string&>());
                    // Otherwise stay at default aes-gcm

                    // Allows a fake starting hop number (to make it harder for intermediate hops
                    // to know where they are).  If omitted, defaults to 0.
                    if (auto it = json_req.find("hop_no"); it != json_req.end())
                        onion.hop_no = std::max(0, it->get<int>());

                    request_handler_.process_onion_req(ciphertext, std::move(onion));
                } catch (const std::exception& e) {
                    auto msg = fmt::format("Error parsing onion request: {}", e.what());
                    log::error(logcat, "{}", msg);
                    call->reply({http::BAD_REQUEST, msg});
                }
            });
}

std::unique_ptr<HTTPS> make_https(
        HttpsBackend backend,
        snode::ServiceNode& sn,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::vector<std::tuple<std::string, uint16_t, bool>> bind,
        const std::filesystem::path& ssl_cert,
        const std::filesystem::path& ssl_key,
        crypto::legacy_keypair legacy_keys) {
    switch (backend) {
        case HttpsBackend::uwebsockets:
#ifdef OXENSS_HTTPS_UWEBSOCKETS
            return std::make_unique<HTTPS_uWS>(
                    sn, rh, rl, std::move(bind), ssl_cert, ssl_key, std::move(legacy_keys));
#else
            break;
#endif
    }
    throw std::invalid_argument{
            "HTTPS backend '{}' is not available in this build (available: {})"_format(
                    to_string(backend), fmt::join(available_https_backends(), ", "))};
}

}  // namespace oxenss::server
