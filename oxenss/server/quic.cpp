#include "quic.h"
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "../snode/service_node.h"

namespace oxenss::server {

static auto logcat = log::Cat("ssquic");

QUIC::QUIC(
        snode::ServiceNode& snode,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        const Address& bind,
        const crypto::ed25519_seckey& sk) :
        local{bind},
        network{std::make_unique<oxen::quic::Network>()},
        tls_creds{oxen::quic::GNUTLSCreds::make_from_ed_seckey(sk.str())},
        ep{network->endpoint(local)},
        request_handler{rh},
        command_handler{[this](quic::message m) { handle_request(std::move(m)); }} {
    service_node_ = &snode;
    request_handler_ = &rh;
    rate_limiter_ = &rl;
}

void QUIC::startup_endpoint() {
    ep->listen(tls_creds, [&](oxen::quic::connection_interface& c) {
        c.queue_incoming_stream<oxen::quic::BTRequestStream>(command_handler);
    });
}

void QUIC::handle_monitor_message(oxen::quic::message m) {
    handle_monitor(
            m.body(),
            [&m](std::string response) { m.respond(std::move(response)); },
            m.stream()->reference_id);
}

void QUIC::handle_ping(oxen::quic::message m) {
    log::debug(logcat, "Remote pinged me");
    service_node_->update_last_ping(snode::ReachType::QUIC);
    m.respond("pong");
}

void QUIC::handle_request(oxen::quic::message m) {
    auto name = m.endpoint();

    if (handle_client_rpc(
                name,
                m.body(),
                m.stream()->remote().host(),
                [m = std::move(m)](http::response_code status, std::string_view body) {
                    m.respond(body);
                }))
        return;

    if (name == "monitor")
        return handle_monitor_message(std::move(m));

    if (name == "snode_ping")
        return handle_ping(std::move(m));

    throw quic::no_such_endpoint{};
}

nlohmann::json QUIC::wrap_response(
        [[maybe_unused]] const http::response_code& status, nlohmann::json body) const {
    // For QUIC requests we always wrap the result into a [CODE, BODY] list (even for successes).
    // This is different from the OMQ because, in OMQ, messages are multi-part and so we can
    // disambiguate success-with-body from failure-with-body by looking at the number of parts; here
    // we can't, so we always make responses a 2-element list.
    auto res = nlohmann::json::array();
    res.push_back(status.first);
    res.push_back(std::move(body));
    return res;
}

void QUIC::notify(std::vector<connection_id>& conns, std::string_view notification) {
    for (const auto& c : conns)
        if (auto* cid = std::get_if<oxen::quic::ConnectionID>(&c))
            if (auto conn = ep->get_conn(*cid))
                if (auto str = conn->get_stream<oxen::quic::BTRequestStream>(0))
                    str->command("notify", notification);
}

void QUIC::reachability_test(std::shared_ptr<snode::sn_test> test) {
    if (!service_node_->hf_at_least(snode::QUIC_REACHABILITY_TESTING))
        return test->add_result(true);

    auto& sn = test->sn;
    auto reported = std::make_shared<bool>(false);
    auto conn_established = [reported, test](quic::connection_interface& conn) {
        *reported = true;
        test->add_result(true);

        log::debug(logcat, "QUIC reachability test successful for {}", test->sn.pubkey_legacy);

        conn.close_connection();
    };
    auto conn_closed = [reported = std::move(reported), test = std::move(test)](
                               quic::connection_interface&, uint64_t ec) {
        log::debug(
                logcat,
                "QUIC reachability testing connection to {} closed ({})",
                test->sn.pubkey_ed25519,
                ec);
        if (!*reported) {
            // If we get called without established having been called then the connection failed.
            test->add_result(false);
            log::debug(
                    logcat,
                    "QUIC reachability test failed for {} with error code {}",
                    test->sn.pubkey_legacy,
                    ec);
        }
    };
    ep->connect(
            {sn.pubkey_ed25519.view(), sn.ip, sn.omq_quic_port},
            tls_creds,
            std::move(conn_established),
            std::move(conn_closed),
            oxen::quic::opt::handshake_timeout{5s});
}

}  // namespace oxenss::server
