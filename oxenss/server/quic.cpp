#include "quic.h"
#include <sodium/crypto_generichash_blake2b.h>
#include "../rpc/rate_limiter.h"
#include "../rpc/request_handler.h"
#include "../snode/service_node.h"
#include "../snode/sn_test.h"
#include "omq.h"
#include "utils.h"

#include <oxen/quic/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxenc/bt_serialize.h>

namespace oxenss::server {

static auto logcat = log::Cat("ssquic");

static constexpr std::string_view static_secret_key = "Storage Server QUIC shared secret hash key";
static quic::opt::static_secret make_endpoint_static_secret(const crypto::ed25519_seckey& sk) {
    std::vector<unsigned char> secret;
    secret.resize(32);

    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st,
            reinterpret_cast<const unsigned char*>(static_secret_key.data()),
            static_secret_key.size(),
            secret.size());
    crypto_generichash_blake2b_update(&st, sk.data(), sk.size());
    crypto_generichash_blake2b_final(
            &st, reinterpret_cast<unsigned char*>(secret.data()), secret.size());

    return quic::opt::static_secret{std::move(secret)};
}

QUIC::QUIC(
        snode::ServiceNode& snode,
        rpc::RequestHandler& rh,
        rpc::RateLimiter& rl,
        std::span<const Address> bind,
        const crypto::ed25519_seckey& sk) :
        tls_creds{quic::GNUTLSCreds::make_from_ed_seckey(sk.str())}, request_handler{rh} {
    service_node_ = &snode;
    request_handler_ = &rh;
    rate_limiter_ = &rl;

    static_cast<quic::GNUTLSCreds*>(tls_creds.get())->enable_inbound_0rtt();

    if (bind.empty())
        throw std::invalid_argument{"No bind addresses given to QUIC listener!"};

    endpoints.reserve(bind.size());
    for (auto& a : bind) {
        // Outbound connections to other storage servers override the ALPN per connection (see
        // sn_connect); the default covers pings to pre-SN_QUIC_VERSION nodes, which only accept
        // the client ALPN.
        endpoints.push_back(quic::Endpoint::endpoint(
                loop,
                a,
                make_endpoint_static_secret(sk),
                quic::opt::inbound_alpns{ALPN, SN_ALPN},
                quic::opt::outbound_alpns{ALPN}));
        if (!reach_ep && (a.is_ipv4() || (a.is_any_addr() && a.dual_stack))) {
            reach_ep = endpoints.back().get();
            reach_ep_idx = endpoints.size() - 1;
        }
    }

    if (!reach_ep)
        throw std::invalid_argument{"No IPv4 bind address given to QUIC listener!"};

    // Runs on the QUIC loop during the handshake, so it must not wait on anything else.
    static_cast<quic::GNUTLSCreds*>(tls_creds.get())
            ->request_client_keys([this](std::span<const unsigned char> key,
                                         std::string_view alpn) {
                if (alpn != SN_ALPN)
                    // Clients need not send a key, but one they do send has to look like one.
                    return key.empty() || key.size() == sizeof(crypto::ed25519_pubkey);

                if (key.size() != sizeof(crypto::ed25519_pubkey)) {
                    log::warning(
                            logcat,
                            "Rejecting {} connection without a valid ed25519 key ({} bytes)",
                            SN_ALPN,
                            key.size());
                    return false;
                }
                auto pk = crypto::ed25519_pubkey::from_bytes(
                        {reinterpret_cast<const char*>(key.data()), key.size()});
                if (pk == service_node_->own_address().pubkey_ed25519) {
                    log::warning(logcat, "Rejecting {} connection claiming our own key", SN_ALPN);
                    return false;
                }
                if (!service_node_->contacts().find(pk)) {
                    log::warning(
                            logcat,
                            "Rejecting {} connection from {}: not a known service node",
                            SN_ALPN,
                            pk);
                    return false;
                }
                return true;
            });

    // Everything arriving over QUIC is handed to oxenmq workers as injected tasks; these categories
    // give them threads and a queue.  Node-to-node work gets its own so that a node ingesting dumps
    // from several peers does not queue client requests behind them (or drop them when the queue
    // fills), mirroring oxenmq's own separate `sn` category.
    service_node_->omq_server()->add_category(
            "quic",
            oxenmq::AuthLevel::basic,
            2,    // minimum # of threads reserved threads for this category
            1000  // max queued requests
    );
    service_node_->omq_server()->add_category(
            "quicsn", oxenmq::AuthLevel::basic, 2 /*reserved threads*/, 1000 /*max queue*/);
}

void QUIC::startup_endpoint() {
    size_t ep_idx = 0;
    for (auto& ep : endpoints) {
        auto handler = [this, ep_idx](quic::message m) { handle_request(std::move(m), ep_idx); };
        ep->listen(
                tls_creds,
                quic::opt::idle_timeout{MAX_IDLE_TIMEOUT},
                // Stream constructor: all incoming streams become BTRequestStreams, allowing
                // clients to use multiple streams to send higher/lower priority data in parallel by
                // juggling streams.
                [handler = std::move(handler)](
                        quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                    return e.loop.make_shared<quic::BTRequestStream>(c, e, handler);
                },
                quic::connection_established_callback{
                        [this](quic::Connection& c) { on_conn_established(c); }},
                quic::connection_closed_callback{[this, ep_idx](quic::Connection& c, uint64_t ec) {
                    on_conn_closed(c, ec, ep_idx);
                }});
        log::info(logcat, "QUIC server listening at {}", ep->local());
        ep_idx++;
    }

    loop.add_timer(SN_CONN_REDUNDANT_LINGER, [this] { close_redundant_sn_conns(); });
}

std::shared_ptr<quic::Connection> QUIC::sn_conn::preferred() const {
    if (inbound && outbound)
        return inbound_wins ? inbound : outbound;
    return inbound ? inbound : outbound;
}

std::shared_ptr<quic::Connection> QUIC::sn_conn::set(
        std::shared_ptr<quic::Connection> c, bool is_inbound) {
    auto& slot = is_inbound ? inbound : outbound;
    auto replaced = std::move(slot);
    slot = std::move(c);
    return replaced;
}

std::shared_ptr<quic::Connection> QUIC::sn_conn::take(bool is_inbound) {
    auto& slot = is_inbound ? inbound : outbound;
    return std::move(slot);
}

// The peer's ed25519 key, if the connection carries one (SN_ALPN connections always do; so do
// outbound connections of any ALPN, since we dialled by key).
static std::optional<crypto::ed25519_pubkey> sn_key(quic::Connection& c) {
    auto key = c.remote_key();
    if (key.size() != sizeof(crypto::ed25519_pubkey))
        return std::nullopt;
    return crypto::ed25519_pubkey::from_bytes(
            {reinterpret_cast<const char*>(key.data()), key.size()});
}

void QUIC::on_conn_established(quic::Connection& c) {
    if (c.selected_alpn() != SN_ALPN)
        return;
    auto pk = sn_key(c);
    if (!pk)
        return;

    std::shared_ptr<quic::Connection> conn;
    for (auto& ep : endpoints)
        if ((conn = ep->get_conn(c.reference_id())))
            break;
    if (!conn) {
        log::error(logcat, "Internal error: established connection {} not found", c.reference_id());
        return;
    }

    // A stream costs nothing until its first byte, so the whole set is opened up front.
    auto handler = [this](quic::message m) { handle_request(std::move(m), reach_ep_idx); };
    sn_streams streams;
    streams.command = conn->open_stream<quic::BTRequestStream>(handler);
    streams.data = conn->open_stream<quic::BTRequestStream>(handler);
    for (auto& s : streams.onion)
        s = conn->open_stream<quic::BTRequestStream>(handler);
    sn_streams_[conn->reference_id()] = std::move(streams);

    auto [it, ins] = sn_conns_.try_emplace(
            *pk, sn_conn{.inbound_wins = *pk < service_node_->own_address().pubkey_ed25519});
    auto& sc = it->second;
    auto replaced = sc.set(conn, c.is_inbound());
    if (sc.inbound && sc.outbound)
        sn_bidir_[*pk] = std::chrono::steady_clock::now();
    auto use = sc.preferred();

    log::debug(
            logcat,
            "{} {} connection with {}{}",
            ins ? "Established" : "Added",
            c.is_inbound() ? "inbound" : "outbound",
            *pk,
            sc.inbound && sc.outbound
                    ? (sc.inbound_wins == c.is_inbound() ? " (replaces the other direction)"
                                                         : " (redundant; will be closed)")
                    : "");

    std::vector<sn_conn_callback> waiting;
    if (c.is_outbound())
        if (auto pit = pending_sn_conns_.find(*pk); pit != pending_sn_conns_.end()) {
            waiting = std::move(pit->second);
            pending_sn_conns_.erase(pit);
        }

    // Closing may re-enter on_conn_closed, which finds the slot already pointing elsewhere.
    if (replaced)
        replaced->close_connection();

    // This runs on the QUIC loop, which does not survive an exception escaping a callback.
    for (auto& cb : waiting)
        try {
            cb(use);
        } catch (const std::exception& e) {
            log::error(
                    logcat,
                    "Exception in connection-established handler for {}: {}",
                    *pk,
                    e.what());
        }

    // Anything queued for this node that was waiting for it to be reachable can go now.
    service_node_->omq_server()->inject_task(
            "quicsn", "quic:(sn_connected)", "", [this] { service_node_->resume_transfers(); });
}

void QUIC::on_conn_closed(quic::Connection& c, uint64_t ec, size_t ep_idx) {
    // A closed connection never comes back, so its monitor subscriptions can never deliver
    // anything again.
    remove_monitors_for(std::pair{ep_idx, c.reference_id()});

    auto pk = sn_key(c);
    if (!pk)
        return;

    sn_streams_.erase(c.reference_id());
    if (auto it = sn_conns_.find(*pk); it != sn_conns_.end()) {
        auto& sc = it->second;
        auto& slot = c.is_inbound() ? sc.inbound : sc.outbound;
        if (slot && slot->reference_id() == c.reference_id()) {
            slot.reset();
            sn_bidir_.erase(*pk);
            log::debug(
                    logcat,
                    "Closed {} connection with {} (ec={}){}",
                    c.is_inbound() ? "inbound" : "outbound",
                    *pk,
                    ec,
                    ec == CONN_CLOSE_REDUNDANT ? " as redundant" : "");
            if (sc.empty())
                sn_conns_.erase(it);
        }
    }

    std::vector<sn_conn_callback> waiting;
    if (c.is_outbound())
        if (auto pit = pending_sn_conns_.find(*pk); pit != pending_sn_conns_.end()) {
            log::debug(logcat, "Connection to {} failed to establish (ec={})", *pk, ec);
            waiting = std::move(pit->second);
            pending_sn_conns_.erase(pit);
        }

    for (auto& cb : waiting)
        try {
            cb(nullptr);
        } catch (const std::exception& e) {
            log::error(logcat, "Exception in connection-failed handler for {}: {}", *pk, e.what());
        }
}

void QUIC::close_redundant_sn_conns() {
    // Collect first: closing re-enters on_conn_closed, which touches the maps being walked.
    std::vector<std::shared_ptr<quic::Connection>> losers;
    auto now = std::chrono::steady_clock::now();
    std::erase_if(sn_bidir_, [&](const auto& e) {
        const auto& [pk, since] = e;
        if (now < since + SN_CONN_REDUNDANT_LINGER)
            return false;
        if (auto cit = sn_conns_.find(pk); cit != sn_conns_.end())
            if (auto loser = cit->second.take(!cit->second.inbound_wins))
                losers.push_back(std::move(loser));
        return true;
    });
    // The slots are already empty, so on_conn_closed ignores these.
    for (auto& c : losers)
        c->close_connection(CONN_CLOSE_REDUNDANT);
}

void QUIC::sweep_sn_connections() {
    loop.call([this] {
        std::vector<std::shared_ptr<quic::Connection>> gone;
        // Not erase_if: the connections are taken out of the element as it goes, and libstdc++
        // 12 (Debian bookworm) hands erase_if's predicate a const element.
        for (auto it = sn_conns_.begin(); it != sn_conns_.end();) {
            auto& [pk, sc] = *it;
            if (service_node_->contacts().find(pk)) {
                ++it;
                continue;
            }
            log::info(logcat, "Closing connection with {}: no longer a service node", pk);
            for (bool inbound : {true, false})
                if (auto c = sc.take(inbound))
                    gone.push_back(std::move(c));
            sn_bidir_.erase(pk);
            it = sn_conns_.erase(it);
        }
        for (auto& c : gone)
            c->close_connection(CONN_CLOSE_NOT_SN);
    });
}

bool QUIC::has_sn_conn(const crypto::ed25519_pubkey& pk) const {
    auto it = sn_conns_.find(pk);
    return it != sn_conns_.end() && !it->second.empty();
}

bool QUIC::sn_connected(const snode::contact& ct) {
    return loop.call_get([this, &ct] { return has_sn_conn(ct.pubkey_ed25519); });
}

bool QUIC::sn_quic_capable(const snode::contact& ct) const {
    return has_sn_conn(ct.pubkey_ed25519) || ct.version >= snode::SN_QUIC_VERSION;
}

void QUIC::sn_request(
        const snode::contact& ct,
        std::string_view cmd,
        std::vector<std::string> parts,
        sn_reply_callback cb,
        std::chrono::milliseconds timeout,
        sn_fallback fallback) {
    // Replies come in on the QUIC loop; hand them to an oxenmq task like every other QUIC event,
    // so that the loop never runs storage server logic (see handle_request).
    auto reply = [this, cb = std::make_shared<sn_reply_callback>(std::move(cb))](
                         bool success, std::vector<std::string> parts) {
        service_node_->omq_server()->inject_task(
                "quicsn", "quic:(sn_reply)", "", [cb, success, parts = std::move(parts)]() mutable {
                    (*cb)(success, std::move(parts));
                });
    };

    loop.call([this,
               ct,
               cmd = std::string{cmd},
               parts = std::move(parts),
               reply,
               timeout,
               fallback = std::move(fallback)]() mutable {
        if (!sn_quic_capable(ct))
            return fallback(std::move(parts));

        std::string body;
        if (parts.size() == 1)
            body = std::move(parts[0]);
        else if (!parts.empty())
            body = oxenc::bt_serialize(parts);

        const bool storage_cc = cmd == "storage_cc", onion = cmd == "onion_request";
        const auto kind = cmd == "data" ? sn_stream_kind::data
                        : onion         ? sn_stream_kind::onion
                                        : sn_stream_kind::command;

        sn_connect(
                ct,
                [this,
                 cmd = std::move(cmd),
                 body = std::move(body),
                 reply,
                 storage_cc,
                 onion,
                 kind,
                 timeout](std::shared_ptr<quic::Connection> conn) {
                    if (!conn)
                        return reply(false, {"TIMEOUT"s});

                    std::shared_ptr<quic::BTRequestStream> stream;
                    try {
                        stream = sn_stream(*conn, kind);
                    } catch (const std::exception& e) {
                        // The connection is on its way out; the caller retries later.
                        log::debug(
                                logcat, "Could not get a stream for {} request: {}", cmd, e.what());
                        return reply(false, {"TIMEOUT"s});
                    }
                    if (!stream) {
                        // For a hop this is the congestion refusal: tell the client now, as a hop
                        // failure it can reroute on, rather than letting it wait out a timeout.
                        if (onion)
                            return reply(
                                    true,
                                    {std::to_string(http::SERVICE_UNAVAILABLE.first),
                                     "Next hop congested"s});
                        return reply(false, {"TIMEOUT"s});
                    }

                    stream->command(
                            cmd, body, timeout, [reply, storage_cc, onion](quic::message m) {
                                if (m.timed_out)
                                    return reply(false, {"TIMEOUT"s});
                                std::string b{m.body()};

                                if (onion) {
                                    // A hop reply is a bt list of [code, body] (see
                                    // handle_sn_onion_request); oxenmq sends the same two as
                                    // separate parts.
                                    if (m.is_error())
                                        return reply(
                                                true,
                                                {std::to_string(http::BAD_GATEWAY.first),
                                                 std::move(b)});
                                    try {
                                        oxenc::bt_list_consumer l{b};
                                        auto code = l.consume_integer<int>();
                                        return reply(
                                                true, {std::to_string(code), l.consume_string()});
                                    } catch (const std::exception&) {
                                        return reply(
                                                true,
                                                {std::to_string(http::INTERNAL_SERVER_ERROR.first),
                                                 "Invalid response from snode"s});
                                    }
                                }

                                if (!storage_cc)
                                    return reply(true, {std::move(b)});

                                // A forwarded client request's reply has the QUIC client-RPC
                                // framing; reshape it into oxenmq's: [code, reason] for a failure
                                // (from "CODE REASON\n\nbody"), the bare result for a success
                                // (from the [code, result] list).
                                if (m.is_error()) {
                                    auto code = b.substr(0, b.find(' '));
                                    auto nl = b.find("\n\n");
                                    return reply(
                                            true,
                                            {std::move(code),
                                             nl == std::string::npos ? "" : b.substr(nl + 2)});
                                }
                                try {
                                    oxenc::bt_list_consumer l{b};
                                    l.consume_integer<int>();
                                    return reply(true, {std::string{l.consume_dict_data()}});
                                } catch (const std::exception&) {
                                    // Unparseable; passing it through as-is makes the caller
                                    // treat it as a bad peer response.
                                    return reply(true, {std::move(b)});
                                }
                            });
                });
    });
}

void QUIC::sn_connect(const snode::contact& ct, sn_conn_callback cb) {
    const auto& pk = ct.pubkey_ed25519;
    if (auto it = sn_conns_.find(pk); it != sn_conns_.end())
        if (auto conn = it->second.preferred())
            return cb(std::move(conn));

    auto [pit, ins] = pending_sn_conns_.try_emplace(pk);
    pit->second.push_back(std::move(cb));
    if (!ins)
        return;  // a connection attempt is already underway

    log::debug(logcat, "Connecting to {} @ {}:{}", pk, ct.ip, ct.omq_quic_port);
    try {
        reach_ep->connect(
                {pk.view(), ct.ip, ct.omq_quic_port},
                tls_creds,
                quic::opt::outbound_alpns{SN_ALPN},
                quic::opt::keep_alive{SN_CONN_KEEP_ALIVE},
                quic::opt::idle_timeout{SN_CONN_IDLE_TIMEOUT},
                quic::opt::handshake_timeout{5s},
                // Streams the peer opens to us on this connection carry its requests:
                [this](quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                    return e.loop.make_shared<quic::BTRequestStream>(c, e, [this](quic::message m) {
                        handle_request(std::move(m), reach_ep_idx);
                    });
                },
                quic::connection_established_callback{
                        [this](quic::Connection& c) { on_conn_established(c); }},
                quic::connection_closed_callback{[this](quic::Connection& c, uint64_t ec) {
                    on_conn_closed(c, ec, reach_ep_idx);
                }});
    } catch (const std::exception& e) {
        log::warning(logcat, "Failed to initiate connection to {}: {}", pk, e.what());
        std::vector<sn_conn_callback> waiting;
        if (auto wit = pending_sn_conns_.find(pk); wit != pending_sn_conns_.end()) {
            waiting = std::move(wit->second);
            pending_sn_conns_.erase(wit);
        }
        for (auto& w : waiting)
            w(nullptr);
    }
}

std::shared_ptr<quic::BTRequestStream> QUIC::sn_stream(
        const quic::Connection& c, sn_stream_kind kind) const {
    auto it = sn_streams_.find(c.reference_id());
    if (it == sn_streams_.end()) {
        log::error(logcat, "Internal error: no stream set for SN connection {}", c.reference_id());
        return nullptr;
    }
    auto& streams = it->second;

    switch (kind) {
        case sn_stream_kind::command: return streams.command;
        case sn_stream_kind::data: return streams.data;
        case sn_stream_kind::onion: break;
    }

    std::shared_ptr<quic::BTRequestStream> best;
    size_t best_outstanding = 0, best_unsent = 0;
    for (auto& s : streams.onion) {
        auto [acked, unacked, unsent, retained] = s->get_stats();
        if (!best || unacked + unsent < best_outstanding) {
            best = s;
            best_outstanding = unacked + unsent;
            best_unsent = unsent;
        }
    }
    if (best_unsent >= SN_ONION_STREAM_MAX_BACKLOG) {
        log::debug(
                logcat,
                "Refusing onion hop on {}: every onion stream has at least {} bytes queued",
                c.reference_id(),
                best_unsent);
        return nullptr;
    }
    return best;
}

void QUIC::handle_monitor_message(quic::message msg, size_t ep_idx) {

    auto body = msg.body();
    auto refid = msg.stream()->reference_id;
    handle_monitor(
            body,
            [msg = std::move(msg)](std::string response) { msg.respond(std::move(response)); },
            std::pair{ep_idx, refid});
}

void QUIC::handle_ping(quic::message msg) {
    log::debug(logcat, "Remote pinged me");
    service_node_->update_last_ping(snode::ReachType::QUIC);
    msg.respond("pong");
}

void QUIC::handle_request(quic::message msg, size_t ep_idx) {
    auto& omq = *service_node_->omq_server();
    auto conn = msg.stream()->get_conn();
    auto remote_host = conn->remote();
    auto remote_ip =
            (remote_host.is_ipv4() ? remote_host.mapped_ipv4_as_ipv6() : remote_host).to_ipv6();

    // The command set depends on the ALPN: an SN_ALPN connection is with an authenticated service
    // node and carries node-to-node commands; the client ALPN carries client ones.  Only the ping
    // is on both.
    auto name = msg.endpoint();
    std::optional<crypto::ed25519_pubkey> peer;
    if (conn->selected_alpn() == SN_ALPN) {
        peer = sn_key(*conn);
        if (!peer || !(name == "snode_ping" || name == "data" || name == "data_ready" ||
                       name == "storage_cc" || name == "onion_request"))
            throw quic::no_such_endpoint{};
    } else if (!(name == "snode_ping" || name == "monitor" || name == "onion_req" ||
                 rpc::RequestHandler::client_rpc_endpoints.contains(name)))
        throw quic::no_such_endpoint{};

    // We handle everything inside an inject task because if we do *anything* that requires
    // `sn_mutex_` we could deadlock (because the `open_stream` we do in reachability testing is
    // synchronous, but is also called with the `sn_mutex_` held).
    omq.inject_task(
            peer ? "quicsn" : "quic",
            "quic:{}"_format(msg.endpoint()),
            remote_host.host(),
            [this, msg, remote_ip, ep_idx, peer]() mutable {
                auto name = msg.endpoint();

                if (name == "snode_ping")
                    return handle_ping(std::move(msg));
                if (peer) {
                    if (name == "data")
                        return handle_sn_data(std::move(msg));
                    if (name == "data_ready")
                        return handle_sn_data_ready(std::move(msg), *peer);
                    if (name == "onion_request")
                        return handle_sn_onion_request(std::move(msg));
                    return handle_sn_storage_cc(std::move(msg));
                }
                if (name == "monitor")
                    return handle_monitor_message(std::move(msg), ep_idx);
                if (name == "onion_req")
                    return handle_onion_request(std::move(msg));

                handle_client_rpc(
                        name,
                        msg.body(),
                        remote_ip,
                        [msg](http::response_code code, std::string_view res_body) {
                            if (code.first == http::OK.first)
                                msg.respond(res_body);
                            else
                                msg.respond(
                                        "{} {}\n\n{}"_format(code.first, code.second, res_body),
                                        true);
                        });
            });
}

void QUIC::handle_sn_data(quic::message msg) {
    auto body = msg.body();
    if (body.empty())
        return msg.respond("Empty data push", true);
    if (!service_node_->process_push_batch(body, msg.stream()->get_conn()->remote().host()))
        return msg.respond("Failed to store messages", true);
    msg.respond("OK");
}

void QUIC::handle_sn_data_ready(quic::message msg, const crypto::ed25519_pubkey& peer) {
    auto pk = service_node_->contacts().lookup(peer);
    if (!pk)
        return msg.respond("Swarm mismatch", true);
    auto reply = service_node_->data_ready_handshake(*pk, msg.body());
    msg.respond(reply, reply != "OK");
}

void QUIC::handle_sn_storage_cc(quic::message msg) {
    // The body is the two message parts of the oxenmq version -- the client command name and the
    // request payload -- as a bt list.
    std::string_view name, payload;
    try {
        oxenc::bt_list_consumer l{msg.body()};
        name = l.consume_string_view();
        payload = l.consume_string_view();
    } catch (const std::exception& e) {
        return msg.respond("Invalid forwarded request: {}"_format(e.what()), true);
    }

    bool found = handle_client_rpc(
            name,
            payload,
            std::nullopt,
            [msg](http::response_code code, std::string_view res_body) {
                if (code.first == http::OK.first)
                    msg.respond(res_body);
                else
                    msg.respond("{} {}\n\n{}"_format(code.first, code.second, res_body), true);
            },
            /*forwarded=*/true);
    if (!found)
        msg.respond("Unknown forwarded command {}"_format(name), true);
}

// A hop of an onion request from another storage server, in oxenmq's sn.onion_request encoding.
// The reply carries oxenmq's two parts, status code and body, as a bt list.
void QUIC::handle_sn_onion_request(quic::message msg) {
    auto respond = [msg](int code, std::string_view body) {
        msg.respond(oxenc::bt_serialize(oxenc::bt_list{code, std::string{body}}));
    };

    std::string_view payload;
    rpc::OnionRequestMetadata data;
    try {
        auto decoded = OMQ::decode_onion_data(msg.body());
        payload = decoded.first;
        data = std::move(decoded.second);
    } catch (const std::exception& e) {
        auto err = "Invalid internal onion request: "s + e.what();
        log::error(logcat, "{}", err);
        return respond(http::BAD_REQUEST.first, err);
    }

    data.cb = [respond](rpc::Response res) {
        if (auto* js = std::get_if<nlohmann::json>(&res.body))
            respond(res.status.first, js->dump());
        else if (auto* binary = std::get_if<std::span<const std::byte>>(&res.body))
            respond(res.status.first,
                    {reinterpret_cast<const char*>(binary->data()), binary->size()});
        else
            respond(res.status.first, rpc::view_body(res));
    };

    if (data.hop_no > rpc::MAX_ONION_HOPS)
        return data.cb({http::BAD_REQUEST, "onion request max path length exceeded"sv});

    request_handler_->process_onion_req(payload, std::move(data));
}

void QUIC::handle_onion_request(quic::message msg) {

    auto started = std::chrono::steady_clock::now();
    try {
        rpc::OnionRequestMetadata onion{
                crypto::x25519_pubkey{},
                [msg, started](rpc::Response res) {
                    log::debug(
                            logcat,
                            "Got an onion response ({} {}) as edge node (after {})",
                            res.status.first,
                            res.status.second,
                            util::friendly_duration(std::chrono::steady_clock::now() - started));

                    std::string json_body;
                    std::string_view body;
                    if (auto json = std::get_if<nlohmann::json>(&res.body)) {
                        json_body = json->dump();
                        body = json_body;
                    } else if (auto* binary = std::get_if<std::span<const std::byte>>(&res.body)) {
                        body = {reinterpret_cast<const char*>(binary->data()), binary->size()};
                    } else {
                        body = rpc::view_body(res);
                    }

                    if (res.status.first != http::OK.first)
                        msg.respond(
                                "{} {}\n\n{}"_format(res.status.first, res.status.second, body),
                                true);
                    else
                        msg.respond(body);
                },
                0,  // hopno
                crypto::EncryptType::aes_gcm,
        };

        auto [ciphertext, json_req] = rpc::parse_combined_payload(msg.body());

        onion.ephem_key = rpc::extract_x25519_from_hex(
                json_req.at("ephemeral_key").get_ref<const std::string&>());

        if (auto it = json_req.find("enc_type"); it != json_req.end())
            onion.enc_type = crypto::parse_enc_type(it->get_ref<const std::string&>());
        // Otherwise stay at default aes-gcm

        // Allows a fake starting hop number (to make it harder for
        // intermediate hops to know where they are).  If omitted, defaults
        // to 0.
        if (auto it = json_req.find("hop_no"); it != json_req.end())
            onion.hop_no = std::max(0, it->get<int>());

        request_handler_->process_onion_req(ciphertext, std::move(onion));

    } catch (const std::exception& e) {
        auto err = fmt::format("Error parsing onion request: {}", e.what());
        log::error(logcat, "{}", err);
        msg.respond(
                "{} {}\n\n{}"_format(http::BAD_REQUEST.first, http::BAD_REQUEST.second, err), true);
    }
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

void QUIC::send_notification(
        std::vector<connection_id>& conns, std::string command, std::string_view notification) {
    for (const auto& c : conns) {
        if (auto* quic_id = std::get_if<std::pair<size_t, quic::ConnectionID>>(&c)) {
            auto& [ep_idx, cid] = *quic_id;
            assert(ep_idx < endpoints.size());
            if (auto conn = endpoints[ep_idx]->get_conn(cid))
                if (auto str = conn->get_stream<quic::BTRequestStream>(0))
                    str->command(command, notification);
        }
    }
}

void QUIC::notify(std::vector<connection_id>& conns, std::string_view notification) {
    send_notification(conns, "notify", notification);
}

void QUIC::notify_monitor_ended(std::vector<connection_id>& conns, std::string_view notification) {
    send_notification(conns, "monitor_ended", notification);
}

void QUIC::reachability_test(std::shared_ptr<snode::sn_test> test) {
    auto maybe_ct = service_node_->contacts().find(test->pubkey);
    if (!maybe_ct || !*maybe_ct)
        // If we don't have any usable contact info then don't do anything: oxend will already fail
        // a node that hasn't broadcast usable contact info, so we don't need to worry about testing
        // it here.
        return;

    // Defer this to an omq task; the same deadlock-avoidance logic described in handle_request
    // applies here.
    auto report = [this](std::shared_ptr<snode::sn_test> test, bool passed) {
        service_node_->omq_server()->inject_task(
                "quicsn", "quic:(reach_report)", "", [test = std::move(test), passed]() {
                    test->add_result(passed);
                });
    };

    auto ping = [this, report](
                        std::shared_ptr<snode::sn_test> test,
                        quic::BTRequestStream& s,
                        bool close_after) {
        s.command(
                "snode_ping",
                ""s,
                [test = std::move(test), report, close_after, this](
                        const quic::message& m) mutable {
                    bool passed;
                    if (m.timed_out || m.body() != "pong"sv) {
                        log::debug(
                                logcat,
                                "QUIC reachability test failed for {}: {}",
                                test->pubkey,
                                m.timed_out ? "timeout" : "unexpected response");
                        passed = false;
                    } else {
                        log::debug(
                                logcat,
                                "Successful response to QUIC reachability ping test of {}",
                                test->pubkey);
                        passed = true;
                    }
                    // Go via reach_ep rather than m.stream(): on a timeout the stream may already
                    // be gone, and m.stream() throws rather than returning nullptr, which would
                    // skip the result reporting below and leave the test unresolved.
                    if (close_after)
                        if (auto conn = reach_ep->get_conn(m.conn_rid()))
                            conn->close_connection();

                    report(std::move(test), passed);
                });
    };

    // The registry is loop-owned, so the rest happens there.  (This is also called with the
    // service node's mutex held, and call() does not block.)
    loop.call([this, test = std::move(test), ct = *maybe_ct, report, ping]() mutable {
        if (sn_quic_capable(ct)) {
            // Ping over the connection we hold with the node (establishing it if needed), and
            // keep it.
            sn_connect(
                    ct,
                    [this, test = std::move(test), ping, report](
                            std::shared_ptr<quic::Connection> conn) mutable {
                        if (!conn) {
                            log::debug(
                                    logcat,
                                    "QUIC reachability test failed for {}: could not connect",
                                    test->pubkey);
                            return report(std::move(test), false);
                        }
                        auto stream = sn_stream(*conn, sn_stream_kind::command);
                        if (!stream)
                            return report(std::move(test), false);
                        ping(std::move(test), *stream, false);
                    });
            return;
        }

        // Older nodes only accept the client ALPN and expect a one-off connection.
        try {
            auto conn = reach_ep->connect(
                    {ct.pubkey_ed25519.view(), ct.ip, ct.omq_quic_port},
                    tls_creds,
                    quic::opt::handshake_timeout{5s});
            ping(std::move(test), *conn->open_stream<quic::BTRequestStream>(), true);
        } catch (const std::exception& e) {
            log::debug(logcat, "QUIC reachability test failed for {}: {}", test->pubkey, e.what());
            report(std::move(test), false);
        }
    });
}

}  // namespace oxenss::server
