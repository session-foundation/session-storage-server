#pragma once
#include "mqbase.h"
#include "../crypto/keys.h"

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json_fwd.hpp>
#include <oxenc/bt_serialize.h>
#include <oxenmq/oxenmq.h>

namespace oxenss {

namespace rpc {
    class RequestHandler;
    class RateLimiter;
    struct OnionRequestMetadata;
    struct Response;
}  // namespace rpc

namespace snode {
    class ServiceNode;
}  // namespace snode

}  // namespace oxenss

namespace oxenss::server {
class OMQ : public MQBase {
    oxenmq::OxenMQ omq_;
    oxenmq::ConnectionID oxend_conn_;

    // Get node's address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Invoked by fellow swarm members to ask if we are ready to transfer data (via sn.data).  Once
    // this returns OK, one or more sn.data follow with the actual data transfer.
    void handle_sn_data_ready(oxenmq::Message& message);

    // Handle Session data coming from peer SN
    void handle_sn_data(oxenmq::Message& message);

    // Called starting at HF18 for SS-to-SS onion requests
    void handle_onion_request(oxenmq::Message& message);

    // Handles a decoded onion request
    void handle_onion_request(
            std::string_view payload,
            rpc::OnionRequestMetadata&& data,
            oxenmq::Message::DeferredSend send);

    // sn.ping - sent by SNs to ping each other.
    void handle_ping(oxenmq::Message& message);

    /// storage.(whatever) -- client request handling.  These reply with [BODY] on success or
    /// [CODE, BODY] on failure (where BODY typically is some sort of error message).
    ///
    /// The return value is either:
    /// [VALUE] for a successful response
    /// [ERRCODE, VALUE] for a failure.
    ///
    /// Successful responses will generally return VALUE as json, if the request was json (or
    /// empty), or a bt-encoded dict if the request was bt-encoded.  Note that base64-encoded
    /// values for json responses are raw byte values (*not* base64-encoded) when returning a
    /// bt-encoded value.
    ///
    /// Failure responses are an HTTP error number and a plain text failure string.
    ///
    /// `forwarded` is set if this request was forwarded from another swarm member rather than
    /// being direct from the client; the request is handled identically except that these
    /// forwarded requests are not-reforwarded again, and the method name is prepended on the
    /// argument list.
    void handle_client_request(
            std::string_view method, oxenmq::Message& message, bool forwarded = false);

    void handle_get_logs(oxenmq::Message& message);

    void handle_get_stats(oxenmq::Message& message);

    // Access pubkeys for the 'service' command category (for access stats & logs), in binary.
    std::unordered_set<std::string> stats_access_keys_;

    // Connects (and blocks until connected) to oxend.  When this returns an oxend connection
    // will be available (and oxend_conn_ will be set to the connection id to reach it).  Throws
    // snode::startup_aborted if `keep_going` returns false while waiting.
    void connect_oxend(const oxenmq::address& oxend_rpc, const std::function<bool()>& keep_going);

  public:
    OMQ(const crypto::x25519_keypair& keys,
        std::span<const crypto::x25519_pubkey> stats_access_keys);

    // Initialize oxenmq: connects to oxend, loads the initial state from it, then starts the
    // oxenmq listener.  Blocks until done; `keep_going` is polled while waiting on oxend and a
    // false return aborts startup with snode::startup_aborted.
    void init(
            snode::ServiceNode* sn,
            rpc::RequestHandler* rh,
            rpc::RateLimiter* rl,
            oxenmq::address oxend_rpc,
            const std::function<bool()>& keep_going);

    // Blocks until oxend tells us how old its top block is.  oxend refuses to say until it is
    // synchronized, so while it reports that it is not this keeps asking, for up to `busy_grace`,
    // then returns nullopt.  Throws after a few failed attempts, or snode::startup_aborted when
    // `keep_going` says to stop; either aborts startup.
    std::optional<std::chrono::seconds> oxend_top_block_age(
            const std::function<bool()>& keep_going, std::chrono::seconds busy_grace);

    /// Dereferencing via * or -> accesses the contained OxenMQ instance.
    oxenmq::OxenMQ& operator*() { return omq_; }
    oxenmq::OxenMQ* operator->() { return &omq_; }

    // Returns the OMQ ConnectionID for the connection to oxend.
    const oxenmq::ConnectionID& oxend_conn() const { return oxend_conn_; }

    // Invokes a request to the local oxend; given arguments (which must contain at least the
    // request name and a callback) are forwarded as `omq.request(connid, ...)`.
    template <typename... Args>
    void oxend_request(Args&&... args) {
        assert(oxend_conn_);
        omq_.request(oxend_conn(), std::forward<Args>(args)...);
    }

    // Sends a one-way message to the local oxend; arguments are forwarded as `omq.send(connid,
    // ...)` (and must contain at least a command name).
    template <typename... Args>
    void oxend_send(Args&&... args) {
        assert(oxend_conn_);
        omq_.send(oxend_conn(), std::forward<Args>(args)...);
    }

    // Encodes the onion request data that we send for internal SN-to-SN onion requests starting
    // at HF18.
    static std::string encode_onion_data(
            std::string_view payload, const rpc::OnionRequestMetadata& data);
    // Decodes onion request data; throws if invalid formatted or missing required fields.
    static std::pair<std::string_view, rpc::OnionRequestMetadata> decode_onion_data(
            std::string_view data);

    void reachability_test(std::shared_ptr<snode::sn_test> test) override;

    // Always sends: oxenmq is the transport for every node not (yet) reached over QUIC.
    void sn_request(
            const snode::contact& ct,
            std::string_view cmd,
            std::vector<std::string> parts,
            sn_reply_callback cb,
            std::chrono::milliseconds timeout,
            sn_fallback) override;
};

}  // namespace oxenss::server
