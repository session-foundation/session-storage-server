#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/connection_ids.hpp>
#include <oxenmq/connections.h>
#include <shared_mutex>

#include "../common/namespace.h"
#include "../common/pubkey.h"
#include "utils.h"

namespace oxenss {

namespace rpc {
    class RequestHandler;
    class RateLimiter;
}  // namespace rpc

namespace snode {
    class ServiceNode;
    struct sn_test;
}  // namespace snode

struct message;

}  // namespace oxenss

namespace oxenss::server {

// For oxenmq: the connection id; for quic: pair of {endpoint_index, endpoint_connectionid}
using connection_id =
        std::variant<oxenmq::ConnectionID, std::pair<size_t, oxen::quic::ConnectionID>>;

using namespace std::literals;

struct MonitorData {
    static constexpr auto MONITOR_EXPIRY_TIME = 65min;

    std::chrono::steady_clock::time_point expiry;  // When this notify reg expires
    std::vector<namespace_id> namespaces;          // sorted namespace_ids
    connection_id conn;
    bool want_data;  // true if the subscriber wants msg data

    MonitorData(
            std::vector<namespace_id> namespaces,
            bool data,
            connection_id c,
            std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) :
            expiry{std::chrono::steady_clock::now() + ttl},
            namespaces{std::move(namespaces)},
            conn{c},
            want_data{data} {}

    void reset_expiry(std::chrono::seconds ttl = MONITOR_EXPIRY_TIME) {
        expiry = std::chrono::steady_clock::now() + ttl;
    }
};

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

    // Called to deal with a monitor request; `reply` is used to respond to the request itself (and
    // will be used during, not after, the method call itself); `conn` is the connection ID used to
    // send notifications back on the connection later.  `conn` is used to uniquely identify the
    // connection: if we get a subsequent subscription request from the same `conn`, we replace the
    // old subscription(s) with the new one(s).
    //
    // The `request` body itself can either be a dict, or a list of dicts, to subscribe to one or
    // multiple addresses at once.
    void handle_monitor(
            std::string_view request, std::function<void(std::string)> reply, connection_id conn);

    void update_monitors(std::vector<sub_info>& subs, connection_id conn);

    // Removes every monitor subscription belonging to `conn`, for a connection that has gone away.
    // Only connections tracked in `monitoring_conns_` can be removed this way; for anything else
    // this does nothing.
    void remove_monitors_for(const connection_id& conn);

    // Drops `account` from `conn`'s entry in `monitoring_conns_`.  Must be called with
    // `monitoring_mutex_` held for writing.
    void unindex_monitor(const connection_id& conn, const std::string& account);

    // Removes every monitor subscription whose account `still_ours` rejects, returning the dropped
    // accounts along with the connections that had been subscribed to each.
    //
    // `still_ours` is called without `monitoring_mutex_` held, because it takes network locks of
    // its own; the table is therefore sampled, tested, and then modified in three separate steps.
    std::vector<std::pair<user_pubkey, std::vector<connection_id>>> extract_foreign_monitors(
            const std::function<bool(const user_pubkey&)>& still_ours);

    // Builds the bt-encoded body of a monitor-terminated notification for `pubkey`: the account,
    // the reason it ended, and the swarm that now holds the account so that the subscriber can
    // resubscribe without first asking us where to go.
    std::string monitor_ended_payload(
            const user_pubkey& pubkey, MonitorResponse reason, std::string_view message);

    // Tracks accounts we are monitoring for OMQ push notification messages
    std::unordered_multimap<std::string, MonitorData> monitoring_;

    // Reverse index of `monitoring_`, listing the accounts subscribed to by each connection so
    // that a connection going away doesn't require a scan of the whole table.
    //
    // Only quic connections are indexed: a closed quic connection is gone for good, and we get
    // told when it closes.  oxenmq, in contrast, gives us no notification at all when an inbound
    // connection goes away, so there would be nothing to trigger a lookup and the index would only
    // accumulate entries; oxenmq subscriptions are cleaned up by expiry instead.
    //
    // Guarded by `monitoring_mutex_` along with `monitoring_` itself so that the two cannot drift
    // apart.
    std::map<connection_id, std::vector<std::string>> monitoring_conns_;

    mutable std::shared_mutex monitoring_mutex_;

  public:
    void get_notifiers(
            message& m, std::vector<connection_id>& to, std::vector<connection_id>& with_data);

    /// Terminates every monitor subscription for an account this node no longer serves, pushing a
    /// `monitor_ended` notification to each affected subscriber.
    ///
    /// A subscription is only useful for as long as we would not answer a request for the account
    /// with a 421, so this must be called after a swarm update has taken effect.  Without it a
    /// client that has stopped polling cannot tell "the swarm moved" from "no messages arrived".
    void drop_foreign_monitors();

    virtual void notify(std::vector<connection_id>&, std::string_view notification) = 0;

    /// Pushes a notification telling `conns` that a monitor subscription of theirs has been
    /// terminated.  This is a separate command from `notify` so that clients which only know
    /// about message notifications are unaffected by it.
    virtual void notify_monitor_ended(
            std::vector<connection_id>&, std::string_view notification) = 0;

    virtual void reachability_test(std::shared_ptr<snode::sn_test> test) = 0;

    virtual ~MQBase() = default;

  private:
    void handle_monitor_message_single(
            oxenc::bt_dict_consumer d, oxenc::bt_dict_producer& out, std::vector<sub_info>& subs);
    void handle_monitor_message_single(
            oxenc::bt_dict_consumer d, oxenc::bt_dict_producer&& out, std::vector<sub_info>& subs);
};

}  // namespace oxenss::server
