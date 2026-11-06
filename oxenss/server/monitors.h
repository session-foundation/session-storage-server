#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <oxen/quic/connection_ids.hpp>
#include <oxenc/bt_producer.h>

#include "../common/namespace.h"
#include "../common/pubkey.h"
#include "../snode/swarm.h"
#include "utils.h"

namespace oxenss {
struct message;
}  // namespace oxenss

namespace oxenss::snode {
class ServiceNode;
class Contacts;
}  // namespace oxenss::snode

namespace oxenss::server {

using namespace std::literals;

// A QUIC connection, as {endpoint index, connection reference id}: monitors are only carried over
// QUIC.
using connection_id = std::pair<size_t, oxen::quic::ConnectionID>;

// One validated subscription from a `monitor` request.
struct subscription {
    std::string pubkey;                    // the account, in bytes (33)
    std::string pubkey_hex;                // the same, hex-encoded, for logging
    std::vector<namespace_id> namespaces;  // sorted, without duplicates
    bool want_data;
};

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

/// The monitor subscriptions held by this node, and the notifications pushed to them.  The QUIC
/// server owns the one instance and supplies the transport by implementing `send`.
///
/// Everything public is thread-safe.
class Monitors {
  public:
    // `sn` supplies the swarm state that the default environment hooks below consult.  It may be
    // null only for a subclass that overrides every one of them.
    explicit Monitors(snode::ServiceNode* sn) : service_node_{sn} {}

    virtual ~Monitors() = default;

    // Handles a `monitor` request arriving on `conn`, returning the reply body.  See
    // QUIC::handle_monitor_message for the request and reply formats.
    //
    // `conn` identifies the connection: a subscription identical to one it already has renews that
    // monitor, and any other adds one.
    std::string handle_monitor(std::string_view request, const connection_id& conn);

    // How often `remove_expired` should be called.
    static constexpr auto EXPIRY_SWEEP_INTERVAL = 1min;

    // Removes expired monitors.  A connection can hold any number of them, as each distinct
    // subscription is a monitor of its own, so those it stops renewing have to be swept away.
    void remove_expired();

    // Removes every monitor subscription belonging to `conn`, for a connection that has gone away.
    void remove_monitors_for(const connection_id& conn);

    // Pushes a `notify` for the newly stored message `m` to each subscriber monitoring its account
    // and namespace.
    void notify_message(const message& m);

    /// Terminates every monitor subscription for an account this node no longer serves, pushing a
    /// `monitor_ended` notification to each affected subscriber.
    ///
    /// A subscription is only useful for as long as we would not answer a request for the account
    /// with a 421, so this must be called after a swarm update has taken effect.  Without it a
    /// client that has stopped polling cannot tell "the swarm moved" from "no messages arrived".
    void drop_foreign_monitors();

  protected:
    // Fire-and-forget push of `command` with `body` to each of `conns`.
    virtual void send(
            const std::vector<connection_id>& conns,
            std::string_view command,
            std::string_view body) = 0;

    // Environment hooks: the swarm state that decides which accounts we store, and the contact
    // details used to describe a swarm to a subscriber.  The defaults ask the service node.
    virtual snode::swarm_membership swarm_for(const user_pubkey& pk) const;
    virtual snode::swarm_id_t our_swarm_id() const;
    virtual const snode::Contacts& contacts() const;

    // Adds or renews a monitor for each of `subs`, returning how long each one now has until it
    // expires.
    std::vector<std::chrono::seconds> update_monitors(
            std::vector<subscription>& subs, const connection_id& conn);

    // These three must be called with `monitoring_mutex_` held for writing.

    // Erases a monitor from `monitoring_`, keeping its connection's reverse index up to date;
    // returns the iterator following it.
    std::unordered_multimap<std::string, MonitorData>::iterator erase_monitor(
            std::unordered_multimap<std::string, MonitorData>::iterator it);

    // The monitor that `sub` renews for `conn`, if any: the one with the same account,
    // connection, namespaces and data flag.
    MonitorData* find_monitor(const subscription& sub, const connection_id& conn);

    // True if `conn` has any monitor of `account`.
    bool has_monitor(const std::string& account, const connection_id& conn);

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

    // Tracks accounts we are monitoring for push notification messages
    std::unordered_multimap<std::string, MonitorData> monitoring_;

    // Reverse index of `monitoring_`, listing the accounts subscribed to by each connection so
    // that a connection going away doesn't require a scan of the whole table.
    //
    // Guarded by `monitoring_mutex_` along with `monitoring_` itself so that the two cannot drift
    // apart.
    std::map<connection_id, std::unordered_set<std::string>> monitoring_conns_;

    mutable std::shared_mutex monitoring_mutex_;

  private:
    snode::ServiceNode* service_node_;

    // Validates one subscription dict of a `monitor` request, returning either the subscription or
    // the encoded reply dict saying why it failed.
    std::variant<subscription, std::string> parse_subscription(oxenc::bt_dict_consumer d);
};

}  // namespace oxenss::server
