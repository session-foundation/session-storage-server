#include <catch2/catch.hpp>

#include <oxenmq/oxenmq.h>
#include <oxenss/common/message.h>
#include <oxenss/common/namespace.h>
#include <oxenss/common/pubkey.h>
#include <oxenss/server/mqbase.h>
#include <oxenss/server/utils.h>
#include <oxenss/snode/contacts.h>
#include <oxenss/snode/swarm.h>

#include <oxenc/bt.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <string>

using namespace std::literals;

using oxenss::namespace_id;
using oxenss::sub_info;
using oxenss::user_pubkey;
using oxenss::server::connection_id;
using oxenss::snode::contact;
using oxenss::snode::Contacts;

namespace {

// Exposes just enough of MQBase to drive the monitoring table without a ServiceNode or any
// transport behind it; `notify_monitor_ended` records what would have gone out on the wire.
class TestMQ : public oxenss::server::MQBase {
  public:
    std::vector<std::pair<std::vector<connection_id>, std::string>> ended;

    void notify(std::vector<connection_id>&, std::string_view) override {}

    void notify_monitor_ended(
            std::vector<connection_id>& conns, std::string_view notification) override {
        ended.emplace_back(conns, std::string{notification});
    }

    void reachability_test(std::shared_ptr<oxenss::snode::sn_test>) override {}

    using MQBase::extract_foreign_monitors;
    using MQBase::monitoring_conns_;
    using MQBase::remove_monitors_for;
    using MQBase::update_monitors;
};

std::string account(unsigned char fill) {
    return "\x05"s + std::string(32, static_cast<char>(fill));
}

connection_id conn(unsigned char fill) {
    return oxenmq::ConnectionID{std::string(32, static_cast<char>(fill))};
}

connection_id quic_conn(uint64_t id) {
    return std::pair{size_t{0}, oxen::quic::ConnectionID{id}};
}

// The connections that would be sent a notification for a message to `acct`.
std::vector<connection_id> notifiers(TestMQ& mq, const std::string& acct) {
    oxenss::message m;
    m.pubkey.load(acct);
    m.msg_namespace = namespace_id::Default;
    std::vector<connection_id> to, with_data;
    mq.get_notifiers(m, to, with_data);
    return to;
}

void subscribe(TestMQ& mq, const std::string& acct, connection_id c) {
    std::vector<sub_info> subs;
    subs.emplace_back(
            acct, oxenc::to_hex(acct), std::vector<namespace_id>{namespace_id::Default}, false);
    mq.update_monitors(subs, c);
}

// Returns the accounts still in the monitoring table, by running an extraction that keeps
// everything and recording what it was asked about.
std::vector<std::string> remaining(TestMQ& mq) {
    std::vector<std::string> seen;
    mq.extract_foreign_monitors([&seen](const user_pubkey& pk) {
        seen.push_back(pk.prefixed_raw());
        return true;
    });
    std::sort(seen.begin(), seen.end());
    return seen;
}

contact dummy_contact(unsigned char fill, uint16_t https_port, uint16_t omq_port) {
    contact c{};
    c.ip = oxen::quic::ipv4{"10.0.0." + std::to_string(fill)};
    c.https_port = https_port;
    c.omq_quic_port = omq_port;
    c.version = {2, 9, 0};
    std::memset(c.pubkey_ed25519.data(), fill, 32);
    std::memset(c.pubkey_x25519.data(), fill + 1, 32);
    return c;
}

oxenss::crypto::legacy_pubkey snode_pubkey(unsigned char fill) {
    oxenss::crypto::legacy_pubkey pk;
    std::memset(pk.data(), fill, 32);
    return pk;
}

}  // namespace

TEST_CASE("monitor - foreign subscriptions are extracted and removed", "[monitor]") {
    TestMQ mq;

    auto ours = account(0x11), theirs = account(0x22), also_ours = account(0x33);
    auto conn_a = conn(0xaa), conn_b = conn(0xbb);

    subscribe(mq, ours, conn_a);
    subscribe(mq, theirs, conn_a);
    subscribe(mq, theirs, conn_b);
    subscribe(mq, also_ours, conn_b);

    auto dropped = mq.extract_foreign_monitors(
            [&theirs](const user_pubkey& pk) { return pk.prefixed_raw() != theirs; });

    REQUIRE(dropped.size() == 1);
    CHECK(dropped[0].first.prefixed_raw() == theirs);

    auto& conns = dropped[0].second;
    REQUIRE(conns.size() == 2);
    CHECK(std::count(conns.begin(), conns.end(), conn_a) == 1);
    CHECK(std::count(conns.begin(), conns.end(), conn_b) == 1);

    // The subscriptions for accounts we still hold must survive, including the one on a connection
    // that also had a dropped subscription.
    auto left = remaining(mq);
    REQUIRE(left.size() == 2);
    CHECK(left[0] == ours);
    CHECK(left[1] == also_ours);
}

TEST_CASE("monitor - extraction keeps everything when nothing is foreign", "[monitor]") {
    TestMQ mq;

    subscribe(mq, account(0x11), conn(0xaa));
    subscribe(mq, account(0x22), conn(0xbb));

    auto dropped = mq.extract_foreign_monitors([](const user_pubkey&) { return true; });

    CHECK(dropped.empty());
    CHECK(remaining(mq).size() == 2);
    CHECK(mq.ended.empty());
}

TEST_CASE("monitor - closing a quic connection drops its subscriptions", "[monitor]") {
    TestMQ mq;

    auto a = account(0x11), b = account(0x22);
    auto q1 = quic_conn(1), q2 = quic_conn(2), omq = conn(0xcc);

    subscribe(mq, a, q1);
    subscribe(mq, b, q1);
    subscribe(mq, b, q2);
    subscribe(mq, a, omq);

    mq.remove_monitors_for(q1);

    // Both of q1's subscriptions go, and nothing else: not the same account on another
    // connection, nor another connection's subscription to an account q1 was also watching.
    CHECK(notifiers(mq, a) == std::vector{omq});
    CHECK(notifiers(mq, b) == std::vector{q2});
    CHECK(mq.monitoring_conns_.count(q1) == 0);
    CHECK(mq.monitoring_conns_.count(q2) == 1);
}

TEST_CASE("monitor - renewing a subscription doesn't duplicate its index entry", "[monitor]") {
    TestMQ mq;

    auto a = account(0x11);
    auto q1 = quic_conn(1);

    subscribe(mq, a, q1);
    subscribe(mq, a, q1);

    CHECK(mq.monitoring_conns_[q1] == std::vector{a});
}

TEST_CASE("monitor - oxenmq subscriptions are not indexed by connection", "[monitor]") {
    TestMQ mq;

    auto a = account(0x11);
    auto omq = conn(0xcc);
    subscribe(mq, a, omq);

    CHECK(mq.monitoring_conns_.empty());

    // Nothing tells us when an inbound oxenmq connection goes away, so there is nothing to trigger
    // a removal and the subscription has to wait for its expiry.
    mq.remove_monitors_for(omq);
    CHECK(notifiers(mq, a) == std::vector{omq});
}

TEST_CASE("monitor - the connection index follows swarm-change removals", "[monitor]") {
    TestMQ mq;

    auto ours = account(0x11), theirs = account(0x22);
    auto q1 = quic_conn(1);

    subscribe(mq, ours, q1);
    subscribe(mq, theirs, q1);

    auto dropped = mq.extract_foreign_monitors(
            [&theirs](const user_pubkey& pk) { return pk.prefixed_raw() != theirs; });
    REQUIRE(dropped.size() == 1);

    REQUIRE(mq.monitoring_conns_.count(q1) == 1);
    CHECK(mq.monitoring_conns_[q1] == std::vector{ours});

    // Losing the last of a connection's accounts takes the connection out of the index rather than
    // leaving an empty entry behind.
    auto rest = mq.extract_foreign_monitors([](const user_pubkey&) { return false; });
    REQUIRE(rest.size() == 1);
    CHECK(mq.monitoring_conns_.empty());
}

TEST_CASE("monitor - bt swarm encoding matches the json one", "[monitor][swarm]") {
    oxenmq::OxenMQ omq;
    Contacts contacts{omq};

    auto pk1 = snode_pubkey(0x41), pk2 = snode_pubkey(0x42), uncontactable = snode_pubkey(0x43);
    contacts.update(pk1, dummy_contact(0x41, 22021, 22020));
    contacts.update(pk2, dummy_contact(0x42, 22023, 22022));
    contacts.update(uncontactable, contact{});

    oxenss::snode::swarm_membership swarm{
            std::pair{0x1234'5678'9abc'def0ULL, std::set{pk1, pk2, uncontactable}}};

    auto as_json = oxenss::snode::swarm_to_json(swarm, contacts);

    oxenc::bt_dict_producer d;
    oxenss::snode::swarm_to_bt(d, swarm, contacts);
    auto as_bt = oxenss::bt_to_json(oxenc::bt_dict_consumer{std::move(d).str()});

    CHECK(as_bt == as_json);

    CHECK(as_json["swarm"] == "123456789abcdef0");
    // The node with no contact details is omitted from both encodings.
    CHECK(as_json["snodes"].size() == 2);
}

TEST_CASE("monitor - swarm encodings for an unknown swarm", "[monitor][swarm]") {
    oxenmq::OxenMQ omq;
    Contacts contacts{omq};

    oxenss::snode::swarm_membership none;

    auto as_json = oxenss::snode::swarm_to_json(none, contacts);

    oxenc::bt_dict_producer d;
    oxenss::snode::swarm_to_bt(d, none, contacts);
    auto as_bt = oxenss::bt_to_json(oxenc::bt_dict_consumer{std::move(d).str()});

    CHECK(as_bt == as_json);
    CHECK(as_json["snodes"].empty());
    CHECK(as_json["swarm"] == "ffffffffffffffff");
}
