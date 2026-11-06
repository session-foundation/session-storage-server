#include <catch2/catch.hpp>

#include <oxenmq/oxenmq.h>
#include <oxenss/common/format.h>
#include <oxenss/common/message.h>
#include <oxenss/common/namespace.h>
#include <oxenss/common/pubkey.h>
#include <oxenss/server/monitors.h>
#include <oxenss/server/utils.h>
#include <oxenss/snode/contacts.h>
#include <oxenss/snode/swarm.h>

#include <oxenc/bt.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <string>

using namespace std::literals;

using oxenss::namespace_id;
using oxenss::user_pubkey;
using oxenss::server::connection_id;
using oxenss::server::subscription;
using oxenss::snode::contact;
using oxenss::snode::Contacts;

namespace {

// Drives the monitoring table without a ServiceNode or any transport behind it: `send` records
// what would have gone out on the wire.
class TestMQ : public oxenss::server::Monitors {
  public:
    TestMQ() : Monitors{nullptr} {}

    struct sent {
        std::vector<connection_id> conns;
        std::string command;
        std::string body;
    };
    std::vector<sent> pushed;

    void send(
            const std::vector<connection_id>& conns,
            std::string_view command,
            std::string_view body) override {
        pushed.push_back({conns, std::string{command}, std::string{body}});
    }

    using Monitors::extract_foreign_monitors;
    using Monitors::monitoring_conns_;
    using Monitors::update_monitors;
};

std::string account(unsigned char fill) {
    return "\x05"s + std::string(32, static_cast<char>(fill));
}

connection_id conn(uint64_t id) {
    return std::pair{size_t{0}, oxen::quic::ConnectionID{id}};
}

// The connections that would be sent a notification for a message to `acct`.
std::vector<connection_id> notifiers(TestMQ& mq, const std::string& acct) {
    oxenss::message m;
    m.pubkey.load(acct);
    m.msg_namespace = namespace_id::Default;
    mq.pushed.clear();
    mq.notify_message(m);
    std::vector<connection_id> to;
    for (auto& p : mq.pushed)
        to.insert(to.end(), p.conns.begin(), p.conns.end());
    mq.pushed.clear();
    return to;
}

void subscribe(TestMQ& mq, const std::string& acct, connection_id c) {
    std::vector<subscription> subs;
    subs.push_back({acct, oxenc::to_hex(acct), {namespace_id::Default}, false});
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
    std::ranges::sort(seen);
    return seen;
}

contact dummy_contact(unsigned char fill, uint16_t https_port, uint16_t omq_port) {
    contact c{};
    c.ip = oxen::quic::ipv4{"10.0.0.{}"_format(fill)};
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
    auto conn_a = conn(1), conn_b = conn(2);

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
    CHECK(std::ranges::count(conns, conn_a) == 1);
    CHECK(std::ranges::count(conns, conn_b) == 1);

    // The subscriptions for accounts we still hold must survive, including the one on a connection
    // that also had a dropped subscription.
    auto left = remaining(mq);
    REQUIRE(left.size() == 2);
    CHECK(left[0] == ours);
    CHECK(left[1] == also_ours);
}

TEST_CASE("monitor - extraction keeps everything when nothing is foreign", "[monitor]") {
    TestMQ mq;

    subscribe(mq, account(0x11), conn(1));
    subscribe(mq, account(0x22), conn(2));

    auto dropped = mq.extract_foreign_monitors([](const user_pubkey&) { return true; });

    CHECK(dropped.empty());
    CHECK(remaining(mq).size() == 2);
    CHECK(mq.pushed.empty());
}

TEST_CASE("monitor - a wrong-sized p= pubkey is rejected outright", "[monitor]") {
    TestMQ mq;

    oxenc::bt_dict_producer req;
    {
        auto ns = req.append_list("n");
        ns.append(0);
    }
    req.append("p", "too short");
    auto request = std::move(req).str();

    auto reply = mq.handle_monitor(request, conn(1));

    // The error must be the only thing in the response: carrying on past a bad pubkey reaches the
    // signature check with a short key, and appends a second errcode to this same dict.
    CHECK(oxenss::bt_to_json(oxenc::bt_dict_consumer{reply}) ==
          nlohmann::json{{"errcode", 2}, {"error", "Provided p= pubkey must be 33 bytes"}});
}

TEST_CASE("monitor - closing a connection drops its subscriptions", "[monitor]") {
    TestMQ mq;

    auto a = account(0x11), b = account(0x22);
    auto q1 = conn(1), q2 = conn(2), q3 = conn(3);

    subscribe(mq, a, q1);
    subscribe(mq, b, q1);
    subscribe(mq, b, q2);
    subscribe(mq, a, q3);

    mq.remove_monitors_for(q1);

    // Both of q1's subscriptions go, and nothing else: not the same account on another
    // connection, nor another connection's subscription to an account q1 was also watching.
    CHECK(notifiers(mq, a) == std::vector{q3});
    CHECK(notifiers(mq, b) == std::vector{q2});
    CHECK(mq.monitoring_conns_.count(q1) == 0);
    CHECK(mq.monitoring_conns_.count(q2) == 1);
}

TEST_CASE("monitor - renewing a subscription doesn't duplicate its index entry", "[monitor]") {
    TestMQ mq;

    auto a = account(0x11);
    auto q1 = conn(1);

    subscribe(mq, a, q1);
    subscribe(mq, a, q1);

    CHECK(mq.monitoring_conns_[q1] == std::vector{a});
}

TEST_CASE("monitor - the connection index follows swarm-change removals", "[monitor]") {
    TestMQ mq;

    auto ours = account(0x11), theirs = account(0x22);
    auto q1 = conn(1);

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
