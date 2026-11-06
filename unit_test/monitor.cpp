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
#include <sodium.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <string>
#include <unordered_set>

using namespace std::literals;

using nlohmann::json;
using oxenss::namespace_id;
using oxenss::user_pubkey;
using oxenss::server::connection_id;
using oxenss::server::subscription;
using oxenss::snode::contact;
using oxenss::snode::Contacts;
using oxenss::snode::swarm_id_t;
using oxenss::snode::swarm_membership;

namespace {

// Drives the monitoring table without a ServiceNode or any transport behind it: `send` records
// what would have gone out on the wire.
class TestMQ : public oxenss::server::Monitors {
  public:
    TestMQ() : Monitors{nullptr} {}

    static constexpr swarm_id_t OUR_SWARM = 0x1000;

    // Accounts that belong to some other swarm, and which; everything else is ours.
    std::map<std::string, swarm_id_t> elsewhere;

    oxenmq::OxenMQ omq;
    Contacts contacts_{omq};

    swarm_membership swarm_for(const user_pubkey& pk) const override {
        auto it = elsewhere.find(pk.prefixed_raw());
        return std::pair{
                it == elsewhere.end() ? OUR_SWARM : it->second,
                std::set<oxenss::crypto::legacy_pubkey>{}};
    }
    swarm_id_t our_swarm_id() const override { return OUR_SWARM; }
    const Contacts& contacts() const override { return contacts_; }

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
    using Monitors::monitoring_;
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

void subscribe(
        TestMQ& mq,
        const std::string& acct,
        connection_id c,
        bool want_data = false,
        std::vector<namespace_id> namespaces = {namespace_id::Default}) {
    std::vector<subscription> subs;
    subs.push_back({acct, oxenc::to_hex(acct), std::move(namespaces), want_data});
    mq.update_monitors(subs, c);
}

std::vector<namespace_id> ns(std::initializer_list<int16_t> ids) {
    std::vector<namespace_id> v;
    for (auto i : ids)
        v.push_back(namespace_id{i});
    return v;
}

// The decoded notifications pushed to `c`.
std::vector<json> notifications(const TestMQ& mq, const connection_id& c) {
    std::vector<json> got;
    for (auto& p : mq.pushed)
        if (p.command == "notify" && std::ranges::count(p.conns, c))
            got.push_back(oxenss::bt_to_json(oxenc::bt_dict_consumer{p.body}));
    return got;
}

// A signing key and the 0x03-prefixed account it owns.
struct test_key {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    test_key() { crypto_sign_keypair(pk, sk); }
    std::string account() const {
        return "\x03"s + std::string{reinterpret_cast<const char*>(pk), sizeof(pk)};
    }
};

// A signed `monitor` subscription dict for namespace 0, with `extra` keys merged in.
std::string signed_monitor_request(
        const test_key& key, bool data, std::map<std::string, oxenc::bt_value> extra = {}) {
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    auto account = key.account();
    auto sig_msg = "MONITOR{}{}{}0"_format(oxenc::to_hex(account), ts, data ? 1 : 0);
    std::string sig(crypto_sign_BYTES, '\0');
    crypto_sign_detached(
            reinterpret_cast<unsigned char*>(sig.data()),
            nullptr,
            reinterpret_cast<const unsigned char*>(sig_msg.data()),
            sig_msg.size(),
            key.sk);
    oxenc::bt_dict req{
            {"n", oxenc::bt_list{0}},
            {"p", account},
            {"s", sig},
            {"t", ts},
    };
    if (data)
        req["d"] = 1;
    for (auto& [k, v] : extra)
        req[k] = std::move(v);
    return oxenc::bt_serialize(req);
}

// "Stores" a message for `acct`, pushing its notifications.
oxenss::message store(
        TestMQ& mq,
        const std::string& acct,
        std::string hash,
        std::string data = "data",
        namespace_id ns = namespace_id::Default) {
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now());
    oxenss::message m;
    m.pubkey.load(acct);
    m.hash = std::move(hash);
    m.msg_namespace = ns;
    m.timestamp = now;
    m.expiry = now + 1h;
    m.data = std::move(data);
    mq.notify_message(m);
    return m;
}

// The hashes of the notifications pushed to `c`, in order, clearing what was pushed.
std::vector<std::string> notified_hashes(TestMQ& mq, const connection_id& c) {
    std::vector<std::string> hashes;
    for (auto& p : mq.pushed)
        if (p.command == "notify" && std::ranges::count(p.conns, c))
            hashes.push_back(
                    oxenss::bt_to_json(oxenc::bt_dict_consumer{p.body}).at("h").get<std::string>());
    mq.pushed.clear();
    return hashes;
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

    CHECK(mq.monitoring_conns_[q1] == std::unordered_set{a});
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
    CHECK(mq.monitoring_conns_[q1] == std::unordered_set{ours});

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

TEST_CASE("monitor - unknown subscription keys are ignored", "[monitor]") {
    TestMQ mq;
    test_key key;

    auto reply = mq.handle_monitor(
            signed_monitor_request(key, false, {{"a", 1}, {"e", "x"}, {"zz", 2}}), conn(1));
    CHECK(reply == "d7:successi1e1:xi3900ee");
}

TEST_CASE("monitor - renewal matches only the identical subscription", "[monitor]") {
    TestMQ mq;
    auto a = account(0x11);
    auto monitors = [&] {
        std::vector<std::pair<std::vector<namespace_id>, bool>> v;
        for (auto& [acct, mon] : mq.monitoring_)
            v.emplace_back(mon.namespaces, mon.want_data);
        std::ranges::sort(v);
        return v;
    };

    // Same account, connection, namespaces and data flag: a renewal.
    subscribe(mq, a, conn(1), true);
    subscribe(mq, a, conn(1), true);
    CHECK(monitors() == decltype(monitors()){{ns({0}), true}});

    // A different data flag, namespace set or connection is another monitor alongside.
    subscribe(mq, a, conn(1));
    subscribe(mq, a, conn(1), true, ns({0, 1}));
    subscribe(mq, a, conn(2), true);
    CHECK(mq.monitoring_.size() == 4);
    CHECK(monitors() ==
          decltype(monitors()){
                  {ns({0}), false}, {ns({0}), true}, {ns({0}), true}, {ns({0, 1}), true}});
}

TEST_CASE("monitor - a superseded namespace set expires on its own", "[monitor]") {
    TestMQ mq;
    auto a = account(0x11);

    subscribe(mq, a, conn(1), false, ns({0}));
    for (auto& [acct, mon] : mq.monitoring_)
        mon.expiry = std::chrono::steady_clock::now() + 1min;
    subscribe(mq, a, conn(1), false, ns({0, 1}));
    REQUIRE(mq.monitoring_.size() == 2);

    // Nothing is unioned into the old one: it keeps its namespaces and its sooner expiry.
    for (auto& [acct, mon] : mq.monitoring_)
        if (mon.namespaces == ns({0}))
            mon.expiry = std::chrono::steady_clock::now() - 1s;
    mq.remove_expired();
    REQUIRE(mq.monitoring_.size() == 1);
    CHECK(mq.monitoring_.begin()->second.namespaces == ns({0, 1}));
    // The connection still has a monitor of the account, so the account stays in its index.
    CHECK(mq.monitoring_conns_[conn(1)] == std::unordered_set{a});
    store(mq, a, "h", "data", namespace_id{1});
    CHECK(notified_hashes(mq, conn(1)) == std::vector<std::string>{"h"});
}

TEST_CASE("monitor - monitors with disjoint namespaces deliver each their own", "[monitor][body]") {
    TestMQ mq;
    auto a = account(0x11);

    subscribe(mq, a, conn(1), false, ns({1, 2, 3}));
    subscribe(mq, a, conn(1), true, ns({4, 5, 6}));

    store(mq, a, "in 2", "two", namespace_id{2});
    auto got = notifications(mq, conn(1));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("h") == "in 2");
    CHECK_FALSE(got[0].contains("~"));
    mq.pushed.clear();

    store(mq, a, "in 5", "five", namespace_id{5});
    got = notifications(mq, conn(1));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("~") == "five");
    mq.pushed.clear();

    store(mq, a, "in 7", "seven", namespace_id{7});
    CHECK(mq.pushed.empty());
}

TEST_CASE("monitor - a swarm change tells each connection once", "[monitor]") {
    TestMQ mq;
    auto moved = account(0x22);
    subscribe(mq, moved, conn(1), false, ns({0}));
    subscribe(mq, moved, conn(1), false, ns({1}));
    subscribe(mq, moved, conn(2));
    mq.elsewhere[moved] = 0x2000;
    mq.drop_foreign_monitors();
    REQUIRE(mq.pushed.size() == 1);
    CHECK(mq.pushed[0].conns == std::vector{conn(1), conn(2)});
    CHECK(mq.monitoring_.empty());
    CHECK(mq.monitoring_conns_.empty());
}

TEST_CASE(
        "monitor - overlapping monitors give one notification per connection", "[monitor][body]") {
    auto a = account(0x11);
    auto body_for = [&](std::vector<bool> data) {
        TestMQ m;
        int16_t i = 0;
        // Distinct namespace sets, all including 0, so that each is its own monitor.
        for (bool d : data)
            subscribe(m, a, conn(1), d, ns({0, ++i}));
        REQUIRE(m.monitoring_.size() == data.size());
        store(m, a, "h", "0123456789");
        auto got = notifications(m, conn(1));
        REQUIRE(got.size() == 1);
        return got[0];
    };

    // Data if any of them wants it.
    CHECK(body_for({false, true}).at("~") == "0123456789");
    CHECK(body_for({true, false}).at("~") == "0123456789");
    CHECK_FALSE(body_for({false, false}).contains("~"));

    // Other connections are on their own.
    TestMQ mq;
    subscribe(mq, a, conn(1), true, ns({0}));
    subscribe(mq, a, conn(1), false, ns({0, 1}));
    subscribe(mq, a, conn(2), false, ns({0}));
    store(mq, a, "h", "x");
    auto one = notifications(mq, conn(1)), two = notifications(mq, conn(2));
    REQUIRE(one.size() == 1);
    REQUIRE(two.size() == 1);
    CHECK(one[0].contains("~"));
    CHECK_FALSE(two[0].contains("~"));
}

TEST_CASE("monitor - a successful subscription reports its expiry", "[monitor]") {
    TestMQ mq;
    test_key key, other;

    auto decode = [](const std::string& r) {
        return r.front() == 'l' ? oxenss::bt_to_json(oxenc::bt_list_consumer{r})
                                : oxenss::bt_to_json(oxenc::bt_dict_consumer{r});
    };

    auto r = decode(mq.handle_monitor(signed_monitor_request(key, false), conn(1)));
    CHECK(r == json{{"success", 1}, {"x", 3900}});

    // A renewal pushes the expiry back out to the full time.
    for (auto& [acct, mon] : mq.monitoring_)
        mon.expiry = std::chrono::steady_clock::now() + 100s;
    r = decode(mq.handle_monitor(signed_monitor_request(key, true), conn(1)));
    CHECK(r == json{{"success", 1}, {"x", 3900}});

    // In a list each entry gets its own result, and only the successful ones an expiry.
    oxenc::bt_dict bad_pubkey{{"n", oxenc::bt_list{0}}, {"p", "too short"}};
    auto list = "l" + signed_monitor_request(other, false) + oxenc::bt_serialize(bad_pubkey) +
                signed_monitor_request(key, false) + "e";
    r = decode(mq.handle_monitor(list, conn(2)));
    REQUIRE(r.size() == 3);
    CHECK(r[0] == json{{"success", 1}, {"x", 3900}});
    CHECK(r[1] == json{{"errcode", 2}, {"error", "Provided p= pubkey must be 33 bytes"}});
    CHECK(r[2] == json{{"success", 1}, {"x", 3900}});
}
