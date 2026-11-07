#include <catch2/catch.hpp>

#include <oxenmq/oxenmq.h>
#include <oxenss/common/format.h>
#include <oxenss/common/message.h>
#include <oxenss/common/namespace.h>
#include <oxenss/common/pubkey.h>
#include <oxenss/server/monitors.h>
#include <oxenss/server/replay_owners.h>
#include <oxenss/server/serial_runs.h>
#include <oxenss/server/utils.h>
#include <oxenss/snode/contacts.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/utils/time.hpp>

#include <oxenc/bt.h>
#include <sodium.h>
#include <oxenc/hex.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <span>
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
    // The one key whose sessions are privileged.
    inline static const std::string PRIVILEGED_KEY = std::string(32, 'P');

    TestMQ() : Monitors{nullptr, {PRIVILEGED_KEY}} {}
    explicit TestMQ(std::unordered_set<std::string> privileged_keys) :
            Monitors{nullptr, std::move(privileged_keys)} {}

    // How many (account, namespace) pairs sessions have noted as missed, and still to replay.
    size_t missed_pairs() const {
        size_t n = 0;
        for (auto& [token, s] : sessions_)
            n += s->missed.size();
        return n;
    }

    // Makes every session's recently sent notifications look sent `by` earlier than they were.
    void age_recent(std::chrono::seconds by) {
        std::lock_guard lock{missed_mutex_};
        for (auto& [token, s] : sessions_)
            for (auto& r : s->recent)
                r.sent -= by;
    }

    // Makes the session with token `token`, if detached, look detached `by` longer than it has.
    void age_session(const std::string& token, std::chrono::seconds by) {
        std::lock_guard lock{missed_mutex_};
        auto& s = *sessions_.at(token);
        REQUIRE(s.detached_since);
        auto& index = detached_[s.privileged];
        index.erase({*s.detached_since, &s});
        *s.detached_since -= by;
        index.emplace(*s.detached_since, &s);
    }

    static constexpr swarm_id_t OUR_SWARM = 0x1000;

    // Accounts that belong to some other swarm, and which; everything else is ours.
    std::map<std::string, swarm_id_t> elsewhere;

    oxenmq::OxenMQ omq;
    Contacts contacts_{omq};

    // How many times a swarm has been looked up.
    mutable int swarm_lookups = 0;

    swarm_membership swarm_for(const user_pubkey& pk) const override {
        ++swarm_lookups;
        auto it = elsewhere.find(pk.prefixed_raw());
        return std::pair{
                it == elsewhere.end() ? OUR_SWARM : it->second,
                std::set<oxenss::crypto::legacy_pubkey>{}};
    }
    swarm_id_t our_swarm_id() const override { return OUR_SWARM; }
    const Contacts& contacts() const override { return contacts_; }

    // Connections the "transport" no longer has.
    std::set<connection_id> dead;

    std::vector<connection_id> gone_connections(std::vector<connection_id> conns) override {
        std::vector<connection_id> gone;
        for (const auto& c : conns)
            if (dead.contains(c))
                gone.push_back(c);
        return gone;
    }

    // The messages "in the database", by row id, for missed notification replays.  (Unlike the
    // database, expiry is not checked: some tests' messages have none.)
    std::map<int64_t, oxenss::message> rows;
    int64_t next_id = 1;
    int lookups = 0;

    // Stores `m` as a new row, returning its id.
    int64_t add_row(const oxenss::message& m) {
        rows[next_id] = m;
        return next_id++;
    }

    // Deletes the row holding the message with hash `hash`.
    void delete_message(const std::string& hash) {
        std::erase_if(rows, [&hash](const auto& r) { return r.second.hash == hash; });
    }

    size_t largest_lookup = 0;

    std::vector<std::pair<int64_t, oxenss::message>> retrieve_from_id(
            const user_pubkey& pubkey,
            namespace_id ns,
            int64_t from_id,
            size_t limit,
            bool newest_first) override {
        ++lookups;
        std::vector<std::pair<int64_t, oxenss::message>> found;
        auto take = [&](const auto& row) {
            auto& [id, m] = row;
            if (id >= from_id && m.pubkey == pubkey && m.msg_namespace == ns)
                found.emplace_back(id, m);
            return found.size() < limit;
        };
        if (newest_first) {
            for (auto it = rows.rbegin(); it != rows.rend() && take(*it); ++it) {
            }
        } else {
            for (auto it = rows.begin(); it != rows.end() && take(*it); ++it) {
            }
        }
        largest_lookup = std::max(largest_lookup, found.size());
        return found;
    }

    int64_t count_id_range(
            const user_pubkey& pubkey,
            namespace_id ns,
            int64_t from_id,
            int64_t before_id) override {
        int64_t n = 0;
        for (auto& [id, m] : rows)
            if (id >= from_id && id < before_id && m.pubkey == pubkey && m.msg_namespace == ns)
                ++n;
        return n;
    }

    // With `manual_later`, the steps of a paced pass wait here for `run_later_queue()`;
    // otherwise they run at once.
    bool manual_later = false;
    std::deque<std::function<void()>> later;

    void run_later(std::function<void()> f) override {
        if (manual_later)
            later.push_back(std::move(f));
        else
            f();
    }

    // Runs the queued steps of paced passes, and any they queue in turn, returning how many ran.
    int run_later_queue() {
        int n = 0;
        while (!later.empty()) {
            auto f = std::move(later.front());
            later.pop_front();
            f();
            ++n;
        }
        return n;
    }

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

    // With `manual_drain`, a paced send's continuation waits here for `drain()`, as for a stream
    // still sending; otherwise it runs at once, as for one that sends instantly.
    bool manual_drain = false;
    std::deque<std::function<void()>> waiting;
    int paced_ends = 0;

    std::vector<uint64_t> replays;  // the replay id of each paced send

    void send_paced(
            const connection_id& conn,
            uint64_t replay,
            std::vector<std::string> bodies,
            std::function<void()> on_drained) override {
        replays.push_back(replay);
        for (auto& body : bodies)
            pushed.push_back({{conn}, "notify", std::move(body)});
        if (!on_drained)
            ++paced_ends;
        else if (manual_drain)
            waiting.push_back(std::move(on_drained));
        else
            on_drained();
    }

    void drain() {
        REQUIRE(!waiting.empty());
        auto next = std::move(waiting.front());
        waiting.pop_front();
        next();
    }

    using Monitors::closed_conns_;
    using Monitors::detached_monitors_;
    using Monitors::extract_foreign_monitors;
    using Monitors::limits_;
    using Monitors::monitoring_;
    using Monitors::monitoring_conns_;
    using Monitors::sessions_;
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
    // An id with no row behind it: only the destinations matter here, and nothing should be
    // replayed from it.
    mq.notify_message(m, mq.next_id++);
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
    mq.notify_message(m, mq.add_row(m));
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

// Sends a `monitor_session` request on `c`, returning the decoded reply.
json session_request(
        TestMQ& mq, connection_id c, std::string_view token = "", std::string_view key = "") {
    oxenc::bt_dict_producer req;
    if (!token.empty())
        req.append("t", token);
    std::string reply;
    mq.handle_monitor_session(
            std::move(req).str(), c, [&reply](std::string r) { reply = std::move(r); }, key);
    return oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
}

// Sends a `monitor_session` request with the given keys on `c`, returning the decoded reply.
json session_with(TestMQ& mq, connection_id c, oxenc::bt_dict req, std::string_view key = "") {
    std::string reply;
    mq.handle_monitor_session(
            oxenc::bt_serialize(req), c, [&reply](std::string r) { reply = std::move(r); }, key);
    return oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
}

// A privileged session_request.
json privileged_session(TestMQ& mq, connection_id c, std::string_view token = "") {
    return session_request(mq, c, token, TestMQ::PRIVILEGED_KEY);
}

// The `m` dict of a reply, as account -> namespace -> count.
using discards = std::map<std::string, std::map<int, int>>;
discards discards_of(const json& r) {
    discards got;
    for (auto& [account, list] : r.at("m").items())
        for (auto& e : list)
            got[account][e.at("n").get<int>()] = e.at("o").get<int>();
    return got;
}

std::string token_of(const json& reply) {
    return reply.at("t").get<std::string>();
}

// Makes every monitor in the table look like it expired a second ago.
void expire_all(TestMQ& mq) {
    for (auto& [account, mon] : mq.monitoring_)
        mon.expiry = std::chrono::steady_clock::now() - 1s;
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

    mq.connection_closed(q1);

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

TEST_CASE("monitor session - a new session is empty and bound", "[monitor][session]") {
    TestMQ mq;

    auto r = session_request(mq, conn(1));
    CHECK(r.at("r") == 0);
    CHECK(r.at("m").empty());
    CHECK_FALSE(r.contains("o"));
    CHECK(r.at("s").empty());
    CHECK(token_of(r).size() == 32);

    // Monitors requested on the bound connection go to it.
    subscribe(mq, account(0x11), conn(1));
    CHECK(notifiers(mq, account(0x11)) == std::vector{conn(1)});
    CHECK(mq.monitoring_conns_.empty());
}

TEST_CASE(
        "monitor session - monitors survive the connection and resume elsewhere",
        "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    subscribe(mq, b, conn(1));

    mq.connection_closed(conn(1));
    CHECK(notifiers(mq, a).empty());
    REQUIRE(mq.monitoring_.size() == 2);

    auto r = session_request(mq, conn(2), token);
    CHECK(r.at("r") == 1);
    auto new_token = token_of(r);
    CHECK(new_token.size() == 32);
    CHECK(new_token != token);

    REQUIRE(r.at("s").size() == 2);
    std::map<std::string, json> listed;
    for (auto& m : r.at("s"))
        listed[m.at("@").get<std::string>()] = m;
    REQUIRE(listed.count(a));
    REQUIRE(listed.count(b));
    CHECK(listed[a].at("d") == 0);
    CHECK(listed[a].at("n") == json::array({0}));
    CHECK_FALSE(listed[a].contains("errcode"));
    auto x = listed[a].at("x").get<int64_t>();
    CHECK(x > 3890);
    CHECK(x <= 3900);

    CHECK(notifiers(mq, a) == std::vector{conn(2)});
    CHECK(notifiers(mq, b) == std::vector{conn(2)});
}

TEST_CASE("monitor session - resuming rotates the token", "[monitor][session]") {
    TestMQ mq;

    auto first = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    auto second = token_of(session_request(mq, conn(2), first));

    // The old token is now unknown, so presenting it starts a new, empty session.
    auto r = session_request(mq, conn(3), first);
    CHECK(r.at("r") == 0);
    CHECK(r.at("s").empty());

    // ... but the current one still resumes (taking it back from conn 2, which is still bound).
    auto r2 = session_request(mq, conn(4), second);
    CHECK(r2.at("r") == 1);
    CHECK(r2.at("s").size() == 1);
}

TEST_CASE(
        "monitor session - resuming takes over from a connection still bound",
        "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));

    CHECK(session_request(mq, conn(2), token).at("r") == 1);
    CHECK(notifiers(mq, a) == std::vector{conn(2)});

    // conn 1 is no longer bound, so what it subscribes to now is its own.
    subscribe(mq, account(0x22), conn(1));
    CHECK(mq.monitoring_conns_.count(conn(1)) == 1);

    // And its closing leaves the session alone.
    mq.connection_closed(conn(1));
    CHECK(notifiers(mq, a) == std::vector{conn(2)});
    CHECK(notifiers(mq, account(0x22)).empty());
}

TEST_CASE("monitor session - the token alone resumes a session", "[monitor][session]") {
    TestMQ mq;

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    mq.connection_closed(conn(1));

    // Nothing but the token: a wrong one starts a new session, the right one from any connection
    // resumes this one.
    CHECK(session_request(mq, conn(2), std::string(32, 'x')).at("r") == 0);
    auto r = session_request(mq, conn(3), token);
    CHECK(r.at("r") == 1);
    CHECK(r.at("s").size() == 1);
}

TEST_CASE("monitor session - a connection can start only one new session", "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11);

    auto first = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));

    // Not another, with no token or with one that no longer resumes anything.
    auto r = session_request(mq, conn(1));
    CHECK(r.at("errcode") == 10);
    CHECK_FALSE(r.contains("t"));
    CHECK(session_request(mq, conn(1), std::string(32, 'x')).at("errcode") == 10);
    // The first carries on unchanged.
    CHECK(mq.sessions_.contains(first));
    CHECK(notifiers(mq, a) == std::vector{conn(1)});

    // Resuming one is still fine: here another, started on connection 2 and left there, which the
    // first gives way to on connection 1 (keeping its monitors for a resume of its own).
    auto other = token_of(session_request(mq, conn(2)));
    mq.connection_closed(conn(2));
    auto resumed = session_request(mq, conn(1), other);
    CHECK(resumed.at("r") == 1);
    CHECK(notifiers(mq, a).empty());

    // And a new connection starts afresh as it likes.
    CHECK(session_request(mq, conn(3)).at("r") == 0);
    CHECK(session_request(mq, conn(4), first).at("r") == 1);
}

TEST_CASE(
        "monitor session - a detached session lasts its lifetime, whatever its monitors",
        "[monitor][session]") {
    TestMQ mq;
    constexpr auto LIFETIME = oxenss::server::Monitors::SESSION_DETACHED_LIFETIME;

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    mq.connection_closed(conn(1));

    SECTION("one whose monitors' expiries have passed is still resumed, and they then go") {
        expire_all(mq);
        // Its subscriber cannot renew them while away, so the sweep leaves them for now.
        mq.remove_expired();
        CHECK(mq.monitoring_.size() == 1);
        mq.age_session(token, LIFETIME - 1min);
        mq.remove_expired();
        auto r = session_request(mq, conn(2), token);
        CHECK(r.at("r") == 1);
        CHECK(r.at("s").empty());
        mq.remove_expired();
        CHECK(mq.monitoring_.empty());
    }
    SECTION("but not past its lifetime, even with live monitors") {
        mq.age_session(token, LIFETIME);
        SECTION("when swept") {
            mq.remove_expired();
            CHECK(mq.sessions_.empty());
            CHECK(mq.monitoring_.empty());
        }
        SECTION("or when a resume finds it so before the sweep") {}
        auto r = session_request(mq, conn(2), token);
        CHECK(r.at("r") == 0);
        CHECK(r.at("s").empty());
    }
}

TEST_CASE("monitor session - a bound session outlives its monitors", "[monitor][session]") {
    TestMQ mq;

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    expire_all(mq);
    mq.remove_expired();

    CHECK(mq.monitoring_.empty());
    REQUIRE(mq.sessions_.size() == 1);
    // A new monitor on the connection still goes to the session.
    subscribe(mq, account(0x22), conn(1));
    CHECK(mq.monitoring_conns_.empty());
    mq.connection_closed(conn(1));
    CHECK(session_request(mq, conn(2), token).at("r") == 1);
}

TEST_CASE(
        "monitor session - the sweep removes expired connection monitors too",
        "[monitor][session]") {
    TestMQ mq;

    subscribe(mq, account(0x11), conn(1));
    expire_all(mq);
    mq.remove_expired();
    CHECK(mq.monitoring_.empty());
    CHECK(mq.monitoring_conns_.empty());
}

TEST_CASE(
        "monitor session - an account that moved swarm is reported at resume",
        "[monitor][session]") {
    TestMQ mq;
    auto ours = account(0x11), moved = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, ours, conn(1));
    subscribe(mq, moved, conn(1));
    mq.connection_closed(conn(1));

    mq.elsewhere[moved] = 0x2000;

    // With nobody bound to tell, the swarm change removes the monitor and keeps a note of it...
    mq.drop_foreign_monitors();
    CHECK(mq.pushed.empty());
    CHECK(mq.monitoring_.size() == 1);

    // ... for the resume to report, against the swarm state at the time of the resume.
    auto r = session_request(mq, conn(2), token);
    REQUIRE(r.at("s").size() == 2);
    json ended;
    for (auto& m : r.at("s"))
        if (m.at("@") == moved)
            ended = m;
    REQUIRE(ended.is_object());
    CHECK(ended.at("errcode") == 6);
    CHECK(ended.at("error") == "Account is no longer stored by this service node's swarm");
    CHECK(ended.at("swarm") == "2000");
    CHECK(ended.at("snodes").empty());
    CHECK_FALSE(ended.contains("x"));
    CHECK_FALSE(ended.contains("n"));

    // Once reported it is gone, not kept as a marker.
    CHECK(mq.monitoring_.size() == 1);
    CHECK(notifiers(mq, moved).empty());
    mq.connection_closed(conn(2));
    auto r2 = session_request(mq, conn(3), token_of(r));
    REQUIRE(r2.at("s").size() == 1);
    CHECK(r2.at("s")[0].at("@") == ours);
}

TEST_CASE("monitor session - a swarm change ends a bound session's monitor", "[monitor][session]") {
    TestMQ mq;
    auto moved = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, moved, conn(1));
    mq.elsewhere[moved] = 0x2000;
    mq.drop_foreign_monitors();

    REQUIRE(mq.pushed.size() == 1);
    CHECK(mq.pushed[0].command == "monitor_ended");
    CHECK(mq.pushed[0].conns == std::vector{conn(1)});
    CHECK(mq.monitoring_.empty());

    // The session itself carries on, and outlasts its connection like any other.
    mq.connection_closed(conn(1));
    CHECK(session_request(mq, conn(2), token).at("r") == 1);
}

TEST_CASE("monitor session - a malformed request is refused", "[monitor][session]") {
    TestMQ mq;
    std::string reply;
    mq.handle_monitor_session("l1:te", conn(1), [&reply](std::string r) { reply = std::move(r); });
    auto r = oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
    CHECK(r.at("errcode") == 1);
    CHECK(mq.sessions_.empty());
}

TEST_CASE(
        "monitor session - missed notifications are replayed on resume",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1), true);
    subscribe(mq, b, conn(1));

    // Sent just before the connection went: it may not have arrived, so it is replayed too.
    store(mq, a, "live", "zero");
    CHECK(notified_hashes(mq, conn(1)) == std::vector<std::string>{"live"});

    mq.connection_closed(conn(1));
    auto m1 = store(mq, a, "m1", "first");
    store(mq, b, "m2");
    store(mq, a, "unmonitored ns", "x", namespace_id{42});
    store(mq, a, "m3", "third");
    store(mq, b, "deleted");
    mq.delete_message("deleted");
    store(mq, a, "m4");
    CHECK(mq.pushed.empty());
    // One entry per account and namespace, whatever the number of messages.
    CHECK(mq.missed_pairs() == 2);

    // The reply goes out before any replayed notification.
    size_t pushed_before_reply = 99;
    oxenc::bt_dict_producer req;
    req.append("t", token);
    std::string reply;
    mq.handle_monitor_session(std::move(req).str(), conn(2), [&](std::string r) {
        pushed_before_reply = mq.pushed.size();
        reply = std::move(r);
    });
    CHECK(pushed_before_reply == 0);
    auto r = oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
    CHECK(r.at("r") == 1);
    CHECK(r.at("m").empty());

    // Each account's oldest first; a message since deleted is simply not found.
    auto got = notifications(mq, conn(2));
    REQUIRE(got.size() == 5);
    std::vector<std::string> hashes;
    for (auto& n : got)
        hashes.push_back(n.at("h"));
    CHECK(hashes == std::vector<std::string>{"live", "m1", "m3", "m4", "m2"});
    // A replayed notification is exactly what would have been sent live, data included.
    CHECK(got[1] == json{{"@", a},
                         {"h", "m1"},
                         {"n", 0},
                         {"t", oxenss::to_epoch_ms(m1.timestamp)},
                         {"z", oxenss::to_epoch_ms(m1.expiry)},
                         {"~", "first"}});
    CHECK_FALSE(got[4].contains("~"));
    CHECK(mq.missed_pairs() == 0);
    mq.pushed.clear();

    // Once replayed, and past the window in which they may yet have been lost, nothing is left.
    mq.age_recent(oxenss::server::Monitors::RECENT_WINDOW + 1s);
    mq.remove_expired();
    mq.connection_closed(conn(2));
    auto r2 = session_request(mq, conn(3), token_of(r));
    CHECK(r2.at("r") == 1);
    CHECK(mq.pushed.empty());
}
TEST_CASE(
        "monitor session - a bound session notes what it sent, not what it missed",
        "[monitor][session][missed]") {
    TestMQ mq;
    session_request(mq, conn(1));
    subscribe(mq, account(0x11), conn(1));
    store(mq, account(0x11), "h");
    CHECK(mq.missed_pairs() == 0);
    CHECK(mq.sessions_.begin()->second->recent.size() == 1);
    CHECK(notified_hashes(mq, conn(1)) == std::vector<std::string>{"h"});
}

TEST_CASE(
        "monitor session - a removed session's missed notifications go with it",
        "[monitor][session][missed]") {
    TestMQ mq;
    session_request(mq, conn(1));
    subscribe(mq, account(0x11), conn(1));
    mq.connection_closed(conn(1));
    store(mq, account(0x11), "h");
    CHECK(mq.missed_pairs() == 1);

    mq.age_session(
            mq.sessions_.begin()->first, oxenss::server::Monitors::SESSION_DETACHED_LIFETIME);
    mq.remove_expired();
    CHECK(mq.sessions_.empty());
    CHECK(mq.missed_pairs() == 0);
}

TEST_CASE("monitor - unknown subscription keys are ignored", "[monitor]") {
    TestMQ mq;
    test_key key;

    auto reply = mq.handle_monitor(
            signed_monitor_request(key, false, {{"a", 1}, {"e", "x"}, {"zz", 2}}), conn(1));
    CHECK(reply == "d7:successi1e1:xi3900ee");
}

TEST_CASE("monitor session - b limits the body of notifications", "[monitor][session][body]") {
    TestMQ mq;
    auto a = account(0x11);

    subscribe(mq, a, conn(1), true);  // connection-bound: never limited
    session_with(mq, conn(2), {});
    subscribe(mq, a, conn(2), true);  // session without b: no limit
    session_with(mq, conn(3), {{"b", 5}});
    subscribe(mq, a, conn(3), true);  // up to 5 bytes
    session_with(mq, conn(4), {{"b", 0}});
    subscribe(mq, a, conn(4), true);  // none of it
    session_with(mq, conn(5), {{"b", 3}});
    subscribe(mq, a, conn(5));  // a limit means nothing without data

    SECTION("a body over the limit") {
        store(mq, a, "h", "0123456789");
        auto conn_full = notifications(mq, conn(1)), full = notifications(mq, conn(2)),
             cut = notifications(mq, conn(3)), omitted = notifications(mq, conn(4)),
             none = notifications(mq, conn(5));
        REQUIRE(conn_full.size() == 1);
        CHECK(conn_full[0].at("~") == "0123456789");
        CHECK_FALSE(conn_full[0].contains("L"));
        CHECK(full == conn_full);
        REQUIRE(cut.size() == 1);
        CHECK(cut[0].at("~") == "01234");
        CHECK(cut[0].at("L") == 10);
        REQUIRE(omitted.size() == 1);
        CHECK_FALSE(omitted[0].contains("~"));
        CHECK(omitted[0].at("L") == 10);
        REQUIRE(none.size() == 1);
        CHECK_FALSE(none[0].contains("~"));
        CHECK_FALSE(none[0].contains("L"));

        // Apart from those two keys the notifications are all the same.
        cut[0].erase("~");
        cut[0].erase("L");
        omitted[0].erase("L");
        CHECK(cut[0] == none[0]);
        CHECK(omitted[0] == none[0]);
    }
    SECTION("a body within the limit is untouched") {
        store(mq, a, "h", "01234");
        // So the unlimited and limited subscribers get the very same notification, built once.
        bool shared = false;
        for (auto& p : mq.pushed)
            if (std::ranges::count(p.conns, conn(1)) && std::ranges::count(p.conns, conn(3)))
                shared = true;
        CHECK(shared);
        auto cut = notifications(mq, conn(3));
        REQUIRE(cut.size() == 1);
        CHECK(cut[0].at("~") == "01234");
        CHECK_FALSE(cut[0].contains("L"));
    }
}

TEST_CASE(
        "monitor session - b is set afresh by every monitor_session", "[monitor][session][body]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_with(mq, conn(1), {{"b", 2}}));
    subscribe(mq, a, conn(1), true);
    store(mq, a, "h1", "hello");
    auto got = notifications(mq, conn(1));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("~") == "he");
    mq.pushed.clear();

    // Resuming (here on the same connection) without b lifts the limit.
    session_with(mq, conn(1), {{"t", token}});
    store(mq, a, "h2", "hello");
    got = notifications(mq, conn(1));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("~") == "hello");
    CHECK_FALSE(got[0].contains("L"));
}

TEST_CASE("monitor session - a replay uses the resume's b", "[monitor][session][body]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_with(mq, conn(1), {{"b", 2}}));
    subscribe(mq, a, conn(1), true);
    subscribe(mq, account(0x22), conn(1));
    mq.connection_closed(conn(1));
    store(mq, a, "h", "hello");
    store(mq, account(0x22), "nodata", "hello");

    auto r = session_with(mq, conn(2), {{"b", 3}, {"t", token}});
    // Not whatever applied when the message arrived.
    auto got = notifications(mq, conn(2));
    REQUIRE(got.size() == 2);
    CHECK(got[0].at("~") == "hel");
    CHECK(got[0].at("L") == 5);
    // A monitor without data gets no body (nor L) whatever the limit.
    CHECK_FALSE(got[1].contains("~"));
    CHECK_FALSE(got[1].contains("L"));

    // The listing has no b of its own.
    REQUIRE(r.at("s").size() == 2);
    for (auto& m : r.at("s"))
        CHECK_FALSE(m.contains("b"));
}

TEST_CASE("monitor session - an invalid b is refused", "[monitor][session][body]") {
    TestMQ mq;
    for (auto bad : {"d1:bi-1ee"s, "d1:b1:5e"s}) {
        std::string reply;
        mq.handle_monitor_session(bad, conn(1), [&reply](std::string r) { reply = std::move(r); });
        CHECK(oxenss::bt_to_json(oxenc::bt_dict_consumer{reply}).at("errcode") == 1);
    }
    CHECK(mq.sessions_.empty());
}

TEST_CASE("monitor - L sorts into the notification dict", "[monitor][body]") {
    TestMQ mq;
    auto a = account(0x11);
    session_with(mq, conn(1), {{"b", 2}});
    subscribe(mq, a, conn(1), true);
    store(mq, a, "h", "abc");
    REQUIRE(mq.pushed.size() == 1);
    // bt dict keys are in byte order, so the capital L lands between @ and h.
    CHECK(mq.pushed[0].body.starts_with("d1:@33:"));
    CHECK(mq.pushed[0].body.substr(7 + 33, 9) == "1:Li3e1:h");
    CHECK(mq.pushed[0].body.ends_with("1:~2:abe"));
}

TEST_CASE("monitor - b in a subscription is ignored", "[monitor][body]") {
    TestMQ mq;
    test_key key;

    session_with(mq, conn(1), {});
    // Any value, even one a session would refuse, as for any key the parser does not know.
    CHECK(mq.handle_monitor(signed_monitor_request(key, true, {{"b", 2}}), conn(1)) ==
          "d7:successi1e1:xi3900ee");
    CHECK(mq.handle_monitor(signed_monitor_request(key, false, {{"b", -1}}), conn(1)) ==
          "d7:successi1e1:xi3900ee");
    CHECK(mq.monitoring_.size() == 2);

    oxenss::message m;
    m.pubkey.load(key.account());
    m.hash = "h";
    m.msg_namespace = namespace_id::Default;
    m.data = "hello";
    mq.notify_message(m, mq.add_row(m));
    auto got = notifications(mq, conn(1));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("~") == "hello");
    CHECK_FALSE(got[0].contains("L"));
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
    auto body_for = [&](std::vector<bool> data, std::optional<int> b) {
        TestMQ m;
        if (b)
            session_with(m, conn(1), {{"b", *b}});
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

    // Data if any of them wants it ...
    auto r = body_for({false, true}, std::nullopt);
    CHECK(r.at("~") == "0123456789");
    CHECK_FALSE(body_for({false, false}, std::nullopt).contains("~"));

    // ... limited by the session's b.
    r = body_for({false, true, true}, 5);
    CHECK(r.at("~") == "01234");
    CHECK(r.at("L") == 10);

    // A connection's own monitors (made before it was bound to the session) have no limit, so one
    // of them matching lifts the session's.
    TestMQ mq;
    subscribe(mq, a, conn(1), true, ns({0}));
    session_with(mq, conn(1), {{"b", 3}});
    subscribe(mq, a, conn(1), true, ns({0, 1}));
    subscribe(mq, a, conn(2), false, ns({0}));
    store(mq, a, "h", "0123456789");
    auto one = notifications(mq, conn(1)), two = notifications(mq, conn(2));
    REQUIRE(one.size() == 1);
    REQUIRE(two.size() == 1);
    CHECK(one[0].at("~") == "0123456789");
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

TEST_CASE(
        "monitor session - requests from a closed connection bind nothing", "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    mq.connection_closed(conn(1));
    store(mq, a, "missed");

    // A request from conn 2 that was handed over after conn 2 had closed.
    mq.connection_closed(conn(2));
    oxenc::bt_dict_producer req;
    req.append("t", token);
    bool replied = false;
    mq.handle_monitor_session(
            std::move(req).str(), conn(2), [&replied](std::string) { replied = true; });
    CHECK_FALSE(replied);
    CHECK(mq.pushed.empty());
    subscribe(mq, account(0x22), conn(2));
    CHECK(mq.monitoring_conns_.empty());

    // The session is untouched: still detached, with its token and missed notification.
    auto r = session_request(mq, conn(3), token);
    CHECK(r.at("r") == 1);
    CHECK(notified_hashes(mq, conn(3)) == std::vector<std::string>{"missed"});

    // The record of closed connections is swept in time.
    for (auto& [c, when] : mq.closed_conns_)
        when -= 2min;
    mq.remove_expired();
    CHECK(mq.closed_conns_.empty());
}

TEST_CASE("monitor session - the listing has one entry per monitor", "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11), moved = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1), false, ns({1, 2}));
    subscribe(mq, a, conn(1), true, ns({3}));
    subscribe(mq, moved, conn(1), false, ns({0}));
    subscribe(mq, moved, conn(1), true, ns({0}));
    // Monitors, not accounts, are what the missed notification limit scales with.
    REQUIRE(mq.sessions_.size() == 1);
    auto& session = *mq.sessions_.begin()->second;
    CHECK(session.monitor_count == 4);
    mq.connection_closed(conn(1));
    mq.elsewhere[moved] = 0x2000;
    mq.drop_foreign_monitors();

    auto r = session_request(mq, conn(2), token);
    REQUIRE(r.at("s").size() == 3);
    std::vector<json> of_a, of_moved;
    for (auto& m : r.at("s"))
        (m.at("@") == a ? of_a : of_moved).push_back(m);
    REQUIRE(of_a.size() == 2);
    std::ranges::sort(of_a, [](auto& x, auto& y) { return x.at("n") < y.at("n"); });
    CHECK(of_a[0].at("n") == json::array({1, 2}));
    CHECK(of_a[0].at("d") == 0);
    CHECK_FALSE(of_a[0].contains("b"));
    CHECK(of_a[0].contains("x"));
    CHECK(of_a[1].at("n") == json::array({3}));
    CHECK(of_a[1].at("d") == 1);
    CHECK_FALSE(of_a[1].contains("b"));
    CHECK(of_a[1].contains("x"));

    // The moved account is reported ended once, however many monitors it had, and they are gone.
    REQUIRE(of_moved.size() == 1);
    CHECK(of_moved[0].at("errcode") == 6);
    CHECK_FALSE(of_moved[0].contains("x"));
    CHECK(mq.monitoring_.size() == 2);
    CHECK(session.monitor_count == 2);
    CHECK(session.accounts == std::unordered_set{a});
}

TEST_CASE(
        "monitor session - overlapping monitors record one missed notification",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_with(mq, conn(1), {{"b", 2}}));
    subscribe(mq, a, conn(1), true, ns({0}));
    subscribe(mq, a, conn(1), false, ns({0, 1}));
    mq.connection_closed(conn(1));
    store(mq, a, "h", "hello");
    CHECK(mq.missed_pairs() == 1);

    session_with(mq, conn(2), {{"b", 2}, {"t", token}});
    auto got = notifications(mq, conn(2));
    REQUIRE(got.size() == 1);
    CHECK(got[0].at("~") == "he");
    CHECK(got[0].at("L") == 5);
}

TEST_CASE("monitor session - l=0 lists only the ended monitors", "[monitor][session]") {
    auto setup = [](TestMQ& mq) {
        auto token = token_of(session_request(mq, conn(1)));
        subscribe(mq, account(0x11), conn(1), {}, ns({0}));
        subscribe(mq, account(0x11), conn(1), true, ns({0, 10}));
        subscribe(mq, account(0x22), conn(1));
        mq.connection_closed(conn(1));
        store(mq, account(0x11), "missed", "data");
        mq.elsewhere[account(0x22)] = 0x2000;
        mq.drop_foreign_monitors();
        return token;
    };
    auto resume = [](TestMQ& mq, const std::string& token, std::optional<int> l) {
        oxenc::bt_dict_producer req;
        if (l)
            req.append("l", *l);
        req.append("t", token);
        std::string reply;
        mq.handle_monitor_session(
                std::move(req).str(), conn(2), [&reply](std::string r) { reply = std::move(r); });
        return oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
    };

    TestMQ mq;
    auto token = setup(mq);
    // Nor does it look anything up in the swarm but for the ended account it reports.
    mq.swarm_lookups = 0;
    auto r = resume(mq, token, 0);
    CHECK(mq.swarm_lookups == 1);
    CHECK(r.at("r") == 1);
    CHECK(token_of(r).size() == 32);
    REQUIRE(r.at("s").size() == 1);
    CHECK(r.at("s")[0].at("@") == account(0x22));
    CHECK(r.at("s")[0].at("errcode") == 6);
    CHECK(r.at("s")[0].contains("swarm"));
    CHECK(r.at("s")[0].contains("snodes"));
    // The replay is unaffected, and the unlisted monitors are still there.
    CHECK(notified_hashes(mq, conn(2)) == std::vector<std::string>{"missed"});
    CHECK(mq.monitoring_.size() == 2);
    store(mq, account(0x11), "live", "data", namespace_id{10});
    CHECK(notified_hashes(mq, conn(2)) == std::vector<std::string>{"live"});

    // l=1 is the same as leaving it out: the full listing.
    TestMQ with_1, without;
    auto r1 = resume(with_1, setup(with_1), 1);
    auto r0 = resume(without, setup(without), std::nullopt);
    CHECK(r1.at("s").size() == 3);
    CHECK(r0.at("s").size() == 3);
    r1.erase("t");
    r0.erase("t");
    for (auto* x : {&r0, &r1})
        for (auto& m : x->at("s"))
            m.erase("x");
    auto by_n = [](const json& a, const json& b) { return a.dump() < b.dump(); };
    std::sort(r1["s"].begin(), r1["s"].end(), by_n);
    std::sort(r0["s"].begin(), r0["s"].end(), by_n);
    CHECK(r1 == r0);
}

TEST_CASE("monitor session - l=0 on a new session", "[monitor][session]") {
    TestMQ mq;
    oxenc::bt_dict_producer req;
    req.append("l", 0);
    req.append("t", std::string(32, 'x'));
    std::string reply;
    mq.handle_monitor_session(
            std::move(req).str(), conn(1), [&reply](std::string r) { reply = std::move(r); });
    auto r = oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
    CHECK(r.at("r") == 0);
    CHECK(r.at("s").empty());
    CHECK(mq.sessions_.size() == 1);
}

TEST_CASE("monitor session - an invalid l is refused", "[monitor][session]") {
    TestMQ mq;
    for (auto bad : {"d1:l1:xe"s, "d1:li2ee"s, "d1:li-1ee"s}) {
        std::string reply;
        mq.handle_monitor_session(bad, conn(1), [&reply](std::string r) { reply = std::move(r); });
        CHECK(oxenss::bt_to_json(oxenc::bt_dict_consumer{reply}).at("errcode") == 1);
    }
    CHECK(mq.sessions_.empty());
}

TEST_CASE(
        "monitor session - m replays each account's newest missed notifications",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    subscribe(mq, b, conn(1));
    mq.connection_closed(conn(1));

    store(mq, a, "a1");
    store(mq, b, "b1");
    store(mq, a, "a2");
    store(mq, a, "a3");
    store(mq, b, "b2");
    store(mq, a, "a4");

    auto r = session_with(mq, conn(2), {{"m", 2}, {"t", token}});
    CHECK(discards_of(r) == discards{{a, {{0, 2}}}});

    // Each account's newest two, oldest first within the account.
    CHECK(notified_hashes(mq, conn(2)) == std::vector<std::string>{"a3", "a4", "b1", "b2"});
    CHECK(mq.missed_pairs() == 0);
}
TEST_CASE("monitor session - without m the m dict is empty", "[monitor][session][missed]") {
    TestMQ mq;
    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    mq.connection_closed(conn(1));
    for (int i = 0; i < 5; i++)
        store(mq, account(0x11), "h{}"_format(i));
    auto r = session_request(mq, conn(2), token);
    REQUIRE(r.contains("m"));
    CHECK(r.at("m").empty());
    CHECK(notified_hashes(mq, conn(2)).size() == 5);
}
TEST_CASE("monitor session - m applies to the resume that gives it", "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);
    uint64_t current = 1;
    auto away = [&](std::vector<std::string> hashes) {
        // What the last connection was sent is past the window in which it might have been lost.
        mq.age_recent(oxenss::server::Monitors::RECENT_WINDOW + 1s);
        mq.remove_expired();
        mq.connection_closed(conn(current++));
        for (auto& h : hashes)
            store(mq, a, h);
    };

    // Given when the session is created, m means nothing for later resumes.
    auto token = token_of(session_with(mq, conn(1), {{"m", 1}}));
    subscribe(mq, a, conn(1));
    away({"x1", "x2", "x3"});
    auto r = session_with(mq, conn(current), {{"t", token}});
    CHECK(r.at("m").empty());
    CHECK(notified_hashes(mq, conn(current)) == std::vector<std::string>{"x1", "x2", "x3"});

    away({"y1", "y2", "y3"});
    r = session_with(mq, conn(current), {{"m", 2}, {"t", token_of(r)}});
    CHECK(discards_of(r) == discards{{a, {{0, 1}}}});
    CHECK(notified_hashes(mq, conn(current)) == std::vector<std::string>{"y2", "y3"});
}
TEST_CASE("monitor session - an invalid m is refused", "[monitor][session]") {
    TestMQ mq;
    for (auto bad : {"d1:mi0ee"s, "d1:mi-3ee"s, "d1:m1:2e"s}) {
        std::string reply;
        mq.handle_monitor_session(bad, conn(1), [&reply](std::string r) { reply = std::move(r); });
        CHECK(oxenss::bt_to_json(oxenc::bt_dict_consumer{reply}).at("errcode") == 1);
    }
    CHECK(mq.sessions_.empty());
}

TEST_CASE("monitor session - a resume's m bounds the replay", "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    SECTION("per account") {
        auto token = token_of(session_with(mq, conn(1), {}));
        subscribe(mq, a, conn(1));
        subscribe(mq, b, conn(1));
        mq.connection_closed(conn(1));
        for (auto h : {"a1", "a2", "b1", "a3", "a4"})
            store(mq, h[0] == 'a' ? a : b, h);

        auto r = session_with(mq, conn(2), {{"m", 2}, {"t", token}});
        CHECK(discards_of(r) == discards{{a, {{0, 2}}}});
        CHECK(notified_hashes(mq, conn(2)) == std::vector<std::string>{"a3", "a4", "b1"});
    }
    SECTION("across an account's namespaces, counted per namespace") {
        auto token = token_of(session_with(mq, conn(1), {}));
        subscribe(mq, a, conn(1), false, ns({0, 5}));
        mq.connection_closed(conn(1));
        store(mq, a, "ns0 first", "data", namespace_id{0});
        store(mq, a, "ns5 first", "data", namespace_id{5});
        store(mq, a, "ns0 second", "data", namespace_id{0});
        store(mq, a, "ns5 second", "data", namespace_id{5});
        store(mq, a, "ns0 third", "data", namespace_id{0});

        // The newest three of the account: one cut in each namespace.
        auto r = session_with(mq, conn(2), {{"m", 3}, {"t", token}});
        CHECK(discards_of(r) == discards{{a, {{0, 1}, {5, 1}}}});
        CHECK(notified_hashes(mq, conn(2)) ==
              std::vector<std::string>{"ns0 second", "ns0 third", "ns5 second"});
    }
    CHECK(mq.missed_pairs() == 0);
}
TEST_CASE("serial runs - a key's items run one after another in order", "[monitor]") {
    using runs = oxenss::server::serial_runs<int, std::string>;
    runs r;
    std::string first = "first", second = "second", third = "third", other = "other";

    CHECK_FALSE(r.running(1));
    CHECK(r.add(1, first) == runs::added::run);
    CHECK(r.running(1));
    CHECK(r.add(1, second) == runs::added::queued);
    CHECK(r.add(1, third) == runs::added::queued);
    // Other keys are independent.
    CHECK(r.add(2, other) == runs::added::run);

    CHECK(r.next(1) == std::deque<std::string>{"second", "third"});
    CHECK(r.running(1));
    CHECK(r.next(1).empty());
    CHECK_FALSE(r.running(1));
    CHECK(r.running(2));

    // Only so many can wait.
    std::string x = "x";
    CHECK(r.add(3, x) == runs::added::run);
    for (size_t i = 0; i < runs::MAX_WAITING; i++) {
        std::string item = "item";
        CHECK(r.add(3, item) == runs::added::queued);
    }
    CHECK(r.add(3, x) == runs::added::full);

    // A forgotten key's run is over, whatever was waiting.
    r.forget(3);
    CHECK_FALSE(r.running(3));
    CHECK(r.next(3).empty());
}

TEST_CASE(
        "monitor session - a message stored over another is replayed in its place",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);
    const auto outbox = namespace_id{-21};

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1), false, ns({-21, 0}));
    auto old = store(mq, a, "old", "data", outbox);
    // Long enough ago that it is past the window of recent sends.
    mq.age_recent(oxenss::server::Monitors::RECENT_WINDOW + 1s);
    mq.remove_expired();
    mq.connection_closed(conn(1));
    store(mq, a, "other", "data", namespace_id{0});

    // A newer message replacing the old one keeps the old one's row id, below anything else
    // missed: that it is still replayed is what keeping the lowest id per namespace is for.
    int64_t old_id = 0;
    for (auto& [id, m] : mq.rows)
        if (m.hash == "old")
            old_id = id;
    auto replacement = old;
    replacement.hash = "replacement";
    mq.rows[old_id] = replacement;
    mq.notify_message(replacement, old_id);

    session_request(mq, conn(2), token);
    auto got = notified_hashes(mq, conn(2));
    std::ranges::sort(got);
    CHECK(got == std::vector<std::string>{"other", "replacement"});
}
TEST_CASE(
        "monitor session - a detached session's monitors do not expire",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1), true);
    subscribe(mq, b, conn(1));
    mq.connection_closed(conn(1));

    // A subscriber away cannot renew: a's monitor passes its expiry while it is gone, but still
    // notes what it misses, and the sweep leaves it.
    for (auto& [acct, mon] : mq.monitoring_)
        if (acct == a)
            mon.expiry = std::chrono::steady_clock::now() - 1s;
    mq.remove_expired();
    REQUIRE(mq.monitoring_.size() == 2);
    store(mq, a, "from a", "data");
    store(mq, b, "from b", "data");

    session_request(mq, conn(2), token);
    auto got = notifications(mq, conn(2));
    REQUIRE(got.size() == 2);
    CHECK(got[0].at("h") == "from a");
    // With data as the monitor wanted when the message arrived.
    CHECK(got[0].at("~") == "data");
    CHECK(got[1].at("h") == "from b");
    CHECK_FALSE(got[1].contains("~"));

    // Bound again, the lapsed one goes with the next sweep.
    mq.remove_expired();
    CHECK(mq.monitoring_.size() == 1);
}
TEST_CASE("monitor session - a replay goes a chunk at a time", "[monitor][session][missed]") {
    TestMQ mq;
    mq.manual_drain = true;
    constexpr size_t CHUNK = oxenss::server::Monitors::REPLAY_CHUNK;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    mq.connection_closed(conn(1));
    const size_t total = 2 * CHUNK + 10;
    std::vector<std::string> stored;
    for (size_t i = 0; i < total; i++) {
        stored.push_back("h{}"_format(i));
        store(mq, a, stored.back());
    }

    SECTION("each waiting for the one before to be sent on") {
        auto r = session_request(mq, conn(2), token);
        // The reply, and the first chunk only.
        CHECK(mq.pushed.size() == CHUNK);
        REQUIRE(mq.waiting.size() == 1);
        mq.drain();
        CHECK(mq.pushed.size() == 2 * CHUNK);
        mq.drain();
        CHECK(mq.pushed.size() == total);
        // The last chunk's drain finds nothing more, and ends the replay.
        CHECK(mq.paced_ends == 0);
        mq.drain();
        CHECK(mq.waiting.empty());
        CHECK(mq.paced_ends == 1);
        CHECK(mq.largest_lookup == CHUNK);
        CHECK(notified_hashes(mq, conn(2)) == stored);
    }
    SECTION("and stopped, losing nothing, if the connection closes meanwhile") {
        auto token2 = token_of(session_request(mq, conn(2), token));
        CHECK(mq.pushed.size() == CHUNK);
        mq.connection_closed(conn(2));
        mq.drain();
        CHECK(mq.pushed.size() == CHUNK);
        CHECK(mq.waiting.empty());
        CHECK(mq.lookups == 1);
        mq.pushed.clear();

        // What was sent may never have arrived, so a resume replays it all again.
        mq.manual_drain = false;
        session_request(mq, conn(3), token2);
        CHECK(notified_hashes(mq, conn(3)) == stored);
    }
}
TEST_CASE(
        "monitor session - privilege comes from the creating connection's key",
        "[monitor][session]") {
    TestMQ mq;
    auto privileged_of = [&](const json& reply) {
        return mq.sessions_.at(token_of(reply))->privileged;
    };

    CHECK(privileged_of(privileged_session(mq, conn(1))));
    CHECK_FALSE(privileged_of(session_request(mq, conn(2))));
    CHECK_FALSE(privileged_of(session_request(mq, conn(3), "", std::string(32, 'X'))));

    // Kept across resumes, whatever (if any) key the resuming connection has.
    auto token = token_of(privileged_session(mq, conn(4)));
    mq.connection_closed(conn(4));
    auto r = session_request(mq, conn(5), token);
    REQUIRE(r.at("r") == 1);
    CHECK(privileged_of(r));
    // Nor does a privileged key make an unprivileged session privileged.
    auto plain = token_of(session_request(mq, conn(6)));
    mq.connection_closed(conn(6));
    r = privileged_session(mq, conn(7), plain);
    REQUIRE(r.at("r") == 1);
    CHECK_FALSE(privileged_of(r));
}

TEST_CASE(
        "monitor session - an unprivileged session has at most 64 monitors", "[monitor][session]") {
    TestMQ mq;
    const size_t limit = mq.limits_.unprivileged_monitors;
    REQUIRE(limit == 64);

    std::vector<test_key> keys(limit + 1);
    auto monitor = [&](size_t i, connection_id c) {
        return oxenss::bt_to_json(oxenc::bt_dict_consumer{
                mq.handle_monitor(signed_monitor_request(keys[i], false), c)});
    };

    session_request(mq, conn(1));
    for (size_t i = 0; i < limit; i++)
        REQUIRE(monitor(i, conn(1)).at("success") == 1);
    auto refused = monitor(limit, conn(1));
    CHECK(refused.at("errcode") == 8);
    CHECK(refused.at("error") == "Too many monitors in this session (at most 64)");
    // Renewing one it has is fine.
    CHECK(monitor(0, conn(1)).at("success") == 1);
    CHECK(mq.monitoring_.size() == limit);

    // A privileged session has no such limit, nor a connection without one.
    privileged_session(mq, conn(2));
    for (size_t i = 0; i <= limit; i++)
        CHECK(monitor(i, conn(2)).at("success") == 1);
    for (size_t i = 0; i <= limit; i++)
        CHECK(monitor(i, conn(3)).at("success") == 1);
}

TEST_CASE(
        "monitor session - nothing missed is discarded, however much",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    mq.connection_closed(conn(1));
    for (size_t i = 1; i <= 1000; i++)
        store(mq, a, "h{}"_format(i));
    CHECK(mq.missed_pairs() == 1);

    session_request(mq, conn(2), token);
    auto got = notified_hashes(mq, conn(2));
    REQUIRE(got.size() == 1000);
    CHECK(got.front() == "h1");
    CHECK(got.back() == "h1000");
}
TEST_CASE(
        "monitor session - the sweep detaches a session from a connection gone unnoticed",
        "[monitor][session]") {
    TestMQ mq;
    auto a = account(0x11), b = account(0x22);

    // Connection 5 closed so long before its monitor_session was handled that the record of its
    // closing is gone, so the request binds a session to it.
    mq.connection_closed(conn(5));
    for (auto& [c, when] : mq.closed_conns_)
        when -= 2min;
    mq.remove_expired();
    REQUIRE(mq.closed_conns_.empty());
    auto token = token_of(session_request(mq, conn(5)));
    subscribe(mq, a, conn(5));
    // Likewise a connection's own monitor.
    subscribe(mq, b, conn(6));
    CHECK(notifiers(mq, a) == std::vector{conn(5)});

    // Still bound while the transport has the connection...
    mq.remove_expired();
    CHECK(notifiers(mq, a) == std::vector{conn(5)});
    CHECK(mq.sessions_.at(token)->conn);

    // ... but once it is gone the sweep treats it as closed: the session is detached (recording,
    // and with its lifetime running) and the connection's own monitor removed.
    mq.dead = {conn(5), conn(6)};
    mq.remove_expired();
    CHECK_FALSE(mq.sessions_.at(token)->conn);
    CHECK(mq.sessions_.at(token)->detached_since);
    CHECK(notifiers(mq, b).empty());
    store(mq, a, "missed");
    CHECK(mq.missed_pairs() == 1);
    auto r = session_request(mq, conn(7), token);
    CHECK(r.at("r") == 1);
    CHECK(notified_hashes(mq, conn(7)) == std::vector<std::string>{"missed"});
}

TEST_CASE(
        "monitor session - notifications sent just before a connection is lost are replayed",
        "[monitor][session][missed]") {
    constexpr auto WINDOW = oxenss::server::Monitors::RECENT_WINDOW;
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    store(mq, a, "long ago");
    mq.age_recent(WINDOW + 1s);
    store(mq, a, "lately");
    mq.age_recent(WINDOW - 10s);
    store(mq, a, "just now");
    mq.pushed.clear();

    // The sweep prunes what is past the window, which would have been noticed lost by now...
    mq.remove_expired();
    CHECK(mq.sessions_.at(token)->recent.size() == 2);

    // ... and the rest is replayed after the connection goes, as it may have been dead already.
    mq.connection_closed(conn(1));
    CHECK(mq.missed_pairs() == 1);
    store(mq, a, "while away");
    session_request(mq, conn(2), token);
    CHECK(notified_hashes(mq, conn(2)) ==
          std::vector<std::string>{"lately", "just now", "while away"});
}

TEST_CASE(
        "monitor session - a resume elsewhere replays what the old connection was sent lately",
        "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);

    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    store(mq, a, "sent on 1");
    mq.pushed.clear();

    // The subscriber resumes on another connection while the old one still looks open: it would
    // not, were the old one working, so what went out on it is replayed.
    session_request(mq, conn(2), token);
    CHECK(notified_hashes(mq, conn(2)) == std::vector<std::string>{"sent on 1"});
    CHECK(notifiers(mq, a) == std::vector{conn(2)});
}

TEST_CASE(
        "monitor session - a resume looks nothing up in the swarm without ended monitors",
        "[monitor][session]") {
    TestMQ mq;
    auto token = token_of(session_request(mq, conn(1)));
    for (unsigned char i = 0; i < 50; i++)
        subscribe(mq, account(0x40 + i), conn(1));
    mq.connection_closed(conn(1));

    mq.swarm_lookups = 0;
    auto r = session_with(mq, conn(2), {{"l", 0}, {"t", token}});
    CHECK(r.at("r") == 1);
    CHECK(r.at("s").empty());
    CHECK(mq.swarm_lookups == 0);
}

TEST_CASE("monitor - the sweep is paced, and one at a time", "[monitor]") {
    TestMQ mq;
    mq.manual_later = true;
    // More accounts than a step covers buckets of the table.
    const size_t n = oxenss::server::Monitors::PASS_BATCH + 1000;
    for (size_t i = 0; i < n; i++) {
        auto acct = account(0x11);
        std::memcpy(acct.data() + 1, &i, sizeof(i));
        subscribe(mq, acct, conn(1));
    }
    REQUIRE(mq.monitoring_.size() == n);
    expire_all(mq);

    mq.remove_expired();
    // The first step sweeps part of the table, leaving the rest to a queued step.
    CHECK(mq.monitoring_.size() > 0);
    CHECK(mq.monitoring_.size() < n);
    REQUIRE(mq.later.size() == 1);
    // A sweep started meanwhile does nothing.
    mq.remove_expired();
    CHECK(mq.later.size() == 1);

    mq.run_later_queue();
    CHECK(mq.monitoring_.empty());
    CHECK(mq.monitoring_conns_.empty());

    // Once it is done another can start.
    subscribe(mq, account(0x11), conn(1));
    expire_all(mq);
    mq.remove_expired();
    mq.run_later_queue();
    CHECK(mq.monitoring_.empty());
}

TEST_CASE("replay owners - only the newest replay paces a connection", "[monitor]") {
    oxenss::server::replay_owners<int> owners;

    // Replay 1 paces connection 7, and finishing turns its pacing off.
    CHECK(owners.claim(7, 1));
    CHECK(owners.claim(7, 1));
    CHECK(owners.release(7, 1));
    CHECK_FALSE(owners.release(7, 1));

    // Replay 3 starts while replay 2 is still going: 2 is superseded, and its chunks and its end
    // touch nothing of 3's.
    CHECK(owners.claim(7, 2));
    CHECK(owners.claim(7, 3));
    CHECK_FALSE(owners.claim(7, 2));
    CHECK_FALSE(owners.release(7, 2));
    CHECK(owners.claim(7, 3));
    CHECK(owners.release(7, 3));
    // Even after 3 is done, 2 stays superseded.
    CHECK_FALSE(owners.claim(7, 2));

    // Connections are independent, and a forgotten one starts afresh.
    CHECK(owners.claim(8, 2));
    owners.forget(7);
    CHECK(owners.claim(7, 2));
}

TEST_CASE("monitor session - each replay has its own increasing id", "[monitor][session][missed]") {
    TestMQ mq;
    auto a = account(0x11);
    auto token = token_of(session_request(mq, conn(1)));
    subscribe(mq, a, conn(1));
    mq.connection_closed(conn(1));
    store(mq, a, "one");
    auto r = session_request(mq, conn(2), token);
    REQUIRE_FALSE(mq.replays.empty());
    auto first = mq.replays.back();
    mq.connection_closed(conn(2));
    store(mq, a, "two");
    session_request(mq, conn(3), token_of(r));
    CHECK(mq.replays.back() > first);
    CHECK(std::ranges::is_sorted(mq.replays));
}
TEST_CASE("monitor session - detached unprivileged monitors are capped", "[monitor][session]") {
    TestMQ mq;
    mq.limits_.detached_monitors = 5;
    auto with_monitors = [&](connection_id c, unsigned char first, int n, bool privileged = false) {
        auto token = token_of(privileged ? privileged_session(mq, c) : session_request(mq, c));
        for (int i = 0; i < n; i++)
            subscribe(mq, account(first + i), c);
        return token;
    };

    auto priv = with_monitors(conn(1), 0x10, 4, true);
    auto u1 = with_monitors(conn(2), 0x20, 2);
    auto u2 = with_monitors(conn(3), 0x30, 2);
    auto u3 = with_monitors(conn(4), 0x40, 2);
    mq.connection_closed(conn(1));
    mq.connection_closed(conn(2));
    mq.connection_closed(conn(3));
    mq.age_session(priv, 3min);
    mq.age_session(u1, 2min);
    mq.age_session(u2, 1min);
    // Bound sessions, and privileged ones, are not counted.
    CHECK(mq.detached_monitors_ == 4);

    SECTION("detaching past the limit removes the longest-detached unprivileged session whole") {
        mq.connection_closed(conn(4));  // 6
        CHECK_FALSE(mq.sessions_.contains(u1));
        CHECK(mq.sessions_.contains(u2));
        CHECK(mq.sessions_.contains(u3));
        CHECK(mq.sessions_.contains(priv));
        CHECK(mq.detached_monitors_ == 4);
        CHECK(notifiers(mq, account(0x20)).empty());
        CHECK(session_request(mq, conn(5), u1).at("r") == 0);
    }
    SECTION("resuming, and an account moving swarm, bring the count down") {
        CHECK(session_request(mq, conn(5), u2).at("r") == 1);
        CHECK(mq.detached_monitors_ == 2);
        mq.elsewhere[account(0x20)] = 0x2000;
        mq.drop_foreign_monitors();
        CHECK(mq.detached_monitors_ == 1);
        mq.connection_closed(conn(4));  // 3: within the limit
        CHECK(mq.sessions_.contains(u1));
        CHECK(mq.sessions_.contains(u3));
    }
}

TEST_CASE(
        "monitor session - a resume is never cut by the detachment it causes",
        "[monitor][session]") {
    TestMQ mq;
    mq.limits_.detached_monitors = 3;

    // x, detached the longest, and z are within the limit between them...
    auto x = token_of(session_request(mq, conn(1)));
    subscribe(mq, account(0x11), conn(1));
    subscribe(mq, account(0x12), conn(1));
    auto z = token_of(session_request(mq, conn(2)));
    subscribe(mq, account(0x21), conn(2));
    mq.connection_closed(conn(1));
    mq.connection_closed(conn(2));
    mq.age_session(x, 1min);
    // ... and y is bound to the connection x is resumed on, so is detached by it.
    session_request(mq, conn(3));
    subscribe(mq, account(0x31), conn(3));
    subscribe(mq, account(0x32), conn(3));
    REQUIRE(mq.detached_monitors_ == 3);

    // Were x still counted as detached, y's two would put it over and x would go first.
    auto r = session_request(mq, conn(3), x);
    CHECK(r.at("r") == 1);
    CHECK(r.at("s").size() == 2);
    CHECK(notifiers(mq, account(0x11)) == std::vector{conn(3)});
    CHECK(mq.detached_monitors_ == 3);
    CHECK(mq.sessions_.contains(z));
}

TEST_CASE(
        "monitor session - each IP has a limited number of unprivileged sessions",
        "[monitor][session]") {
    TestMQ mq;
    mq.limits_.sessions_per_ip = 3;
    const std::string A = "fd00::a", B = "fd00::b";
    auto from = [&](connection_id c, const std::string& ip, std::string_view key = "") {
        std::string reply;
        mq.handle_monitor_session(
                "de", c, [&reply](std::string r) { reply = std::move(r); }, key, ip);
        return oxenss::bt_to_json(oxenc::bt_dict_consumer{reply});
    };

    auto a1 = token_of(from(conn(1), A));
    auto a2 = token_of(from(conn(2), A));
    auto a3 = token_of(from(conn(3), A));
    auto b1 = token_of(from(conn(10), B));
    mq.connection_closed(conn(1));
    mq.connection_closed(conn(2));
    mq.connection_closed(conn(10));
    mq.age_session(b1, 5min);  // detached longest of all, but not A's to give up
    mq.age_session(a1, 2min);
    mq.age_session(a2, 1min);

    // A fourth from A displaces A's own session detached the longest, then the next.
    auto a4 = token_of(from(conn(4), A));
    CHECK_FALSE(mq.sessions_.contains(a1));
    CHECK(mq.sessions_.contains(a2));
    CHECK(mq.sessions_.contains(b1));
    auto a5 = token_of(from(conn(5), A));
    CHECK_FALSE(mq.sessions_.contains(a2));
    CHECK(mq.sessions_.contains(b1));

    // With all of A's sessions bound, another is refused.
    auto refused = from(conn(6), A);
    CHECK(refused.at("errcode") == 9);
    CHECK_FALSE(refused.contains("t"));
    CHECK(mq.sessions_.size() == 4);

    // Neither another address, nor privileged sessions from A, are affected; nor is resuming.
    CHECK(from(conn(11), B).contains("t"));
    CHECK(from(conn(7), A, TestMQ::PRIVILEGED_KEY).contains("t"));
    mq.connection_closed(conn(3));
    std::string reply;
    oxenc::bt_dict_producer req;
    req.append("t", a3);
    mq.handle_monitor_session(
            std::move(req).str(),
            conn(8),
            [&reply](std::string r) { reply = std::move(r); },
            "",
            A);
    CHECK(oxenss::bt_to_json(oxenc::bt_dict_consumer{reply}).at("r") == 1);
    CHECK(mq.sessions_.contains(a4));
    CHECK(mq.sessions_.contains(a5));
}

TEST_CASE(
        "monitor session - the push server's key is built in on mainnet only",
        "[monitor][session]") {
    using oxenss::server::default_privileged_keys;
    const auto key = oxenc::from_hex(oxenss::server::MAINNET_PUSH_SERVER_KEY);
    REQUIRE(key.size() == 32);
    CHECK(default_privileged_keys(true) == std::unordered_set{key});
    CHECK(default_privileged_keys(false).empty());

    // So on mainnet a session made with that key is privileged.
    TestMQ mq{default_privileged_keys(true)};
    auto token = token_of(session_request(mq, conn(1), "", key));
    CHECK(mq.sessions_.at(token)->privileged);
}
