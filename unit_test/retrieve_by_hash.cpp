#include <catch2/catch.hpp>

#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/omq.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/storage/database.hpp>
#include <oxenss/utils/time.hpp>
#include <oxenss/version.h>
#include <oxenss/common/format.h>

#include <nlohmann/json.hpp>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium.h>

#include <filesystem>
#include <random>

using namespace oxenss;
using namespace std::literals;
using json = nlohmann::json;

namespace {

struct temp_dir {
    std::filesystem::path path;
    temp_dir() :
            path{std::filesystem::temp_directory_path() /
                 "oxenss-rbh-test-{}"_format(std::random_device{}())} {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~temp_dir() { std::filesystem::remove_all(path); }
};

struct node_keys {
    crypto::legacy_keypair legacy;
    crypto::ed25519_keypair ed25519;
    crypto::x25519_keypair x25519;
    node_keys() {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);
        std::string_view sk_view{reinterpret_cast<const char*>(sk), sizeof(sk)};
        legacy = crypto::legacy_keypair::from_secret_bytes(sk_view.substr(0, 32));
        ed25519 = crypto::ed25519_keypair::from_secret_bytes(sk_view);
        unsigned char xsk[crypto_scalarmult_curve25519_BYTES];
        crypto_sign_ed25519_sk_to_curve25519(xsk, sk);
        x25519 = crypto::x25519_keypair::from_secret_bytes(
                {reinterpret_cast<const char*>(xsk), sizeof(xsk)});
    }
};

struct test_node {
    temp_dir dir;
    node_keys keys;
    server::OMQ omq;
    snode::ServiceNode sn;
    crypto::ChannelEncryption ce;
    rpc::RequestHandler rh;

    test_node() :
            omq{keys.x25519, {}},
            sn{keys.legacy,
               snode::contact{
                       oxen::quic::ipv4{127, 0, 0, 1},
                       1,
                       2,
                       STORAGE_SERVER_VERSION,
                       keys.ed25519.pub,
                       keys.x25519.pub},
               omq,
               dir.path,
               0ms,
               true,
               true},
            ce{keys.x25519},
            rh{sn, ce, keys.ed25519.sec} {
        // A handler serves only accounts of its own swarm, and ServiceNode's swarm is otherwise
        // set only from oxend.  One swarm covers every account.  The const_cast is well defined:
        // the Swarm is a non-const member, and swarm() is the only accessor.
        snode::swarms_t swarms;
        swarms[1000].insert(keys.legacy.pub);
        const_cast<snode::Swarm&>(sn.swarm()).update_swarms(1, std::move(swarms), {});
    }
};

// A 03-prefixed account, whose signatures verify against the pubkey itself.
struct account {
    std::array<unsigned char, 32> pk;
    std::array<unsigned char, 64> sk;
    user_pubkey upk;
    std::string hex;
    account() {
        crypto_sign_keypair(pk.data(), sk.data());
        hex = "03" + oxenc::to_hex(pk.begin(), pk.end());
        REQUIRE(upk.load(hex));
    }
    std::string sign(std::string_view msg) const {
        std::array<unsigned char, 64> sig;
        crypto_sign_detached(
                sig.data(),
                nullptr,
                reinterpret_cast<const unsigned char*>(msg.data()),
                msg.size(),
                sk.data());
        return std::string{reinterpret_cast<const char*>(sig.data()), sig.size()};
    }
};

std::pair<int, json> call(test_node& n, const json& params) {
    std::optional<rpc::Response> got;
    n.rh.process_client_req(
            "retrieve_by_hash"sv, params, [&](rpc::Response r) { got = std::move(r); });
    REQUIRE(got);
    json body;
    if (auto* j = std::get_if<json>(&got->body))
        body = *j;
    else if (auto* s = std::get_if<std::string>(&got->body))
        body = *s;
    else if (auto* sv = std::get_if<std::string_view>(&got->body))
        body = std::string{*sv};
    return {got->status.first, body};
}

std::string store(
        test_node& n,
        const user_pubkey& pk,
        namespace_id hash_ns,
        namespace_id stored_ns,
        std::string data,
        std::chrono::system_clock::time_point now) {
    auto hash = rpc::computeMessageHash(pk, hash_ns, data);
    REQUIRE(n.sn.db->store({pk, hash, stored_ns, now, now + 1h, std::move(data)}) ==
            StoreResult::New);
    return hash;
}

json signed_req(
        const account& a,
        int ns,
        std::vector<std::string> hashes,
        std::optional<int64_t> ts = std::nullopt,
        std::string_view prefix = "") {
    auto t = ts.value_or(to_epoch_ms(std::chrono::system_clock::now()));
    std::string msg{"retrieve_by_hash"};
    if (ns != 0)
        msg += std::to_string(ns);
    msg += std::to_string(t);
    for (auto& h : hashes)
        msg += h;
    json p{{"pubkey", a.hex},
           {"messages", hashes},
           {"timestamp", static_cast<uint64_t>(t)},
           {"signature", oxenc::to_base64(a.sign(std::string{prefix} + msg))}};
    if (ns != 0)
        p["namespace"] = ns;
    return p;
}

}  // namespace

TEST_CASE("retrieve_by_hash handler", "[rpc][retrieve_by_hash]") {
    test_node node;
    account me, them;
    const auto now = std::chrono::system_clock::now();
    const auto ns0 = namespace_id::Default;
    const auto ns13 = namespace_id{13};
    const auto outbox = namespace_id{-21};

    auto m0a = store(node, me.upk, ns0, ns0, "zero a", now - 1s);
    auto m0b = store(node, me.upk, ns0, ns0, "zero b", now - 2s);
    auto m13 = store(node, me.upk, ns13, ns13, "thirteen", now - 3s);
    // Filed under the default namespace, as a sync from an old storage server leaves it
    auto misfiled = store(node, me.upk, ns13, ns0, "misfiled thirteen", now - 4s);
    auto pub = store(node, me.upk, outbox, outbox, "public", now - 5s);
    auto theirs = store(node, them.upk, ns0, ns0, "theirs", now);
    const std::string unknown(43, 'A');

    auto hashes_of = [](const json& body) {
        std::vector<std::string> h;
        for (auto& m : body["messages"])
            h.push_back(m["hash"].get<std::string>());
        return h;
    };

    SECTION("own messages found, in request order; unknown and other accounts' omitted") {
        auto [code, body] = call(node, signed_req(me, 0, {m0b, unknown, theirs, m0a}));
        REQUIRE(code == 200);
        CHECK(hashes_of(body) == std::vector{m0b, m0a});
        auto& first = body["messages"][0];
        CHECK(first["data"] == oxenc::to_base64("zero b"));
        CHECK(first["timestamp"] == to_epoch_ms(now - 2s));
        CHECK(first["expiration"] == to_epoch_ms(now - 2s + 1h));
        CHECK(first.size() == 4);
        CHECK(body.contains("t"));
        CHECK(body.contains("hf"));
        CHECK_FALSE(body.contains("more"));
    }

    SECTION("namespace must match, except for a misfiled copy whose hash proves its namespace") {
        // The misfiled copy is also found where it is filed; namespace 0 always needs the
        // account's full authentication, so this grants nothing new.
        auto [code, body] = call(node, signed_req(me, 0, {m13, misfiled, m0a}));
        REQUIRE(code == 200);
        CHECK(hashes_of(body) == std::vector{misfiled, m0a});

        // A namespace 13 copy is not returned to a request naming another namespace
        std::tie(code, body) = call(node, signed_req(me, 5, {m13, misfiled}));
        REQUIRE(code == 200);
        CHECK(body["messages"].empty());

        std::tie(code, body) = call(node, signed_req(me, 13, {m13, misfiled, m0a}));
        REQUIRE(code == 200);
        CHECK(hashes_of(body) == std::vector{m13, misfiled});
    }

    SECTION("over the cap is refused") {
        std::vector<std::string> many(21, unknown);
        auto [code, body] = call(node, signed_req(me, 0, many));
        CHECK(code == 400);
        CHECK(body.get<std::string>() ==
              "invalid request: too many message hashes: at most 20 may be requested at once");

        many.resize(20);
        std::tie(code, body) = call(node, signed_req(me, 0, many));
        CHECK(code == 200);
    }

    SECTION("bad signatures are refused") {
        // Signed by another account
        auto req = signed_req(me, 0, {m0a});
        req["signature"] = signed_req(them, 0, {m0a}, req["timestamp"].get<int64_t>())["signature"];
        auto [code, body] = call(node, req);
        CHECK(code == 401);
        CHECK(body.get<std::string>() == "retrieve_by_hash signature verification failed");

        // Signed for different hashes
        req = signed_req(me, 0, {m0b});
        req["messages"] = json::array({m0a});
        std::tie(code, body) = call(node, req);
        CHECK(code == 401);

        // Signed for another namespace
        req = signed_req(me, 13, {m13});
        req.erase("namespace");
        std::tie(code, body) = call(node, req);
        CHECK(code == 401);

        // Stale timestamp
        std::tie(code, body) = call(
                node,
                signed_req(me, 0, {m0a}, to_epoch_ms(std::chrono::system_clock::now() - 2min)));
        CHECK(code == 406);
    }

    SECTION("unsigned requests only for retrieve's no-auth namespaces") {
        auto [code, body] = call(node, json{{"pubkey", me.hex}, {"messages", {m0a}}});
        CHECK(code == 401);
        CHECK(body.get<std::string>() == "retrieve_by_hash: request signature required");

        std::tie(code, body) =
                call(node, json{{"pubkey", me.hex}, {"namespace", 13}, {"messages", {m13}}});
        CHECK(code == 401);

        // A public outbox may be read without a signature, but only its own messages
        std::tie(code, body) = call(
                node, json{{"pubkey", me.hex}, {"namespace", -21}, {"messages", {pub, m0a, m13}}});
        REQUIRE(code == 200);
        CHECK(hashes_of(body) == std::vector{pub});

        // The testing namespace is always empty
        std::tie(code, body) =
                call(node, json{{"pubkey", me.hex}, {"namespace", -3741}, {"messages", {m0a}}});
        REQUIRE(code == 200);
        CHECK(body["messages"].empty());
    }

    SECTION("malformed requests") {
        auto [code, body] = call(node, signed_req(me, 0, {}));
        CHECK(code == 400);
        std::tie(code, body) = call(node, signed_req(me, 0, {"not-a-hash"}));
        CHECK(code == 400);
        auto req = signed_req(me, 0, {m0a});
        req.erase("timestamp");
        std::tie(code, body) = call(node, req);
        CHECK(code == 400);
        CHECK(body.get<std::string>() == "invalid request: Required field 'timestamp' missing");
    }

    SECTION("bt-encoded requests carry raw data") {
        auto t = to_epoch_ms(std::chrono::system_clock::now());
        auto sig = me.sign("retrieve_by_hash13{}{}"_format(t, m13));
        oxenc::bt_dict d{
                {"messages", oxenc::bt_list{m13}},
                {"namespace", 13},
                {"pubkey",
                 std::string{static_cast<char>(3)} +
                         std::string{reinterpret_cast<const char*>(me.pk.data()), 32}},
                {"signature", sig},
                {"timestamp", static_cast<uint64_t>(t)}};
        auto encoded = oxenc::bt_serialize(d);
        std::optional<rpc::Response> got;
        rpc::RequestHandler::client_rpc_endpoints.at("retrieve_by_hash")
                .mq(node.rh, encoded, false, [&](rpc::Response r) { got = std::move(r); });
        REQUIRE(got);
        REQUIRE(got->status.first == 200);
        auto& body = std::get<json>(got->body);
        REQUIRE(body["messages"].size() == 1);
        CHECK(body["messages"][0]["data"] == "thirteen");
    }
}
