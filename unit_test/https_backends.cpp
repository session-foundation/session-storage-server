// End-to-end tests of the HTTPS listener, run against every backend compiled in.  The point is
// parity: the same requests must produce the same status, headers and bodies whichever library is
// underneath, so that switching backends at runtime is invisible to clients.

#include <catch2/catch.hpp>

#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/rate_limiter.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/server/https.h>
#include <oxenss/server/omq.h>
#include <oxenss/server/server_certificates.h>
#include <oxenss/snode/service_node.h>
#include <oxenss/version.h>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <oxenc/base64.h>
#include <sodium.h>

#include <filesystem>
#include <random>
#include <string>
#include <thread>

using namespace oxenss;
using namespace std::literals;

namespace {

struct temp_dir {
    std::filesystem::path path;
    temp_dir() :
            path{std::filesystem::temp_directory_path() /
                 ("oxenss-https-test-" + std::to_string(std::random_device{}()))} {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~temp_dir() { std::filesystem::remove_all(path); }
};

struct test_keys {
    crypto::legacy_keypair legacy;
    crypto::ed25519_keypair ed25519;
    crypto::x25519_keypair x25519;

    test_keys() {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);
        std::string_view sk_view{reinterpret_cast<const char*>(sk), sizeof(sk)};
        // A legacy key is the 32-byte seed half of an ed25519 secret key.
        legacy = crypto::legacy_keypair::from_secret_bytes(sk_view.substr(0, 32));
        ed25519 = crypto::ed25519_keypair::from_secret_bytes(sk_view);
        unsigned char xsk[crypto_scalarmult_curve25519_BYTES];
        crypto_sign_ed25519_sk_to_curve25519(xsk, sk);
        x25519 = crypto::x25519_keypair::from_secret_bytes(
                {reinterpret_cast<const char*>(xsk), sizeof(xsk)});
    }
};

// Everything an HTTPS listener needs, wired up the way the daemon does it but with no oxend: the
// OxenMQ instance is started bare (so that inject_task() has worker threads) rather than through
// OMQ::init(), and force_start makes snode_ready() true.
struct test_node {
    temp_dir dir;
    test_keys keys;
    server::OMQ omq;
    snode::ServiceNode sn;
    crypto::ChannelEncryption ce;
    rpc::RequestHandler rh;
    rpc::RateLimiter rl;
    std::unique_ptr<server::HTTPS> https;
    uint16_t port;

    explicit test_node(server::HttpsBackend backend) :
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
               /*force_start=*/true,
               /*skip_bootstrap=*/true},
            ce{keys.x25519},
            rh{sn, ce, keys.ed25519.sec},
            rl{*omq} {
        auto cert = dir.path / "cert.pem", key = dir.path / "key.pem";
        generate_cert(cert, key);
        https = server::make_https(
                backend, sn, rh, rl, {{"127.0.0.1", 0, true}}, cert, key, keys.legacy);
        (*omq).start();
        https->start();
        port = https->listening_ports().at(0);
    }

    ~test_node() { https->shutdown(true); }

    std::string url(std::string_view path) const {
        return "https://127.0.0.1:" + std::to_string(port) + std::string{path};
    }
};

// Our certificate is self-signed and not something a client can verify (see server_certificates);
// real clients turn verification off the same way.
const cpr::SslOptions no_verify =
        cpr::Ssl(cpr::ssl::VerifyHost{false}, cpr::ssl::VerifyPeer{false});

cpr::Response post(
        const test_node& node,
        std::string_view path,
        std::string body = "",
        cpr::Header headers = {}) {
    return cpr::Post(
            cpr::Url{node.url(path)}, cpr::Body{std::move(body)}, std::move(headers), no_verify);
}

cpr::Response get(const test_node& node, std::string_view path) {
    return cpr::Get(cpr::Url{node.url(path)}, no_verify);
}

const std::string info_request = R"({"method":"info","params":{}})";

}  // namespace

TEST_CASE("https backends", "[https]") {
    for (auto backend : server::available_https_backends()) {
        DYNAMIC_SECTION("backend " << to_string(backend)) {
            test_node node{backend};
            REQUIRE(node.port != 0);

            SECTION("ping") {
                auto r = post(node, "/ping_test/v1");
                CHECK(r.status_code == 200);
                CHECK(r.status_line == "HTTP/1.1 200 OK");
                CHECK(r.header["X-Oxen-Snode-Pubkey"] ==
                      oxenc::to_base64(node.keys.legacy.pub.view()));
                CHECK(r.header["Server"] ==
                      "Oxen Storage Server/" + std::string{STORAGE_SERVER_VERSION_STRING});
                CHECK(r.header["Content-Type"] == "text/plain");
                CHECK(r.text.empty());
            }

            SECTION("deprecated stats endpoint") {
                auto r = get(node, "/get_stats/v1");
                CHECK(r.status_code == 200);
                CHECK(r.header["Content-Type"] == "application/json");
                auto j = nlohmann::json::parse(r.text);
                CHECK(j["version"] == STORAGE_SERVER_VERSION_STRING);
            }

            SECTION("unknown routes") {
                auto r = get(node, "/nope");
                CHECK(r.status_code == 404);
                CHECK(r.status_line == "HTTP/1.1 404 Not Found");
                CHECK(r.header["Content-Type"] == "text/plain");
                CHECK(r.text == "GET /nope Not Found");

                // Right path, wrong method:
                r = get(node, "/storage_rpc/v1");
                CHECK(r.status_code == 404);
                CHECK(r.text == "GET /storage_rpc/v1 Not Found");
            }

            SECTION("storage rpc round trip through OMQ") {
                auto r = post(node, "/storage_rpc/v1", info_request);
                CHECK(r.status_code == 200);
                CHECK(r.header["Content-Type"] == "application/json");
                auto j = nlohmann::json::parse(r.text);
                CHECK(j.count("version"));
            }

            SECTION("obsolete long-poll header") {
                auto r = post(node, "/storage_rpc/v1", info_request, {{"X-Loki-Long-Poll", "1"}});
                CHECK(r.status_code == 410);
            }

            SECTION("onion request that does not parse") {
                auto r = post(node, "/onion_req/v2", "this is not an onion request");
                CHECK(r.status_code == 400);
                CHECK(r.text.starts_with("Error parsing onion request"));
            }

            SECTION("body size limit applies to chunked uploads") {
                // No Content-Length for the pre-body check to see, so this exercises the
                // running-total enforcement while the body streams in.
                std::string big(server::MAX_REQUEST_BODY_SIZE + 1, 'x');
                auto r = post(
                        node, "/onion_req/v2", std::move(big), {{"Transfer-Encoding", "chunked"}});
                CHECK(r.status_code == 413);
            }

            SECTION("keep-alive") {
                cpr::Session s;
                s.SetUrl(cpr::Url{node.url("/storage_rpc/v1")});
                s.SetSslOptions(no_verify);
                s.SetBody(cpr::Body{info_request});
                for (int i = 0; i < 3; i++) {
                    auto r = s.Post();
                    CHECK(r.status_code == 200);
                    CHECK(r.header["Connection"] != "close");
                }
            }

            SECTION("concurrent requests") {
                constexpr int threads = 8, per_thread = 10;
                std::atomic<int> ok{0}, total{0};
                std::vector<std::thread> pool;
                for (int t = 0; t < threads; t++)
                    pool.emplace_back([&] {
                        for (int i = 0; i < per_thread; i++) {
                            auto r = post(node, "/storage_rpc/v1", info_request);
                            total++;
                            if (r.status_code == 200)
                                ok++;
                        }
                    });
                for (auto& t : pool)
                    t.join();
                CHECK(total == threads * per_thread);
                CHECK(ok == threads * per_thread);
            }
        }
    }
}
