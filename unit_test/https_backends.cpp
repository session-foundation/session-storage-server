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

#include <oxenss/common/format.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#if defined(OXENSS_HTTPS_MICROHTTPD) && defined(__linux__)
#include <gnutls/gnutls.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <fstream>
#include <optional>
#include <sstream>
#endif

using namespace oxenss;
using namespace std::literals;

namespace {

struct temp_dir {
    std::filesystem::path path;
    temp_dir() :
            path{std::filesystem::temp_directory_path() /
                 "oxenss-https-test-{}"_format(std::random_device{}())} {
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
        return "https://127.0.0.1:{}{}"_format(port, path);
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
                // An immediate reply (no body read) must not cost the client its connection.
                CHECK(r.header["Connection"] != "close");
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

#if defined(OXENSS_HTTPS_MICROHTTPD) && defined(__linux__)

namespace {

// CPU time consumed so far, in milliseconds, by the thread of this process named `name`.
std::optional<long> thread_cpu_ms(std::string_view name) {
    for (const auto& task : std::filesystem::directory_iterator{"/proc/self/task"}) {
        std::string comm;
        std::getline(std::ifstream{task.path() / "comm"}, comm);
        if (comm != name)
            continue;
        std::string stat;
        std::getline(std::ifstream{task.path() / "stat"}, stat);
        // The fields after the parenthesised name are whitespace separated, starting at field 3;
        // utime and stime are fields 14 and 15.
        std::istringstream fields{stat.substr(stat.rfind(')') + 2)};
        std::string tok;
        long ticks = 0;
        for (int field = 3; fields >> tok && field <= 15; field++)
            if (field >= 14)
                ticks += std::stol(tok);
        return ticks * 1000 / sysconf(_SC_CLK_TCK);
    }
    return std::nullopt;
}

}  // namespace

// libmicrohttpd's epoll mode left a connection whose TLS handshake was waiting on the client on
// its ready list, so it polled with a zero timeout and re-ran the handshake continuously until
// the client's next flight arrived; a client that never finished kept it spinning until the
// connection timeout.  session-deps carries a patch for it; this makes sure it stays fixed.
TEST_CASE("https backend - a stalled TLS handshake does not spin libmicrohttpd", "[https]") {
    test_node node{server::HttpsBackend::microhttpd};

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);

    // Send the ClientHello and then never send anything else: the server answers with its flight
    // and is left waiting for our Finished.
    gnutls_certificate_credentials_t cred;
    REQUIRE(gnutls_certificate_allocate_credentials(&cred) == 0);
    gnutls_session_t session;
    REQUIRE(gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NONBLOCK) == 0);
    REQUIRE(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred) == 0);
    REQUIRE(gnutls_set_default_priority(session) == 0);
    gnutls_transport_set_int(session, fd);
    REQUIRE(gnutls_handshake(session) == GNUTLS_E_AGAIN);
    std::this_thread::sleep_for(200ms);

    auto before = thread_cpu_ms("MHD-single");
    REQUIRE(before);
    std::this_thread::sleep_for(500ms);
    auto after = thread_cpu_ms("MHD-single");
    REQUIRE(after);
    // Waiting on the client costs nothing; the spin burns the whole interval.
    CHECK(*after - *before < 50);

    gnutls_deinit(session);
    gnutls_certificate_free_credentials(cred);
    close(fd);
}

#endif

// Throughput/latency comparison of the backends on loopback.  Everything but the HTTP/TLS layer
// is identical between them, so this isolates exactly the thing the runtime switch changes.
// Hidden from normal runs; invoke with:  ./Test "[https-bench]"
TEST_CASE("https backend benchmark", "[.][https-bench]") {
    using clock = std::chrono::steady_clock;
    using namespace std::chrono;

    struct scenario {
        const char* name;
        std::string_view path;
        std::string body;
        int threads;
        int requests;    // total, split across threads
        bool keepalive;  // one connection per thread, or a fresh TLS handshake per request
    };
    const std::vector<scenario> scenarios{
            {"ping, keep-alive, 1 thread", "/ping_test/v1", "", 1, 2000, true},
            {"ping, keep-alive, 16 threads", "/ping_test/v1", "", 16, 8000, true},
            {"info via OMQ, keep-alive, 16 threads",
             "/storage_rpc/v1",
             info_request,
             16,
             8000,
             true},
            {"ping, new connection each, 8 threads", "/ping_test/v1", "", 8, 800, false},
    };

    fmt::print(
            stderr,
            "\n{:<40} {:>12} {:>10} {:>10} {:>10}\n",
            "scenario",
            "backend",
            "req/s",
            "p50 ms",
            "p99 ms");

    for (auto backend : server::available_https_backends()) {
        test_node node{backend};
        // Everything comes from 127.0.0.1, which the per-IP limiter would otherwise cut off.
        node.rl.set_client_limiting(false);
        for (const auto& sc : scenarios) {
            std::mutex mu;
            std::vector<double> latencies;
            latencies.reserve(sc.requests);
            std::atomic<int> failures{0};
            const int per_thread = sc.requests / sc.threads;

            auto worker = [&] {
                std::vector<double> mine;
                mine.reserve(per_thread);
                std::optional<cpr::Session> session;
                if (sc.keepalive) {
                    session.emplace();
                    session->SetUrl(cpr::Url{node.url(sc.path)});
                    session->SetSslOptions(no_verify);
                    session->SetBody(cpr::Body{sc.body});
                }
                for (int i = 0; i < per_thread; i++) {
                    auto t0 = clock::now();
                    auto r = session ? session->Post() : post(node, sc.path, sc.body);
                    mine.push_back(duration<double, std::milli>(clock::now() - t0).count());
                    if (r.status_code != 200)
                        failures++;
                }
                std::lock_guard lock{mu};
                latencies.insert(latencies.end(), mine.begin(), mine.end());
            };

            auto start = clock::now();
            std::vector<std::thread> pool;
            for (int t = 0; t < sc.threads; t++)
                pool.emplace_back(worker);
            for (auto& t : pool)
                t.join();
            auto elapsed = duration<double>(clock::now() - start).count();

            std::ranges::sort(latencies);
            auto pct = [&](double p) {
                return latencies[std::min(latencies.size() - 1, size_t(p * latencies.size()))];
            };
            fmt::print(
                    stderr,
                    "{:<40} {:>12} {:>10.0f} {:>10.2f} {:>10.2f}{}\n",
                    sc.name,
                    to_string(backend),
                    latencies.size() / elapsed,
                    pct(0.50),
                    pct(0.99),
                    failures ? fmt::format("   ({} failed!)", failures.load()) : "");
            CHECK(failures == 0);
        }
    }
}
