#include <catch2/catch.hpp>

#include <oxenss/server/server_certificates.h>

#ifdef OXENSS_HTTPS_UWEBSOCKETS
#include <uWebSockets/App.h>
#endif
#ifdef OXENSS_HTTPS_MICROHTTPD
#include <microhttpd.h>
#endif

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

using namespace oxenss;

namespace {

// Somewhere to put generated certificates that goes away again when the test finishes.
struct temp_dir {
    std::filesystem::path path;
    temp_dir() :
            path{std::filesystem::temp_directory_path() /
                 ("oxenss-cert-test-" + std::to_string(std::random_device{}()))} {
        std::filesystem::remove_all(path);
        std::filesystem::create_directories(path);
    }
    ~temp_dir() { std::filesystem::remove_all(path); }
};

#ifdef OXENSS_HTTPS_MICROHTTPD
std::string slurp(const std::filesystem::path& p) {
    std::ifstream f{p, std::ios::binary};
    return {std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{}};
}

// Starts (and immediately stops) a TLS daemon on an ephemeral port with the given PEMs, returning
// whether libmicrohttpd accepted them.  This is the same call the https server makes.
bool mhd_accepts(const std::string& key_pem, const std::string& cert_pem) {
    auto handler = [](void*,
                      MHD_Connection*,
                      const char*,
                      const char*,
                      const char*,
                      const char*,
                      size_t*,
                      void**) -> MHD_Result { return MHD_NO; };
    MHD_OptionItem opts[] = {
            {MHD_OPTION_HTTPS_MEM_KEY, 0, const_cast<char*>(key_pem.c_str())},
            {MHD_OPTION_HTTPS_MEM_CERT, 0, const_cast<char*>(cert_pem.c_str())},
            {MHD_OPTION_END, 0, nullptr},
    };
    auto* d = MHD_start_daemon(
            MHD_USE_AUTO_INTERNAL_THREAD | MHD_USE_TLS,
            0,
            nullptr,
            nullptr,
            +handler,
            nullptr,
            MHD_OPTION_ARRAY,
            opts,
            MHD_OPTION_END);
    if (!d)
        return false;
    MHD_stop_daemon(d);
    return true;
}
#endif

}  // namespace

TEST_CASE("certificate generation", "[certs]") {
    temp_dir dir;
    auto cert = dir.path / "cert.pem";
    auto key = dir.path / "key.pem";

    generate_cert(cert, key);

    REQUIRE(std::filesystem::exists(cert));
    REQUIRE(std::filesystem::exists(key));

    // The private key must not be readable by anyone else.
    using std::filesystem::perms;
    auto key_perms = std::filesystem::status(key).permissions();
    CHECK((key_perms & (perms::group_all | perms::others_all)) == perms::none);

#ifdef OXENSS_HTTPS_UWEBSOCKETS
    SECTION("openssl accepts what gnutls wrote") {
        // The certificates are written by gnutls but parsed by OpenSSL inside uSockets, so the
        // thing worth testing is that round trip rather than that gnutls can read its own output.
        // Constructing an SSLApp is exactly what the https server does.
        auto cert_s = cert.string(), key_s = key.string();
        uWS::SSLApp app{{.key_file_name = key_s.c_str(), .cert_file_name = cert_s.c_str()}};
        CHECK_FALSE(app.constructorFailed());
    }

    SECTION("a mismatched key is rejected") {
        // Guards against the above passing for some reason other than the files being valid.
        auto other_cert = dir.path / "other-cert.pem";
        auto other_key = dir.path / "other-key.pem";
        generate_cert(other_cert, other_key);

        auto cert_s = cert.string(), key_s = other_key.string();
        uWS::SSLApp app{{.key_file_name = key_s.c_str(), .cert_file_name = cert_s.c_str()}};
        CHECK(app.constructorFailed());
    }
#endif

#ifdef OXENSS_HTTPS_MICROHTTPD
    SECTION("libmicrohttpd accepts what gnutls wrote") {
        CHECK(mhd_accepts(slurp(key), slurp(cert)));
    }

    SECTION("libmicrohttpd rejects a mismatched key") {
        auto other_cert = dir.path / "other-cert.pem";
        auto other_key = dir.path / "other-key.pem";
        generate_cert(other_cert, other_key);
        CHECK_FALSE(mhd_accepts(slurp(other_key), slurp(cert)));
    }
#endif
}
