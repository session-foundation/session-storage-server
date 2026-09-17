#include <catch2/catch.hpp>

#include <oxenss/server/server_certificates.h>

#include <uWebSockets/App.h>

#include <filesystem>
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
}
