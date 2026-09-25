#include "server_certificates.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <oxenss/common/format.h>

#include <array>
#include <chrono>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <type_traits>

namespace oxenss {

namespace {

    void check(int rc, std::string_view what) {
        if (rc < 0)
            throw std::runtime_error{"{} failed: {}"_format(what, gnutls_strerror(rc))};
    }

    template <typename T>
    using gnutls_ptr = std::unique_ptr<std::remove_pointer_t<T>, void (*)(T)>;

    // The export2 calls allocate with gnutls_malloc, so the result needs gnutls_free rather than
    // delete.
    struct datum {
        gnutls_datum_t d{nullptr, 0};
        ~datum() { gnutls_free(d.data); }
        std::string_view view() const { return {reinterpret_cast<const char*>(d.data), d.size}; }
    };

    using std::filesystem::perms;

    constexpr auto secret_perms = perms::owner_read | perms::owner_write;
    constexpr auto public_perms = secret_perms | perms::group_read | perms::others_read;

    // Permissions are applied to the created-but-still-empty file, so that a private key is never
    // briefly on disk world-readable.
    void write_pem(const std::filesystem::path& path, std::string_view pem, perms mode) {
        std::ofstream out;
        out.exceptions(std::ios::failbit | std::ios::badbit);
        out.open(path, std::ios::binary | std::ios::trunc);
        std::filesystem::permissions(path, mode);
        out.write(pem.data(), pem.size());
    }

}  // namespace

void generate_cert(const std::filesystem::path& cert_path, const std::filesystem::path& key_path) {
    using namespace std::chrono;

    gnutls_x509_privkey_t key_raw{};
    check(gnutls_x509_privkey_init(&key_raw), "private key init");
    gnutls_ptr<gnutls_x509_privkey_t> key{key_raw, gnutls_x509_privkey_deinit};

    // P-256 rather than RSA because the server signs once per handshake and this certificate is
    // never verified by anyone: ECDSA signing is roughly 30x faster than RSA-2048 here, which is
    // the only property of it that matters to us.  It is also mandatory to implement for TLS 1.3
    // (RFC 8446 §9.1), so no client that can reach us can fail to handle it.
    check(gnutls_x509_privkey_generate(
                  key.get(), GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0),
          "private key generation");

    gnutls_x509_crt_t crt_raw{};
    check(gnutls_x509_crt_init(&crt_raw), "certificate init");
    gnutls_ptr<gnutls_x509_crt_t> crt{crt_raw, gnutls_x509_crt_deinit};

    // 3 here is the actual X.509 version, unlike OpenSSL's X509_set_version which takes 2 for a v3
    // certificate.
    check(gnutls_x509_crt_set_version(crt.get(), 3), "certificate version");

    constexpr unsigned char serial = 1;
    check(gnutls_x509_crt_set_serial(crt.get(), &serial, sizeof(serial)), "certificate serial");

    const auto now = system_clock::to_time_t(system_clock::now());
    check(gnutls_x509_crt_set_activation_time(crt.get(), now), "certificate activation time");
    check(gnutls_x509_crt_set_expiration_time(
                  crt.get(), now + duration_cast<seconds>(days{10000}).count()),
          "certificate expiration time");

    check(gnutls_x509_crt_set_key(crt.get(), key.get()), "certificate key");

    // Self-signed, so the issuer and subject are the same.
    for (auto* set_dn : {gnutls_x509_crt_set_dn_by_oid, gnutls_x509_crt_set_issuer_dn_by_oid}) {
        check(set_dn(crt.get(), GNUTLS_OID_X520_COUNTRY_NAME, 0, "AU", 2), "certificate DN (C)");
        check(set_dn(crt.get(), GNUTLS_OID_X520_COMMON_NAME, 0, "localhost", 9),
              "certificate DN (CN)");
        check(set_dn(crt.get(), GNUTLS_OID_X520_ORGANIZATION_NAME, 0, "Oxen", 4),
              "certificate DN (O)");
    }

    std::array<unsigned char, 20> key_id;
    size_t key_id_len = key_id.size();
    check(gnutls_x509_crt_get_key_id(crt.get(), 0, key_id.data(), &key_id_len),
          "certificate key id");
    check(gnutls_x509_crt_set_subject_key_id(crt.get(), key_id.data(), key_id_len),
          "certificate subject key id");

    check(gnutls_x509_crt_sign2(crt.get(), crt.get(), key.get(), GNUTLS_DIG_SHA256, 0),
          "certificate signing");

    datum key_pem;
    check(gnutls_x509_privkey_export2(key.get(), GNUTLS_X509_FMT_PEM, &key_pem.d),
          "private key export");
    datum crt_pem;
    check(gnutls_x509_crt_export2(crt.get(), GNUTLS_X509_FMT_PEM, &crt_pem.d),
          "certificate export");

    write_pem(key_path, key_pem.view(), secret_perms);
    write_pem(cert_path, crt_pem.view(), public_perms);
}

}  // namespace oxenss
