#include <catch2/catch.hpp>
#include <oxenc/hex.h>
#include <oxenss/crypto/channel_encryption.hpp>
#include <oxenss/crypto/keys.h>

using namespace std::literals;
using namespace oxenss::crypto;

constexpr auto plaintext_data = "Grumpy cat says no!"sv;

const auto alice_keys = x25519_keypair::from_secret_hex(
        "7d446468c186d6fb3c83365ab77a37b1f9fa3e59eb9788a40ae2e9560f196f30");
const auto bob_keys = x25519_keypair::from_secret_hex(
        "f512f68e81a932aa2ff6d8723baa260a43a6f789d61c91b71f73e4f284e3600a");

TEST_CASE("AES-GCM encryption", "[encrypt][gcm]") {
    ChannelEncryption alice_box{alice_keys};
    ChannelEncryption bob_box{bob_keys};

    auto ctext_bob = alice_box.encrypt_gcm(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 28);
    auto ptext_bob = bob_box.decrypt_gcm(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    auto ctext_alice = bob_box.encrypt_gcm(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 28);
    auto ptext_alice = alice_box.decrypt_gcm(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);
}

TEST_CASE("AES-GCM known answer", "[encrypt][gcm]") {
    // A round-trip test only proves the implementation agrees with itself; this pins the actual
    // wire format (HMAC-SHA256("LOKI") key derivation, 12-byte IV prefix, 16-byte tag suffix,
    // AES-256-GCM) so that swapping the underlying crypto library cannot silently change what
    // clients see.  Generated independently with python-cryptography, and verified to decrypt
    // under the openssl implementation this replaced.
    auto ctext = oxenc::from_hex(
            "000102030405060708090a0b254141d0fb10f0f25e1e316f3f47bf675d49eb6c238bd3c18b86df3fc8d56"
            "87cc64c7a"sv);

    ChannelEncryption bob_box{bob_keys};
    CHECK(bob_box.decrypt_gcm(ctext, alice_keys.pub) == plaintext_data);

    // Negative control: flipping a bit anywhere must fail the tag check rather than return
    // garbage, otherwise the check above could pass with authentication broken.
    for (size_t i : {size_t{0}, size_t{12}, ctext.size() - 1}) {
        auto damaged = ctext;
        damaged[i] ^= 0x01;
        CHECK_THROWS_AS(bob_box.decrypt_gcm(damaged, alice_keys.pub), std::runtime_error);
    }

    CHECK_THROWS_AS(bob_box.decrypt_gcm(ctext.substr(0, 27), alice_keys.pub), std::runtime_error);
}

TEST_CASE("XChaCha20-Poly1309 encryption", "[encrypt][xchacha20]") {
    ChannelEncryption alice_server{alice_keys};
    ChannelEncryption alice_client{alice_keys, false};
    ChannelEncryption bob_server{bob_keys};
    ChannelEncryption bob_client{bob_keys, false};

    auto ctext_bob = alice_client.encrypt_xchacha20(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    auto ptext_bob = bob_server.decrypt_xchacha20(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_client.decrypt_xchacha20(ctext_bob, alice_keys.pub), std::runtime_error);

    auto ctext_alice = bob_client.encrypt_xchacha20(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    auto ptext_alice = alice_server.decrypt_xchacha20(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_client.decrypt_xchacha20(ctext_alice, bob_keys.pub), std::runtime_error);

    ctext_bob = alice_server.encrypt_xchacha20(plaintext_data, bob_keys.pub);
    CHECK(ctext_bob.size() == plaintext_data.size() + 40);
    ptext_bob = bob_client.decrypt_xchacha20(ctext_bob, alice_keys.pub);

    CHECK(ptext_bob == plaintext_data);

    CHECK_THROWS_AS(bob_server.decrypt_xchacha20(ctext_bob, alice_keys.pub), std::runtime_error);

    ctext_alice = bob_server.encrypt_xchacha20(plaintext_data, alice_keys.pub);
    CHECK(ctext_alice.size() == plaintext_data.size() + 40);
    ptext_alice = alice_client.decrypt_xchacha20(ctext_alice, bob_keys.pub);

    CHECK(ptext_alice == plaintext_data);

    CHECK_THROWS_AS(alice_server.decrypt_xchacha20(ctext_alice, bob_keys.pub), std::runtime_error);
}
