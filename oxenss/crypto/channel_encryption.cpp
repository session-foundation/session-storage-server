#include "channel_encryption.hpp"

#include <oxenss/utils/string_utils.hpp>

#include <cassert>
#include <memory>
#include <span>

#include <gnutls/crypto.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>

namespace oxenss::crypto {

namespace {
    // Derive shared secret from our (ephemeral) `seckey` and the other party's
    // `pubkey`
    std::array<uint8_t, crypto_scalarmult_BYTES> calculate_shared_secret(
            const x25519_seckey& seckey, const x25519_pubkey& pubkey) {
        std::array<uint8_t, crypto_scalarmult_BYTES> secret;
        if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0)
            throw std::runtime_error("Shared key derivation failed (crypto_scalarmult)");
        return secret;
    }

    std::span<const unsigned char> to_uchar(std::string_view sv) {
        return util::to_span<unsigned char>(sv);
    }

    inline constexpr std::string_view salt{"LOKI"};

    std::array<uint8_t, crypto_scalarmult_BYTES> derive_symmetric_key(
            const x25519_seckey& seckey, const x25519_pubkey& pubkey) {
        auto key = calculate_shared_secret(seckey, pubkey);

        auto usalt = to_uchar(salt);

        crypto_auth_hmacsha256_state state;

        crypto_auth_hmacsha256_init(&state, usalt.data(), usalt.size());
        crypto_auth_hmacsha256_update(&state, key.data(), key.size());
        crypto_auth_hmacsha256_final(&state, key.data());

        return key;
    }

    // Wire format constants, not library preferences: the aes-gcm ciphertext a client sends is
    // `IV || ciphertext || tag`, with these sizes, and changing either breaks every client.
    inline constexpr size_t gcm_iv_size = 12;
    inline constexpr size_t gcm_tag_size = 16;

    struct aead_cipher_deleter {
        void operator()(gnutls_aead_cipher_hd_t h) const { gnutls_aead_cipher_deinit(h); }
    };

    using aead_cipher_ptr =
            std::unique_ptr<std::remove_pointer_t<gnutls_aead_cipher_hd_t>, aead_cipher_deleter>;

    aead_cipher_ptr aes_gcm_cipher(const std::array<uint8_t, crypto_scalarmult_BYTES>& key) {
        gnutls_datum_t k{
                const_cast<unsigned char*>(key.data()), static_cast<unsigned int>(key.size())};
        gnutls_aead_cipher_hd_t h;
        if (int rc = gnutls_aead_cipher_init(&h, GNUTLS_CIPHER_AES_256_GCM, &k); rc < 0)
            throw std::runtime_error{
                    "Could not initialise AES-256-GCM cipher: "s + gnutls_strerror(rc)};
        return aead_cipher_ptr{h};
    }

}  // namespace

EncryptType parse_enc_type(std::string_view enc_type) {
    if (enc_type == "xchacha20" || enc_type == "xchacha20-poly1305")
        return EncryptType::xchacha20;
    if (enc_type == "aes-gcm" || enc_type == "gcm")
        return EncryptType::aes_gcm;
    throw std::runtime_error{"Invalid encryption type " + std::string{enc_type}};
}

std::string ChannelEncryption::encrypt(
        EncryptType type, std::string_view plaintext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return encrypt_xchacha20(plaintext, pubkey);
        case EncryptType::aes_gcm: return encrypt_gcm(plaintext, pubkey);
    }
    throw std::runtime_error{"Invalid encryption type"};
}

std::string ChannelEncryption::decrypt(
        EncryptType type, std::string_view ciphertext, const x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return decrypt_xchacha20(ciphertext, pubkey);
        case EncryptType::aes_gcm: return decrypt_gcm(ciphertext, pubkey);
    }
    throw std::runtime_error{"Invalid decryption type"};
}

std::string ChannelEncryption::encrypt_gcm(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {
    auto plaintext = to_uchar(plaintext_);
    auto cipher = aes_gcm_cipher(derive_symmetric_key(keys_.sec, pubKey));

    std::string output;
    output.resize(gcm_iv_size + plaintext.size() + gcm_tag_size);
    auto* iv = reinterpret_cast<unsigned char*>(output.data());
    randombytes_buf(iv, gcm_iv_size);

    size_t ctext_size = output.size() - gcm_iv_size;
    if (int rc = gnutls_aead_cipher_encrypt(
                cipher.get(),
                iv,
                gcm_iv_size,
                nullptr,
                0,  // additional data
                gcm_tag_size,
                plaintext.data(),
                plaintext.size(),
                iv + gcm_iv_size,
                &ctext_size);
        rc < 0)
        throw std::runtime_error{"Could not encrypt plaintext: "s + gnutls_strerror(rc)};

    assert(ctext_size == output.size() - gcm_iv_size);
    return output;
}

std::string ChannelEncryption::decrypt_gcm(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {
    auto ciphertext = to_uchar(ciphertext_);

    // We prepend the iv and append the tag, so both have to fit.  This has to be checked up front
    // because subspan, unlike string_view::substr, does not clamp to the available length.
    if (ciphertext.size() < gcm_iv_size + gcm_tag_size)
        throw std::runtime_error{"Encrypted value is too short"};

    auto iv = ciphertext.first(gcm_iv_size);
    ciphertext = ciphertext.subspan(gcm_iv_size);

    auto cipher = aes_gcm_cipher(derive_symmetric_key(keys_.sec, pubKey));

    std::string output;
    output.resize(ciphertext.size() - gcm_tag_size);
    size_t ptext_size = output.size();
    if (int rc = gnutls_aead_cipher_decrypt(
                cipher.get(),
                iv.data(),
                iv.size(),
                nullptr,
                0,  // additional data
                gcm_tag_size,
                ciphertext.data(),
                ciphertext.size(),
                output.data(),
                &ptext_size);
        rc < 0)
        throw std::runtime_error{"Could not decrypt (AES-256-GCM): "s + gnutls_strerror(rc)};

    assert(ptext_size == output.size());
    return output;
}

static std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> xchacha20_shared_key(
        const x25519_pubkey& local_pub,
        const x25519_seckey& local_sec,
        const x25519_pubkey& remote_pub,
        bool local_first) {
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key;
    static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES >= crypto_scalarmult_BYTES);
    if (0 != crypto_scalarmult(
                     key.data(),
                     local_sec.data(),
                     remote_pub.data()))  // Use key as tmp storage for aB
        throw std::runtime_error{"Failed to compute shared key for xchacha20"};
    crypto_generichash_state h;
    crypto_generichash_init(&h, nullptr, 0, key.size());
    crypto_generichash_update(&h, key.data(), crypto_scalarmult_BYTES);
    crypto_generichash_update(&h, (local_first ? local_pub : remote_pub).data(), local_pub.size());
    crypto_generichash_update(&h, (local_first ? remote_pub : local_pub).data(), local_pub.size());
    crypto_generichash_final(&h, key.data(), key.size());
    return key;
}

std::string ChannelEncryption::encrypt_xchacha20(
        std::string_view plaintext_, const x25519_pubkey& pubKey) const {
    auto plaintext = to_uchar(plaintext_);

    std::string ciphertext;
    ciphertext.resize(
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

    const auto key = xchacha20_shared_key(keys_.pub, keys_.sec, pubKey, !server_);

    // Generate random nonce, and stash it at the beginning of ciphertext:
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    auto* c = reinterpret_cast<unsigned char*>(ciphertext.data()) +
              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            c,
            &clen,
            plaintext.data(),
            plaintext.size(),
            nullptr,
            0,        // additional data
            nullptr,  // nsec (always unused)
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            key.data());
    assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen <= ciphertext.size());
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen);
    return ciphertext;
}

std::string ChannelEncryption::decrypt_xchacha20(
        std::string_view ciphertext_, const x25519_pubkey& pubKey) const {
    auto ciphertext = to_uchar(ciphertext_);

    // Extract nonce from the beginning of the ciphertext.  The length check has to come first
    // because subspan, unlike string_view::substr, does not clamp to the available length.
    if (ciphertext.size() <
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error{"Invalid ciphertext: too short"};
    auto nonce = ciphertext.first(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext = ciphertext.subspan(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const auto key = xchacha20_shared_key(keys_.pub, keys_.sec, pubKey, !server_);

    std::string plaintext;
    plaintext.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    auto* m = reinterpret_cast<unsigned char*>(plaintext.data());
    unsigned long long mlen;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     m,
                     &mlen,
                     nullptr,  // nsec (always unused)
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,  // additional data
                     nonce.data(),
                     key.data()))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    assert(mlen <= plaintext.size());
    plaintext.resize(mlen);
    return plaintext;
}

}  // namespace oxenss::crypto
