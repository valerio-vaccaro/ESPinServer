#include "crypto_utils.h"
#include <string.h>

#include "utility/trezor/secp256k1.h"
#include "utility/trezor/ecdsa.h"
#include "utility/trezor/bignum.h"
#include "utility/trezor/hasher.h"
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include "esp_random.h"

void crypto_init() {
    // nothing needed for trezor-crypto
}

void crypto_random(uint8_t* out, size_t len) {
    while (len >= sizeof(uint32_t)) {
        uint32_t value = esp_random();
        memcpy(out, &value, sizeof(value));
        out += sizeof(value);
        len -= sizeof(value);
    }
    if (len) {
        uint32_t value = esp_random();
        memcpy(out, &value, len);
    }
}

bool derive_storage_keys(const char* password, const uint8_t* salt, size_t salt_len,
                         uint8_t* encryption_key, uint8_t* authentication_key) {
    // PBKDF2-HMAC-SHA256 with a deliberately expensive work factor for a local
    // unlock password. Two blocks provide independent AES and HMAC keys.
    const uint32_t iterations = 120000;
    uint8_t block_input[64];
    if (salt_len > 48) return false;
    memcpy(block_input, salt, salt_len);
    uint8_t u[32];
    uint8_t t[32];
    const uint8_t* password_bytes = (const uint8_t*)password;
    size_t password_len = strlen(password);
    for (uint32_t block = 1; block <= 2; block++) {
        block_input[salt_len] = (uint8_t)(block >> 24);
        block_input[salt_len + 1] = (uint8_t)(block >> 16);
        block_input[salt_len + 2] = (uint8_t)(block >> 8);
        block_input[salt_len + 3] = (uint8_t)block;
        hmac_crypto_sha256(password_bytes, password_len, block_input, salt_len + 4, u);
        memcpy(t, u, sizeof(t));
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_crypto_sha256(password_bytes, password_len, u, sizeof(u), u);
            for (size_t j = 0; j < sizeof(t); j++) t[j] ^= u[j];
        }
        memcpy(block == 1 ? encryption_key : authentication_key, t, 32);
    }
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    return true;
}

bool storage_encrypt(const uint8_t* encryption_key, const uint8_t* authentication_key,
                     const uint8_t* plaintext, size_t plaintext_len,
                     const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag) {
    size_t pad = 16 - (plaintext_len % 16);
    size_t padded_len = plaintext_len + pad;
    uint8_t* padded = (uint8_t*)malloc(padded_len);
    if (!padded) return false;
    memcpy(padded, plaintext, plaintext_len);
    memset(padded + plaintext_len, (uint8_t)pad, pad);
    uint8_t chain[16];
    memcpy(chain, iv, sizeof(chain));
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    bool ok = mbedtls_aes_setkey_enc(&aes, encryption_key, 256) == 0 &&
              mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, chain, padded, ciphertext) == 0;
    mbedtls_aes_free(&aes);
    if (ok) hmac_crypto_sha256(authentication_key, 32, ciphertext, padded_len, tag);
    memset(padded, 0, padded_len);
    free(padded);
    return ok;
}

bool storage_decrypt(const uint8_t* encryption_key, const uint8_t* authentication_key,
                     const uint8_t* iv, const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* tag, uint8_t* plaintext, size_t* plaintext_len) {
    if (!ciphertext_len || ciphertext_len % 16) return false;
    uint8_t expected_tag[32];
    hmac_crypto_sha256(authentication_key, 32, ciphertext, ciphertext_len, expected_tag);
    uint8_t difference = 0;
    for (size_t i = 0; i < sizeof(expected_tag); i++) difference |= expected_tag[i] ^ tag[i];
    if (difference != 0) return false;
    uint8_t chain[16];
    memcpy(chain, iv, sizeof(chain));
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    bool ok = mbedtls_aes_setkey_dec(&aes, encryption_key, 256) == 0 &&
              mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, chain, ciphertext, plaintext) == 0;
    mbedtls_aes_free(&aes);
    if (!ok) return false;
    uint8_t pad = plaintext[ciphertext_len - 1];
    if (pad == 0 || pad > 16 || pad > ciphertext_len) return false;
    for (size_t i = 0; i < pad; i++) if (plaintext[ciphertext_len - 1 - i] != pad) return false;
    *plaintext_len = ciphertext_len - pad;
    return true;
}

void crypto_sha256(const uint8_t* data, size_t len, uint8_t* out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, data, len);
    mbedtls_md_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

void hmac_crypto_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, data, data_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

void hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, data, data_len);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

bool derive_ephemeral_privkey(const uint8_t* server_priv, const uint8_t* cke, const uint8_t* replay_counter, uint8_t* d_e) {
    uint8_t hmac_key[32];
    hmac_crypto_sha256(cke, 33, replay_counter, 4, hmac_key);

    // The client uses libwally's ec_public_key_bip341_tweak().  Its second
    // argument is the Taproot merkle-root input, not the final scalar tweak.
    // Reproduce BIP341's tagged TapTweak hash here:
    // SHA256(SHA256("TapTweak") || SHA256("TapTweak") || xonly(P) || root).
    uint8_t tweak_root[32];
    crypto_sha256(hmac_key, 32, tweak_root);
    
    uint8_t server_pub_comp[33];
    ecdsa_get_public_key33(&secp256k1, server_priv, server_pub_comp);
    bool is_odd = (server_pub_comp[0] == 0x03);

    static const uint8_t tap_tweak_tag[] = "TapTweak";
    uint8_t tag_hash[32];
    crypto_sha256(tap_tweak_tag, sizeof(tap_tweak_tag) - 1, tag_hash);
    uint8_t tap_tweak_input[128];
    memcpy(tap_tweak_input, tag_hash, 32);
    memcpy(tap_tweak_input + 32, tag_hash, 32);
    memcpy(tap_tweak_input + 64, server_pub_comp + 1, 32);
    memcpy(tap_tweak_input + 96, tweak_root, 32);
    uint8_t tweak[32];
    crypto_sha256(tap_tweak_input, sizeof(tap_tweak_input), tweak);
    
    bignum256 d_bn;
    bn_read_be(server_priv, &d_bn);
    if (is_odd) {
        bignum256 order = secp256k1.order;
        bn_subtract(&order, &d_bn, &d_bn);
    }
    
    bignum256 tweak_bn;
    bn_read_be(tweak, &tweak_bn);
    bn_add(&d_bn, &tweak_bn);
    bn_mod(&d_bn, &secp256k1.order);
    
    bn_write_be(&d_bn, d_e);
    return true;
}

bool get_ecdh_keys(const uint8_t* priv_key, const uint8_t* pub_key_bytes, const char* label, uint8_t* enc_key, uint8_t* hmac_key_out) {
    uint8_t session_key[65];
    if (ecdh_multiply(&secp256k1, priv_key, pub_key_bytes, session_key) != 0) return false;
    
    uint8_t compressed[33];
    compressed[0] = (session_key[64] & 1) ? 0x03 : 0x02;
    memcpy(compressed + 1, session_key + 1, 32);
    
    uint8_t secret[32];
    crypto_sha256(compressed, 33, secret);
    
    uint8_t keys[64];
    hmac_sha512(secret, 32, (const uint8_t*)label, strlen(label), keys);
    
    memcpy(enc_key, keys, 32);
    memcpy(hmac_key_out, keys + 32, 32);
    return true;
}

bool decrypt_payload(const uint8_t* priv_key, const uint8_t* pub_key, const char* label, const uint8_t* encrypted, size_t encrypted_len, uint8_t* decrypted, size_t* decrypted_len) {
    if (encrypted_len < 16 + 32) return false;
    
    uint8_t enc_key[32];
    uint8_t hmac_key[32];
    if (!get_ecdh_keys(priv_key, pub_key, label, enc_key, hmac_key)) return false;
    
    size_t payload_len = encrypted_len - 32;
    uint8_t hmac[32];
    hmac_crypto_sha256(hmac_key, 32, encrypted, payload_len, hmac);
    if (memcmp(hmac, encrypted + payload_len, 32) != 0) return false;
    
    size_t ciphertext_len = payload_len - 16;
    if (ciphertext_len % 16 != 0) return false;
    
    uint8_t iv[16];
    memcpy(iv, encrypted, 16);
    
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, enc_key, 256);
    
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len, iv, encrypted + 16, decrypted);
    mbedtls_aes_free(&aes);
    
    uint8_t pad = decrypted[ciphertext_len - 1];
    if (pad == 0 || pad > 16 || pad > ciphertext_len) return false;
    for (size_t i = 0; i < pad; i++) {
        if (decrypted[ciphertext_len - 1 - i] != pad) return false;
    }
    
    *decrypted_len = ciphertext_len - pad;
    return true;
}

bool encrypt_payload(const uint8_t* priv_key, const uint8_t* pub_key, const char* label, const uint8_t* plaintext, size_t plaintext_len, uint8_t* encrypted, size_t* encrypted_len) {
    uint8_t enc_key[32];
    uint8_t hmac_key[32];
    if (!get_ecdh_keys(priv_key, pub_key, label, enc_key, hmac_key)) return false;
    
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = random(256);
    memcpy(encrypted, iv, 16);
    
    size_t pad = 16 - (plaintext_len % 16);
    size_t padded_len = plaintext_len + pad;
    uint8_t* padded = (uint8_t*)malloc(padded_len);
    memcpy(padded, plaintext, plaintext_len);
    memset(padded + plaintext_len, pad, pad);
    
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, enc_key, 256);
    
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded, encrypted + 16);
    mbedtls_aes_free(&aes);
    free(padded);
    
    size_t payload_len = 16 + padded_len;
    hmac_crypto_sha256(hmac_key, 32, encrypted, payload_len, encrypted + payload_len);
    
    *encrypted_len = payload_len + 32;
    return true;
}

bool recover_pubkey(const uint8_t* cke, const uint8_t* replay_counter, const uint8_t* pin_secret, const uint8_t* entropy, size_t entropy_len, const uint8_t* signature, uint8_t* pubkey_out) {
    size_t msg_len = 33 + 4 + 32 + entropy_len;
    uint8_t* msg = (uint8_t*)malloc(msg_len);
    memcpy(msg, cke, 33);
    memcpy(msg + 33, replay_counter, 4);
    memcpy(msg + 37, pin_secret, 32);
    if (entropy_len > 0) {
        memcpy(msg + 69, entropy, entropy_len);
    }
    
    uint8_t msg_hash[32];
    crypto_sha256(msg, msg_len, msg_hash);
    free(msg);
    
    int recid = (signature[0] - 27) & 3;
    uint8_t recovered_pub[65];
    if (ecdsa_recover_pub_from_sig(&secp256k1, recovered_pub, signature + 1, msg_hash, recid) != 0) return false;
    
    pubkey_out[0] = (recovered_pub[64] & 1) ? 0x03 : 0x02;
    memcpy(pubkey_out + 1, recovered_pub + 1, 32);
    return true;
}
