#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <Arduino.h>

void crypto_init();
void crypto_sha256(const uint8_t* data, size_t len, uint8_t* out);
void hmac_crypto_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out);
bool derive_ephemeral_privkey(const uint8_t* server_priv, const uint8_t* cke, const uint8_t* replay_counter, uint8_t* d_e);
bool decrypt_payload(const uint8_t* priv_key, const uint8_t* pub_key, const char* label, const uint8_t* encrypted, size_t encrypted_len, uint8_t* decrypted, size_t* decrypted_len);
bool encrypt_payload(const uint8_t* priv_key, const uint8_t* pub_key, const char* label, const uint8_t* plaintext, size_t plaintext_len, uint8_t* encrypted, size_t* encrypted_len);
bool recover_pubkey(const uint8_t* cke, const uint8_t* replay_counter, const uint8_t* pin_secret, const uint8_t* entropy, size_t entropy_len, const uint8_t* signature, uint8_t* pubkey_out);

#endif
