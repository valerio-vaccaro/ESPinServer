#include "tls_credentials.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>
#include <mbedtls/bignum.h>

static bool generateTlsCredentials(const String& hostname, const IPAddress& address,
                                   String& certificate_pem, String& private_key_pem) {
    // These contexts are large on ESP32. Keep them off loopTask's small
    // Arduino stack while the first-boot certificate is generated.
    mbedtls_entropy_context* entropy = (mbedtls_entropy_context*)calloc(1, sizeof(*entropy));
    mbedtls_ctr_drbg_context* drbg = (mbedtls_ctr_drbg_context*)calloc(1, sizeof(*drbg));
    mbedtls_pk_context* key = (mbedtls_pk_context*)calloc(1, sizeof(*key));
    mbedtls_x509write_cert* certificate = (mbedtls_x509write_cert*)calloc(1, sizeof(*certificate));
    if (!entropy || !drbg || !key || !certificate) {
        free(entropy); free(drbg); free(key); free(certificate);
        return false;
    }
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_pk_init(key);
    mbedtls_x509write_crt_init(certificate);
    const char personalization[] = "ESPinServer HTTPS certificate";
    int result = mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy,
                                       (const unsigned char*)personalization,
                                       sizeof(personalization) - 1);
    if (result == 0) result = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (result == 0) result = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                                   mbedtls_pk_ec(*key),
                                                   mbedtls_ctr_drbg_random, drbg);

    String subject = "CN=" + hostname;
    if (result == 0) result = mbedtls_x509write_crt_set_subject_name(certificate, subject.c_str());
    if (result == 0) result = mbedtls_x509write_crt_set_issuer_name(certificate, subject.c_str());
    if (result == 0) {
        mbedtls_x509write_crt_set_version(certificate, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(certificate, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(certificate, key);
        mbedtls_x509write_crt_set_issuer_key(certificate, key);
        result = mbedtls_x509write_crt_set_validity(certificate, "20200101000000", "20400101000000");
    }

    uint8_t serial[16];
    mbedtls_mpi serial_mpi;
    mbedtls_mpi_init(&serial_mpi);
    if (result == 0) {
        mbedtls_ctr_drbg_random(drbg, serial, sizeof(serial));
        serial[0] &= 0x7f;
        result = mbedtls_mpi_read_binary(&serial_mpi, serial, sizeof(serial));
        if (result == 0) result = mbedtls_x509write_crt_set_serial(certificate, &serial_mpi);
    }

    // Add DNS and IP subject-alternative names. Build the small DER extension
    // directly because older Arduino-ESP32 releases do not provide the newer
    // mbedtls_x509write_crt_set_subject_alternative_name helper.
    uint8_t ip_bytes[4] = {address[0], address[1], address[2], address[3]};
    uint8_t san_extension[160] = {};
    size_t hostname_len = hostname.length();
    size_t names_len = 2 + hostname_len + 2 + sizeof(ip_bytes);
    size_t san_len = 2 + names_len;
    if (hostname_len > 126 || san_len > 126) result = -1;
    if (result == 0) {
        size_t offset = 0;
        san_extension[offset++] = 0x30;
        san_extension[offset++] = (uint8_t)names_len;
        san_extension[offset++] = 0x82; // dNSName [2], IA5String
        san_extension[offset++] = (uint8_t)hostname_len;
        memcpy(san_extension + offset, hostname.c_str(), hostname_len);
        offset += hostname_len;
        san_extension[offset++] = 0x87; // iPAddress [7], OCTET STRING
        san_extension[offset++] = sizeof(ip_bytes);
        memcpy(san_extension + offset, ip_bytes, sizeof(ip_bytes));
        offset += sizeof(ip_bytes);
        const char san_oid[] = "\x55\x1d\x11";
        result = mbedtls_x509write_crt_set_extension(certificate, san_oid, 3, false,
                                                     san_extension, offset);
    }

    unsigned char* certificate_buffer = (unsigned char*)calloc(1, 4096);
    unsigned char* key_buffer = (unsigned char*)calloc(1, 2048);
    if (!certificate_buffer || !key_buffer) result = -1;
    if (result == 0) result = mbedtls_x509write_crt_pem(certificate, certificate_buffer,
                                                        4096, mbedtls_ctr_drbg_random, drbg);
    if (result == 0) result = mbedtls_pk_write_key_pem(key, key_buffer, 2048);
    if (result == 0) {
        certificate_pem = String((char*)certificate_buffer);
        private_key_pem = String((char*)key_buffer);
    }

    memset(serial, 0, sizeof(serial));
    mbedtls_mpi_free(&serial_mpi);
    if (certificate_buffer) { memset(certificate_buffer, 0, 4096); free(certificate_buffer); }
    if (key_buffer) { memset(key_buffer, 0, 2048); free(key_buffer); }
    mbedtls_x509write_crt_free(certificate);
    mbedtls_pk_free(key);
    mbedtls_ctr_drbg_free(drbg);
    mbedtls_entropy_free(entropy);
    free(certificate); free(key); free(drbg); free(entropy);
    return result == 0 && certificate_pem.length() > 0 && private_key_pem.length() > 0;
}

bool loadOrGenerateTlsCredentials(Preferences& preferences, const String& mdns_name,
                                  const IPAddress& address, String& certificate_pem,
                                  String& private_key_pem) {
    String hostname = mdns_name + ".local";
    String stored_hostname = preferences.getString("tls_host", "");
    String stored_ip = preferences.getString("tls_ip", "");
    certificate_pem = preferences.getString("tls_cert", "");
    private_key_pem = preferences.getString("tls_key", "");
    if (stored_hostname == hostname && stored_ip == address.toString() &&
        certificate_pem.length() > 0 && private_key_pem.length() > 0) return true;
    if (!generateTlsCredentials(hostname, address, certificate_pem, private_key_pem)) return false;
    preferences.putString("tls_host", hostname);
    preferences.putString("tls_ip", address.toString());
    preferences.putString("tls_cert", certificate_pem);
    preferences.putString("tls_key", private_key_pem);
    return true;
}

bool regenerateTlsCredentials(Preferences& preferences, const String& mdns_name,
                              const IPAddress& address, String& certificate_pem,
                              String& private_key_pem) {
    String hostname = mdns_name + ".local";
    if (!generateTlsCredentials(hostname, address, certificate_pem, private_key_pem)) return false;
    preferences.putString("tls_host", hostname);
    preferences.putString("tls_ip", address.toString());
    preferences.putString("tls_cert", certificate_pem);
    preferences.putString("tls_key", private_key_pem);
    return true;
}
