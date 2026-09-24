#include "tls_credentials.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509.h>

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
    if (result == 0) {
        mbedtls_ctr_drbg_random(drbg, serial, sizeof(serial));
        serial[0] &= 0x7f;
        result = mbedtls_x509write_crt_set_serial_raw(certificate, serial, sizeof(serial));
    }

    // Add the configured mDNS hostname. The HTTP redirect always uses this
    // name, so it remains valid even when the DHCP address changes.
    mbedtls_x509_san_list san[2] = {};
    uint8_t ip_bytes[4] = {address[0], address[1], address[2], address[3]};
    san[0].node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san[0].node.san.unstructured_name.tag = MBEDTLS_ASN1_IA5_STRING;
    san[0].node.san.unstructured_name.p = (unsigned char*)hostname.c_str();
    san[0].node.san.unstructured_name.len = hostname.length();
    san[0].next = &san[1];
    san[1].node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
    san[1].node.san.unstructured_name.tag = MBEDTLS_ASN1_OCTET_STRING;
    san[1].node.san.unstructured_name.p = ip_bytes;
    san[1].node.san.unstructured_name.len = 4;
    san[1].next = nullptr;
    if (result == 0) result = mbedtls_x509write_crt_set_subject_alternative_name(certificate, san);

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
