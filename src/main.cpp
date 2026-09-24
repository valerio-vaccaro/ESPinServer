// ESPinServer — the ESP-based PinServer.
#include "utility/trezor/secp256k1.h"
#include "utility/trezor/ecdsa.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <WiFiManager.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <time.h>
#include <mbedtls/base64.h>
#include "crypto_utils.h"
#include "version.h"

WebServer server(80);
Preferences preferences;
bool enable_led_activity = true;

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

void flashRequestLed() {
    if (!enable_led_activity) return;
    digitalWrite(LED_BUILTIN, HIGH);
    delay(20);
    digitalWrite(LED_BUILTIN, LOW);
}

// Configuration
String mdns_name = "espinserver";
String pairing_url_a = "";
String pairing_url_b = "";
uint8_t server_privkey[32];
uint8_t server_pubkey[33];
uint32_t pin_save_successes = 0;
uint32_t pin_save_errors = 0;
uint32_t saved_pin_successes = 0;
uint32_t saved_pin_failures = 0;
bool enable_diagnostics = true;

// Connection Logging (Pure RAM-based circular buffer - Idea 1/2 additions)
#define MAX_LOGS 50
struct ConnLog {
    String client_ip;
    String endpoint;
    String status;
    uint32_t timestamp;
    bool valid;
};
ConnLog conn_logs[MAX_LOGS];
int log_index = 0;

void addLog(String ip, String ep, String status) {
    conn_logs[log_index].client_ip = ip;
    conn_logs[log_index].endpoint = ep;
    conn_logs[log_index].status = status;
    conn_logs[log_index].timestamp = millis();
    conn_logs[log_index].valid = true;
    log_index = (log_index + 1) % MAX_LOGS;
}

// The PIN database is encrypted at rest. The unlock key is derived from a
// browser-entered password and is never persisted by the firmware.
//
// Pin Database (matching exact Blockstream security model)
#define MAX_PINS 16
struct PinRecord {
    uint8_t pin_pubkey_hash[32];   // Unique wallet ID (SHA256 of recovered static pubkey)
    uint8_t hash_pin_secret[32];   // SHA256 of client pin_secret to verify correctness
    uint8_t aes_key[32];           // Stored key share (saved_key)
    uint8_t attempts;              // Attempt counter (0-3)
    uint8_t replay_counter[4];     // Stored replay counter to prevent replays
    uint32_t last_attempt_time;    // millis() timestamp of last attempt for Cooldown (Idea 2)
    uint32_t created_timestamp;    // Unix timestamp when the row was created
    uint32_t last_attempt_timestamp; // Unix timestamp of the latest real attempt
    uint32_t get_successes;        // Successful retrievals for this PIN record
    uint32_t get_failures;         // Failed retrievals for this PIN record
    bool valid;
};
PinRecord pin_db[MAX_PINS];

static const uint8_t PIN_BLOB_MAGIC[8] = {'E','S','P','I','N','E','N','C'};
static const uint8_t PIN_BLOB_VERSION = 1;
static const size_t PIN_BLOB_SALT_LEN = 16;
struct PinBlobHeader {
    uint8_t magic[8];
    uint8_t version;
    uint8_t reserved[3];
    uint32_t plaintext_len;
    uint32_t ciphertext_len;
    uint8_t salt[16];
    uint8_t iv[16];
};
bool pin_blob_exists = false;
bool pin_unlocked = false;
bool legacy_pin_data_loaded = false;
uint8_t storage_encryption_key[32];
uint8_t storage_authentication_key[32];
uint8_t storage_salt[PIN_BLOB_SALT_LEN];

const size_t PIN_BLOB_MAX_CIPHERTEXT = sizeof(pin_db) + 16;

String htmlEscape(const String& value);

struct LegacyTimestampPinRecord {
    uint8_t pin_pubkey_hash[32];
    uint8_t hash_pin_secret[32];
    uint8_t aes_key[32];
    uint8_t attempts;
    uint8_t replay_counter[4];
    uint32_t last_attempt_time;
    uint32_t created_timestamp;
    uint32_t last_attempt_timestamp;
    bool valid;
};

struct LegacyPinRecord {
    uint8_t pin_pubkey_hash[32];
    uint8_t hash_pin_secret[32];
    uint8_t aes_key[32];
    uint8_t attempts;
    uint8_t replay_counter[4];
    uint32_t last_attempt_time;
    bool valid;
};

// Unified Cyber-Dark CSS styles used across all pages
const String UNIFIED_CSS = 
    "<style>"
    "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: center; margin: 0; padding: 20px; background: radial-gradient(circle at 50% -10%, #202B35 0, #0B0B0E 48%, #070709 100%); background-size: 180% 180%; animation: background-drift 18s ease-in-out infinite alternate; color: #ECECF1; -webkit-font-smoothing: antialiased; overflow-x: hidden; }"
    ".card { background: linear-gradient(145deg, rgba(25,25,34,0.98), rgba(14,14,20,0.98)); padding: 30px; border-radius: 18px; box-shadow: 0 18px 45px rgba(0,0,0,0.55), 0 0 0 1px rgba(0,230,118,0.04); display: inline-block; max-width: 500px; width: 100%; box-sizing: border-box; text-align: left; border: 1px solid #2A2A3A; margin-top: 20px; animation: card-in .45s ease-out both; }"
    "h1 { color: #00E676; font-size: 26px; margin-top: 0; margin-bottom: 20px; text-align: center; font-weight: 800; letter-spacing: -0.5px; text-shadow: 0 0 15px rgba(0,230,118,0.25); }"
    "h2 { color: #ECECF1; font-size: 18px; margin-top: 0; margin-bottom: 15px; border-bottom: 1px solid #20202E; padding-bottom: 10px; }"
    "p { font-size: 14px; color: #8F8F9D; line-height: 1.5; margin-bottom: 20px; }"
    ".info-item { margin-bottom: 15px; font-size: 14px; }"
    ".info-item strong { color: #8F8F9D; display: block; margin-bottom: 5px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }"
    "input[type='text'] { width: 100%; padding: 12px 14px; background: #171722; border: 1px solid #20202E; color: #ECECF1; border-radius: 8px; box-sizing: border-box; margin-top: 5px; font-family: monospace; font-size: 14px; transition: all 0.2s; }"
    "input[type='text']:focus { border-color: #00E676; box-shadow: 0 0 10px rgba(0,230,118,0.15); outline: none; background: #1B1B26; }"
    "input[type='text'][readonly] { background: #0E0E12; color: #5F5F6E; border-color: #171722; cursor: not-allowed; }"
    "input[type='submit'] { width: 100%; padding: 14px; background: #00E676; border: none; color: #0B0B0E; font-weight: bold; border-radius: 8px; cursor: pointer; margin-top: 15px; font-size: 14px; transition: all 0.2s; letter-spacing: 0.5px; }"
    "input[type='submit']:hover { background: #00B0FF; color: white; box-shadow: 0 0 15px rgba(0,176,255,0.4); }"
    ".btn { display: block; text-align: center; padding: 14px; margin-top: 12px; border-radius: 9px; text-decoration: none; font-weight: bold; font-size: 14px; transition: transform .2s, box-shadow .2s, background .2s; box-sizing: border-box; letter-spacing: 0.5px; }"
    ".btn:hover { transform: translateY(-2px); }"
    ".btn-primary { background: #00E676; color: #0B0B0E; }"
    ".btn-primary:hover { background: #00C853; box-shadow: 0 0 15px rgba(0,230,118,0.4); }"
    ".btn-outline { border: 2px solid #00E676; color: #00E676; background: transparent; padding: 12px; }"
    ".btn-outline:hover { background: rgba(0,230,118,0.08); box-shadow: 0 0 10px rgba(0,230,118,0.2); }"
    ".btn-secondary { border: 2px solid #00B0FF; color: #00B0FF; background: transparent; padding: 12px; }"
    ".btn-secondary:hover { background: rgba(0,176,255,0.08); box-shadow: 0 0 10px rgba(0,176,255,0.2); }"
    ".btn-danger { background: #FF3D00; color: white; border: none; }"
    ".btn-danger:hover { background: #DD2C00; box-shadow: 0 0 15px rgba(255,61,0,0.4); }"
    "input[type='submit'].btn-danger { background: #D50000; color: #FFFFFF; border: 1px solid #FF5252; box-shadow: 0 0 12px rgba(213,0,0,0.22); }"
    "input[type='submit'].btn-danger:hover { background: #FF1744; color: #FFFFFF; box-shadow: 0 0 20px rgba(255,23,68,0.55); }"
    ".danger-zone { border: 1px solid rgba(255,23,68,0.35); background: linear-gradient(145deg, rgba(80,10,20,0.28), rgba(30,8,14,0.2)); padding: 16px; border-radius: 12px; animation: danger-pulse 3s ease-in-out infinite; }"
    ".badge { display: inline-block; padding: 4px 8px; background: #20202E; color: #00E676; border-radius: 5px; font-size: 11px; font-weight: bold; font-family: monospace; border: 1px solid rgba(0,230,118,0.2); animation: glow 3s ease-in-out infinite; }"
    "#qrcode { margin: 20px auto; padding: 15px; background: white; border-radius: 12px; display: inline-block; border: 40px solid white; box-shadow: 0 0 0 2px #20202E; }"
    "#qrcode img { width: 256px; height: 256px; image-rendering: pixelated; }"
    ".topbar { max-width: 900px; margin: 0 auto 18px; display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; }"
    ".topbar a { color: #8F8F9D; border: 1px solid #20202E; background: rgba(19,19,26,.82); border-radius: 9px; padding: 9px 12px; text-decoration: none; font-size: 12px; font-weight: 700; transition: transform .2s, color .2s, background .2s, box-shadow .2s; }"
    ".topbar a:hover { transform: translateY(-2px); box-shadow: 0 8px 18px rgba(0,0,0,.25); }"
    ".topbar a:hover, .topbar a.active { color: #0B0B0E; background: #00E676; border-color: #00E676; }"
    ".nav-icon { margin-right: 5px; font-size: 14px; vertical-align: -1px; }"
    "table { width: 100%; border-collapse: collapse; border: 1px solid #20202E; border-radius: 8px; overflow: hidden; margin-top: 15px; }"
    "th, td { padding: 12px 14px; text-align: left; font-size: 13px; font-family: monospace; }"
    "th { background: #1B1B26; color: #8F8F9D; font-weight: bold; border-bottom: 2px solid #20202E; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }"
    "tr { border-bottom: 1px solid #1B1B26; transition: background 0.15s; }"
    "tr:nth-child(even) { background: #161622; }"
    "tr:hover { background: rgba(0,230,118,0.05); }"
    ".checkbox-container { display: flex; align-items: center; cursor: pointer; user-select: none; margin-top: 10px; font-size: 14px; color: #ECECF1; }"
    ".checkbox-container input { margin-right: 10px; accent-color: #00E676; width: 18px; height: 18px; }"
    ".stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 10px; }"
    "@keyframes background-drift { 0% { background-position: 0% 0%; } 50% { background-position: 100% 35%; } 100% { background-position: 20% 100%; } }"
    "@keyframes card-in { from { opacity: 0; transform: translateY(10px) scale(.985); } to { opacity: 1; transform: translateY(0) scale(1); } }"
    "@keyframes danger-pulse { 0%,100% { box-shadow: 0 0 0 rgba(255,23,68,0); } 50% { box-shadow: 0 0 20px rgba(255,23,68,.10); } }"
    "@keyframes glow { 0%,100% { box-shadow: 0 0 0 rgba(0,230,118,0); } 50% { box-shadow: 0 0 14px rgba(0,230,118,.12); } }"
    "@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }"
    "</style>";

bool savePins() {
    if (!pin_unlocked) return false;
    PinBlobHeader header;
    memset(&header, 0, sizeof(header));
    bool valid_header = false;
    memcpy(header.magic, PIN_BLOB_MAGIC, sizeof(header.magic));
    header.version = PIN_BLOB_VERSION;
    memset(header.reserved, 0, sizeof(header.reserved));
    header.plaintext_len = sizeof(pin_db);
    header.ciphertext_len = sizeof(pin_db) + 16;
    // Keep the salt stable for the current password-derived session.
    File old = LittleFS.open("/pins.bin", FILE_READ);
    if (old && old.size() >= sizeof(PinBlobHeader)) {
        old.read((uint8_t*)&header, sizeof(header));
        valid_header = memcmp(header.magic, PIN_BLOB_MAGIC, sizeof(header.magic)) == 0 &&
                       header.version == PIN_BLOB_VERSION;
    }
    old.close();
    memcpy(header.magic, PIN_BLOB_MAGIC, sizeof(header.magic));
    header.version = PIN_BLOB_VERSION;
    header.plaintext_len = sizeof(pin_db);
    header.ciphertext_len = sizeof(pin_db) + 16;
    if (!valid_header) memcpy(header.salt, storage_salt, sizeof(header.salt));
    crypto_random(header.iv, sizeof(header.iv));
    uint8_t ciphertext[PIN_BLOB_MAX_CIPHERTEXT];
    uint8_t tag[32];
    if (!storage_encrypt(storage_encryption_key, storage_authentication_key,
                         (uint8_t*)pin_db, sizeof(pin_db), header.iv, ciphertext, tag)) return false;
    File f = LittleFS.open("/pins.tmp", FILE_WRITE);
    if (!f) return false;
    f.write((uint8_t*)&header, sizeof(header));
    f.write(ciphertext, header.ciphertext_len);
    f.write(tag, sizeof(tag));
    f.close();
    LittleFS.remove("/pins.bin");
    LittleFS.rename("/pins.tmp", "/pins.bin");
    pin_blob_exists = true;
    return true;
}

bool passwordIsSafe(const String& password) {
    if (password.length() < 12 || password.length() > 64) return false;
    bool upper = false, lower = false, digit = false, special = false;
    for (size_t i = 0; i < password.length(); i++) {
        char c = password[i];
        if (c >= 'A' && c <= 'Z') upper = true;
        else if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= '0' && c <= '9') digit = true;
        else if (c >= 33 && c <= 126) special = true;
        else return false;
    }
    return upper && lower && digit && special;
}

bool unlockStorage(const String& password) {
    File f = LittleFS.open("/pins.bin", FILE_READ);
    if (!f || f.size() < sizeof(PinBlobHeader) + 32) return false;
    PinBlobHeader header;
    if (f.read((uint8_t*)&header, sizeof(header)) != sizeof(header) ||
        memcmp(header.magic, PIN_BLOB_MAGIC, sizeof(header.magic)) != 0 ||
        header.version != PIN_BLOB_VERSION || header.plaintext_len != sizeof(pin_db) ||
        header.ciphertext_len != sizeof(pin_db) + 16 ||
        f.size() != sizeof(PinBlobHeader) + header.ciphertext_len + 32) {
        f.close();
        return false;
    }
    uint8_t* ciphertext = (uint8_t*)malloc(header.ciphertext_len);
    uint8_t tag[32];
    uint8_t plaintext[sizeof(pin_db)];
    bool read_ok = ciphertext && f.read(ciphertext, header.ciphertext_len) == header.ciphertext_len &&
                   f.read(tag, sizeof(tag)) == sizeof(tag);
    f.close();
    if (!read_ok || !derive_storage_keys(password.c_str(), header.salt, sizeof(header.salt),
                                         storage_encryption_key, storage_authentication_key)) {
        free(ciphertext);
        return false;
    }
    size_t plaintext_len = 0;
    bool ok = storage_decrypt(storage_encryption_key, storage_authentication_key, header.iv,
                              ciphertext, header.ciphertext_len, tag, plaintext, &plaintext_len);
    free(ciphertext);
    if (!ok || plaintext_len != sizeof(pin_db)) {
        memset(storage_encryption_key, 0, sizeof(storage_encryption_key));
        memset(storage_authentication_key, 0, sizeof(storage_authentication_key));
        return false;
    }
    memcpy(pin_db, plaintext, sizeof(pin_db));
    memcpy(storage_salt, header.salt, sizeof(storage_salt));
    pin_unlocked = true;
    return true;
}

String authPage(const String& message = "") {
    bool setup_mode = !pin_blob_exists;
    String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>" + UNIFIED_CSS + "</head><body>";
    html += "<div class='card'><h1>ESPinServer Security</h1>";
    html += setup_mode ? "<h2>Create storage password</h2><p>Protect the PIN database stored in flash. Use 12–64 characters with uppercase, lowercase, a number, and a symbol.</p>" : "<h2>Unlock storage</h2><p>Enter the storage password to load the PIN database and continue.</p>";
    if (message.length()) html += "<p style='color:#FF5252;'>" + htmlEscape(message) + "</p>";
    html += "<form method='POST' action='/auth'><div class='info-item'><strong>Password</strong><input type='password' name='password' required minlength='12' maxlength='64' autocomplete='current-password'></div>";
    if (setup_mode) html += "<div class='info-item'><strong>Repeat password</strong><input type='password' name='password_confirm' required minlength='12' maxlength='64' autocomplete='new-password'></div>";
    html += "<input type='submit' value='" + String(setup_mode ? "CREATE ENCRYPTED STORAGE" : "UNLOCK STORAGE") + "'></form></div></body></html>";
    return html;
}

void handleAuth() {
    if (pin_unlocked) { server.sendHeader("Location", "/"); server.send(303); return; }
    if (server.method() == HTTP_POST) {
        String password = server.arg("password");
        if (!passwordIsSafe(password)) {
            server.send(400, "text/html", authPage("Password must be 12–64 characters and include uppercase, lowercase, a number, and a symbol."));
            return;
        }
        if (!pin_blob_exists) {
            if (password != server.arg("password_confirm")) {
                server.send(400, "text/html", authPage("The two passwords do not match."));
                return;
            }
            uint8_t salt[PIN_BLOB_SALT_LEN];
            crypto_random(salt, sizeof(salt));
            memcpy(storage_salt, salt, sizeof(storage_salt));
            if (!derive_storage_keys(password.c_str(), salt, sizeof(salt), storage_encryption_key, storage_authentication_key)) {
                server.send(500, "text/plain", "Could not derive storage key");
                return;
            }
            pin_unlocked = true;
            if (!savePins()) {
                pin_unlocked = false;
                server.send(500, "text/plain", "Could not create encrypted storage");
                return;
            }
            pin_blob_exists = true;
        } else if (!unlockStorage(password)) {
            server.send(401, "text/html", authPage("Wrong password or corrupted encrypted storage."));
            return;
        }
        server.sendHeader("Location", "/");
        server.send(303);
        return;
    }
    server.send(200, "text/html", authPage());
}

bool requireStorageAccess(bool api = false) {
    if (pin_unlocked) return true;
    if (api) server.send(423, "text/plain", "Storage is locked");
    else { server.sendHeader("Location", "/auth"); server.send(303); }
    return false;
}

void loadPins() {
    memset(pin_db, 0, sizeof(pin_db));
    File f = LittleFS.open("/pins.bin", FILE_READ);
    if (f) {
        if (f.size() >= sizeof(PinBlobHeader) + 32) {
            PinBlobHeader header;
            f.read((uint8_t*)&header, sizeof(header));
            pin_blob_exists = memcmp(header.magic, PIN_BLOB_MAGIC, sizeof(header.magic)) == 0 &&
                              header.version == PIN_BLOB_VERSION &&
                              header.plaintext_len == sizeof(pin_db) &&
                              header.ciphertext_len == sizeof(pin_db) + 16 &&
                              f.size() == sizeof(PinBlobHeader) + header.ciphertext_len + 32;
        } else if (f.size() == sizeof(pin_db)) {
            // One-time migration path for the old unencrypted firmware.
            f.read((uint8_t*)pin_db, sizeof(pin_db));
            legacy_pin_data_loaded = true;
        } else if (f.size() >= sizeof(LegacyTimestampPinRecord) &&
                   (f.size() % sizeof(LegacyTimestampPinRecord)) == 0) {
            LegacyTimestampPinRecord legacy;
            size_t legacy_count = f.size() / sizeof(LegacyTimestampPinRecord);
            if (legacy_count > MAX_PINS) legacy_count = MAX_PINS;
            for (size_t i = 0; i < legacy_count; i++) {
                if (f.read((uint8_t*)&legacy, sizeof(legacy)) != sizeof(legacy)) break;
                memcpy(pin_db[i].pin_pubkey_hash, legacy.pin_pubkey_hash, sizeof(legacy.pin_pubkey_hash));
                memcpy(pin_db[i].hash_pin_secret, legacy.hash_pin_secret, sizeof(legacy.hash_pin_secret));
                memcpy(pin_db[i].aes_key, legacy.aes_key, sizeof(legacy.aes_key));
                pin_db[i].attempts = legacy.attempts;
                memcpy(pin_db[i].replay_counter, legacy.replay_counter, sizeof(legacy.replay_counter));
                pin_db[i].last_attempt_time = legacy.last_attempt_time;
                pin_db[i].created_timestamp = legacy.created_timestamp;
                pin_db[i].last_attempt_timestamp = legacy.last_attempt_timestamp;
                pin_db[i].valid = legacy.valid;
            }
            f.close();
            legacy_pin_data_loaded = true;
            return;
        } else if (f.size() >= sizeof(LegacyPinRecord) &&
                   (f.size() % sizeof(LegacyPinRecord)) == 0) {
            LegacyPinRecord legacy;
            size_t legacy_count = f.size() / sizeof(LegacyPinRecord);
            if (legacy_count > MAX_PINS) legacy_count = MAX_PINS;
            for (size_t i = 0; i < legacy_count; i++) {
                if (f.read((uint8_t*)&legacy, sizeof(legacy)) != sizeof(legacy)) break;
                memcpy(pin_db[i].pin_pubkey_hash, legacy.pin_pubkey_hash, sizeof(legacy.pin_pubkey_hash));
                memcpy(pin_db[i].hash_pin_secret, legacy.hash_pin_secret, sizeof(legacy.hash_pin_secret));
                memcpy(pin_db[i].aes_key, legacy.aes_key, sizeof(legacy.aes_key));
                pin_db[i].attempts = legacy.attempts;
                memcpy(pin_db[i].replay_counter, legacy.replay_counter, sizeof(legacy.replay_counter));
                pin_db[i].last_attempt_time = legacy.last_attempt_time;
                pin_db[i].valid = legacy.valid;
            }
            f.close();
            legacy_pin_data_loaded = true;
            return;
        }
        f.close();
    }
}

uint32_t localTimestamp() {
    time_t now = time(nullptr);
    return now > 100000 ? (uint32_t)now : 0;
}

String formatTimestamp(uint32_t timestamp) {
    if (timestamp == 0) return "Not available";
    time_t raw = timestamp;
    struct tm local_time;
    localtime_r(&raw, &local_time);
    char buffer[24];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time);
    return String(buffer);
}

void updateLocalTime() {
    configTzTime("CET-1CEST,M3.5.0,M10.5.0/3", "pool.ntp.org", "time.nist.gov");
    struct tm local_time;
    for (int attempt = 0; attempt < 20; attempt++) {
        if (getLocalTime(&local_time, 250)) return;
    }
}

void saveConfig() {
    preferences.putString("mdns_name", mdns_name);
    preferences.putString("url_a", pairing_url_a);
    preferences.putString("url_b", pairing_url_b);
    preferences.putBytes("privkey", server_privkey, 32);
    preferences.putUInt("pin_set_ok", pin_save_successes);
    preferences.putUInt("pin_set_err", pin_save_errors);
    preferences.putUInt("pin_get_ok", saved_pin_successes);
    preferences.putUInt("pin_get_err", saved_pin_failures);
    preferences.putBool("diag", enable_diagnostics);
    preferences.putBool("led", enable_led_activity);
}

void startMDNS() {
    MDNS.end();
    if (MDNS.begin(mdns_name.c_str())) {
        MDNS.addService("http", "tcp", 80);
        Serial.println("mDNS responder started: http://" + mdns_name + ".local (broadcasting _http._tcp on port 80)");
    } else {
        Serial.println("Error setting up MDNS responder!");
    }
}

void loadConfig() {
    String default_name = "espinserver";

    // Remove the obsolete Requests Served preference left by older firmware.
    preferences.remove("served");
    mdns_name = preferences.getString("mdns_name", default_name);
    pairing_url_a = preferences.getString("url_a", "");
    pairing_url_b = preferences.getString("url_b", "");
    pin_save_successes = preferences.getUInt("pin_set_ok", 0);
    pin_save_errors = preferences.getUInt("pin_set_err", 0);
    saved_pin_successes = preferences.getUInt("pin_get_ok", 0);
    saved_pin_failures = preferences.getUInt("pin_get_err", 0);
    enable_diagnostics = preferences.getBool("diag", true);
    enable_led_activity = preferences.getBool("led", true);
    if (preferences.getBytesLength("privkey") == 32) {
        preferences.getBytes("privkey", server_privkey, 32);
    } else {
        // Generate new random privkey
        for (int i = 0; i < 32; i++) server_privkey[i] = random(256);
        saveConfig();
    }
    
    // Derive pubkey
    ecdsa_get_public_key33(&secp256k1, server_privkey, server_pubkey);
}

String bytesToHex(const uint8_t* data, size_t len) {
    String out = "";
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        sprintf(buf, "%02x", data[i]);
        out += buf;
    }
    return out;
}

String htmlEscape(const String& value) {
    String escaped = value;
    escaped.replace("&", "&amp;");
    escaped.replace("<", "&lt;");
    escaped.replace(">", "&gt;");
    escaped.replace("\"", "&quot;");
    escaped.replace("'", "&#39;");
    return escaped;
}

bool validPairingUrl(const String& url) {
    return url.length() > 0 && url.length() <= 255 &&
           (url.startsWith("http://") || url.startsWith("https://"));
}

String pageNav(const String& active = "") {
    String nav = "<nav class='topbar'>";
    nav += "<a href='/' class='" + String(active == "home" ? "active" : "") + "'><span class='nav-icon'>&#8962;</span>Dashboard</a>";
    nav += "<a href='/share' class='" + String(active == "pairing" ? "active" : "") + "'><span class='nav-icon'>&#128279;</span>Pairing</a>";
    nav += "<a href='/config' class='" + String(active == "config" ? "active" : "") + "'><span class='nav-icon'>&#9881;</span>Configuration</a>";
    nav += "<a href='/diagnostics' class='" + String(active == "diagnostics" ? "active" : "") + "'><span class='nav-icon'>&#128202;</span>Diagnostics</a>";
    nav += "</nav>";
    return nav;
}

void hexToBytes(String hex, uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char buf[3] = {hex[i*2], hex[i*2+1], 0};
        data[i] = strtol(buf, NULL, 16);
    }
}

void handleRoot() {
    if (!requireStorageAccess()) return;
    flashRequestLed();
    String client_ip = server.client().remoteIP().toString();
    if (server.method() == HTTP_POST) {
        if (server.hasArg("wipe_pins")) {
            memset(pin_db, 0, sizeof(pin_db));
            savePins();
            addLog(client_ip, "/ (wipe)", "200 OK");
        }
        saveConfig();
        
        // Re-broadcast mDNS service
        startMDNS();
        addLog(client_ip, "/ (save)", "200 OK");
        
        server.sendHeader("Location", "/");
        server.send(303);
        return;
    }

    addLog(client_ip, "/", "200 OK");

    // Calculate free slots dynamically
    int active_records = 0;
    for (int i = 0; i < MAX_PINS; i++) {
        if (pin_db[i].valid) active_records++;
    }
    int free_slots = MAX_PINS - active_records;

    // Retrieve Hardware Statistics data (Idea 1/2 additions!)
    String chip_model = ESP.getChipModel();
    uint32_t cpu_freq = ESP.getCpuFreqMHz();
    uint32_t free_heap = ESP.getFreeHeap() / 1024; // KB
    float chip_temp = temperatureRead();           // Built-in Espressif Temp API (°C)

    String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    html += UNIFIED_CSS;
    html += "</head><body>";
    html += pageNav("home");
    html += "<div class='card'>";
    html += "<h1>ESPinServer <span style='font-size:14px;color:#00B0FF;font-weight:normal;'>v" + String(FIRMWARE_VERSION) + "</span></h1>";
    html += "<p style='text-align:center;'>The ESP-based PinServer for local research and interoperability testing.</p>";
    
    html += "<div class='info-item'><strong>Database Slots Usage</strong><span class='badge' style='font-size:14px;padding:6px 12px;color:#00B0FF;border-color:rgba(0,176,255,0.25);'>" + String(active_records) + " / " + String(MAX_PINS) + " Used (" + String(free_slots) + " Free)</span></div>";

    html += "<h2 style='margin-top:25px;'>PIN Request Statistics</h2>";
    html += "<div class='stats-grid'>";
    html += "<div class='info-item'><strong>Save PIN / OK</strong><span class='badge' style='color:#00E676;'>" + String(pin_save_successes) + "</span></div>";
    html += "<div class='info-item'><strong>Save PIN / Error</strong><span class='badge' style='color:#FF3D00;'>" + String(pin_save_errors) + "</span></div>";
    html += "<div class='info-item'><strong>Get PIN / Successful</strong><span class='badge' style='color:#00E676;'>" + String(saved_pin_successes) + "</span></div>";
    html += "<div class='info-item'><strong>Get PIN / Not Successful</strong><span class='badge' style='color:#FF3D00;'>" + String(saved_pin_failures) + "</span></div>";
    html += "</div>";
    
    html += "<h2 style='margin-top:25px;'>Hardware Statistics</h2>";
    html += "<div class='stats-grid'>";
    html += "<div class='info-item'><strong>Chip Model / Board</strong><span class='badge' style='color:#00B0FF;border-color:rgba(0,176,255,0.2);'>" + chip_model + "</span></div>";
    html += "<div class='info-item'><strong>CPU frequency</strong><span class='badge'>" + String(cpu_freq) + " MHz</span></div>";
    html += "<div class='info-item'><strong>Free Memory (RAM Heap)</strong><span class='badge'>" + String(free_heap) + " KB</span></div>";
    html += "<div class='info-item'><strong>Core Chip Temperature</strong><span class='badge' style='color:#FF9100;border-color:rgba(255,145,0,0.2);'>" + String(chip_temp, 1) + " &deg;C</span></div>";
    html += "</div>";

    html += "</div></body></html>";
    server.send(200, "text/html", html);
}

void handleConfig() {
    if (!requireStorageAccess()) return;
    flashRequestLed();
    String client_ip = server.client().remoteIP().toString();

    if (server.method() == HTTP_POST) {
        if (server.hasArg("reset_stats")) {
            pin_save_successes = 0;
            pin_save_errors = 0;
            saved_pin_successes = 0;
            saved_pin_failures = 0;
            saveConfig();
            addLog(client_ip, "/config", "200 OK (Statistics Reset)");
            server.sendHeader("Location", "/config");
            server.send(303);
            return;
        }

        if (server.hasArg("generate_key")) {
            for (size_t i = 0; i < sizeof(server_privkey); i++) {
                server_privkey[i] = random(256);
            }
            ecdsa_get_public_key33(&secp256k1, server_privkey, server_pubkey);
            saveConfig();
            addLog(client_ip, "/config", "200 OK (Random Server Key Generated)");
            server.sendHeader("Location", "/config");
            server.send(303);
            return;
        }

        String requested_name = server.arg("mdns_name");
        String requested_key = server.arg("privkey_hex");
        if (requested_name.length() == 0 || requested_name.length() > 31) {
            addLog(client_ip, "/config", "400 Invalid mDNS name");
            server.send(400, "text/plain", "mDNS name must contain between 1 and 31 characters.");
            return;
        }
        if (requested_key.length() != 64) {
            addLog(client_ip, "/config", "400 Invalid private key");
            server.send(400, "text/plain", "Private key must contain exactly 64 hexadecimal characters.");
            return;
        }
        mdns_name = requested_name;
        hexToBytes(requested_key, server_privkey, 32);
        ecdsa_get_public_key33(&secp256k1, server_privkey, server_pubkey);
        enable_diagnostics = server.hasArg("enable_diag");
        enable_led_activity = server.hasArg("enable_led");
        saveConfig();
        startMDNS();
        addLog(client_ip, "/config", "200 OK (Parameters Saved)");
        server.sendHeader("Location", "/config");
        server.send(303);
        return;
    }

    addLog(client_ip, "/config", "200 OK");
    String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    html += UNIFIED_CSS;
    html += "</head><body>";
    html += pageNav("config");
    html += "<div class='card'><h1>Configuration</h1>";
    html += "<p>Change the mDNS name and diagnostic endpoint availability, then save the parameters.</p>";
    html += "<form method='POST'>";
    html += "<div class='info-item'><strong>mDNS Broadcast Name</strong><input type='text' name='mdns_name' value='" + mdns_name + "' required maxlength='31' pattern='[A-Za-z0-9-]+'></div>";
    html += "<div class='info-item'><strong>Server Private Key (64 hex characters)</strong><input type='text' name='privkey_hex' value='" + bytesToHex(server_privkey, 32) + "' required pattern='[0-9a-fA-F]{64}'></div>";
    html += "<div class='info-item'><strong>Server Public Key (Hex - Readonly)</strong><input type='text' value='" + bytesToHex(server_pubkey, 33) + "' readonly></div>";
    html += "<div class='info-item'><label class='checkbox-container'><input type='checkbox' name='enable_diag' value='1'" + String(enable_diagnostics ? " checked" : "") + ">Enable Diagnostics Endpoints</label></div>";
    html += "<div class='info-item'><label class='checkbox-container'><input type='checkbox' name='enable_led' value='1'" + String(enable_led_activity ? " checked" : "") + ">Enable blue LED request flash</label></div>";
    html += "<input type='submit' value='SAVE PARAMETERS'>";
    html += "</form>";
    html += "<h2 style='margin-top:30px;'>Request Statistics</h2>";
    html += "<div class='stats-grid'>";
    html += "<div class='info-item'><strong>Save PIN / OK</strong><span class='badge' style='color:#00E676;'>" + String(pin_save_successes) + "</span></div>";
    html += "<div class='info-item'><strong>Save PIN / Error</strong><span class='badge' style='color:#FF3D00;'>" + String(pin_save_errors) + "</span></div>";
    html += "<div class='info-item'><strong>Get PIN / Successful</strong><span class='badge' style='color:#00E676;'>" + String(saved_pin_successes) + "</span></div>";
    html += "<div class='info-item'><strong>Get PIN / Not Successful</strong><span class='badge' style='color:#FF3D00;'>" + String(saved_pin_failures) + "</span></div>";
    html += "</div>";
    html += "<h2 style='margin-top:30px;'>Security</h2>";
    html += "<div class='danger-zone'>";
    html += "<form method='POST' onsubmit='return confirm(\"Reset all request statistics?\");'>";
    html += "<input type='hidden' name='reset_stats' value='1'>";
    html += "<input type='submit' class='btn-danger' value='RESET REQUEST STATISTICS'>";
    html += "</form>";
    html += "<form method='POST' onsubmit='return confirm(\"Generate a new random server key? The current key and public key will be replaced.\");'>";
    html += "<input type='hidden' name='generate_key' value='1'>";
    html += "<input type='submit' class='btn-danger' value='GENERATE NEW SERVER KEY'>";
    html += "</form>";
    html += "<form method='POST' action='/' style='margin-top:25px;' onsubmit='return confirm(\"Wipe all records permanently?\");'>";
    html += "<input type='hidden' name='wipe_pins' value='1'>";
    html += "<input type='submit' class='btn-danger' style='margin-top:0;' value='WIPE ENTIRE DATABASE'>";
    html += "</form></div></div></body></html>";
    server.send(200, "text/html", html);
}

void handleShare() {
    if (!requireStorageAccess()) return;
    flashRequestLed();
    String client_ip = server.client().remoteIP().toString();

    if (server.method() == HTTP_POST) {
        String requested_url_a = server.arg("url_a");
        String requested_url_b = server.arg("url_b");
        if (!validPairingUrl(requested_url_a) || !validPairingUrl(requested_url_b)) {
            addLog(client_ip, "/share", "400 Invalid pairing URL");
            server.send(400, "text/plain", "Both URLs must be valid HTTP or HTTPS URLs (maximum 255 characters).");
            return;
        }
        pairing_url_a = requested_url_a;
        pairing_url_b = requested_url_b;
        saveConfig();
        addLog(client_ip, "/share", "200 OK (Pairing URLs Saved)");
        server.sendHeader("Location", "/share");
        server.send(303);
        return;
    }

    addLog(client_ip, "/share", "200 OK");

    String ip_addr = WiFi.localIP().toString();
    String pub_hex = bytesToHex(server_pubkey, 33);
    String default_url_a = "http://" + ip_addr + ":80";
    String default_url_b = "http://" + mdns_name + ".local:80";
    String effective_url_a = pairing_url_a.length() > 0 ? pairing_url_a : default_url_a;
    String effective_url_b = pairing_url_b.length() > 0 ? pairing_url_b : default_url_b;
    
    String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    html += "<script src='https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js'></script>";
    html += UNIFIED_CSS;
    html += "</head><body>";
    html += pageNav("pairing");
    html += "<div class='card'>";
    html += "<h1>Pairing Setup</h1>";
    html += "<p>Scan the QR below with your Jade camera to auto-configure this device as its remote oracle.</p>";
    html += "<div style='text-align:center;'><div id='qrcode'></div></div>";
    
    html += "<form method='POST'>";
    html += "<div class='info-item' style='margin-top:20px;'><strong>URL A (Primary)</strong><input id='urlA' name='url_a' type='text' value='" + htmlEscape(effective_url_a) + "' oninput='updateQRCode()' maxlength='255' required placeholder='http://192.168.1.10:80'></div>";
    html += "<div class='info-item'><strong>URL B (Secondary)</strong><input id='urlB' name='url_b' type='text' value='" + htmlEscape(effective_url_b) + "' oninput='updateQRCode()' maxlength='255' required placeholder='http://espinserver.local:80'></div>";
    html += "<p style='margin-top:8px;'>Edit either URL to reconfigure the pairing data. The QR code updates automatically. Save to keep the URLs after reboot.</p>";
    html += "<input type='submit' value='SAVE PAIRING URLS'>";
    html += "</form>";
    html += "<div class='info-item'><strong>Server Public Key</strong><input type='text' value='" + pub_hex + "' readonly></div>";
    
    html += "</div>";
    
    html += "<script>";
    html += "const bytewords = ['ae', 'ad', 'ao', 'ax', 'aa', 'ah', 'am', 'at', 'ay', 'as', 'bk', 'bd', 'bn', 'bt', 'ba', 'bs', 'be', 'by', 'bg', 'bw', 'bb', 'bz', 'cm', 'ch', 'cs', 'cf', 'cy', 'cw', 'ce', 'ca', 'ck', 'ct', 'cx', 'cl', 'cp', 'cn', 'dk', 'da', 'ds', 'di', 'de', 'dt', 'dr', 'dn', 'dw', 'dp', 'dm', 'dl', 'dy', 'eh', 'ey', 'eo', 'ee', 'ec', 'en', 'em', 'et', 'es', 'ft', 'fr', 'fn', 'fs', 'fm', 'fh', 'fz', 'fp', 'fw', 'fx', 'fy', 'fe', 'fg', 'fl', 'fd', 'ga', 'ge', 'gr', 'gs', 'gt', 'gl', 'gw', 'gd', 'gy', 'gm', 'gu', 'gh', 'go', 'hf', 'hg', 'hd', 'hk', 'ht', 'hp', 'hh', 'hl', 'hy', 'he', 'hn', 'hs', 'id', 'ia', 'ie', 'ih', 'iy', 'io', 'is', 'in', 'im', 'je', 'jz', 'jn', 'jt', 'jl', 'jo', 'js', 'jp', 'jk', 'jy', 'kp', 'ko', 'kt', 'ks', 'kk', 'kn', 'kg', 'ke', 'ki', 'kb', 'lb', 'la', 'ly', 'lf', 'ls', 'lr', 'lp', 'ln', 'lt', 'lo', 'ld', 'le', 'lu', 'lk', 'lg', 'mn', 'my', 'mh', 'me', 'mo', 'mu', 'mw', 'md', 'mt', 'ms', 'mk', 'nl', 'ny', 'nd', 'ns', 'nt', 'nn', 'ne', 'nb', 'oy', 'oe', 'ot', 'ox', 'on', 'ol', 'os', 'pd', 'pt', 'pk', 'py', 'ps', 'pm', 'pl', 'pe', 'pf', 'pa', 'pr', 'qd', 'qz', 're', 'rp', 'rl', 'ro', 'rh', 'rd', 'rk', 'rf', 'ry', 'rn', 'rs', 'rt', 'se', 'sa', 'sr', 'ss', 'sk', 'sw', 'st', 'sp', 'so', 'sg', 'sb', 'sf', 'sn', 'to', 'tk', 'ti', 'tt', 'td', 'te', 'ty', 'tl', 'tb', 'ts', 'tp', 'ta', 'tn', 'uy', 'uo', 'ut', 'ue', 'ur', 'vt', 'vy', 'vo', 'vl', 've', 'vw', 'va', 'vd', 'vs', 'wl', 'wd', 'warm','wasp','wave','waxy','webs','what','when','whiz','wolf','work','yank','yawn','yell','yoga','yurt','zaps','zero','zest','zinc','zone','zoom'];";
    html += "function crc32(bytes) {";
    html += "  let crc = 0xFFFFFFFF;";
    html += "  for (let i = 0; i < bytes.length; i++) {";
    html += "    crc ^= bytes[i];";
    html += "    for (let j = 0; j < 8; j++) {";
    html += "      if (crc & 1) crc = (crc >>> 1) ^ 0xEDB88320;";
    html += "      else crc = crc >>> 1;";
    html += "    }";
    html += "  }";
    html += "  return (crc ^ 0xFFFFFFFF) >>> 0;";
    html += "}";
    html += "function encodeString(bytes, str) {";
    html += "  let len = str.length;";
    html += "  if (len < 24) bytes.push(0x60 + len);";
    html += "  else if (len < 256) { bytes.push(0x78); bytes.push(len); }";
    html += "  else { bytes.push(0x79); bytes.push((len >>> 8) & 0xFF); bytes.push(len & 0xFF); }";
    html += "  for (let i = 0; i < len; i++) bytes.push(str.charCodeAt(i));";
    html += "}";
    html += "function encodeCBOR(urlA, urlB, pubkeyHex) {";
    html += "  let bytes = [];";
    html += "  bytes.push(0xa3);"; // Map of 3 items (method, id, params)
    html += "  bytes.push(0x66);"; // Key "method"
    html += "  for (let c of 'method') bytes.push(c.charCodeAt(0));";
    html += "  bytes.push(0x70);"; // Value "update_pinserver"
    html += "  for (let c of 'update_pinserver') bytes.push(c.charCodeAt(0));";
    html += "  bytes.push(0x62);"; // Key "id"
    html += "  for (let c of 'id') bytes.push(c.charCodeAt(0));";
    html += "  bytes.push(0x63); bytes.push(0x30); bytes.push(0x30); bytes.push(0x31);"; // Value "001"
    html += "  bytes.push(0x66);"; // Key "params"
    html += "  for (let c of 'params') bytes.push(c.charCodeAt(0));";
    html += "  bytes.push(0xa3);"; // Map of 3 items
    html += "  bytes.push(0x64);"; // Key "urlA"
    html += "  for (let c of 'urlA') bytes.push(c.charCodeAt(0));";
    html += "  encodeString(bytes, urlA);"; // urlA is a complete HTTP URL
    html += "  bytes.push(0x64);"; // Key "urlB"
    html += "  for (let c of 'urlB') bytes.push(c.charCodeAt(0));";
    html += "  encodeString(bytes, urlB);"; // urlB is a complete HTTP URL
    html += "  bytes.push(0x66);"; // Key "pubkey"
    html += "  for (let c of 'pubkey') bytes.push(c.charCodeAt(0));";
    html += "  bytes.push(0x58); bytes.push(0x21);"; // Byte string of 33 bytes
    html += "  for (let i = 0; i < 33; i++) bytes.push(parseInt(pubkeyHex.substr(i*2, 2), 16));";
    html += "  return new Uint8Array(bytes);";
    html += "}";
    html += "function generateUR(urlA, urlB, pubkeyHex) {";
    html += "  let cborBytes = encodeCBOR(urlA, urlB, pubkeyHex);";
    html += "  let c = crc32(cborBytes);";
    html += "  let full = new Uint8Array(cborBytes.length + 4);";
    html += "  full.set(cborBytes);";
    html += "  full[cborBytes.length] = (c >>> 24) & 0xFF;";
    html += "  full[cborBytes.length + 1] = (c >>> 16) & 0xFF;";
    html += "  full[cborBytes.length + 2] = (c >>> 8) & 0xFF;";
    html += "  full[cborBytes.length + 3] = c & 0xFF;";
    html += "  let encoded = '';";
    html += "  for (let b of full) { let word = bytewords[b]; encoded += word.length === 2 ? word : word[0] + word[word.length - 1]; }";
    html += "  return 'UR:JADE-UPDPS/' + encoded.toUpperCase();";
    html += "}";
    
    html += "function updateQRCode() {";
    html += "  const urlA = document.getElementById('urlA').value.trim();";
    html += "  const urlB = document.getElementById('urlB').value.trim();";
    html += "  if (!urlA || !urlB) return;";
    html += "  const ur = generateUR(urlA, urlB, '" + pub_hex + "');";
    html += "  console.log('UR generated:', ur);";
    html += "  try { let qr = qrcode(0, 'L'); qr.addData(ur, 'Alphanumeric'); qr.make(); document.getElementById('qrcode').innerHTML = qr.createImgTag(4, 0); console.log('QR code generated'); } catch(e) { console.error('QR generation error:', e); document.getElementById('qrcode').innerHTML = '<p style=\"color:red;\">Error: ' + e.message + '</p>'; }";
    html += "}";
    html += "updateQRCode();";
    html += "</script>";
    html += "</body></html>";
    
    server.send(200, "text/html", html);
}

void handleDiagnostics() {
    if (!requireStorageAccess()) return;
    flashRequestLed();
    String client_ip = server.client().remoteIP().toString();
    if (!enable_diagnostics) {
        addLog(client_ip, "/diagnostics", "403 Forbidden");
        server.send(403, "text/plain", "Forbidden - Diagnostics pages are disabled in parameters.");
        return;
    }

    addLog(client_ip, "/diagnostics", "200 OK");

    String html = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    html += UNIFIED_CSS;
    html += "</head><body>";
    html += pageNav("diagnostics");
    html += "<div class='card' style='max-width:650px;'>";
    html += "<h1>Database Diagnostics</h1>";
    html += "<p>PIN records and their timestamps are stored in flash. Connection logs below are kept in RAM only.</p>";
    
    html += "<table><thead><tr><th>Index</th><th>Wallet Pubkey Hash</th><th>Attempts</th><th>Get OK</th><th>Get Error</th><th>Created</th><th>Last Attempt</th></tr></thead><tbody>";
    int active_records = 0;
    for (int i = 0; i < MAX_PINS; i++) {
        if (pin_db[i].valid) {
            active_records++;
            html += "<tr>";
            html += "<td>" + String(i) + "</td>";
            html += "<td><small>" + bytesToHex(pin_db[i].pin_pubkey_hash, 8) + "...</small></td>";
            html += "<td><span class='badge' style='color:" + String(pin_db[i].attempts > 0 ? "#FF3D00" : "#00E676") + ";'>" + String(pin_db[i].attempts) + "/3</span></td>";
            html += "<td><span class='badge' style='color:#00E676;'>" + String(pin_db[i].get_successes) + "</span></td>";
            html += "<td><span class='badge' style='color:#FF3D00;'>" + String(pin_db[i].get_failures) + "</span></td>";
            html += "<td><small>" + formatTimestamp(pin_db[i].created_timestamp) + "</small></td>";
            html += "<td><small>" + formatTimestamp(pin_db[i].last_attempt_timestamp) + "</small></td>";
            html += "</tr>";
        }
    }
    if (active_records == 0) {
        html += "<tr><td colspan='7' style='text-align:center;color:#8F8F9D;padding:20px;'>No active slots. Pair your Jade to begin.</td></tr>";
    }
    html += "</tbody></table>";

    html += "<h2 style='margin-top:30px;'>Connection Diagnostics</h2>";
    html += "<p>Last 50 connections received by the ESP32 (stored only in RAM).</p>";
    html += "<table><thead><tr><th>Time</th><th>Client IP</th><th>Endpoint</th><th>Status</th></tr></thead><tbody>";
    uint32_t now = millis();
    int connection_count = 0;
    for (int i = 0; i < MAX_LOGS; i++) {
        int idx = (log_index - 1 - i + MAX_LOGS) % MAX_LOGS;
        if (conn_logs[idx].valid) {
            connection_count++;
            uint32_t elapsed = now - conn_logs[idx].timestamp;
            if (now < conn_logs[idx].timestamp) elapsed = 0;
            String time_str;
            if (elapsed < 1000) time_str = "Just now";
            else if (elapsed < 60000) time_str = String(elapsed / 1000) + "s ago";
            else time_str = String(elapsed / 60000) + "m ago";
            String ep = conn_logs[idx].endpoint;
            String ep_color = ep == "/set_pin" ? "#00E676" : (ep == "/get_pin" ? "#00B0FF" : "#ECECF1");
            String stat = conn_logs[idx].status;
            String stat_color = stat == "200 OK" ? "#00E676" : (stat.startsWith("429") ? "#FF9100" : (stat.startsWith("403") || stat.startsWith("400") ? "#FF3D00" : "#ECECF1"));
            html += "<tr><td>" + time_str + "</td><td>" + conn_logs[idx].client_ip + "</td><td style='color:" + ep_color + ";font-weight:bold;'>" + ep + "</td><td style='color:" + stat_color + ";'>" + stat + "</td></tr>";
        }
    }
    if (connection_count == 0) html += "<tr><td colspan='4' style='text-align:center;color:#8F8F9D;padding:20px;'>No connection logs recorded yet.</td></tr>";
    html += "</tbody></table>";
    html += "</div></body></html>";
    server.send(200, "text/html", html);
}

void handlePinRequest(bool is_set) {
    if (!requireStorageAccess(true)) return;
    flashRequestLed();
    String client_ip = server.client().remoteIP().toString();
    String endpoint = is_set ? "/set_pin" : "/get_pin";

    // Count every PIN-save request as an error first. A successful response
    // converts it to the success counter at the end of the handler.
    if (is_set) {
        pin_save_errors++;
        saveConfig();
    }

    if (server.method() != HTTP_POST) {
        addLog(client_ip, endpoint, "405 Method Not Allowed");
        server.send(405, "text/plain", "Method Not Allowed");
        return;
    }
    if (!server.hasArg("plain")) {
        addLog(client_ip, endpoint, "400 Bad Request (Missing body)");
        server.send(400, "text/plain", "Bad Request");
        return;
    }
    
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, server.arg("plain"));
    if (err || !doc["data"].is<const char*>()) {
        addLog(client_ip, endpoint, "400 Bad Request (Invalid JSON)");
        server.send(400, "text/plain", "Invalid JSON");
        return;
    }
    
    const char* b64_in = doc["data"];
    size_t req_data_len = 0;
    mbedtls_base64_decode(NULL, 0, &req_data_len, (const unsigned char*)b64_in, strlen(b64_in));
    uint8_t* req_data = (uint8_t*)malloc(req_data_len);
    mbedtls_base64_decode(req_data, req_data_len, &req_data_len, (const unsigned char*)b64_in, strlen(b64_in));
    
    if (req_data_len < 33 + 4 + 16 + 32 + 1) { // minimum size check
        free(req_data);
        addLog(client_ip, endpoint, "400 Bad Request (Data too small)");
        server.send(400, "text/plain", "Data too small");
        return;
    }
    
    uint8_t cke[33];
    uint8_t replay_counter[4];
    memcpy(cke, req_data, 33);
    memcpy(replay_counter, req_data + 33, 4);
    
    uint8_t* encrypted = req_data + 37;
    size_t encrypted_len = req_data_len - 37;
    
    uint8_t d_e[32];
    if (!derive_ephemeral_privkey(server_privkey, cke, replay_counter, d_e)) {
        free(req_data);
        addLog(client_ip, endpoint, "500 Crypto derivation error");
        server.send(500, "text/plain", "Crypto error");
        return;
    }
    
    uint8_t* decrypted = (uint8_t*)malloc(encrypted_len);
    size_t decrypted_len = 0;
    if (!decrypt_payload(d_e, cke, "blind_oracle_request", encrypted, encrypted_len, decrypted, &decrypted_len)) {
        free(req_data);
        free(decrypted);
        addLog(client_ip, endpoint, "400 Decryption failed");
        server.send(400, "text/plain", "Decryption failed");
        return;
    }
    free(req_data);
    
    if (decrypted_len < 32 + 65) {
        free(decrypted);
        addLog(client_ip, endpoint, "400 Invalid payload length");
        server.send(400, "text/plain", "Invalid payload length");
        return;
    }
    
    uint8_t pin_secret[32];
    memcpy(pin_secret, decrypted, 32);
    
    size_t entropy_len = decrypted_len - 32 - 65;
    uint8_t* entropy = entropy_len > 0 ? (decrypted + 32) : NULL;
    uint8_t* signature = decrypted + 32 + entropy_len;
    
    uint8_t pin_pubkey[33];
    if (!recover_pubkey(cke, replay_counter, pin_secret, entropy, entropy_len, signature, pin_pubkey)) {
        free(decrypted);
        addLog(client_ip, endpoint, "400 Signature recovery failed");
        server.send(400, "text/plain", "Signature recovery failed");
        return;
    }
    free(decrypted);
    
    uint8_t pin_pubkey_hash[32];
    crypto_sha256(pin_pubkey, 33, pin_pubkey_hash);
    
    // Look up in DB by pin_pubkey_hash (Correct blind oracle security!)
    int slot = -1;
    for (int i = 0; i < MAX_PINS; i++) {
        if (pin_db[i].valid && memcmp(pin_db[i].pin_pubkey_hash, pin_pubkey_hash, 32) == 0) {
            slot = i;
            break;
        }
    }
    
    uint32_t client_ctr = replay_counter[0] | (replay_counter[1] << 8) | (replay_counter[2] << 16) | (replay_counter[3] << 24);
    uint8_t final_aes_key[32];
    bool saved_pin_verified = false;
    
    if (is_set) {
        if (slot == -1) {
            // Find empty slot
            for (int i = 0; i < MAX_PINS; i++) {
                if (!pin_db[i].valid) {
                    slot = i;
                    break;
                }
            }
        }
        if (slot == -1) {
            addLog(client_ip, endpoint, "500 No empty slots available");
            server.send(500, "text/plain", "No empty slots");
            return;
        }
        
        // Generate new random saved_key
        uint8_t saved_key[32];
        for (int i = 0; i < 32; i++) saved_key[i] = random(256);
        
        memcpy(pin_db[slot].pin_pubkey_hash, pin_pubkey_hash, 32);
        crypto_sha256(pin_secret, 32, pin_db[slot].hash_pin_secret);
        memcpy(pin_db[slot].aes_key, saved_key, 32);
        pin_db[slot].attempts = 0;
        memcpy(pin_db[slot].replay_counter, replay_counter, 4);
        pin_db[slot].last_attempt_time = millis();
        uint32_t request_timestamp = localTimestamp();
        pin_db[slot].created_timestamp = request_timestamp;
        pin_db[slot].last_attempt_timestamp = request_timestamp;
        pin_db[slot].valid = true;
        savePins();
        
        hmac_crypto_sha256(saved_key, 32, pin_secret, 32, final_aes_key);
        addLog(client_ip, endpoint, "200 OK (New PIN Created)");
    } else {
        if (slot == -1) {
            // Blind security: if not found, return random dummy response
            uint8_t dummy_key[32];
            for (int i = 0; i < 32; i++) dummy_key[i] = random(256);
            hmac_crypto_sha256(dummy_key, 32, pin_secret, 32, final_aes_key);
            addLog(client_ip, endpoint, "200 OK (Blind Dummy Served)");
        } else {
            // Persist the time as soon as a stored record is addressed, including
            // replay and cooldown failures, so diagnostics show the real latest use.
            pin_db[slot].last_attempt_timestamp = localTimestamp();
            pin_db[slot].get_failures++;
            saved_pin_failures++;
            saveConfig();
            savePins();

            // Anti-replay check
            uint32_t stored_ctr = pin_db[slot].replay_counter[0] | (pin_db[slot].replay_counter[1] << 8) | (pin_db[slot].replay_counter[2] << 16) | (pin_db[slot].replay_counter[3] << 24);
            if (client_ctr <= stored_ctr) {
                addLog(client_ip, endpoint, "400 Replay Attack Blocked");
                server.send(400, "text/plain", "Anti-replay check failed");
                return;
            }
            
            // Progressive Cooldown Delay (Tarpitting - Idea 2!)
            uint32_t now = millis();
            uint32_t elapsed = now - pin_db[slot].last_attempt_time;
            if (now < pin_db[slot].last_attempt_time) elapsed = now; // rollover check
            
            uint32_t required_delay = 0;
            if (pin_db[slot].attempts == 1) required_delay = 5000;       // 5 seconds
            else if (pin_db[slot].attempts == 2) required_delay = 60000; // 1 minute
            
            if (elapsed < required_delay) {
                uint32_t wait_sec = (required_delay - elapsed) / 1000 + 1;
                addLog(client_ip, endpoint, "429 Tarpit Cooldown Active");
                server.send(429, "text/plain", "Too Many Requests. Cooldown: " + String(wait_sec) + "s");
                return;
            }
            
            pin_db[slot].last_attempt_time = now;
            memcpy(pin_db[slot].replay_counter, replay_counter, 4);
            
            uint8_t hash_pin_secret[32];
            crypto_sha256(pin_secret, 32, hash_pin_secret);
            
            if (memcmp(hash_pin_secret, pin_db[slot].hash_pin_secret, 32) == 0) {
                // Correct pin! Reset attempts
                pin_db[slot].attempts = 0;
                saved_pin_verified = true;
                savePins();
                hmac_crypto_sha256(pin_db[slot].aes_key, 32, pin_secret, 32, final_aes_key);
                addLog(client_ip, endpoint, "200 OK (PIN Verified)");
            } else {
                // Incorrect pin!
                pin_db[slot].attempts++;
                if (pin_db[slot].attempts >= 3) {
                    pin_db[slot].valid = false; // Delete row permanently!
                    savePins();
                    addLog(client_ip, endpoint, "403 Brute Force Wiped Row");
                    server.send(403, "Rate limit exceeded. Slot deleted.");
                    return;
                }
                savePins();
                
                // Return dummy key to avoid disclosing failure
                uint8_t dummy_key[32];
                for (int i = 0; i < 32; i++) dummy_key[i] = random(256);
                hmac_crypto_sha256(dummy_key, 32, pin_secret, 32, final_aes_key);
                addLog(client_ip, endpoint, "200 OK (Wrong PIN - Dummy Served)");
            }
        }
    }
    
    uint8_t resp_encrypted[128];
    size_t resp_encrypted_len = 0;
    if (!encrypt_payload(d_e, cke, "blind_oracle_response", final_aes_key, 32, resp_encrypted, &resp_encrypted_len)) {
        server.send(500, "text/plain", "Encryption failed");
        return;
    }
    
    size_t b64_out_len = 0;
    mbedtls_base64_encode(NULL, 0, &b64_out_len, resp_encrypted, resp_encrypted_len);
    char* b64_out = (char*)malloc(b64_out_len + 1);
    mbedtls_base64_encode((unsigned char*)b64_out, b64_out_len, &b64_out_len, resp_encrypted, resp_encrypted_len);
    b64_out[b64_out_len] = 0;
    
    if (is_set) {
        pin_save_errors--;
        pin_save_successes++;
    } else if (slot != -1 && saved_pin_verified) {
        pin_db[slot].get_failures--;
        pin_db[slot].get_successes++;
        savePins();
        saved_pin_failures--;
        saved_pin_successes++;
    }
    saveConfig();
    
    doc.clear();
    doc["data"] = b64_out;
    String out_json;
    serializeJson(doc, out_json);
    free(b64_out);
    
    server.send(200, "application/json", out_json);
}

void setup() {
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);
    LittleFS.begin(true);
    preferences.begin("espinserver", false);
    
    crypto_init();
    loadConfig();
    loadPins();
    
    WiFiManager wm;
    wm.autoConnect("ESPinServer-Setup");
    updateLocalTime();
    
    startMDNS();
    
    server.on("/auth", handleAuth);
    server.on("/", handleRoot);
    server.on("/share", handleShare);
    server.on("/config", handleConfig);
    server.on("/diagnostics", handleDiagnostics);
    server.on("/get_pin", [](){ handlePinRequest(false); });
    server.on("/set_pin", [](){ handlePinRequest(true); });
    
    server.begin();
    Serial.println("Server started.");
}

void loop() {
    server.handleClient();
}
