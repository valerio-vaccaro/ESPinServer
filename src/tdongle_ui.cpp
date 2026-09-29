#include "tdongle_ui.h"

#ifdef ESPIN_TDONGLE

#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <FastLED.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace {
constexpr int TFT_CS = 4;
constexpr int TFT_MOSI = 3;
constexpr int TFT_SCLK = 5;
constexpr int TFT_DC = 2;
constexpr int TFT_RST = 1;
constexpr int RGB_DATA = 40;
constexpr int RGB_CLOCK = 39;

Adafruit_ST7735 display(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);
CRGB led[1];
String current_status = "BOOT";
volatile bool activity_pending = false;
uint32_t last_animation = 0;
int last_page = -1;
int rendered_page = -1;
String rendered_ip;
bool rendered_wifi = false;
bool rendered_unlocked = false;
int rendered_active = -1;
int rendered_max = -1;
uint32_t rendered_save_ok = 0;
uint32_t rendered_save_errors = 0;
uint32_t rendered_get_ok = 0;
uint32_t rendered_get_errors = 0;
TaskHandle_t wifi_animation_task = nullptr;
volatile bool wifi_animation_running = false;

void setLed(const CRGB& color, uint8_t brightness = 48) {
    led[0] = color;
    FastLED.setBrightness(brightness);
    FastLED.show();
}

// The T-Dongle panel presents the RGB565 red and blue channels reversed.
uint16_t panelColor(uint16_t color) {
    uint16_t red = (color >> 11) & 0x1F;
    uint16_t green = (color >> 5) & 0x3F;
    uint16_t blue = color & 0x1F;
    return (blue << 11) | (green << 5) | red;
}

void writeLine(int y, const String& text, uint16_t color = ST7735_WHITE, uint8_t size = 1) {
    // Keep the large type for normal labels, but fit long SSIDs/IP strings
    // using the compact font instead of truncating them at the screen edge.
    if (size == 2 && text.length() > 13) size = 1;
    display.setTextSize(size);
    display.setCursor(0, y);
    display.setTextColor(panelColor(color), 0x0000);
    display.print(text.substring(0, size == 2 ? 13 : 26));
}

void drawKnightRider(uint32_t now) {
    if (now - last_animation < 100) return;
    last_animation = now;

    int phase = (now / 100) % 44;
    int position = phase <= 22 ? phase : 44 - phase;
    int x = position * 6;
    display.fillRect(0, 68, 160, 12, 0x0000);
    display.setTextSize(1);
    display.setCursor(x, 68);
    display.setTextColor(panelColor(ST7735_RED), 0x0000);
    display.print("***");
}

void wifiAnimationTask(void*) {
    while (wifi_animation_running) {
        drawKnightRider(millis());
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    wifi_animation_task = nullptr;
    vTaskDelete(nullptr);
}
}

void boardUiBegin() {
    FastLED.addLeds<APA102, RGB_DATA, RGB_CLOCK, BGR>(led, 1);
    setLed(CRGB::Yellow, 40);

    // The T-Dongle display is an 80x160 ST7735 rotated to a 160x80 layout.
    // T-Dongle-S3 uses the inverted ST7735 160x80 panel variant.
    display.initR(INITR_MINI160x80_PLUGIN);
    display.setRotation(1);
    display.fillScreen(0x0000);
    display.setTextWrap(false);
    writeLine(0, "ESPinServer", ST7735_CYAN, 2);
    writeLine(24, "Starting...", ST7735_YELLOW, 1);
}

void boardUiShowWifiSetup(const String& ssid, const String& password, const String& ip) {
    display.enableDisplay(true);
    display.fillScreen(0x0000);
    writeLine(0, "Configuration", ST7735_YELLOW, 2);
    writeLine(20, "SSID " + ssid, ST7735_CYAN, 1);
    writeLine(36, "PASS " + password, ST7735_WHITE, 1);
    writeLine(52, "IP " + ip, ST7735_GREEN, 1);
    drawKnightRider(millis());
}

void boardUiStartWifiAnimation() {
    if (wifi_animation_task) return;
    wifi_animation_running = true;
    xTaskCreatePinnedToCore(wifiAnimationTask, "lcd_knight_rider", 3072,
                            nullptr, 1, &wifi_animation_task, 1);
}

void boardUiStopWifiAnimation() {
    wifi_animation_running = false;
    while (wifi_animation_task) delay(10);
}

void boardUiSetStatus(const char* status) {
    current_status = status;
}

void boardUiRequestActivity() {
    activity_pending = true;
}

void boardUiUpdate(const String& ip, bool wifi_connected, bool unlocked,
                  int active_records, int max_records,
                  uint32_t save_ok, uint32_t save_errors,
                  uint32_t get_ok, uint32_t get_errors) {
    uint32_t now = millis();

    int page = (now / 3000) % 2;
    bool screen_changed = page != rendered_page || ip != rendered_ip ||
                          wifi_connected != rendered_wifi || unlocked != rendered_unlocked ||
                          active_records != rendered_active || max_records != rendered_max ||
                          save_ok != rendered_save_ok || save_errors != rendered_save_errors ||
                          get_ok != rendered_get_ok || get_errors != rendered_get_errors;
    bool activity = activity_pending;
    activity_pending = false;

    if (activity) {
        setLed(CRGB::Blue, 64);
    } else if (screen_changed) {
        // Green means the encrypted store is locked. Red means it is open and
        // usable; capacity is shown on the display rather than changing the
        // security-state indicator.
        CRGB status_color = unlocked ? CRGB::Red : CRGB(0, 180, 40);
        setLed(status_color, 48);
    }

    if (!screen_changed) return;

    rendered_page = page;
    rendered_ip = ip;
    rendered_wifi = wifi_connected;
    rendered_unlocked = unlocked;
    rendered_active = active_records;
    rendered_max = max_records;
    rendered_save_ok = save_ok;
    rendered_save_errors = save_errors;
    rendered_get_ok = get_ok;
    rendered_get_errors = get_errors;
    last_page = page;

    display.fillScreen(0x0000);
    writeLine(0, "ESPinServer", ST7735_CYAN, 2);
    if (page == 0) {
        writeLine(16, wifi_connected ? (unlocked ? "READY" : "LOCKED") : "WIFI OFF",
                  wifi_connected ? ST7735_GREEN : ST7735_RED, 2);
        writeLine(32, "IP " + (wifi_connected ? ip : String("--")), ST7735_YELLOW, 2);
        writeLine(48, "SLOTS " + String(active_records) + "/" + String(max_records),
                  active_records >= max_records ? ST7735_RED : ST7735_WHITE, 2);
    } else {
        writeLine(16, "SET " + String(save_ok) + "/" + String(save_errors), ST7735_GREEN, 2);
        writeLine(32, "GET " + String(get_ok) + "/" + String(get_errors), ST7735_GREEN, 2);
        writeLine(48, "USED " + String(active_records) + "/" + String(max_records), ST7735_YELLOW, 2);
    }
}

#else

void boardUiBegin() {}
void boardUiShowWifiSetup(const String&, const String&, const String&) {}
void boardUiStartWifiAnimation() {}
void boardUiStopWifiAnimation() {}
void boardUiSetStatus(const char*) {}
void boardUiRequestActivity() {}
void boardUiUpdate(const String&, bool, bool, int, int, uint32_t, uint32_t, uint32_t, uint32_t) {}

#endif
