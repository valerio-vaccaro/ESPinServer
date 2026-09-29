#pragma once

#include <Arduino.h>

void boardUiBegin();
void boardUiShowWifiSetup(const String& ssid, const String& password, const String& ip);
void boardUiStartWifiAnimation();
void boardUiStopWifiAnimation();
void boardUiSetStatus(const char* status);
void boardUiRequestActivity();
void boardUiUpdate(const String& ip, bool wifi_connected, bool unlocked,
                  int active_records, int max_records,
                  uint32_t save_ok, uint32_t save_errors,
                  uint32_t get_ok, uint32_t get_errors);
