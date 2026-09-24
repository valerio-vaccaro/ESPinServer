#ifndef ESPINSERVER_TLS_CREDENTIALS_H
#define ESPINSERVER_TLS_CREDENTIALS_H

#include <Arduino.h>
#include <IPAddress.h>
#include <Preferences.h>

bool loadOrGenerateTlsCredentials(Preferences& preferences, const String& mdns_name,
                                  const IPAddress& address, String& certificate_pem,
                                  String& private_key_pem);

bool regenerateTlsCredentials(Preferences& preferences, const String& mdns_name,
                              const IPAddress& address, String& certificate_pem,
                              String& private_key_pem);

#endif
