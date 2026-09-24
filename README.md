# ESPinServer — the ESP-based PinServer

ESP32-based research implementation of a local Blockstream-style PIN server.

> **Security warning — research use only**
>
> The PIN database is encrypted at rest in LittleFS with AES-256-CBC and
> HMAC-SHA256 keys derived from a browser-created storage password using
> PBKDF2-HMAC-SHA256. The password is not persisted and the database remains
> locked until it is entered after Wi-Fi activation. The server private key and
> configuration remain in the ESP32's NVS. Do not use this firmware in
> production, with real funds, or with credentials that need strong physical
> attack resistance. It is intended for research and interoperability testing.

## What it demonstrates

The firmware exposes a local HTTPS web interface for configuration. Pages are
served on port 443; the PIN API endpoints `/set_pin` and `/get_pin` remain
available over HTTP on port 80 for client compatibility, while other HTTP paths
redirect to HTTPS. On first boot the ESP32 generates and stores a
self-signed certificate for its mDNS hostname. Browsers will show a trust
warning until that certificate is explicitly trusted. It implements
the Blockstream PIN-server v2 blind-oracle flow, including client key recovery,
encrypted requests and responses, replay counters, PIN-attempt cooldowns, and
dummy responses for unknown or incorrect PINs.

See the [PIN-server protocol notes](docs/PINSERVER_PROTOCOL.md) for the wire
format and implementation details.

## Firmware web interface

After Wi-Fi setup, open `https://espinserver.local/` or the ESP32 IP address.
The first visit may show a browser warning because the ESP32 creates its own
self-signed certificate. The interface is protected by a storage password:
create it on first boot by entering it twice, or enter it once on later boots
to unlock the encrypted PIN database.

The interface contains four main pages:

- **Dashboard** shows database slot usage, PIN request counters, and hardware
  information such as chip model, CPU frequency, free heap, and temperature.
- **Pairing** shows the QR code, primary and secondary API URLs, and the server
  public key used by a Jade. The normal local API URLs are `http://<device-ip>:80`
  and `http://<mdns-name>.local:80`.
- **Configuration** changes the mDNS name, server key, diagnostics and LED
  options. It also provides controls to reset counters, refresh the self-signed
  HTTPS certificate, generate a new server key, or wipe the PIN database.
- **Diagnostics** displays stored PIN-record metadata and recent in-memory
  connection logs. It does not display PINs.

The browser pages use HTTPS on port 443. For Jade compatibility, the PIN API
uses HTTP on port 80 at `/set_pin` and `/get_pin`; other HTTP paths redirect to
HTTPS.

## Use ESPinServer with a Blockstream Jade

1. Flash ESPinServer, connect it to the same Wi-Fi network as the Jade, and
   unlock the web interface.
2. Open **Pairing** and confirm both URLs use `http://` and port `80`. Leave
   the server public key included in the generated QR code.
3. On the Jade, open its custom PIN-server configuration flow and scan the QR
   code shown by ESPinServer. Menu wording can vary between Jade firmware
   versions; the flow accepts the primary URL, optional secondary URL, and
   server public key.
4. Test the setup by locking and unlocking the Jade with a test PIN. The first
   successful setup creates a PIN record; later unlocks use `/get_pin`.

For scripted USB configuration, the Jade repository also provides
[`set_jade_pinserver.py`](https://github.com/Blockstream/Jade/blob/master/set_jade_pinserver.py),
which can set the two URLs and public key directly. Use test wallets and test
PINs only.

An informational documentation site is published at
[`valerio-vaccaro.github.io/ESPinServer`](https://valerio-vaccaro.github.io/ESPinServer/).
It includes setup, protocol, and security pages. GitHub Pages is deployed
automatically when files under `docs/` change on `main`.

## Related resources

- [Blockstream Jade repository](https://github.com/Blockstream/Jade)
- [Blockstream Jade DIY and development documentation](https://github.com/Blockstream/Jade#readme)
- [Blockstream DIY Jade flasher](https://github.com/Blockstream/jadediyflasher)
- [ESPinServer-compatible DIY flasher](https://valerio-vaccaro.github.io/diyflasher/)
- [Blockstream firmware update notes](https://github.com/Blockstream/Jade/blob/master/FWUPDATE.md)

## Build

Use the repository's local virtual environment:

```sh
./venv/bin/pio run
```

The GitHub Actions workflow builds every PlatformIO environment and publishes
browser-flasher-compatible binaries and `index.json` as an artifact.
