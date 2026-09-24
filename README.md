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

The firmware exposes a local HTTP PIN server for DIY hardware. It implements
the Blockstream PIN-server v2 blind-oracle flow, including client key recovery,
encrypted requests and responses, replay counters, PIN-attempt cooldowns, and
dummy responses for unknown or incorrect PINs.

See the [PIN-server protocol notes](docs/PINSERVER_PROTOCOL.md) for the wire
format and implementation details.

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
