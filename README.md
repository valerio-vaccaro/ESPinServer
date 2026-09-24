# ESPinServer

ESPinServer is an ESP32-based research implementation of a local,
Blockstream-style PIN server for [Blockstream Jade](https://github.com/Blockstream/Jade)
interoperability testing.

> **Research use only**
>
> Do not use this firmware with production funds, real wallet PINs, or
> credentials that require strong physical-attack resistance. The PIN database
> is encrypted at rest, but the server private key and configuration remain in
> ESP32 NVS. The firmware is experimental and unaudited.

## Start here

The complete first-time setup is in the [step-by-step tutorial](docs/TUTORIAL.md).
The shortest path is:

1. Build and flash an ESP32 with PlatformIO.
2. Join the `ESPinServer-Setup` Wi-Fi network and configure local Wi-Fi.
3. Open the HTTPS administration page and create or enter the storage password.
4. Open **Pairing**, scan its QR code with a Jade, and test with a disposable PIN.

The project also has a [web documentation site](https://valerio-vaccaro.github.io/ESPinServer/)
with the tutorial, screenshots, protocol notes, and security model.

## What the firmware does

ESPinServer provides a local web administration interface and the Jade PIN-server
v2 blind-oracle API:

| Service | Address | Use |
| --- | --- | --- |
| Administration | `https://<device>:443` | Setup, pairing, configuration, and diagnostics |
| PIN API | `http://<device>:80/set_pin` | Create or replace a PIN record |
| PIN API | `http://<device>:80/get_pin` | Retrieve a key share after PIN verification |

The browser interface uses HTTPS with a device-generated self-signed certificate.
The two API endpoints intentionally remain on HTTP port 80 for Jade compatibility;
other HTTP paths redirect to HTTPS. Use an isolated, trusted test network.

The PIN database is locked until the storage password is entered after Wi-Fi is
available. On first boot, create a 12–64 character password containing uppercase,
lowercase, a number, and a symbol. The password is not stored.

## Web interface

- **Dashboard** — database slot usage, PIN request counters, and ESP32 status.
- **Pairing** — QR code, primary and secondary API URLs, and server public key.
- **Configuration** — mDNS name, server key, diagnostics and LED options,
  statistics reset, certificate refresh, key generation, and database wipe.
- **Diagnostics** — PIN-record metadata and recent in-memory connection logs;
  PINs are never displayed.

Use `https://espinserver.local/` when mDNS works, or the device IP address shown
by your router or serial monitor. The Pairing page's API URLs must use `http://`
and port `80`; they are different from the HTTPS address used by the browser.

## Build and flash

The repository includes a local PlatformIO environment. From the repository root:

```sh
./venv/bin/pio run
```

Build a specific board and upload it over USB:

```sh
./venv/bin/pio run -e esp32dev -t upload
./venv/bin/pio device monitor -b 115200
```

For an ESP32-S3 DevKitC-1, use `-e esp32-s3-devkitc-1`. If PlatformIO cannot
find the serial port, add `--upload-port <port>` to the upload command. The
available environments and their partition layout are defined in
[`platformio.ini`](platformio.ini).

Prebuilt browser-flasher artifacts are produced by GitHub Actions. The workflow
builds both board environments and packages the four binaries plus `index.json`
for the [ESPinServer-compatible browser flasher](https://valerio-vaccaro.github.io/diyflasher/).

## Technical reference

- [Step-by-step tutorial](docs/TUTORIAL.md)
- [Protocol implementation notes](docs/PINSERVER_PROTOCOL.md)
- [Protocol overview](docs/protocol.html)
- [Security model and limitations](docs/security.html)
- [Web documentation](https://valerio-vaccaro.github.io/ESPinServer/)

The protocol implementation includes ECDH-derived request and response keys,
AES-256-CBC/HMAC-SHA256 encrypted envelopes, replay counters, progressive
failed-attempt cooldowns, and dummy responses for unknown or incorrect PINs.

## Related resources

- [Blockstream Jade](https://github.com/Blockstream/Jade)
- [Jade scripted PIN-server setup](https://github.com/Blockstream/Jade/blob/master/set_jade_pinserver.py)
- [Blockstream DIY Jade flasher](https://github.com/Blockstream/jadediyflasher)
- [ESPinServer-compatible DIY flasher](https://valerio-vaccaro.github.io/diyflasher/)
- [Blockstream firmware update notes](https://github.com/Blockstream/Jade/blob/master/FWUPDATE.md)

## Development checks

Build all PlatformIO environments with:

```sh
./venv/bin/pio run
```

The integration tests target a running, disposable ESPinServer and deliberately
wipe its PIN database before and after the test session. They require the
additional client dependencies described in the test file:

```sh
./venv/bin/python -m pytest -q tests/test_pinserver_integration.py \
  --pinserver-url http://espinserver.local
```

Do not point this suite at a device containing data you want to keep.
