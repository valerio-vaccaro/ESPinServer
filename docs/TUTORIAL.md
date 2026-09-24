# ESPinServer step-by-step tutorial

This tutorial takes a blank ESP32 board from firmware build to a first test
PIN-server connection with a Blockstream Jade. Use a disposable test wallet
and PIN throughout.

## Before you begin

You need:

- an ESP32 or ESP32-S3 board supported by [`platformio.ini`](../platformio.ini);
- a USB data cable and a computer with the repository checked out;
- a 2.4 GHz Wi-Fi network that the ESP32 and Jade can both reach;
- a Blockstream Jade configured for custom PIN-server use;
- a test-only PIN and wallet.

The API is intentionally HTTP on port 80 for Jade compatibility. Do not expose
the device to the internet or use it on an untrusted network.

## 1. Build the firmware

From the repository root, build both configured environments:

```sh
./venv/bin/pio run
```

To build only one board, select its PlatformIO environment:

```sh
./venv/bin/pio run -e esp32dev
# or
./venv/bin/pio run -e esp32-s3-devkitc-1
```

If the local virtual environment is not available, install PlatformIO in your
usual Python environment and replace `./venv/bin/pio` with `pio`.

## 2. Flash the board

Connect the board by USB and upload the matching environment:

```sh
./venv/bin/pio run -e esp32dev -t upload
```

If there is more than one serial device, specify it explicitly:

```sh
./venv/bin/pio run -e esp32dev -t upload --upload-port /dev/ttyUSB0
```

You can also use the [browser flasher](https://valerio-vaccaro.github.io/diyflasher/)
with a packaged build. The repository's GitHub Actions build publishes the
bootloader, partition table, boot app, firmware, and manifest needed by that
flasher.

## 3. Configure Wi-Fi on first boot

1. Start a serial monitor at 115200 baud if you want to watch startup:

   ```sh
   ./venv/bin/pio device monitor -b 115200
   ```

2. On first boot, connect your computer or phone to the Wi-Fi network named
   `ESPinServer-Setup`.
3. Follow the captive portal to select the local Wi-Fi network and enter its
   password.
4. Return to the same local network. The board reconnects using the saved
   credentials on later boots.

If the captive portal does not open automatically, open the network's portal
notification or visit the address shown by the Wi-Fi setup page.

## 4. Open the administration page

After Wi-Fi connects, open one of these addresses in a browser:

```text
https://espinserver.local/
https://<device-ip>/
```

The device creates a self-signed certificate for its mDNS name. A browser trust
warning is expected. Inspect that you are connected to your own board, then
accept the certificate for this local test device.

If `espinserver.local` does not resolve, use the IP address reported by your
router or visible in the serial output. The administration page is HTTPS on
port 443; do not append `:80` to the browser URL.

## 5. Create or unlock the storage password

On a new device, the page asks you to create a storage password. Use a
12–64-character password containing all of the following:

- uppercase letter;
- lowercase letter;
- number;
- printable symbol.

Enter it twice. ESPinServer derives encryption and authentication keys and
creates the encrypted `/pins.bin` database. The password itself is not saved.

After a reboot, enter the same password once to unlock the database. The PIN
API remains unavailable with status `423` until this step is complete.

## 6. Check the server identity and pairing data

Open **Pairing** and confirm:

1. the primary URL is reachable from the Jade;
2. the secondary URL is a useful fallback;
3. both device-local URLs use `http://` and port `80`;
4. the displayed server public key belongs to this device.

The browser address remains HTTPS, but the QR code must contain the HTTP API
URLs. A typical pair looks like this:

```text
Browser:  https://192.168.1.42/
Primary:  http://192.168.1.42:80
Fallback: http://espinserver.local:80
```

Edit the URLs on the Pairing page if your network requires different names or
addresses, then save them before scanning the QR code.

## 7. Pair the Jade

1. On the Jade, open its custom PIN-server configuration flow.
2. Scan the QR code shown on ESPinServer's **Pairing** page.
3. Confirm the two URLs and server public key on the Jade.
4. Save the configuration.

Menu names vary between Jade firmware versions. If scanning is unavailable,
the official Jade repository provides
[`set_jade_pinserver.py`](https://github.com/Blockstream/Jade/blob/master/set_jade_pinserver.py)
for setting the URLs and public key over USB.

## 8. Perform a first test

Lock and unlock the Jade with the test PIN. The expected flow is:

```text
First setup      Jade -> POST /set_pin -> ESPinServer creates a record
Later unlock     Jade -> POST /get_pin -> ESPinServer verifies the PIN
```

Use the **Dashboard** to watch request counters and the **Diagnostics** page
to inspect metadata and recent requests. Neither page displays the PIN.

An incorrect PIN receives a protocol-shaped dummy response. After the first
wrong attempt the record has a 5-second cooldown; after the second it has a
60-second cooldown; the third wrong attempt invalidates the record. This is
expected behavior, not a network failure.

## 9. Maintenance and recovery

- **Certificate refresh:** Configuration → refresh certificate. Reconnect and
  accept the new self-signed certificate again.
- **Server key generation:** Configuration → generate a new key. This changes
  the public key and requires pairing every Jade again.
- **Database wipe:** Configuration → wipe PIN database. This removes all PIN
  records and cannot be used to recover them.
- **Statistics:** Configuration → reset statistics. Connection logs are kept in
  RAM and disappear after reboot.

## Troubleshooting

### The browser cannot open the page

Confirm that the computer is on the same Wi-Fi network as the ESP32, try the
device IP instead of mDNS, and use `https://`. Check the serial monitor at
115200 baud for the network address and startup errors.

### The Jade cannot reach the API

Open Pairing and verify that the QR URLs use `http://` and port `80`, not the
browser's `https://` URL. Confirm that the Jade and ESP32 are on the same LAN
and that the address is reachable from the Jade.

### The API returns `423`

The database is still locked. Open the HTTPS administration page and enter the
storage password.

### The API returns `429` or `403`

The record is in its failed-attempt cooldown or has been invalidated after
three wrong PIN attempts. Wait for the cooldown where applicable, then create a
new test record with `/set_pin` by repeating the Jade setup flow.

### The certificate warning returns

This is expected after a certificate refresh or when the device identity
changes. Verify the local address and accept the new self-signed certificate.

For protocol fields, status codes, encryption, and replay behavior, see the
[PIN-server protocol notes](PINSERVER_PROTOCOL.md). For deployment limits, see
the [security model](security.html).
