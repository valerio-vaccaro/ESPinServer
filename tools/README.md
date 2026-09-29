# PIN client utility

`pinclient.py` protects files with a Jade-compatible blind PIN-server exchange.
It creates `.pin` files containing an encrypted JSON document. The PIN is
never written to the `.pin` file.

## Dependencies

```bash
python3 -m pip install -r tools/requirements.txt
```

`openssl` must also be available on `PATH`.

## Blind a file

The output name is the input name with `.pin` appended:

```bash
python3 tools/pinclient.py blind notes.txt 123456
# creates notes.txt.pin
```

The JSON inside the encrypted payload contains the original filename and
content. Binary files are stored as base64 content automatically.

## Unblind a file

```bash
python3 tools/pinclient.py unblind notes.txt.pin 123456
# recreates notes.txt
```

The original filename is taken from the encrypted JSON. If it is absent, the
utility removes `.pin` from the envelope filename and uses the result.

## Blind a string

Use `--string` instead of a file. The generated envelope has no internal
filename and is saved as `pin_<random>.txt.pin`:

```bash
python3 tools/pinclient.py blind --string "hello from Jade" 123456
python3 tools/pinclient.py unblind pin_a1b2c3d4.txt.pin 123456
```

The second command recreates `pin_a1b2c3d4.txt` because the string envelope has
no stored filename.

Logs use coloured icons when stderr is a terminal. Disable them with
`--no-color`. Logs intentionally omit PINs, file contents, payloads, private
keys, and full URLs.

## Local ESPinServer

Use the local API URLs instead of the official Jade defaults:

```bash
python3 tools/pinclient.py blind notes.txt 123456 \
  --url-a http://espinserver.local:80 --url-b ""
```

The utility uses the same server-key response structure as official Jade.
Treat `.pin` files as sensitive because they contain the client private key
needed for the later `/get_pin` request.

## Command reference

```text
pinclient.py blind [FILE] PIN [options]
pinclient.py blind --string TEXT PIN [options]
pinclient.py unblind FILE.pin PIN [options]
```

Options for `blind`:

```text
--url-a URL       primary PIN-server URL
--url-b URL       fallback PIN-server URL; use "" to disable it
--server-key HEX  compressed 33-byte server public key
--counter N       starting replay counter for blind, default: 1
--no-color        disable coloured icon logs
```

## Complete examples

### Protect a text file

```bash
printf 'temporary test note\n' > note.txt
python3 tools/pinclient.py blind note.txt 123456
python3 tools/pinclient.py unblind note.txt.pin 123456
cat note.txt
```

`blind` contacts `/set_pin`, encrypts a JSON document containing `note.txt`
and its content, and writes `note.txt.pin`. `unblind` contacts `/get_pin`,
authenticates the envelope, and recreates `note.txt` beside the `.pin` file.

### Protect a JSON document as a file

The JSON is treated as file content and is restored byte-for-byte as UTF-8:

```bash
printf '{"network":"testnet","enabled":true}\n' > settings.json
python3 tools/pinclient.py blind settings.json 123456
python3 tools/pinclient.py unblind settings.json.pin 123456
```

### Protect binary data

Binary files are detected when they are not valid UTF-8 and are stored as
base64 inside the encrypted document. The recreated file has the original
bytes:

```bash
python3 tools/pinclient.py blind firmware.bin 123456
python3 tools/pinclient.py unblind firmware.bin.pin 123456
sha256sum firmware.bin
```

### Protect a string

String mode does not store an internal filename. The output name is generated
as `pin_<random>.txt.pin`:

```bash
python3 tools/pinclient.py blind --string 'hello from Jade' 123456
python3 tools/pinclient.py unblind pin_7f3a91c2.txt.pin 123456
cat pin_7f3a91c2.txt
```

If the encrypted document has no `filename`, unblind removes the final `.pin`
suffix and uses that as the output filename.

### Use a local ESPinServer

The local firmware exposes the Jade-compatible API on HTTP port 80. Disable
the official onion fallback when using a local server:

```bash
python3 tools/pinclient.py blind note.txt 123456 \
  --url-a http://espinserver.local:80 \
  --url-b ""
python3 tools/pinclient.py unblind note.txt.pin 123456
```

The server public key must match the configured ESPinServer key. For a custom
server key, pass its compressed public key as hex:

```bash
python3 tools/pinclient.py blind note.txt 123456 \
  --url-a http://192.168.1.50:80 --url-b "" \
  --server-key 0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547
```

The URLs and server key are saved inside the `.pin` envelope, so unblind reads
them from the file.

## Replay counters

The first `/set_pin` request uses counter `1`. Unblinding uses the counter in
the envelope plus one, as required by the PIN-server replay protection. A
single `.pin` file should normally be unblinded once. Reusing it sends the
same replay counter and will be rejected by the server. For repeated access,
create a new envelope or build a workflow that updates the counter and keeps
the server record synchronized.

## Failure behavior

- A wrong PIN causes envelope authentication to fail; no output file is
  created.
- A modified `.pin` file fails its HMAC check; no output file is created.
- A replayed envelope is rejected by the PIN server before decryption.
- After repeated wrong PIN attempts, the server may apply cooldowns or erase
  the associated record according to its configured policy.

Logs show only high-level operation status and use icons when stderr is a
terminal. They never print the PIN, key material, payload, file content, or
full URL. Use `--no-color` for plain output in scripts and CI.
