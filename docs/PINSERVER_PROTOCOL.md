# Local PIN-server protocol

This document describes the protocol implemented by ESPinServer, the ESP-based
PinServer. It is an
interoperability and research note, not a security certification. For the
original project and production-oriented implementation, consult
[Blockstream Jade](https://github.com/Blockstream/Jade), especially its
[`pinserver`](https://github.com/Blockstream/Jade/tree/master/pinserver)
component.

## Important security limitation

ESP32 NVS stores the server private key in the `privkey` entry. LittleFS stores
the PIN database in `/pins.bin`. Both are persisted as ordinary device data;
this firmware does not provide secure boot, flash encryption, a secure element,
or encrypted database storage. A physical attacker with flash access can read
or modify the server key, PIN verification material, replay state, and AES key
shares. Keep this firmware on an isolated test network and use test data only.

## HTTP endpoints

The server listens on HTTP port 80:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/set_pin` | `POST` | Register a wallet PIN record and return its derived key |
| `/get_pin` | `POST` | Verify a PIN record and return its derived key |
| `/config` | `GET`/`POST` | Configure the mDNS name and server key |
| `/diagnostics` | `GET` | Show local request and database diagnostics |

`/set_pin` and `/get_pin` accept JSON of the form:

```json
{"data":"<base64 request>"}
```

Successful requests return the same shape with an encrypted response:

```json
{"data":"<base64 response>"}
```

The transport is HTTP, so deployments should remain on a trusted local
network. The protocol payload has its own authenticated encryption, but that
does not protect the unencrypted configuration and database on the board.

## Request format

After base64 decoding, the request is:

```text
client_ephemeral_public_key  33 bytes, compressed secp256k1 key
replay_counter                4 bytes, little-endian
encrypted_payload            remaining bytes
```

The encrypted payload uses AES-256-CBC with PKCS#7 padding and an HMAC-SHA256
authentication tag. The ECDH-derived key material is separated using the
label `blind_oracle_request`.

The decrypted request payload is:

```text
pin_secret                    32 bytes
client_entropy                 0 or 32 bytes (`set_pin` requires 32)
recoverable_signature         65 bytes
```

The client normally sets `pin_secret = SHA256(user_pin)`. The signature covers
the concatenation:

```text
SHA256(client_public_key || replay_counter || pin_secret || client_entropy)
```

The server recovers the client public key from that signature and identifies a
wallet record by `SHA256(recovered_client_public_key)`.

## Server key derivation

For each request, the server derives an ephemeral private key from its stored
server private key, the client public key, and the replay counter. The client
derives the matching server ephemeral public key using the Blockstream/Jade
TapTweak-compatible construction. ECDH then derives separate AES and HMAC keys
from the shared point and the protocol label.

Responses use the label `blind_oracle_response` and contain one 32-byte value:

- On `set_pin`, the server generates a random 32-byte saved key and stores it.
- On a correct `get_pin`, it returns `HMAC-SHA256(saved_key, pin_secret)`.
- On an unknown or wrong PIN, it derives a response from a random dummy key so
  the response remains indistinguishable at the protocol level.

## Replay and failed attempts

Each wallet record stores the greatest accepted replay counter. Requests with a
counter that is not greater than the stored value are rejected. Failed PIN
attempts use progressive delays (5 seconds, then 60 seconds); after the third
failed attempt the record is invalidated. Unknown records receive a dummy
response rather than a direct “not found” result.

## Further reading

- [Blockstream Jade source repository](https://github.com/Blockstream/Jade)
- [Blockstream Jade pinserver implementation](https://github.com/Blockstream/Jade/tree/master/pinserver)
- [Blockstream Jade update and DIY notes](https://github.com/Blockstream/Jade/blob/master/FWUPDATE.md)
- [Blockstream DIY flasher](https://github.com/Blockstream/jadediyflasher)
- [ESPinServer browser flasher](https://valerio-vaccaro.github.io/diyflasher/)
