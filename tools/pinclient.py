#!/usr/bin/env python3
"""Blind and unblind files through a Jade-compatible PIN server.

The wire protocol is the Jade v2 blind-oracle protocol.  The resulting JSON
file is a portable encrypted envelope; it deliberately contains the client
private key because that key is required to perform the later /get_pin call.
The PIN is never written to the envelope.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import requests
    import wallycore as wally
except ImportError as exc:  # pragma: no cover - exercised by the CLI
    raise SystemExit(
        "Missing dependency. Install requests and the Jade/libwally Python "
        "client dependencies before using this utility."
    ) from exc


# Values are copied from Blockstream/Jade's main/process/pinclient.c and
# pinserver_public_key.pub.  Keep these in the file so an envelope is
# self-describing and remains usable if Jade changes its defaults later.
DEFAULT_URL_A = "https://j8d.io"
DEFAULT_URL_B = (
    "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion"
)
DEFAULT_SERVER_PUBLIC_KEY = bytes.fromhex(
    "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec"
    "87c547"
)
REQUEST_LABEL = b"blind_oracle_request"
RESPONSE_LABEL = b"blind_oracle_response"
FORMAT = "jade-pinclient-file-v1"


class Log:
    RESET = "\033[0m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"

    def __init__(self, enabled=True):
        self.enabled = enabled and sys.stderr.isatty()

    def write(self, icon, message, colour):
        prefix = f"{colour}{icon}{self.RESET}" if self.enabled else icon
        print(f"{prefix} {message}", file=sys.stderr)

    def info(self, message):
        self.write("ℹ", message, self.BLUE)

    def ok(self, message):
        self.write("✓", message, self.GREEN)

    def warn(self, message):
        self.write("⚠", message, self.YELLOW)

    def error(self, message):
        self.write("✗", message, self.RED)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def pin_secret(pin: str, private_key: bytes) -> bytes:
    """Match Jade's nested HMAC PIN-secret derivation."""
    subkey = hmac.new(private_key, b"\x00", hashlib.sha256).digest()
    return hmac.new(subkey, pin.encode(), hashlib.sha256).digest()


def openssl_aes(encrypt: bool, key: bytes, iv: bytes, data: bytes) -> bytes:
    command = ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()]
    if not encrypt:
        command.append("-d")
    try:
        result = subprocess.run(
            command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode(errors="replace").strip()
        raise ValueError(f"AES operation failed: {detail or exc}") from exc
    return result.stdout


class JadePinserver:
    def __init__(self, urls, server_public_key, private_key, counter, timeout=20):
        self.urls = [url.rstrip("/") for url in urls if url]
        if not self.urls:
            raise ValueError("At least one pinserver URL is required")
        self.server_public_key = server_public_key
        self.private_key = private_key
        self.public_key = wally.ec_public_key_from_private_key(private_key)
        self.counter = counter
        self.timeout = timeout
        self.server_ephemeral_pubkey = self._derive_server_ephemeral_pubkey()

    def _counter_bytes(self):
        return self.counter.to_bytes(4, "little")

    def _derive_server_ephemeral_pubkey(self):
        tweak = wally.sha256(wally.hmac_sha256(self.public_key, self._counter_bytes()))
        return wally.ec_public_key_bip341_tweak(self.server_public_key, tweak, 0)

    def _payload(self, secret, entropy):
        message_hash = wally.sha256(self.public_key + self._counter_bytes() + secret + entropy)
        signature = wally.ec_sig_from_bytes(
            self.private_key,
            message_hash,
            wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE,
        )
        cleartext = secret + entropy + signature
        iv = os.urandom(16)
        encrypted = wally.aes_cbc_with_ecdh_key(
            self.private_key,
            iv,
            cleartext,
            self.server_ephemeral_pubkey,
            REQUEST_LABEL,
            wally.AES_FLAG_ENCRYPT,
        )
        return b64(self.public_key + self._counter_bytes() + encrypted)

    def call(self, endpoint, pin, creating):
        secret = pin_secret(pin, self.private_key)
        entropy = os.urandom(32) if creating else b""
        body = {"data": self._payload(secret, entropy)}
        last_error = None
        for base_url in self.urls:
            try:
                response = requests.post(
                    f"{base_url}/{endpoint}", json=body, timeout=self.timeout
                )
                if response.status_code != 200:
                    raise RuntimeError(f"{response.status_code}: {response.text[:200]}")
                encrypted = unb64(response.json()["data"])
                return wally.aes_cbc_with_ecdh_key(
                    self.private_key,
                    None,
                    encrypted,
                    self.server_ephemeral_pubkey,
                    RESPONSE_LABEL,
                    wally.AES_FLAG_DECRYPT,
                )
            except (requests.RequestException, KeyError, ValueError, RuntimeError) as exc:
                last_error = exc
        # Do not include the exception or URL in CLI output: request errors
        # can contain user-supplied credentials embedded in a URL.
        raise RuntimeError("all configured pinserver URLs failed") from last_error


def parse_key(value: str) -> bytes:
    key = bytes.fromhex(value)
    if len(key) != 33:
        raise argparse.ArgumentTypeError("server public key must be 33 bytes")
    return key


def load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot read {path}: {exc}") from exc


def read_input(args):
    if args.string is not None:
        return {"content": args.string}, None
    if args.input is None:
        raise ValueError("provide an input file or --string")
    try:
        data = args.input.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {args.input}: {exc}") from exc
    try:
        content = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = b64(data)
        encoding = "base64"
    return {"filename": args.input.name, "content": content, "encoding": encoding}, args.input


def make_envelope(args, log):
    document, source_path = read_input(args)
    if args.string is not None:
        output_path = Path(f"pin_{os.urandom(4).hex()}.txt.pin")
    else:
        output_path = Path(f"{source_path}.pin")
    log.info(f"Preparing {output_path.name}")
    plaintext = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    private_key = os.urandom(32)
    # os.urandom(32) is overwhelmingly likely to be a valid secp256k1 scalar;
    # let libwally validate it while constructing the public key below.
    server_key = args.server_key
    client = JadePinserver(
        [args.url_a, args.url_b], server_key, private_key, args.counter
    )
    # Never log the PIN, payload, key material, file contents, or URL details.
    log.info("Registering with the configured PIN server")
    returned_key = client.call("set_pin", args.pin, creating=True)
    encryption_key = hmac.new(returned_key, args.pin.encode(), hashlib.sha256).digest()
    iv = os.urandom(16)
    ciphertext = openssl_aes(True, encryption_key, iv, plaintext)
    tag = hmac.new(encryption_key, iv + ciphertext, hashlib.sha256).digest()
    return {
        "format": FORMAT,
        "server": {
            "url_a": args.url_a,
            "url_b": args.url_b,
            "public_key": server_key.hex(),
        },
        "client": {
            "private_key": private_key.hex(),
            "public_key": client.public_key.hex(),
        },
        "replay_counter": args.counter,
        "payload": {
            "cipher": "aes-256-cbc+hmac-sha256",
            "encoding": "json",
            "iv": iv.hex(),
            "ciphertext": b64(ciphertext),
            "tag": tag.hex(),
        },
    }, output_path


def unblind(envelope, pin, input_path):
    if envelope.get("format") != FORMAT:
        raise ValueError(f"Unsupported envelope format: {envelope.get('format')}")
    server = envelope["server"]
    client_data = envelope["client"]
    private_key = bytes.fromhex(client_data["private_key"])
    client = JadePinserver(
        [server.get("url_a"), server.get("url_b")],
        bytes.fromhex(server["public_key"]),
        private_key,
        int(envelope["replay_counter"]) + 1,
    )
    returned_key = client.call("get_pin", pin, creating=False)
    encryption_key = hmac.new(returned_key, pin.encode(), hashlib.sha256).digest()
    payload = envelope["payload"]
    iv = bytes.fromhex(payload["iv"])
    ciphertext = unb64(payload["ciphertext"])
    expected = hmac.new(encryption_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, bytes.fromhex(payload["tag"])):
        raise ValueError("Payload authentication failed (wrong PIN or changed file)")
    document = json.loads(openssl_aes(False, encryption_key, iv, ciphertext).decode("utf-8"))
    filename = document.get("filename")
    if not filename:
        name = input_path.name
        filename = name[:-4] if name.endswith(".pin") else name
    output_path = input_path.parent / Path(filename).name
    content = document.get("content")
    if not isinstance(content, str):
        raise ValueError("decrypted document has no string content")
    if document.get("encoding") == "base64":
        output_path.write_bytes(unb64(content))
    else:
        output_path.write_text(content, encoding="utf-8")
    return output_path


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url-a", default=DEFAULT_URL_A, help="Primary pinserver URL")
    common.add_argument("--url-b", default=DEFAULT_URL_B, help="Fallback pinserver URL")
    common.add_argument(
        "--server-key", type=parse_key, default=DEFAULT_SERVER_PUBLIC_KEY,
        help="33-byte compressed server public key in hex",
    )
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    blind = commands.add_parser("blind", parents=[common], help="Encrypt a file")
    source = blind.add_mutually_exclusive_group()
    source.add_argument("input", type=Path, nargs="?", help="file to encrypt")
    source.add_argument("--string", help="encrypt this string instead of a file")
    blind.add_argument("pin")
    blind.add_argument("--counter", type=int, default=1)
    blind.add_argument("--no-color", action="store_true", help="disable coloured logs")
    unblind_parser = commands.add_parser("unblind", help="Decrypt a .pin file")
    unblind_parser.add_argument("input", type=Path)
    unblind_parser.add_argument("pin")
    unblind_parser.add_argument("--no-color", action="store_true", help="disable coloured logs")
    return root


def main():
    args = parser().parse_args()
    log = Log(not args.no_color)
    try:
        if args.command == "blind":
            envelope, output_path = make_envelope(args, log)
            output = json.dumps(envelope, indent=2) + "\n"
            output_path.write_text(output, encoding="utf-8")
            log.ok(f"Created {output_path}")
        else:
            log.info(f"Unblinding {args.input}")
            output_path = unblind(load_json(args.input), args.pin, args.input)
            log.ok(f"Restored {output_path}")
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        log.error(str(exc))
        raise SystemExit(f"error: {exc}") from exc


if __name__ == "__main__":
    main()
