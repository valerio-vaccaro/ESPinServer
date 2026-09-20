"""Integration tests for a locally running ESPinServer.

Run with:

    pytest -q tests/test_pinserver_integration.py

The lockout test waits for the firmware's progressive cooldown (about 65 s).
"""

import base64
import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

try:
    import requests
except ImportError:  # pragma: no cover - reported by the fixture
    requests = None

try:
    import wallycore as wally
    from pinserver_client_v2_libwally import PinserverClientV2Libwally
except ImportError:  # pragma: no cover - reported by crypto tests
    wally = None
    PinserverClientV2Libwally = None


def require_crypto():
    if wally is None or PinserverClientV2Libwally is None:
        pytest.fail("wallycore and pinserver_client_v2_libwally are required for crypto tests")


def request_with_retry(session, method, url, **kwargs):
    last_error = None
    for attempt in range(5):
        try:
            return session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 4:
                time.sleep(1)
    raise last_error


def crypto_call_with_retry(operation):
    last_error = None
    for attempt in range(5):
        try:
            return operation()
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 4:
                time.sleep(1)
    raise last_error


@pytest.fixture(scope="session")
def base_url(pytestconfig):
    return pytestconfig.getoption("--pinserver-url").rstrip("/")


@pytest.fixture(scope="session")
def http(base_url):
    if requests is None:
        pytest.fail("requests is required for integration tests")
    session = requests.Session()
    try:
        response = request_with_retry(session, "GET", base_url + "/", timeout=3)
        response.raise_for_status()
    except requests.RequestException as exc:
        pytest.fail(f"pinserver is not reachable at {base_url} after 5 attempts: {exc}")
    return session


@pytest.fixture(scope="session")
def server_public_key(http, base_url):
    # The public key is intentionally shown on the Configuration page only.
    page = request_with_retry(http, "GET", base_url + "/config", timeout=3)
    page.raise_for_status()
    match = re.search(
        r"Server Public Key \(Hex - Readonly\).*?value='([0-9a-fA-F]{66})'",
        page.text,
        re.DOTALL,
    )
    assert match, "could not find the server public key on /config"
    return bytes.fromhex(match.group(1))


@pytest.fixture(autouse=True)
def clean_database(http, base_url):
    # The integration suite is destructive by design and must target a local
    # test instance, not a production server.
    response = request_with_retry(
        http,
        "POST",
        base_url + "/", data={"wipe_pins": "1"}, allow_redirects=False, timeout=3
    )
    assert response.status_code == 303, response.text
    yield
    request_with_retry(
        http,
        "POST",
        base_url + "/", data={"wipe_pins": "1"}, allow_redirects=False, timeout=3
    )


def post_json(http, base_url, payload):
    return request_with_retry(http, "POST", base_url + "/set_pin", json=payload, timeout=3)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"data": "not-base64"},
        {"data": base64.b64encode(b"too short").decode()},
    ],
)
def test_malformed_messages_are_rejected(http, base_url, payload):
    response = post_json(http, base_url, payload)
    assert response.status_code == 400


def test_malformed_json_is_rejected(http, base_url):
    response = request_with_retry(
        http,
        "POST",
        base_url + "/set_pin",
        data="{not valid json",
        headers={"Content-Type": "application/json"},
        timeout=3,
    )
    assert response.status_code == 400


def test_registration_and_correct_pin_retrieval(base_url, server_public_key):
    require_crypto()
    client = PinserverClientV2Libwally(base_url, server_public_key, replay_counter=1)
    pin_secret = wally.sha256(b"correct pin")
    stored_key = crypto_call_with_retry(
        lambda: client.set_pin(pin_secret, os.urandom(32))
    )
    assert len(stored_key) == 32

    client.increment_replay_counter()
    retrieved_key = crypto_call_with_retry(lambda: client.get_pin(pin_secret))
    assert retrieved_key == stored_key


@pytest.mark.slow
def test_wrong_pin_lockout_prevents_later_correct_retrieval(base_url, server_public_key):
    require_crypto()
    client = PinserverClientV2Libwally(base_url, server_public_key, replay_counter=1)
    correct_pin = wally.sha256(b"correct pin")
    wrong_pin = wally.sha256(b"wrong pin")
    stored_key = crypto_call_with_retry(
        lambda: client.set_pin(correct_pin, os.urandom(32))
    )

    # The firmware applies a 5-second delay after the first wrong attempt and
    # a 60-second delay after the second one.
    client.increment_replay_counter()
    assert crypto_call_with_retry(lambda: client.get_pin(wrong_pin)) != stored_key
    time.sleep(5.2)

    client.increment_replay_counter()
    assert crypto_call_with_retry(lambda: client.get_pin(wrong_pin)) != stored_key
    time.sleep(60.2)

    client.increment_replay_counter()
    with pytest.raises(Exception, match="403"):
        client.get_pin(wrong_pin)

    # The third failure deletes the slot. A later correct request receives a
    # blind dummy response, never the originally stored key.
    client.increment_replay_counter()
    assert crypto_call_with_retry(lambda: client.get_pin(correct_pin)) != stored_key


@pytest.mark.slow
def test_pin_database_has_exactly_16_slots(base_url, server_public_key):
    require_crypto()
    for index in range(16):
        client = PinserverClientV2Libwally(
            base_url, server_public_key, replay_counter=1
        )
        pin_secret = wally.sha256(f"capacity-pin-{index}".encode())
        stored_key = crypto_call_with_retry(
            lambda client=client, pin_secret=pin_secret: client.set_pin(
                pin_secret, os.urandom(32)
            )
        )
        assert len(stored_key) == 32

    extra_client = PinserverClientV2Libwally(
        base_url, server_public_key, replay_counter=1
    )
    with pytest.raises(Exception, match="500"):
        extra_client.set_pin(wally.sha256(b"capacity-pin-16"), os.urandom(32))
