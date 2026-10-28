from __future__ import annotations

import time

import pytest

from webhooks.dispatcher import Config, Dispatcher, backoff_delay, should_retry
from webhooks.signing import canonical_body, sign, verify

SECRET = "whsec_test_0123456789"


class FakeTransport:
    def __init__(self, statuses: list[int] | None = None) -> None:
        self.statuses = list(statuses or [200])
        self.calls: list[tuple[str, bytes, dict]] = []

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        self.calls.append((url, body, headers))
        return self.statuses.pop(0) if self.statuses else 200


# --------------------------------------------------------------- signing
def test_signature_verifies():
    body = canonical_body({"b": 2, "a": 1})
    header = sign(SECRET, body, int(time.time()))
    assert verify(SECRET, body, header) is True


def test_canonical_json_is_order_independent():
    assert canonical_body({"a": 1, "b": 2}) == canonical_body({"b": 2, "a": 1})


def test_tampered_body_fails():
    body = canonical_body({"amount": 10})
    header = sign(SECRET, body, int(time.time()))
    assert verify(SECRET, canonical_body({"amount": 1000}), header) is False


def test_wrong_secret_fails():
    body = b"{}"
    header = sign("other-secret", body, int(time.time()))
    assert verify(SECRET, body, header) is False


def test_replay_outside_tolerance_fails():
    body = b"{}"
    old = int(time.time()) - 3600
    assert verify(SECRET, body, sign(SECRET, body, old)) is False


def test_malformed_signature_header_fails():
    for header in ("", "garbage", "t=abc,v1=def", "v1=only"):
        assert verify(SECRET, b"{}", header) is False


# ------------------------------------------------------------ dispatcher
@pytest.fixture()
def config():
    return Config(secret=SECRET, max_attempts=3, base_delay=1.0, jitter=lambda: 1.0)


def test_successful_delivery(config):
    transport = FakeTransport([200])
    dispatcher = Dispatcher(transport, config)
    result = dispatcher.dispatch("https://hook.test", "order.created", {"id": 1})
    assert result.status == "delivered" and result.attempts == 1
    assert dispatcher.stats == {"total": 1, "delivered": 1, "dead": 0}


def test_headers_are_signed(config):
    transport = FakeTransport([200])
    Dispatcher(transport, config).dispatch("https://hook.test", "ping", {})
    _, body, headers = transport.calls[0]
    assert verify(SECRET, body, headers["X-Webhook-Signature"])


def test_retries_then_succeeds(config):
    transport = FakeTransport([500, 503, 200])
    dispatcher = Dispatcher(transport, config)
    result = dispatcher.dispatch("https://hook.test", "evt", {})
    assert result.status == "delivered" and result.attempts == 3
    assert len(dispatcher.sleeps) == 2


def test_exhausted_retries_go_to_dlq(config):
    transport = FakeTransport([500, 500, 500])
    dispatcher = Dispatcher(transport, config)
    result = dispatcher.dispatch("https://hook.test", "evt", {})
    assert result.status == "dead"
    assert len(dispatcher.dead_letter) == 1


def test_client_errors_are_not_retried(config):
    transport = FakeTransport([400])
    result = Dispatcher(transport, config).dispatch("https://hook.test", "evt", {})
    assert result.status == "dead" and result.attempts == 1


def test_transport_exception_is_retried(config):
    class Boom:
        def __init__(self):
            self.n = 0

        def post(self, url, body, headers):
            self.n += 1
            if self.n == 1:
                raise ConnectionError("network down")
            return 200

    result = Dispatcher(Boom(), config).dispatch("https://hook.test", "evt", {})
    assert result.status == "delivered" and result.attempts == 2


def test_backoff_grows_and_is_capped(config):
    assert backoff_delay(0, config) == pytest.approx(1.0)
    assert backoff_delay(3, config) == pytest.approx(8.0)
    assert backoff_delay(20, config) == pytest.approx(30.0)


def test_full_jitter_bounds():
    import random

    cfg = Config(secret=SECRET, base_delay=1, max_delay=8, jitter=lambda: 0.0)
    assert backoff_delay(5, cfg) == 0.0
    cfg_high = Config(secret=SECRET, base_delay=1, max_delay=8, jitter=lambda: 0.999)
    assert backoff_delay(5, cfg_high) < 8


@pytest.mark.parametrize("status,expected", [(200, False), (404, False), (429, True), (500, True), (503, True)])
def test_retry_classification(status, expected):
    assert should_retry(status) == expected


def test_dead_letter_replay(config):
    transport = FakeTransport([500, 500, 500, 200])
    dispatcher = Dispatcher(transport, config)
    dispatcher.dispatch("https://hook.test", "evt", {"x": 1})
    assert dispatcher.dead_letter
    replayed = dispatcher.retry_dead_letters()
    assert replayed[0].status == "delivered"
    assert dispatcher.dead_letter == []
