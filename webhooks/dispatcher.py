"""Delivery with exponential backoff, jitter, and a dead-letter queue after N attempts."""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .signing import canonical_body, sign


class Transport(Protocol):
    """Anything with post(url, body, headers) -> status code. Injected so tests are offline."""

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> int: ...


@dataclass(slots=True)
class Delivery:
    id: str
    url: str
    event: str
    payload: dict
    attempts: int = 0
    status: str = "pending"  # pending | delivered | dead
    last_status: int | None = None


@dataclass(slots=True)
class Config:
    secret: str
    max_attempts: int = 5
    base_delay: float = 0.5
    max_delay: float = 30.0
    timeout_statuses: tuple[int, ...] = (408, 429, 500, 502, 503, 504)
    jitter: Callable[[], float] = field(default=random.random)


def backoff_delay(attempt: int, config: Config) -> float:
    """Full jitter: delay = random(0, min(cap, base * 2**attempt)) - prevents thundering herds."""
    ceiling = min(config.max_delay, config.base_delay * (2 ** attempt))
    return ceiling * config.jitter()


def should_retry(status: int) -> bool:
    return status in (408, 425, 429) or 500 <= status < 600


class Dispatcher:
    def __init__(self, transport: Transport, config: Config, *, sleeper: Callable[[float], None] = lambda s: None):
        self.transport = transport
        self.config = config
        self.sleeper = sleeper
        self.deliveries: list[Delivery] = []
        self.dead_letter: list[Delivery] = []
        self.sleeps: list[float] = []

    def dispatch(self, url: str, event: str, payload: dict) -> Delivery:
        delivery = Delivery(uuid.uuid4().hex[:12], url, event, payload)
        self.deliveries.append(delivery)
        body = canonical_body({"event": event, "data": payload, "id": delivery.id})

        for attempt in range(self.config.max_attempts):
            delivery.attempts = attempt + 1
            headers = {
                "Content-Type": "application/json",
                "X-Webhook-Id": delivery.id,
                "X-Webhook-Event": event,
                "X-Webhook-Signature": sign(self.config.secret, body, int(__import__("time").time())),
            }
            try:
                status = self.transport.post(url, body, headers)
                retryable = should_retry(status)
            except Exception:
                # a transport exception is a retryable failure, not a crash
                status, retryable = 0, True
            delivery.last_status = status

            if 200 <= status < 300:
                delivery.status = "delivered"
                return delivery
            if not retryable or attempt == self.config.max_attempts - 1:
                break

            delay = backoff_delay(attempt, self.config)
            self.sleeps.append(delay)
            self.sleeper(delay)

        delivery.status = "dead"
        self.dead_letter.append(delivery)
        return delivery

    def retry_dead_letters(self) -> list[Delivery]:
        """Replays the DLQ once; callers decide when and how often."""
        pending, self.dead_letter = self.dead_letter, []
        results = []
        for delivery in pending:
            delivery.status = "pending"
            delivery.attempts = 0
            results.append(self.dispatch(delivery.url, delivery.event, delivery.payload))
        return results

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total": len(self.deliveries),
            "delivered": sum(d.status == "delivered" for d in self.deliveries),
            "dead": len(self.dead_letter),
        }
