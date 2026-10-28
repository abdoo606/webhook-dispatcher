# 14 · webhooks

Signed webhook delivery with retries, jitter and a dead-letter queue.

## Run

```bash
from webhooks.dispatcher import Dispatcher, Config
```

## Test

```bash
pytest projects/14-webhook-dispatcher -q
```

## What it demonstrates

- HMAC signatures with a timestamp, so receivers can reject replays
- Exponential backoff with full jitter; 4xx is not retried, 5xx and timeouts are
- Transport injected - the entire retry matrix is tested offline
- Dead-letter queue plus a replay method for after the incident

## Repository
- GitHub: https://github.com/{owner}/webhook-dispatcher
- Python 3.11+ · tests: `pytest` · runtime dependencies: none (standard library only)
