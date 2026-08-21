"""DB-free tests for the rate limiter and client-key selection backing
`POST /v1/public/workflows/{id}/access` (app/api/routers/public.py). This is the
sole brute-force control on an unauthenticated password endpoint, so it needs
coverage that runs in the default (non-integration) suite, not only via the
deselected integration tests in tests/integration/test_public_workflows.py.
"""

import pytest

from app.api.routers.public import _client_ip, _RateLimiter


class _FakePeer:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, *, peer_host: str | None, headers: dict[str, str]) -> None:
        self.client = _FakePeer(peer_host) if peer_host is not None else None
        self.headers = headers


class _FakeSettings:
    def __init__(self, trusted_proxies: str) -> None:
        self.trusted_proxies = trusted_proxies


# ---- _RateLimiter -----------------------------------------------------------


def test_check_allows_before_any_failure() -> None:
    limiter = _RateLimiter()
    assert limiter.check(("wf-1", "1.2.3.4")) is None


def test_backoff_escalates_and_caps() -> None:
    limiter = _RateLimiter(base_seconds=1.0, max_seconds=8.0)
    key = ("wf-1", "1.2.3.4")

    delays: list[float | None] = []
    for _ in range(5):
        limiter.record_failure(key)
        delays.append(limiter.check(key))

    assert all(d is not None for d in delays)
    # 1s, 2s, 4s, 8s, 8s (capped) — checked immediately after each failure, so
    # each delay is just under its nominal value.
    assert delays[0] == pytest.approx(1.0, abs=0.1)
    assert delays[1] == pytest.approx(2.0, abs=0.1)
    assert delays[2] == pytest.approx(4.0, abs=0.1)
    assert delays[3] == pytest.approx(8.0, abs=0.1)
    assert delays[4] == pytest.approx(8.0, abs=0.1)  # capped, not 16


def test_record_success_unblocks_immediately() -> None:
    limiter = _RateLimiter(base_seconds=10.0)
    key = ("wf-1", "1.2.3.4")

    limiter.record_failure(key)
    assert limiter.check(key) is not None  # blocked

    limiter.record_success(key)
    assert limiter.check(key) is None  # a legitimate caller isn't penalized


def test_record_success_resets_the_escalation_not_just_the_block() -> None:
    """After a success, the NEXT failure must start back at the base delay —
    if only `_blocked_until` were cleared and `_attempts` survived, the next
    failure would jump straight to a late point in the backoff curve."""
    limiter = _RateLimiter(base_seconds=1.0, max_seconds=100.0)
    key = ("wf-1", "1.2.3.4")

    limiter.record_failure(key)
    limiter.record_failure(key)
    limiter.record_failure(key)  # third failure -> next would be 4s if unreset
    limiter.record_success(key)

    limiter.record_failure(key)
    assert limiter.check(key) == pytest.approx(1.0, abs=0.1)


def test_different_keys_are_independent() -> None:
    """One workflow's brute-force attempts must not lock out a different
    workflow, or a different client on the same workflow."""
    limiter = _RateLimiter(base_seconds=10.0)
    limiter.record_failure(("wf-1", "1.2.3.4"))

    assert limiter.check(("wf-2", "1.2.3.4")) is None
    assert limiter.check(("wf-1", "5.6.7.8")) is None


# ---- _client_ip ---------------------------------------------------------------


def test_client_ip_uses_leftmost_xff_when_peer_is_a_trusted_proxy() -> None:
    settings = _FakeSettings(trusted_proxies="10.0.0.1")
    request = _FakeRequest(
        peer_host="10.0.0.1", headers={"x-forwarded-for": "203.0.113.5, 10.0.0.1"}
    )
    assert _client_ip(request, settings) == "203.0.113.5"


def test_client_ip_ignores_xff_from_an_untrusted_peer() -> None:
    """An attacker who is not the configured proxy cannot rotate the rate-limit
    key by spoofing X-Forwarded-For."""
    settings = _FakeSettings(trusted_proxies="10.0.0.1")
    request = _FakeRequest(peer_host="203.0.113.99", headers={"x-forwarded-for": "1.1.1.1"})
    assert _client_ip(request, settings) == "203.0.113.99"


def test_client_ip_falls_back_to_peer_with_no_trusted_proxies_configured() -> None:
    """Safe default: with TRUSTED_PROXIES unset, every caller is keyed by its own
    socket address rather than trusting a header nobody has vetted."""
    settings = _FakeSettings(trusted_proxies="")
    request = _FakeRequest(peer_host="10.0.0.1", headers={"x-forwarded-for": "203.0.113.5"})
    assert _client_ip(request, settings) == "10.0.0.1"
