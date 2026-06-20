"""Unit tests for the Cloudflare DNS connector.

All HTTP calls are intercepted by ``respx`` — no real network calls are made.

Run with:
    docker compose run --rm api pytest backend/tests/test_cloudflare_connector.py -v
or locally (from /backend):
    pytest tests/test_cloudflare_connector.py -v
"""

from __future__ import annotations

import pytest
import respx
import httpx

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.cloudflare_schema import (
    CLOUDFLARE_ACCESS_POLICY,
    CLOUDFLARE_RULESET,
    CLOUDFLARE_WAF_RULE,
    CLOUDFLARE_ZONE_SETTING,
)
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)

# ── Constants ────────────────────────────────────────────────────────────────

VALID_CREDS = {"api_token": "test-token-abc123", "zone_id": "zone1234567890abcdef"}

CF_BASE = "https://api.cloudflare.com/client/v4"
DNS_URL = f"{CF_BASE}/zones/{VALID_CREDS['zone_id']}/dns_records"
ZONE_ID = VALID_CREDS["zone_id"]

# Setting IDs the connector fetches (mirrors _ZONE_SETTING_IDS in the connector)
_SETTING_IDS = (
    "ssl",
    "always_use_https",
    "min_tls_version",
    "security_level",
    "browser_check",
    "development_mode",
    "automatic_https_rewrites",
    "security_header",
)


# ── Stub helper ──────────────────────────────────────────────────────────────

def _stub_extra_surfaces() -> None:
    """Register 403 responses for every secondary surface the connector
    fetches after DNS records. This allows DNS-focused tests to run without
    real Cloudflare scope for WAF, settings, page rules, workers, or Access.

    All of those surfaces use _safe_get() which treats 403 as a graceful
    skip, so fetch() returns only the DNS records when they return 403.
    """
    _empty_403 = httpx.Response(403, json={"success": False, "errors": []})

    # WAF rulesets (called twice: once for _fetch_rulesets, once for _fetch_waf_rules)
    respx.get(f"{CF_BASE}/zones/{ZONE_ID}/rulesets").mock(return_value=_empty_403)

    # Individual zone settings
    for sid in _SETTING_IDS:
        respx.get(f"{CF_BASE}/zones/{ZONE_ID}/settings/{sid}").mock(
            return_value=_empty_403
        )

    # Page rules
    respx.get(f"{CF_BASE}/zones/{ZONE_ID}/pagerules").mock(return_value=_empty_403)

    # Worker routes
    respx.get(f"{CF_BASE}/zones/{ZONE_ID}/workers/routes").mock(
        return_value=_empty_403
    )

    # Account-id resolution (GET /zones/{zone_id}) — 403 means no account context,
    # so worker scripts, Access apps/policies are also skipped.
    respx.get(f"{CF_BASE}/zones/{ZONE_ID}").mock(return_value=_empty_403)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _raw_record(
    record_id: str = "rec1",
    record_type: str = "A",
    name: str = "example.com",
    content: str = "1.2.3.4",
    ttl: int = 3600,
    proxied: bool = False,
    priority: int | None = None,
    comment: str | None = None,
    modified_on: str = "2024-01-15T10:00:00Z",
) -> dict:
    """Build a raw Cloudflare API DNS record dict."""
    raw: dict = {
        "id": record_id,
        "type": record_type,
        "name": name,
        "content": content,
        "ttl": ttl,
        "proxied": proxied,
        "modified_on": modified_on,
        # Fields that Cloudflare always returns but we don't use:
        "zone_id": VALID_CREDS["zone_id"],
        "zone_name": "example.com",
    }
    if priority is not None:
        raw["priority"] = priority
    if comment is not None:
        raw["comment"] = comment
    return raw


def _cf_response(
    records: list[dict],
    page: int = 1,
    per_page: int = 100,
    total_count: int | None = None,
) -> dict:
    """Build a successful Cloudflare API response envelope."""
    if total_count is None:
        total_count = len(records)
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": records,
        "result_info": {
            "page": page,
            "per_page": per_page,
            "total_count": total_count,
            "count": len(records),
        },
    }


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def connector() -> CloudflareConnector:
    return CloudflareConnector()


# ── fetch(): normalisation ────────────────────────────────────────────────────

@respx.mock
def test_fetch_returns_normalised_fields(connector: CloudflareConnector) -> None:
    """All CloudflareDNSRecord fields are correctly mapped from the raw response."""
    raw = _raw_record(
        record_id="abc123",
        record_type="A",
        name="api.example.com",
        content="93.184.216.34",
        ttl=120,
        proxied=True,
        modified_on="2024-06-01T12:00:00Z",
    )
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([raw])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)

    # Only DNS records are returned (secondary surfaces return 403 and are skipped).
    dns_records = [r for r in records if r.get("record_type") == "A"]
    assert len(dns_records) == 1
    r = dns_records[0]
    assert r["record_id"] == "abc123"
    assert r["record_type"] == "A"
    assert r["name"] == "api.example.com"
    assert r["content"] == "93.184.216.34"
    assert r["ttl"] == 120
    assert r["proxied"] is True
    assert r["priority"] is None
    assert r["comment"] is None
    assert r["modified_on"] == "2024-06-01T12:00:00Z"


@respx.mock
def test_fetch_cloudflare_id_maps_to_record_id(connector: CloudflareConnector) -> None:
    """Cloudflare's ``id`` field is mapped to ``record_id``."""
    raw = _raw_record(record_id="cf_id_xyz")
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([raw])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    dns = [r for r in records if "content" in r]
    assert dns[0]["record_id"] == "cf_id_xyz"
    # The original Cloudflare ``id`` key should not appear at the top level
    assert "id" not in dns[0]


@respx.mock
def test_fetch_cloudflare_type_maps_to_record_type(connector: CloudflareConnector) -> None:
    """Cloudflare's ``type`` field is mapped to ``record_type``."""
    raw = _raw_record(record_type="CNAME")
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([raw])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    dns = [r for r in records if "content" in r]
    assert dns[0]["record_type"] == "CNAME"
    assert "type" not in dns[0]


@respx.mock
def test_fetch_mx_record_preserves_priority(connector: CloudflareConnector) -> None:
    """MX records have their ``priority`` field forwarded."""
    raw = _raw_record("mx1", "MX", "example.com", "mail.example.com", priority=10)
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([raw])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    dns = [r for r in records if "content" in r]
    assert dns[0]["priority"] == 10


@respx.mock
def test_fetch_comment_forwarded_when_present(connector: CloudflareConnector) -> None:
    """Optional ``comment`` field is preserved when set."""
    raw = _raw_record(comment="primary web server IP")
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([raw])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    dns = [r for r in records if "content" in r]
    assert dns[0]["comment"] == "primary web server IP"


@respx.mock
def test_fetch_returns_empty_list_for_empty_zone(connector: CloudflareConnector) -> None:
    """An empty zone returns an empty list when secondary surfaces are also absent."""
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([])))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    # With all secondary surfaces returning 403, the overall result is empty.
    assert records == []


# ── fetch(): pagination ───────────────────────────────────────────────────────

@respx.mock
def test_fetch_paginates_through_all_pages(connector: CloudflareConnector) -> None:
    """Records are fetched from every page when total_count > per_page."""
    page1 = [_raw_record(f"rec{i}") for i in range(3)]
    page2 = [_raw_record(f"rec{i + 3}") for i in range(2)]

    # per_page=3, total_count=5 → 2 pages
    route = respx.get(DNS_URL)
    route.side_effect = [
        httpx.Response(200, json=_cf_response(page1, page=1, per_page=3, total_count=5)),
        httpx.Response(200, json=_cf_response(page2, page=2, per_page=3, total_count=5)),
    ]
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)

    # DNS records only (secondary surfaces stubbed out with 403).
    dns = [r for r in records if "content" in r]
    assert len(dns) == 5
    assert [r["record_id"] for r in dns] == [f"rec{i}" for i in range(5)]


@respx.mock
def test_fetch_single_page_when_records_equal_total_count(connector: CloudflareConnector) -> None:
    """No second request is made when the first page exhausts total_count."""
    raws = [_raw_record(f"rec{i}") for i in range(3)]
    route = respx.get(DNS_URL)
    route.mock(return_value=httpx.Response(200, json=_cf_response(raws, total_count=3)))
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)

    dns = [r for r in records if "content" in r]
    assert len(dns) == 3
    assert route.call_count == 1


# ── fetch(): authentication errors ────────────────────────────────────────────

@respx.mock
def test_fetch_401_raises_authentication_error(connector: CloudflareConnector) -> None:
    body = {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
    respx.get(DNS_URL).mock(return_value=httpx.Response(401, json=body))

    with pytest.raises(AuthenticationError) as exc_info:
        connector.fetch(VALID_CREDS)

    assert exc_info.value.status_code == 401


@respx.mock
def test_fetch_403_raises_authentication_error(connector: CloudflareConnector) -> None:
    respx.get(DNS_URL).mock(return_value=httpx.Response(403, json={"success": False, "errors": []}))

    with pytest.raises(AuthenticationError) as exc_info:
        connector.fetch(VALID_CREDS)

    assert exc_info.value.status_code == 403


# ── fetch(): other API errors ────────────────────────────────────────────────

@respx.mock
def test_fetch_500_raises_connector_error(connector: CloudflareConnector) -> None:
    respx.get(DNS_URL).mock(return_value=httpx.Response(500, text="Internal Server Error"))

    with pytest.raises(ConnectorError) as exc_info:
        connector.fetch(VALID_CREDS)

    assert exc_info.value.status_code == 500


@respx.mock
def test_fetch_success_false_raises_connector_error(connector: CloudflareConnector) -> None:
    """``success=false`` in the response body raises ``ConnectorError``."""
    body = {
        "success": False,
        "errors": [{"code": 7003, "message": "No route for that URI"}],
        "result": [],
    }
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=body))

    with pytest.raises(ConnectorError):
        connector.fetch(VALID_CREDS)


def test_fetch_missing_api_token_raises_connector_error(connector: CloudflareConnector) -> None:
    with pytest.raises(ConnectorError, match="api_token"):
        connector.fetch({"api_token": "", "zone_id": "some-zone"})


def test_fetch_missing_zone_id_raises_connector_error(connector: CloudflareConnector) -> None:
    with pytest.raises(ConnectorError, match="api_token"):
        connector.fetch({"api_token": "tok", "zone_id": ""})


def test_fetch_empty_credentials_raises_connector_error(connector: CloudflareConnector) -> None:
    with pytest.raises(ConnectorError):
        connector.fetch({})


# ── fetch(): rate limit / 429 ────────────────────────────────────────────────

@respx.mock
def test_fetch_retries_on_429_and_succeeds(
    connector: CloudflareConnector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 429 followed by a 200 succeeds after one retry (sleep is patched)."""
    monkeypatch.setattr("app.connectors.cloudflare.time.sleep", lambda _: None)

    raw = [_raw_record("rec1")]
    route = respx.get(DNS_URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "1"}, json={}),
        httpx.Response(200, json=_cf_response(raw)),
    ]
    _stub_extra_surfaces()

    records = connector.fetch(VALID_CREDS)
    dns = [r for r in records if "content" in r]
    assert len(dns) == 1
    assert dns[0]["record_id"] == "rec1"


@respx.mock
def test_fetch_raises_rate_limit_error_after_max_retries(
    connector: CloudflareConnector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Consecutive 429s exhaust all retries and raise ``RateLimitError``."""
    monkeypatch.setattr("app.connectors.cloudflare.time.sleep", lambda _: None)

    respx.get(DNS_URL).mock(
        return_value=httpx.Response(429, headers={"Retry-After": "1"}, json={})
    )

    with pytest.raises(RateLimitError):
        connector.fetch(VALID_CREDS)


@respx.mock
def test_fetch_uses_retry_after_header_for_sleep_duration(
    connector: CloudflareConnector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The value passed to ``time.sleep`` matches the ``Retry-After`` header."""
    sleep_calls: list[float] = []
    monkeypatch.setattr(
        "app.connectors.cloudflare.time.sleep",
        lambda secs: sleep_calls.append(secs),
    )

    raw = [_raw_record()]
    route = respx.get(DNS_URL)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "42"}, json={}),
        httpx.Response(200, json=_cf_response(raw)),
    ]
    _stub_extra_surfaces()

    connector.fetch(VALID_CREDS)

    assert sleep_calls == [42.0]


# ── fetch(): network errors ───────────────────────────────────────────────────

@respx.mock
def test_fetch_timeout_raises_network_error(connector: CloudflareConnector) -> None:
    respx.get(DNS_URL).mock(side_effect=httpx.TimeoutException("timed out"))

    with pytest.raises(NetworkError, match="timed out"):
        connector.fetch(VALID_CREDS)


@respx.mock
def test_fetch_connection_error_raises_network_error(connector: CloudflareConnector) -> None:
    respx.get(DNS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    with pytest.raises(NetworkError):
        connector.fetch(VALID_CREDS)


# ── validate_credentials() ────────────────────────────────────────────────────

@respx.mock
def test_validate_credentials_returns_true_for_valid_token(
    connector: CloudflareConnector,
) -> None:
    respx.get(DNS_URL).mock(return_value=httpx.Response(200, json=_cf_response([])))

    result = connector.validate_credentials(VALID_CREDS)
    assert result is True


@respx.mock
def test_validate_credentials_raises_for_invalid_token(
    connector: CloudflareConnector,
) -> None:
    respx.get(DNS_URL).mock(return_value=httpx.Response(401, json={"success": False, "errors": []}))

    with pytest.raises(AuthenticationError):
        connector.validate_credentials(VALID_CREDS)


@respx.mock
def test_validate_credentials_raises_for_bad_zone(
    connector: CloudflareConnector,
) -> None:
    """A valid token but non-existent zone raises ``ConnectorError``."""
    body = {"success": False, "errors": [{"code": 7003, "message": "No route for that URI"}]}
    respx.get(DNS_URL).mock(return_value=httpx.Response(400, json=body))

    with pytest.raises(ConnectorError):
        connector.validate_credentials(VALID_CREDS)


def test_validate_credentials_missing_creds_raises_connector_error(
    connector: CloudflareConnector,
) -> None:
    with pytest.raises(ConnectorError):
        connector.validate_credentials({"api_token": "", "zone_id": ""})


# ── exception hierarchy ───────────────────────────────────────────────────────

def test_authentication_error_is_subclass_of_connector_error() -> None:
    exc = AuthenticationError("bad token", status_code=401)
    assert isinstance(exc, ConnectorError)
    assert exc.status_code == 401


def test_rate_limit_error_is_subclass_of_connector_error() -> None:
    exc = RateLimitError("too many requests", retry_after=30.0)
    assert isinstance(exc, ConnectorError)
    assert exc.status_code == 429
    assert exc.retry_after == 30.0


def test_network_error_is_subclass_of_connector_error() -> None:
    exc = NetworkError("timeout")
    assert isinstance(exc, ConnectorError)
    assert exc.status_code is None
