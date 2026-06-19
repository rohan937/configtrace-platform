"""PagerDuty configuration drift connector (M84A, M84D activity ingestion).

Connects to the PagerDuty REST API v2 using an API token and snapshots
eight safe configuration surfaces.  All raw secrets, URLs, user identities,
integration keys, routing keys, and PII are discarded before the record
is returned.

Surfaces covered
────────────────
  Services              — status, escalation policy ref, timeout categories,
                          team/integration counts; never keys or incident data
  Escalation policies   — rule/level/loop structure; never user targets
  Schedules             — layer/user/team counts; never user identities
  Service integrations  — type category, vendor name, key presence boolean;
                          never integration key or routing key values
  Webhook subscriptions — active, event count, URL scheme category;
                          never delivery URL or secret
  Event orchestrations  — route count, team presence; never rule expressions
  Business services     — team/contact presence; never subscriber lists
  Response plays        — responder/subscriber counts, runnability;
                          never responder identities or conference numbers

Credentials dict expected by fetch() and validate_credentials():
  {
    "api_token": "<PagerDuty API token>"
  }

SECURITY:
  The api_token is passed only in request headers and is NEVER stored on
  the connector instance or in any normalised record.  This file must not
  log, print, or persist the token value under any circumstances.

  Raw API responses are processed immediately and discarded.  Only flat
  safe scalars (opaque IDs, booleans, counts, category strings) are
  returned.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.connectors.base import BaseConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)
from app.connectors.pagerduty_schema import (
    PAGERDUTY_BUSINESS_SERVICE,
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_RECORD_TYPES,
    PAGERDUTY_RESPONSE_PLAY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.pagerduty.com"
_TIMEOUT = 30.0
_MAX_STR_LEN = 100
_PAGE_LIMIT = 100    # records per page request

# Per-surface record caps (bounds runaway pagination)
_MAX_SERVICES = 100
_MAX_ESCALATION_POLICIES = 100
_MAX_SCHEDULES = 100
_MAX_INTEGRATIONS_PER_SERVICE = 50
_MAX_INTEGRATIONS_TOTAL = 200
_MAX_WEBHOOK_SUBSCRIPTIONS = 100
_MAX_EVENT_ORCHESTRATIONS = 100
_MAX_BUSINESS_SERVICES = 100
_MAX_RESPONSE_PLAYS = 100

# Acknowledgement / auto-resolve timeout thresholds (seconds)
_TIMEOUT_THRESHOLDS = (
    (1_800, "short"),    # ≤ 30 min
    (14_400, "medium"),  # ≤ 4 hr
)

# ── Helper functions ──────────────────────────────────────────────────────────


def _trunc(value: Any, length: int = _MAX_STR_LEN) -> str:
    if isinstance(value, str):
        return value[:length]
    return ""


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    return default


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(0, value)
    return default


def _timeout_category(seconds: Any) -> str:
    """Convert a timeout value in seconds to a category label."""
    if seconds is None or seconds == 0:
        return "disabled"
    s = _int(seconds)
    if s == 0:
        return "disabled"
    for threshold, label in _TIMEOUT_THRESHOLDS:
        if s <= threshold:
            return label
    return "long"


def _sanitize_token(token: Any) -> str:
    """Return the API token string without logging it."""
    if not isinstance(token, str) or not token.strip():
        raise AuthenticationError("PagerDuty api_token is missing or empty.")
    return token.strip()


def _url_scheme_category(url: Any) -> str:
    """Derive URL scheme category and discard the raw URL."""
    if not isinstance(url, str) or not url.strip():
        return "absent"
    u = url.strip().lower()
    if u.startswith("https://"):
        return "https"
    if u.startswith("http://"):
        return "http"
    return "other"


# ── Connector ─────────────────────────────────────────────────────────────────


class PagerDutyConnector(BaseConnector):
    """PagerDuty REST API v2 configuration drift connector (M84A).

    Uses Token-based auth.  The token is never stored on the instance.
    """

    def _make_client(self, api_token: str) -> httpx.Client:
        """Build an httpx Client with safe PagerDuty headers.

        SECURITY: api_token is injected as a header ONLY at request time.
        It is never stored as an instance attribute.
        """
        return httpx.Client(
            base_url=_BASE_URL,
            headers={
                "Authorization": f"Token token={api_token}",
                "Accept": "application/vnd.pagerduty+json;version=2",
                "Content-Type": "application/json",
            },
            timeout=_TIMEOUT,
            follow_redirects=False,
        )

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Map PagerDuty HTTP status codes to connector exceptions."""
        code = response.status_code
        if code == 401:
            raise AuthenticationError(
                "PagerDuty authentication failed — check the API token."
            )
        if code == 403:
            raise ConnectorError(
                f"PagerDuty permission denied (403) for {response.url.path!r}."
            )
        if code == 429:
            raise RateLimitError("PagerDuty rate limit exceeded (429).")
        if code >= 500:
            raise ConnectorError(
                f"PagerDuty server error ({code}) for {response.url.path!r}."
            )
        if code >= 400:
            raise ConnectorError(
                f"PagerDuty client error ({code}) for {response.url.path!r}."
            )

    def _paginate(
        self,
        client: httpx.Client,
        path: str,
        key: str,
        params: Optional[dict] = None,
        max_records: int = _PAGE_LIMIT,
    ) -> list[dict]:
        """Fetch all pages from a PagerDuty list endpoint.

        Caps at max_records to prevent runaway pagination.
        Uses offset/limit pagination (PagerDuty classic REST API v2).
        """
        records: list[dict] = []
        offset = 0
        limit = min(_PAGE_LIMIT, max_records)
        try:
            while True:
                query: dict = {"limit": limit, "offset": offset}
                if params:
                    query.update(params)
                try:
                    resp = client.get(path, params=query)
                except httpx.TransportError as exc:
                    raise NetworkError(f"PagerDuty network error on {path!r}: {exc}") from exc
                self._raise_for_status(resp)
                data = resp.json()
                page = data.get(key, [])
                if not isinstance(page, list):
                    break
                records.extend(page)
                if len(records) >= max_records or not data.get("more", False):
                    break
                offset += limit
        except (AuthenticationError, RateLimitError, NetworkError, ConnectorError):
            raise
        except Exception as exc:
            raise ConnectorError(f"PagerDuty paginate error on {path!r}: {exc}") from exc
        return records[:max_records]

    # ── Normalizers ───────────────────────────────────────────────────────────

    def _normalize_service(self, raw: dict) -> dict:
        """Normalise one PagerDuty service to a safe flat record.

        SECURITY: integration keys, routing keys, webhook URLs, incident
        data, and user/customer PII are never stored.
        """
        svc_id = _trunc(raw.get("id", ""), 64) or "unknown"
        ep = raw.get("escalation_policy") or {}
        ep_id = _trunc(ep.get("id", ""), 64) if isinstance(ep, dict) else ""
        teams = raw.get("teams") or []
        intgs = raw.get("integrations") or []
        sched_actions = raw.get("scheduled_actions") or []
        support_hours = raw.get("support_hours")
        urg = raw.get("incident_urgency_rule") or {}
        urg_type = _trunc(urg.get("type", "unknown"), 64) if isinstance(urg, dict) else "unknown"
        alert_cat_raw = _trunc(raw.get("alert_creation", ""), 64)
        if alert_cat_raw == "create_alerts_and_incidents":
            alert_cat = "alerts_and_incidents"
        elif alert_cat_raw == "create_incidents":
            alert_cat = "incidents_only"
        else:
            alert_cat = "unknown"
        status_raw = _trunc(raw.get("status", ""), 32)
        if status_raw in ("active", "warning", "critical", "maintenance"):
            status_cat = status_raw
        else:
            status_cat = "unknown"
        return {
            "record_type": PAGERDUTY_SERVICE,
            "provider": "pagerduty",
            "record_id": svc_id,
            "resource_id": svc_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "status_category": status_cat,
            "escalation_policy_id": ep_id,
            "team_count": _int(len(teams) if isinstance(teams, list) else 0),
            "integration_count": _int(len(intgs) if isinstance(intgs, list) else 0),
            "alert_creation_category": alert_cat,
            "incident_urgency_rule_type": urg_type,
            "support_hours_enabled": support_hours is not None,
            "scheduled_actions_count": _int(len(sched_actions) if isinstance(sched_actions, list) else 0),
            "auto_resolve_timeout_category": _timeout_category(raw.get("auto_resolve_timeout")),
            "acknowledgement_timeout_category": _timeout_category(raw.get("acknowledgement_timeout")),
        }

    def _normalize_escalation_policy(self, raw: dict) -> dict:
        """Normalise one PagerDuty escalation policy to a safe flat record.

        SECURITY: user targets, user emails, names, phone numbers, and
        contact methods are never stored.  Target counts are derived from
        the target list then discarded — only the integers are retained.
        """
        ep_id = _trunc(raw.get("id", ""), 64) or "unknown"
        teams = raw.get("teams") or []
        rules = raw.get("escalation_rules") or []
        levels: set = set()
        target_count = 0
        user_target_count = 0
        schedule_target_count = 0
        for rule in (rules if isinstance(rules, list) else []):
            if isinstance(rule, dict):
                lvl = rule.get("escalation_delay_in_minutes")
                if lvl is not None:
                    levels.add(lvl)
                # Count targets by type category — never store IDs or names
                for tgt in (rule.get("targets") or []):
                    if not isinstance(tgt, dict):
                        continue
                    target_count += 1
                    tgt_type = _trunc(tgt.get("type", ""), 64).lower()
                    if "schedule" in tgt_type:
                        schedule_target_count += 1
                    elif "user" in tgt_type:
                        user_target_count += 1
        handoff_raw = _trunc(raw.get("on_call_handoff_notifications", ""), 64)
        if handoff_raw in ("if_has_services", "always", "never"):
            handoff = handoff_raw
        else:
            handoff = "unknown"
        num_loops = _int(raw.get("num_loops", 0))
        repeat_enabled = num_loops > 0
        return {
            "record_type": PAGERDUTY_ESCALATION_POLICY,
            "provider": "pagerduty",
            "record_id": ep_id,
            "resource_id": ep_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "team_count": _int(len(teams) if isinstance(teams, list) else 0),
            "escalation_rule_count": _int(len(rules) if isinstance(rules, list) else 0),
            "escalation_level_count": _int(len(levels)),
            "repeat_enabled": repeat_enabled,
            "num_loops": num_loops,
            "on_call_handoff_notifications": handoff,
            # M84C safe target-count fields
            "target_count": target_count,
            "user_target_count": user_target_count,
            "schedule_target_count": schedule_target_count,
            "has_schedule_targets": schedule_target_count > 0,
        }

    def _normalize_schedule(self, raw: dict) -> dict:
        """Normalise one PagerDuty schedule to a safe flat record.

        SECURITY: user identities, emails, names, phone numbers, and
        on-call assignment data are never stored.  Restriction counts are
        derived from layer restriction lists then discarded.
        """
        sched_id = _trunc(raw.get("id", ""), 64) or "unknown"
        teams = raw.get("teams") or []
        layers = raw.get("schedule_layers") or []
        users: set = set()
        restriction_count = 0
        for layer in (layers if isinstance(layers, list) else []):
            if isinstance(layer, dict):
                for u in (layer.get("users") or []):
                    if isinstance(u, dict) and u.get("id"):
                        users.add(u["id"])
                # Count restrictions — never store restriction content
                restrictions = layer.get("restrictions") or []
                if isinstance(restrictions, list):
                    restriction_count += len(restrictions)
        return {
            "record_type": PAGERDUTY_SCHEDULE,
            "provider": "pagerduty",
            "record_id": sched_id,
            "resource_id": sched_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "time_zone_present": bool(raw.get("time_zone")),
            "layer_count": _int(len(layers) if isinstance(layers, list) else 0),
            "user_count": _int(len(users)),
            "team_count": _int(len(teams) if isinstance(teams, list) else 0),
            # M84C safe restriction fields
            "restriction_count": restriction_count,
            "has_restrictions": restriction_count > 0,
        }

    def _normalize_service_integration(self, raw: dict, service_id: str) -> dict:
        """Normalise one PagerDuty service integration to a safe flat record.

        SECURITY: integration keys, routing keys, and integration email
        addresses are never stored.  The has_integration_key boolean is
        derived then the value is discarded.
        """
        intg_id = _trunc(raw.get("id", ""), 64) or "unknown"
        type_raw = _trunc(raw.get("type", ""), 64)
        if "email" in type_raw:
            type_cat = "email"
        elif "generic_events_api" in type_raw or "events_api_v2" in type_raw:
            type_cat = "generic_events_api"
        elif raw.get("vendor"):
            type_cat = "vendor"
        else:
            type_cat = "other"
        vendor = raw.get("vendor") or {}
        vendor_name: Optional[str] = None
        if isinstance(vendor, dict) and vendor.get("summary"):
            vendor_name = _trunc(vendor["summary"], _MAX_STR_LEN)
        # Derive key presence then discard raw key values
        has_key = bool(
            raw.get("integration_key") or raw.get("routing_key")
        )
        routing_key_present = bool(raw.get("routing_key"))
        return {
            "record_type": PAGERDUTY_SERVICE_INTEGRATION,
            "provider": "pagerduty",
            "record_id": intg_id,
            "resource_id": intg_id,
            "service_id": _trunc(service_id, 64),
            "type_category": type_cat,
            "vendor_name": vendor_name,
            "has_integration_key": has_key,
            # M84C safe key-type field
            "routing_key_present": routing_key_present,
        }

    def _normalize_webhook_subscription(self, raw: dict) -> dict:
        """Normalise one PagerDuty V3 webhook subscription to a safe record.

        SECURITY: delivery URL and webhook secret are never stored.
        The URL scheme category is derived from the URL then discarded.
        """
        ws_id = _trunc(raw.get("id", ""), 64) or "unknown"
        events = raw.get("events") or []
        delivery = raw.get("delivery_method") or {}
        delivery_url = None
        has_custom_headers = False
        if isinstance(delivery, dict):
            delivery_url = delivery.get("url") or delivery.get("temporarily_disabled")
            if not isinstance(delivery_url, str):
                delivery_url = None
            # Derive custom-headers presence; discard all header names/values
            custom_headers = delivery.get("custom_headers") or []
            has_custom_headers = isinstance(custom_headers, list) and len(custom_headers) > 0
        url_scheme = _url_scheme_category(delivery_url)
        flt = raw.get("filter") or {}
        filter_type_raw = _trunc(flt.get("type", "unknown"), 64) if isinstance(flt, dict) else "unknown"
        if filter_type_raw in ("account_reference", "account"):
            filter_type = "account"
        elif filter_type_raw in ("service_reference",):
            filter_type = "service_reference"
        elif filter_type_raw in ("team_reference",):
            filter_type = "team_reference"
        else:
            filter_type = "unknown"
        return {
            "record_type": PAGERDUTY_WEBHOOK_SUBSCRIPTION,
            "provider": "pagerduty",
            "record_id": ws_id,
            "resource_id": ws_id,
            "active": _bool(raw.get("active"), default=True),
            "event_count": _int(len(events) if isinstance(events, list) else 0),
            "delivery_url_scheme_category": url_scheme,
            "filter_type": filter_type,
            # M84C safe auth-indicator field
            "has_custom_headers": has_custom_headers,
        }

    def _normalize_event_orchestration(self, raw: dict) -> dict:
        """Normalise one PagerDuty event orchestration to a safe flat record.

        SECURITY: routing expressions, condition logic, action details,
        and integration keys are never stored.
        """
        eo_id = _trunc(raw.get("id", ""), 64) or "unknown"
        team = raw.get("team") or {}
        routes = raw.get("routes") or []
        return {
            "record_type": PAGERDUTY_EVENT_ORCHESTRATION,
            "provider": "pagerduty",
            "record_id": eo_id,
            "resource_id": eo_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "team_present": bool(team and isinstance(team, dict) and team.get("id")),
            "route_count": _int(len(routes) if isinstance(routes, list) else 0),
        }

    def _normalize_business_service(self, raw: dict) -> dict:
        """Normalise one PagerDuty business service to a safe flat record.

        SECURITY: subscriber lists, contact information, and user
        identities are never stored.
        """
        bs_id = _trunc(raw.get("id", ""), 64) or "unknown"
        team = raw.get("team") or {}
        poc = raw.get("point_of_contact")
        return {
            "record_type": PAGERDUTY_BUSINESS_SERVICE,
            "provider": "pagerduty",
            "record_id": bs_id,
            "resource_id": bs_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "team_present": bool(team and isinstance(team, dict) and team.get("id")),
            "point_of_contact_present": bool(poc),
        }

    def _normalize_response_play(self, raw: dict) -> dict:
        """Normalise one PagerDuty response play to a safe flat record.

        SECURITY: responder identities, subscriber identities, and
        conference phone numbers are never stored.
        """
        rp_id = _trunc(raw.get("id", ""), 64) or "unknown"
        team = raw.get("team") or {}
        responders = raw.get("responders") or []
        subscribers = raw.get("subscribers") or []
        conf_number = raw.get("conference_number")
        runnability_raw = _trunc(raw.get("runnability", ""), 32)
        if runnability_raw in ("owner", "team", "any"):
            runnability = runnability_raw
        else:
            runnability = "unknown"
        return {
            "record_type": PAGERDUTY_RESPONSE_PLAY,
            "provider": "pagerduty",
            "record_id": rp_id,
            "resource_id": rp_id,
            "resource_name": _trunc(raw.get("name", ""), _MAX_STR_LEN),
            "team_present": bool(team and isinstance(team, dict) and team.get("id")),
            "responder_count": _int(len(responders) if isinstance(responders, list) else 0),
            "subscriber_count": _int(len(subscribers) if isinstance(subscribers, list) else 0),
            "conference_number_present": bool(conf_number),
            "runnability": runnability,
        }

    # ── Surface fetchers ──────────────────────────────────────────────────────

    def _fetch_services(self, client: httpx.Client) -> list[dict]:
        raw = self._paginate(
            client, "/services", "services",
            params={"include[]": ["integrations", "teams", "scheduled_actions"]},
            max_records=_MAX_SERVICES,
        )
        return [self._normalize_service(r) for r in raw]

    def _fetch_escalation_policies(self, client: httpx.Client) -> list[dict]:
        raw = self._paginate(
            client, "/escalation_policies", "escalation_policies",
            params={"include[]": ["teams"]},
            max_records=_MAX_ESCALATION_POLICIES,
        )
        return [self._normalize_escalation_policy(r) for r in raw]

    def _fetch_schedules(self, client: httpx.Client) -> list[dict]:
        raw = self._paginate(
            client, "/schedules", "schedules",
            params={"include[]": ["users", "teams", "schedule_layers"]},
            max_records=_MAX_SCHEDULES,
        )
        return [self._normalize_schedule(r) for r in raw]

    def _fetch_service_integrations(
        self, client: httpx.Client, services: list[dict]
    ) -> list[dict]:
        """Fetch integrations for each service.  Fail-soft on 403/404 per service."""
        records: list[dict] = []
        for svc in services:
            svc_id = svc.get("record_id") or svc.get("id", "")
            if not svc_id or len(records) >= _MAX_INTEGRATIONS_TOTAL:
                break
            try:
                resp = client.get(
                    f"/services/{svc_id}/integrations",
                    params={"include[]": ["integration_key", "vendor"]},
                )
                if resp.status_code in (403, 404):
                    continue
                if resp.status_code == 429:
                    raise RateLimitError("PagerDuty rate limit (429) fetching integrations.")
                if resp.status_code in (401,):
                    raise AuthenticationError("PagerDuty auth failed fetching integrations.")
                if resp.status_code >= 400:
                    continue
                intgs = resp.json().get("integrations") or []
                for raw in (intgs if isinstance(intgs, list) else []):
                    if len(records) >= _MAX_INTEGRATIONS_TOTAL:
                        break
                    records.append(self._normalize_service_integration(raw, svc_id))
            except (AuthenticationError, RateLimitError):
                raise
            except Exception:
                continue
        return records

    def _fetch_webhook_subscriptions(self, client: httpx.Client) -> list[dict]:
        """Fetch V3 webhook subscriptions.  Fail-soft on 403/404/405."""
        try:
            raw = self._paginate(
                client, "/webhook_subscriptions", "webhook_subscriptions",
                max_records=_MAX_WEBHOOK_SUBSCRIPTIONS,
            )
            return [self._normalize_webhook_subscription(r) for r in raw]
        except ConnectorError:
            return []

    def _fetch_event_orchestrations(self, client: httpx.Client) -> list[dict]:
        """Fetch event orchestrations.  Fail-soft on 403/404 (plan-gated)."""
        try:
            raw = self._paginate(
                client, "/event_orchestrations", "orchestrations",
                max_records=_MAX_EVENT_ORCHESTRATIONS,
            )
            return [self._normalize_event_orchestration(r) for r in raw]
        except ConnectorError:
            return []

    def _fetch_business_services(self, client: httpx.Client) -> list[dict]:
        """Fetch business services.  Fail-soft on 403/404 (plan-gated)."""
        try:
            raw = self._paginate(
                client, "/business_services", "business_services",
                max_records=_MAX_BUSINESS_SERVICES,
            )
            return [self._normalize_business_service(r) for r in raw]
        except ConnectorError:
            return []

    def _fetch_response_plays(self, client: httpx.Client) -> list[dict]:
        """Fetch response plays.  Fail-soft on 403/404 (plan-gated)."""
        try:
            raw = self._paginate(
                client, "/response_plays", "response_plays",
                max_records=_MAX_RESPONSE_PLAYS,
            )
            return [self._normalize_response_play(r) for r in raw]
        except ConnectorError:
            return []

    # ── Public interface ──────────────────────────────────────────────────────

    def fetch(self, credentials: dict) -> list[dict]:
        """Snapshot all PagerDuty configuration surfaces and return safe records.

        SECURITY: The api_token is used only within the httpx.Client context
        and is never stored on the connector instance or in any returned record.
        """
        api_token = _sanitize_token(credentials.get("api_token", ""))
        records: list[dict] = []
        with self._make_client(api_token) as client:
            # Required surfaces — propagate auth/rate-limit errors
            services = self._fetch_services(client)
            records.extend(services)
            records.extend(self._fetch_escalation_policies(client))
            records.extend(self._fetch_schedules(client))

            # Service integrations — require service list; fail-soft per service
            records.extend(self._fetch_service_integrations(client, services))

            # Optional plan-gated surfaces — fail-soft on 403/404
            records.extend(self._fetch_webhook_subscriptions(client))
            records.extend(self._fetch_event_orchestrations(client))
            records.extend(self._fetch_business_services(client))
            records.extend(self._fetch_response_plays(client))

        return records

    def list_activity_events(
        self,
        credentials: dict,
        *,
        max_events: int = 100,
        lookback_hours: int = 24,
    ) -> list[dict]:
        """Synthesize review-safe PagerDuty configuration-state activity events.

        PagerDuty's audit trail API includes actor emails, user IDs, IP
        addresses, and user agents in every entry — ingesting those would
        violate ConfigTrace's privacy contract. Instead, activity events are
        synthesized from the same safe drift surfaces the drift connector
        already reads (M84A–M84C):

        Surfaces covered:
        - Services (status, escalation policy, team/integration posture)
        - Escalation policies (rule/level/target count, loop structure)
        - Schedules (layer/user/team/restriction posture)
        - Service integrations (type category, key presence)
        - Webhook subscriptions (active, event count, delivery scheme)
        - Event orchestrations (route count, team presence)
        - Business services (team/contact presence)
        - Response plays (responder/subscriber counts, runnability)

        Each event represents configuration state observed at poll time.
        Events are scoped to a UTC-day fingerprint for idempotency — re-polling
        on the same UTC day yields the same provider_event_id.

        PRIVACY — what is NEVER returned:
        - PagerDuty API tokens, routing keys, integration keys.
        - Webhook secrets, delivery URLs, custom header names/values.
        - User emails, user names, phone numbers, contact methods.
        - On-call user identities, responder identities, subscriber identities.
        - Incident payloads, alert payloads, conference phone numbers.
        - Raw routing expressions, IP addresses, user agents.
        - Raw PagerDuty audit payloads, raw API response dicts.
        - Customer PII of any kind.

        Raises:
            AuthenticationError: 401 from the PagerDuty API.
            RateLimitError: 429 rate limit hit.
            NetworkError: Transport-level failure.
            ConnectorError: Unexpected 4xx/5xx.
        """
        from datetime import datetime, timezone

        max_events = min(max(1, max_events), 1000)
        lookback_hours = min(max(1, lookback_hours), 168)  # noqa: F841 — context only

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events: list[dict] = []

        api_token = _sanitize_token(credentials.get("api_token", ""))
        with self._make_client(api_token) as client:
            # Required surfaces — propagate auth/rate-limit errors.
            services = self._fetch_services(client)
            self._collect_service_events(services, events, day)

            eps = self._fetch_escalation_policies(client)
            self._collect_escalation_policy_events(eps, events, day)

            scheds = self._fetch_schedules(client)
            self._collect_schedule_events(scheds, events, day)

            intgs = self._fetch_service_integrations(client, services)
            self._collect_service_integration_events(intgs, events, day)

            # Optional plan-gated surfaces — fail-soft on 403/404.
            try:
                whs = self._fetch_webhook_subscriptions(client)
                self._collect_webhook_events(whs, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("pagerduty_activity: webhook_subscriptions surface skipped")

            try:
                eos = self._fetch_event_orchestrations(client)
                self._collect_orchestration_events(eos, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("pagerduty_activity: event_orchestrations surface skipped")

            try:
                bss = self._fetch_business_services(client)
                self._collect_business_service_events(bss, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("pagerduty_activity: business_services surface skipped")

            try:
                rps = self._fetch_response_plays(client)
                self._collect_response_play_events(rps, events, day)
            except Exception:  # noqa: BLE001
                logger.debug("pagerduty_activity: response_plays surface skipped")

        return events[:max_events]

    # ── Activity surface collectors (M84D) ────────────────────────────────────
    #
    # Each collector emits one config-state activity event per normalized record.
    # Only safe allowlisted fields from the M84A–M84C schema are included.
    # Raw API payloads, URLs, secrets, tokens, and all user/PII data are NEVER
    # stored.

    def _collect_service_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:service:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_service",
                "resource_id": rid,
                "record_type": "pagerduty_service",
                "operation_family": "pagerduty.service",
                "operation_action": "updated",
                "category": "Service configuration",
                "status_category": rec.get("status_category"),
                "escalation_policy_id": rec.get("escalation_policy_id") or None,
                "team_count": rec.get("team_count"),
                "integration_count": rec.get("integration_count"),
                "alert_creation_category": rec.get("alert_creation_category"),
                "acknowledgement_timeout_category": rec.get("acknowledgement_timeout_category"),
                "auto_resolve_timeout_category": rec.get("auto_resolve_timeout_category"),
                "support_hours_enabled": rec.get("support_hours_enabled"),
                "scheduled_actions_count": rec.get("scheduled_actions_count"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.service.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_escalation_policy_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:escalation_policy:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_escalation_policy",
                "resource_id": rid,
                "record_type": "pagerduty_escalation_policy",
                "operation_family": "pagerduty.escalation_policy",
                "operation_action": "updated",
                "category": "Escalation policy configuration",
                "team_count": rec.get("team_count"),
                "escalation_rule_count": rec.get("escalation_rule_count"),
                "escalation_level_count": rec.get("escalation_level_count"),
                "target_count": rec.get("target_count"),
                "schedule_target_count": rec.get("schedule_target_count"),
                "has_schedule_targets": rec.get("has_schedule_targets"),
                "repeat_enabled": rec.get("repeat_enabled"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.escalation_policy.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_schedule_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:schedule:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_schedule",
                "resource_id": rid,
                "record_type": "pagerduty_schedule",
                "operation_family": "pagerduty.schedule",
                "operation_action": "updated",
                "category": "Schedule configuration",
                "layer_count": rec.get("layer_count"),
                "user_count": rec.get("user_count"),
                "team_count": rec.get("team_count"),
                "restriction_count": rec.get("restriction_count"),
                "has_restrictions": rec.get("has_restrictions"),
                "time_zone_present": rec.get("time_zone_present"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.schedule.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_service_integration_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:service_integration:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_service_integration",
                "resource_id": rid,
                "record_type": "pagerduty_service_integration",
                "operation_family": "pagerduty.service_integration",
                "operation_action": "updated",
                "category": "Service integration configuration",
                "integration_type_category": rec.get("type_category"),
                "key_present": rec.get("has_integration_key"),
                "routing_key_present": rec.get("routing_key_present"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.service_integration.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_webhook_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:webhook_subscription:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_webhook_subscription",
                "resource_id": rid,
                "record_type": "pagerduty_webhook_subscription",
                "operation_family": "pagerduty.webhook_subscription",
                "operation_action": "updated",
                "category": "Webhook subscription configuration",
                "active": rec.get("active"),
                "event_count": rec.get("event_count"),
                "url_scheme_category": rec.get("delivery_url_scheme_category"),
                "event_scope_category": rec.get("filter_type"),
                "secret_present": rec.get("has_custom_headers"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.webhook_subscription.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_orchestration_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:event_orchestration:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_event_orchestration",
                "resource_id": rid,
                "record_type": "pagerduty_event_orchestration",
                "operation_family": "pagerduty.event_orchestration",
                "operation_action": "updated",
                "category": "Event orchestration configuration",
                "route_count": rec.get("route_count"),
                "team_present": rec.get("team_present"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.event_orchestration.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_business_service_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:business_service:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_business_service",
                "resource_id": rid,
                "record_type": "pagerduty_business_service",
                "operation_family": "pagerduty.business_service",
                "operation_action": "updated",
                "category": "Business service configuration",
                "team_present": rec.get("team_present"),
                "description_present": rec.get("point_of_contact_present"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.business_service.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def _collect_response_play_events(
        self, records: list[dict], events: list, day: str
    ) -> None:
        for rec in records:
            rid = rec.get("record_id") or "unknown"
            eid = f"pagerduty:response_play:{rid}:{day}"
            meta: dict = {
                "resource_type": "pagerduty_response_play",
                "resource_id": rid,
                "record_type": "pagerduty_response_play",
                "operation_family": "pagerduty.response_play",
                "operation_action": "updated",
                "category": "Response play configuration",
                "responder_count": rec.get("responder_count"),
                "subscriber_count": rec.get("subscriber_count"),
                "team_present": rec.get("team_present"),
                "runnable": rec.get("runnability"),
                "conference_present": rec.get("conference_number_present"),
                "pagerduty_event_id": eid,
            }
            events.append({
                "event_type": "pagerduty.response_play.updated",
                "provider": "pagerduty",
                "source": "pagerduty_activity_event",
                "event_source": "pagerduty_activity_event",
                "provider_event_id": eid,
                "metadata": {k: v for k, v in meta.items() if v is not None},
            })

    def validate_credentials(self, credentials: dict) -> bool:
        """Validate PagerDuty credentials by making a minimal API call.

        Uses GET /abilities which requires a valid API token and returns
        fast.  Returns False rather than raising on auth failure so the
        caller can surface a clean error message.
        """
        try:
            api_token = _sanitize_token(credentials.get("api_token", ""))
        except AuthenticationError:
            return False
        try:
            with self._make_client(api_token) as client:
                try:
                    resp = client.get("/abilities")
                except httpx.TransportError:
                    return False
                return resp.status_code in (200, 204)
        except Exception:
            return False
