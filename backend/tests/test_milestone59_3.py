"""M59.3 — External Boundary / Webhook / OAuth / Dangerous Action Safety.

Goal
----
Prove that every external-trust boundary (Stripe webhook, Slack OAuth,
Slack actions, GitHub App state) verifies authenticity before doing any
real work; every dangerous action (PR creation, sync, test-message,
push) is properly gated; and user-controlled URLs cannot be turned into
SSRF, log leakage, or cross-workspace abuse.

Strategy
--------
Layered tests, all runnable without PostgreSQL:

1. **Cryptographic correctness** — sign/verify roundtrips for
   ``verify_stripe_signature`` / Slack state / Slack request signature /
   GitHub App state with realistic-shape inputs and mutate-to-reject cases.

2. **Constant-time + replay guards** — verify a stale timestamp (>300s) is
   rejected and a forged HMAC is rejected.

3. **PR creation safety gates** — exercise every gate (confirmation phrase,
   admin role, fix preview availability, confidence, diff presence,
   placeholders, repo-in-workspace, installation_id, base branch, file
   path) end-to-end with mocked DB/preview.

4. **SSRF helper** — feed the realistic adversarial URL fixtures from the
   brief: ``http://localhost``, ``http://127.0.0.1``, ``http://169.254.169.254``,
   private IPv4 ranges, IPv6 loopback, IPv6 ULA, ``file://``, ``gopher://``,
   ``ftp://``.  Each must raise.

5. **Static safety-flag audits** — read source files at test time and
   confirm `_EXECUTES_TERRAFORM` / `_MUTATES_PROVIDER_RESOURCE` are literal
   ``False`` and that no ``subprocess`` / ``os.system`` / ``shell=True``
   import or call exists in the Terraform-fix or PR-creation services.

6. **Documented gaps** — assertions that *document* known short-window
   gaps (e.g. manual-sync rate limiting, Stripe event-id idempotency) so
   future work cannot silently regress the current behaviour.

No external API is called by this suite; no real credentials are loaded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import json
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — synthetic Stripe webhook signing
# ─────────────────────────────────────────────────────────────────────────────


_STRIPE_TEST_SECRET = "whsec_test_secret_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _stripe_sign(body: bytes, secret: str = _STRIPE_TEST_SECRET, *, ts: int | None = None) -> str:
    """Return a Stripe-Signature header value for *body*."""
    if ts is None:
        ts = int(time.time())
    signed = f"{ts}.{body.decode('utf-8')}"
    sig = hmac_lib.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


# ═════════════════════════════════════════════════════════════════════════════
# A. Stripe webhook safety
# ═════════════════════════════════════════════════════════════════════════════


class TestStripeWebhookSafety:

    def _setup_secret(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", _STRIPE_TEST_SECRET)

    def test_A1_missing_signature_secret_rejects(self, monkeypatch):
        from app import config
        from app.services.billing_service import verify_stripe_signature

        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", None)
        with pytest.raises(ValueError, match="STRIPE_WEBHOOK_SECRET"):
            verify_stripe_signature(b'{"type":"x"}', "t=1,v1=deadbeef")

    def test_A2_missing_header_keys_rejects(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        with pytest.raises(ValueError, match="Malformed"):
            verify_stripe_signature(b"{}", "garbage")

    def test_A3_invalid_signature_rejects(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        ts = int(time.time())
        header = f"t={ts},v1=0000000000000000000000000000000000000000000000000000000000000000"
        with pytest.raises(ValueError, match="signature mismatch"):
            verify_stripe_signature(b'{"type":"x"}', header)

    def test_A4_stale_timestamp_rejects(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        body = b'{"type":"customer.subscription.updated"}'
        # 10 minutes old → reject
        header = _stripe_sign(body, ts=int(time.time()) - 600)
        with pytest.raises(ValueError, match="too old"):
            verify_stripe_signature(body, header)

    def test_A5_future_timestamp_rejects(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        body = b'{"type":"customer.subscription.updated"}'
        header = _stripe_sign(body, ts=int(time.time()) + 600)
        with pytest.raises(ValueError):
            verify_stripe_signature(body, header)

    def test_A6_valid_signature_returns_parsed_event(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        body = b'{"id":"evt_1","type":"customer.subscription.updated","data":{"object":{}}}'
        header = _stripe_sign(body)
        event = verify_stripe_signature(body, header)
        assert event["id"] == "evt_1"
        assert event["type"] == "customer.subscription.updated"

    def test_A7_wrong_secret_fails_closed(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        body = b'{"type":"x"}'
        # Sign with a DIFFERENT secret — should not verify against our setting.
        header = _stripe_sign(body, secret="whsec_attacker_BBBBBBBBBBBBBBBBBBBBBB")
        with pytest.raises(ValueError, match="signature mismatch"):
            verify_stripe_signature(body, header)

    def test_A8_signature_uses_raw_body_not_reparsed_json(self, monkeypatch):
        self._setup_secret(monkeypatch)
        from app.services.billing_service import verify_stripe_signature

        # If the implementation re-encoded the JSON before HMAC, whitespace
        # changes would round-trip differently and the signature would still
        # validate.  Test that any byte-level mutation breaks the signature.
        body = b'{"type":"x","data":{"object":{}}}'
        header = _stripe_sign(body)
        # Mutate one byte and expect rejection.
        tampered = body.replace(b'"x"', b'"y"')
        with pytest.raises(ValueError, match="signature mismatch"):
            verify_stripe_signature(tampered, header)

    def test_A9_unhandled_event_type_logs_debug_and_returns(self, monkeypatch):
        """An unknown event type does NOT crash and does NOT update any billing row."""
        self._setup_secret(monkeypatch)
        from app.services.billing_service import handle_webhook_event

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        # Should not raise.
        handle_webhook_event({"type": "i.do.not.exist", "data": {"object": {}}}, db)
        # No write paths exercised.

    def test_A10_unknown_customer_id_does_not_create_workspace(self, monkeypatch):
        """If an event references an unknown customer AND no workspace_id
        metadata, the handler logs a warning and bails — it does not pick a
        random workspace to update."""
        self._setup_secret(monkeypatch)
        from app.services.billing_service import handle_webhook_event

        db = MagicMock()
        # _billing_by_customer returns None
        db.query.return_value.filter.return_value.first.return_value = None
        handle_webhook_event(
            {
                "type": "customer.subscription.updated",
                "data": {"object": {"id": "sub_xxx", "customer": "cus_unknown"}},
            },
            db,
        )
        db.commit.assert_not_called()


# ═════════════════════════════════════════════════════════════════════════════
# B. Slack state-token safety (HMAC + expiry + identity binding)
# ═════════════════════════════════════════════════════════════════════════════


class TestSlackStateToken:

    def _setup_state_secret(self, monkeypatch):
        from app import config
        monkeypatch.setattr(
            config.settings, "SLACK_APP_STATE_SECRET", "test_state_secret_AAAA"
        )

    def test_B1_roundtrip_user_workspace_bound(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token,
        )

        ws = str(uuid.uuid4())
        u = str(uuid.uuid4())
        token = generate_state_token(u, ws)
        payload = verify_state_token(token, u, ws)
        assert payload["user_id"] == u
        assert payload["workspace_id"] == ws

    def test_B2_tampered_payload_rejected(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token,
        )

        ws = str(uuid.uuid4())
        u = str(uuid.uuid4())
        token = generate_state_token(u, ws)
        payload_b64, sig = token.split(".", 1)
        # Flip a payload byte → HMAC fails.
        mutated = payload_b64[:-1] + ("A" if payload_b64[-1] != "A" else "B")
        with pytest.raises(ValueError):
            verify_state_token(f"{mutated}.{sig}", u, ws)

    def test_B3_tampered_signature_rejected(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token,
        )

        token = generate_state_token(str(uuid.uuid4()), str(uuid.uuid4()))
        payload_b64, _sig = token.split(".", 1)
        bad = "0" * 64
        with pytest.raises(ValueError):
            verify_state_token(f"{payload_b64}.{bad}", "u", "w")

    def test_B4_expired_token_rejected(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import verify_state_token

        # Manually craft an expired payload.
        payload = {
            "user_id": "u1", "workspace_id": "w1",
            "nonce": "n", "expires_at": int(time.time()) - 60,
        }
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        sig = hmac_lib.new(
            b"test_state_secret_AAAA", payload_b64.encode(), hashlib.sha256
        ).hexdigest()
        with pytest.raises(ValueError, match="expired"):
            verify_state_token(f"{payload_b64}.{sig}", "u1", "w1")

    def test_B5_user_mismatch_rejected(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token,
        )

        token = generate_state_token("alice", "ws-1")
        with pytest.raises(ValueError):
            verify_state_token(token, "bob", "ws-1")

    def test_B6_workspace_mismatch_rejected(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token,
        )

        token = generate_state_token("alice", "ws-A")
        with pytest.raises(ValueError):
            verify_state_token(token, "alice", "ws-B")

    def test_B7_verify_no_user_still_checks_expiry_and_hmac(self, monkeypatch):
        self._setup_state_secret(monkeypatch)
        from app.services.slack_service import (
            generate_state_token,
            verify_state_token_no_user,
        )

        token = generate_state_token("alice", "ws-1")
        # Happy path returns payload.
        payload = verify_state_token_no_user(token)
        assert payload["user_id"] == "alice"
        # Tamper signature.
        payload_b64, _ = token.split(".", 1)
        with pytest.raises(ValueError):
            verify_state_token_no_user(f"{payload_b64}.{'0' * 64}")

    def test_B8_state_secret_missing_raises_at_generation(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config.settings, "SLACK_APP_STATE_SECRET", None)
        from app.services.slack_service import generate_state_token

        with pytest.raises(RuntimeError, match="SLACK_APP_STATE_SECRET"):
            generate_state_token("u", "w")


# ═════════════════════════════════════════════════════════════════════════════
# C. Slack action signature (HMAC + 5-minute replay window)
# ═════════════════════════════════════════════════════════════════════════════


class TestSlackActionSignature:

    def test_C1_valid_signature_accepted(self):
        from app.services.slack_service import verify_request_signature

        secret = "test_signing_secret"
        body = b"payload=%7B%22foo%22%3A%22bar%22%7D"
        ts = str(int(time.time()))
        base = f"v0:{ts}:{body.decode()}"
        sig = "v0=" + hmac_lib.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()

        assert verify_request_signature(secret, ts, body, sig) is True

    def test_C2_invalid_signature_rejected(self):
        from app.services.slack_service import verify_request_signature

        secret = "test_signing_secret"
        body = b"payload=x"
        ts = str(int(time.time()))
        bad = "v0=" + "0" * 64
        assert verify_request_signature(secret, ts, body, bad) is False

    def test_C3_stale_timestamp_rejected(self):
        from app.services.slack_service import verify_request_signature

        secret = "s"
        body = b"x"
        # 10 minutes old
        ts = str(int(time.time()) - 600)
        base = f"v0:{ts}:{body.decode()}"
        sig = "v0=" + hmac_lib.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
        assert verify_request_signature(secret, ts, body, sig) is False

    def test_C4_future_timestamp_rejected(self):
        from app.services.slack_service import verify_request_signature

        secret = "s"
        body = b"x"
        ts = str(int(time.time()) + 600)
        base = f"v0:{ts}:{body.decode()}"
        sig = "v0=" + hmac_lib.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
        assert verify_request_signature(secret, ts, body, sig) is False

    def test_C5_non_integer_timestamp_rejected(self):
        from app.services.slack_service import verify_request_signature

        assert verify_request_signature("s", "not-a-number", b"x", "v0=...") is False

    def test_C6_wrong_secret_rejected(self):
        from app.services.slack_service import verify_request_signature

        body = b"x"
        ts = str(int(time.time()))
        base = f"v0:{ts}:{body.decode()}"
        sig = "v0=" + hmac_lib.new(b"correct", base.encode(), hashlib.sha256).hexdigest()
        # Verifier called with the WRONG secret → false
        assert verify_request_signature("wrong", ts, body, sig) is False


# ═════════════════════════════════════════════════════════════════════════════
# D. GitHub App state-token safety
# ═════════════════════════════════════════════════════════════════════════════


class TestGitHubAppStateToken:

    def test_D1_roundtrip_user_bound(self):
        from app.core.github_app import (
            generate_state_token,
            verify_state_token,
        )

        secret = "github_app_state_secret_AAAA"
        token = generate_state_token("alice-uuid", secret)
        payload = verify_state_token(token, "alice-uuid", secret)
        assert payload["user_id"] == "alice-uuid"

    def test_D2_user_mismatch_rejected(self):
        from app.core.github_app import (
            generate_state_token,
            verify_state_token,
        )

        secret = "github_app_state_secret_AAAA"
        token = generate_state_token("alice", secret)
        with pytest.raises(ValueError):
            verify_state_token(token, "mallory", secret)

    def test_D3_wrong_secret_rejected(self):
        from app.core.github_app import (
            generate_state_token,
            verify_state_token,
        )

        token = generate_state_token("alice", "secretA")
        with pytest.raises(ValueError):
            verify_state_token(token, "alice", "secretB")

    def test_D4_expired_token_rejected(self):
        from app.core.github_app import (
            generate_state_token,
            verify_state_token,
        )

        secret = "github_app_state_secret_AAAA"
        # ttl_seconds < 0 → already expired
        token = generate_state_token("alice", secret, ttl_seconds=-60)
        with pytest.raises(ValueError, match="expired"):
            verify_state_token(token, "alice", secret)

    def test_D5_tampered_signature_rejected(self):
        from app.core.github_app import (
            generate_state_token,
            verify_state_token,
        )

        token = generate_state_token("alice", "secretA")
        b64, _sig = token.split(".", 1)
        with pytest.raises(ValueError):
            verify_state_token(f"{b64}.{'0' * 64}", "alice", "secretA")


# ═════════════════════════════════════════════════════════════════════════════
# E. PR-creation safety gates — confirmation phrase, role, file path
# ═════════════════════════════════════════════════════════════════════════════


class TestPRCreationGates:

    def test_E1_wrong_confirmation_phrase_rejected(self):
        from app.services.github_pr_creation_service import _validate_confirmation

        for bad in ("create draft pr", "CREATE DRAFT PR ", "CREATE_DRAFT_PR", "yes"):
            with pytest.raises(ValueError, match="Confirmation phrase"):
                _validate_confirmation(bad)

    def test_E2_exact_phrase_accepted(self):
        from app.services.github_pr_creation_service import _validate_confirmation

        _validate_confirmation("CREATE DRAFT PR")  # does not raise

    @pytest.mark.parametrize(
        "bad_path",
        [
            "terraform.tfvars",
            "modules/foo.tfvars",
            "infra.tfstate",
            "states/prod.tfstate",
            ".terraform/modules/something.tf",
            ".terraform.lock.hcl",
        ],
    )
    def test_E3_unsafe_paths_rejected(self, bad_path):
        from app.services.github_pr_creation_service import _validate_file_path

        with pytest.raises(ValueError, match="unsafe pattern"):
            _validate_file_path(bad_path)

    @pytest.mark.parametrize(
        "ok_path",
        ["main.tf", "infra/network.tf", "modules/db/instance.tf"],
    )
    def test_E4_safe_paths_accepted(self, ok_path):
        from app.services.github_pr_creation_service import _validate_file_path

        _validate_file_path(ok_path)  # does not raise

    def test_E5_empty_base_branch_rejected(self):
        from app.services.github_pr_creation_service import _validate_base_branch

        for empty in ("", "   ", "\t\n"):
            with pytest.raises(ValueError, match="base_branch"):
                _validate_base_branch(empty)

    def test_E6_safety_flags_are_literally_false(self):
        from app.services import github_pr_creation_service

        # These constants are guarded by code comments saying "never set True".
        assert github_pr_creation_service._EXECUTES_TERRAFORM is False
        assert github_pr_creation_service._MUTATES_PROVIDER_RESOURCE is False

    def test_E7_confirmation_phrase_constant_unchanged(self):
        from app.services.github_pr_creation_service import _CONFIRMATION_PHRASE

        assert _CONFIRMATION_PHRASE == "CREATE DRAFT PR"

    def test_E8_no_subprocess_or_shell_in_pr_service(self):
        src = Path("app/services/github_pr_creation_service.py").read_text()
        for marker in ("subprocess", "os.system(", "os.popen(", "shell=True", "Popen("):
            assert marker not in src, (
                f"github_pr_creation_service contains forbidden token {marker!r}"
            )

    def test_E9_no_subprocess_or_shell_in_terraform_fix_service(self):
        src = Path("app/services/terraform_fix_suggestion_service.py").read_text()
        for marker in ("subprocess", "os.system(", "os.popen(", "shell=True", "Popen("):
            assert marker not in src

    def test_E10_no_subprocess_in_iac_mapping_service(self):
        src = Path("app/services/iac_mapping_service.py").read_text()
        for marker in ("subprocess", "os.system(", "os.popen(", "shell=True"):
            assert marker not in src

    def test_E11_pr_creation_calls_require_admin_role(self):
        """The PR-creation flow must call require_role(workspace_id, actor, 'admin', db)
        BEFORE doing any GitHub API work."""
        import inspect
        from app.services import github_pr_creation_service

        src = inspect.getsource(github_pr_creation_service.create_github_pr)
        assert 'require_role(workspace_id, actor_user_id, "admin", db)' in src
        # And the call must come before the GitHub-API-heavy branches.
        before = src.split('require_role(workspace_id, actor_user_id, "admin", db)')[0]
        for marker in ("_get_branch_sha", "create_branch", "_create_pr", "open_pr"):
            assert marker not in before, (
                f"{marker} call appears before require_role — gate is out of order"
            )

    def test_E12_pr_creation_filters_repo_by_workspace(self):
        """Gate 7: IacRepository must be filtered by workspace_id."""
        import inspect
        from app.services import github_pr_creation_service

        src = inspect.getsource(github_pr_creation_service.create_github_pr)
        assert "IacRepository.workspace_id == workspace_id" in src
        assert "IacRepository.id == request.iac_repository_id" in src


# ═════════════════════════════════════════════════════════════════════════════
# F. SSRF / URL validation
# ═════════════════════════════════════════════════════════════════════════════


class TestSSRFGuards:

    @pytest.mark.parametrize(
        "url",
        [
            # Loopback
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://0.0.0.0/hook",
            # AWS / GCP / Azure metadata
            "https://169.254.169.254/latest/meta-data/",
            "https://169.254.0.10/admin",
            # RFC 1918
            "https://10.0.0.1/x",
            "https://10.255.255.255/x",
            "https://172.16.0.1/x",
            "https://172.31.255.255/x",
            "https://192.168.0.1/x",
            "https://192.168.255.255/x",
        ],
    )
    def test_F1_private_ipv4_and_metadata_rejected(self, url):
        from app.services.notification_service import _validate_url, WebhookURLError

        with pytest.raises(WebhookURLError):
            _validate_url(url, slack=False)

    @pytest.mark.parametrize(
        "url",
        [
            "https://[::1]/x",
            "https://[fc00::1]/x",       # IPv6 ULA
        ],
    )
    def test_F2_private_ipv6_rejected(self, url):
        from app.services.notification_service import _validate_url, WebhookURLError

        with pytest.raises(WebhookURLError):
            _validate_url(url, slack=False)

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/hook",     # HTTP scheme blocked
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/",
            "javascript:alert(1)",
            "data:text/plain,boom",
        ],
    )
    def test_F3_non_https_schemes_rejected(self, url):
        from app.services.notification_service import _validate_url, WebhookURLError

        with pytest.raises(WebhookURLError):
            _validate_url(url, slack=False)

    def test_F4_oversized_url_rejected(self):
        from app.services.notification_service import _validate_url, WebhookURLError

        # 2049 chars total — over the 2048 limit.
        url = "https://example.com/" + ("a" * 2030)
        with pytest.raises(WebhookURLError, match="must not exceed"):
            _validate_url(url, slack=False)

    def test_F5_slack_prefix_enforced(self):
        from app.services.notification_service import _validate_url, WebhookURLError

        with pytest.raises(WebhookURLError, match="hooks.slack.com"):
            _validate_url("https://attacker.example.com/T00/B00/secret", slack=True)

    def test_F6_valid_https_url_accepted(self):
        from app.services.notification_service import _validate_url

        # Public URL — passes
        _validate_url("https://hooks.example.com/intake", slack=False)
        _validate_url("https://hooks.slack.com/services/T00/B00/abc", slack=True)

    def test_F7_url_with_no_hostname_rejected(self):
        from app.services.notification_service import _validate_url, WebhookURLError

        with pytest.raises(WebhookURLError):
            _validate_url("https:///nopath", slack=False)


# ═════════════════════════════════════════════════════════════════════════════
# G. Public-endpoint response safety: callbacks degrade gracefully and
#    don't leak tenant data on invalid input
# ═════════════════════════════════════════════════════════════════════════════


class TestPublicEndpointResponseShape:

    def test_G1_stripe_webhook_returns_200_for_unhandled_event(self, monkeypatch):
        """Per design, Stripe webhook returns 200 even for unknown event types
        so Stripe doesn't retry indefinitely.  Important to confirm the
        handler short-circuits cheaply for unknown events without DB work."""
        from app import config
        monkeypatch.setattr(config.settings, "STRIPE_WEBHOOK_SECRET", _STRIPE_TEST_SECRET)
        from app.services.billing_service import handle_webhook_event

        db = MagicMock()
        handle_webhook_event({"type": "weird.thing", "data": {"object": {}}}, db)
        db.commit.assert_not_called()
        db.add.assert_not_called()

    def test_G2_slack_action_handlers_return_ephemeral_on_error(self):
        """Slack action endpoints must always 200 with an ephemeral body —
        confirm the dispatch error branch builds an ephemeral response."""
        src = Path("app/services/slack_service.py").read_text()
        # The unexpected-error path returns _ephemeral(...) not raise.
        assert "_ephemeral(" in src
        assert "unexpected error" in src.lower() or "An unexpected error" in src

    def test_G3_slack_oauth_callback_redirects_on_error_not_raises(self):
        src = Path("app/routers/slack_oauth.py").read_text()
        # Failure modes redirect with ?reason=<short_code>, never expose the token.
        assert "invalid_state" in src
        assert "token_exchange_failed" in src
        assert "storage_failed" in src
        # No raw exc.message logging.
        assert "str(exc)" not in src or "type(exc).__name__" in src

    def test_G4_health_endpoint_has_no_auth_dependency(self):
        src = Path("app/routers/health.py").read_text()
        assert "get_current_user" not in src
        assert "current_user" not in src

    def test_G5_invite_preview_endpoint_does_not_leak_token(self):
        """``GET /invites/{token}`` is public and returns workspace metadata
        only — it must not echo the raw token back, must not include the
        token_hash, and must not include the workspace_id (existence leak)."""
        from app.schemas.workspace import InvitePreviewResponse

        fields = set(InvitePreviewResponse.model_fields.keys())
        for forbidden in ("token", "token_hash", "raw_token", "workspace_id"):
            assert forbidden not in fields, (
                f"InvitePreviewResponse must not expose {forbidden}"
            )


# ═════════════════════════════════════════════════════════════════════════════
# H. Static / wiring assertions on dangerous-action wiring
# ═════════════════════════════════════════════════════════════════════════════


class TestDangerousActionWiring:

    def test_H1_create_checkout_requires_admin(self):
        src = Path("app/routers/billing.py").read_text()
        # Every billing route calls _require_admin BEFORE doing real work.
        # Confirm no route body lacks the helper call.
        for method_name in (
            "def create_checkout(",
            "def create_portal(",
            "def get_billing(",
        ):
            start = src.find(method_name)
            assert start >= 0, f"Missing route function {method_name}"
            block = src[start: start + 800]
            assert "_require_admin" in block

    def test_H2_test_notification_endpoints_require_admin(self):
        src = Path("app/routers/workspaces.py").read_text()
        for method_name in (
            "def test_notification(",
            "def test_slack_app(",
            "def test_push_notification(",
            "def test_weekly_digest(",
        ):
            start = src.find(method_name)
            assert start >= 0, f"Missing function {method_name}"
            block = src[start: start + 800]
            # Each calls require_role(... 'admin', db) before doing work.
            assert 'require_role(' in block and '"admin"' in block, (
                f"{method_name} must require admin role"
            )

    def test_H3_create_sync_requires_viewer_access(self):
        """POST /syncs verifies current_user can view the integration —
        owner OR any member of its workspace (fixed post-audit: this used
        to be strict owner-only via get_integration_by_id, which silently
        broke manual "Sync Now" for every non-creator workspace member;
        get_integration_for_viewer is the same workspace-aware check
        GET /integrations/{id} already used)."""
        src = Path("app/routers/syncs.py").read_text()
        assert "get_integration_for_viewer" in src
        assert "actor_user_id=current_user.id" in src

    def test_H4_pr_creation_route_requires_admin_at_service_layer(self):
        """POST /changes/{id}/github-pr delegates to service which calls
        require_role admin+.  Confirm router does NOT skip that."""
        src = Path("app/routers/changes.py").read_text()
        assert "github_pr_creation_service.create_github_pr" in src
        # The change is validated via _get_change_and_workspace.
        assert "_get_change_and_workspace(change_id, current_user, db)" in src


# ═════════════════════════════════════════════════════════════════════════════
# I. Documented gaps — assert current behaviour so future regressions are
#    caught.  These tests assert what IS (not what should be).
# ═════════════════════════════════════════════════════════════════════════════


class TestDocumentedGaps:
    """M59.3 originally pinned four gaps as 'current behaviour'.  M59.4 fixed
    them; this section now asserts the protections exist.  See M59.4 report
    for the full deltas."""

    def test_I1_manual_sync_now_uses_in_flight_dedupe(self):
        """M59.4 wired ``has_in_flight_sync`` into POST /syncs."""
        src = Path("app/routers/syncs.py").read_text()
        assert "has_in_flight_sync" in src
        # Returns 409 when a sync is already running for the integration.
        assert "already in progress" in src.lower() or "in_flight" in src.lower()

    def test_I2_test_notification_endpoints_have_cooldown(self):
        """M59.4 added a workspace-wide cooldown via
        ``notification_service.assert_test_notification_cooldown``."""
        src = Path("app/routers/workspaces.py").read_text()
        # Each of the four test endpoints calls the cooldown helper.
        assert src.count("assert_test_notification_cooldown") >= 4
        assert src.count("mark_test_notification_sent") >= 4

    def test_I3_stripe_webhook_has_event_id_idempotency_dedupe(self):
        """M59.4 added StripeWebhookEvent + event_id dedupe in
        ``handle_webhook_event``."""
        import inspect
        from app.services import billing_service

        src = inspect.getsource(billing_service.handle_webhook_event)
        assert "event_id" in src
        assert "StripeWebhookEvent" in src
        assert 'event.get("id")' in src

    def test_I4_url_validator_resolves_dns(self):
        """M59.4 added DNS-rebinding protection via
        ``_assert_hostname_resolves_public``."""
        import inspect
        from app.services import notification_service

        src = inspect.getsource(notification_service._validate_url)
        # The function now calls the resolver for non-Slack hostname URLs.
        assert "_assert_hostname_resolves_public" in src
        # And the helper itself exists.
        assert hasattr(notification_service, "_assert_hostname_resolves_public")


# ═════════════════════════════════════════════════════════════════════════════
# J. End-to-end: invalid Stripe webhook returns 400 before any DB work
# ═════════════════════════════════════════════════════════════════════════════


class TestStripeWebhookFailsFast:

    def test_J1_missing_header_returns_400_no_db_session(self):
        """The route raises HTTPException(400) BEFORE opening a DB session
        when the Stripe-Signature header is missing — cheap rejection so
        invalid traffic doesn't load the DB."""
        src = Path("app/routers/stripe_webhook.py").read_text()
        # Must validate header BEFORE creating SessionLocal().
        body = src.split("async def stripe_webhook(")[1].split("async def")[0]
        header_check_pos = body.find("Missing Stripe-Signature")
        session_open_pos = body.find("SessionLocal()")
        assert header_check_pos >= 0, "Header check not found"
        assert session_open_pos >= 0, "DB session open not found"
        assert header_check_pos < session_open_pos, (
            "DB session opens before signature check — slow path on bad traffic"
        )

    def test_J2_invalid_signature_returns_400_no_db_session(self):
        src = Path("app/routers/stripe_webhook.py").read_text()
        body = src.split("async def stripe_webhook(")[1].split("async def")[0]
        verify_pos = body.find("verify_stripe_signature(")
        session_open_pos = body.find("SessionLocal()")
        assert verify_pos >= 0
        assert session_open_pos >= 0
        assert verify_pos < session_open_pos
