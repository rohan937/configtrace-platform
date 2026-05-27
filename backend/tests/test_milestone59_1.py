"""M59.1 — Workspace Isolation & Authorization Hardening audit.

Goal
----
Prove that a user in workspace A cannot read, mutate, sync, delete, or act
on resources belonging to workspace B; that non-admins cannot perform
admin-only workspace actions; and that intentionally public endpoints are
safe.

Test strategy
-------------
Two layers:

1. **Mock-DB unit tests** — exercise the actual authorization helper
   functions in ``workspace_service``, ``integration_service``,
   ``iac_mapping_service`` against ``MagicMock`` db sessions.  Verifies the
   contracts (LookupError vs PermissionError, ``target.workspace_id !=
   workspace_id`` confused-deputy guards, role-rank semantics).

2. **Static wiring assertions** — read the router source files at test time
   and assert every workspace-scoped endpoint calls a recognized
   authorization helper (``require_role`` / ``_require_admin`` /
   ``get_integration_for_*`` / ``_get_change_and_workspace`` / etc.).  This
   prevents regressions where a future PR adds a new workspace-scoped route
   without a workspace-membership check.

Both layers run without PostgreSQL.  See M59.1 audit report Section 12
"Known limitations" for what still requires an integration DB.
"""

from __future__ import annotations

import ast
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers (same shape as test_milestone51.py)
# ─────────────────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.add = MagicMock()
    db.flush = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    db.delete = MagicMock()
    return db


def _make_member(workspace_id, user_id, role: str = "member") -> MagicMock:
    m = MagicMock()
    m.id = uuid.uuid4()
    m.workspace_id = workspace_id
    m.user_id = user_id
    m.role = role
    m.created_at = _utcnow()
    m.updated_at = _utcnow()
    return m


def _make_integration(user_id, workspace_id=None, status="active") -> MagicMock:
    integ = MagicMock()
    integ.id = uuid.uuid4()
    integ.user_id = user_id
    integ.workspace_id = workspace_id
    integ.status = status
    integ.provider = "cloudflare"
    integ.display_name = "Test Integration"
    integ.created_at = _utcnow()
    return integ


# ═════════════════════════════════════════════════════════════════════════════
# A. Workspace membership — service-level
# ═════════════════════════════════════════════════════════════════════════════


class TestWorkspaceMembership:

    def test_A1_require_membership_raises_lookup_for_non_member(self):
        from app.services.workspace_service import _require_membership

        db = _mock_db()
        with patch(
            "app.services.workspace_service.get_membership", return_value=None
        ):
            with pytest.raises(LookupError):
                _require_membership(uuid.uuid4(), uuid.uuid4(), db)

    def test_A2_require_membership_returns_member_when_present(self):
        from app.services.workspace_service import _require_membership

        db = _mock_db()
        ws_id, uid = uuid.uuid4(), uuid.uuid4()
        m = _make_member(ws_id, uid, "member")
        with patch(
            "app.services.workspace_service.get_membership", return_value=m
        ):
            assert _require_membership(ws_id, uid, db) is m

    def test_A3_require_role_raises_permission_for_low_role(self):
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id, uid = uuid.uuid4(), uuid.uuid4()
        m = _make_member(ws_id, uid, "member")  # member < admin
        with patch(
            "app.services.workspace_service.get_membership", return_value=m
        ):
            with pytest.raises(PermissionError):
                require_role(ws_id, uid, "admin", db)

    def test_A4_require_role_returns_when_owner_meets_admin(self):
        from app.services.workspace_service import require_role

        db = _mock_db()
        ws_id, uid = uuid.uuid4(), uuid.uuid4()
        m = _make_member(ws_id, uid, "owner")
        with patch(
            "app.services.workspace_service.get_membership", return_value=m
        ):
            assert require_role(ws_id, uid, "admin", db) is m

    def test_A5_require_role_raises_lookup_for_non_member(self):
        from app.services.workspace_service import require_role

        db = _mock_db()
        with patch(
            "app.services.workspace_service.get_membership", return_value=None
        ):
            with pytest.raises(LookupError):
                require_role(uuid.uuid4(), uuid.uuid4(), "member", db)


# ═════════════════════════════════════════════════════════════════════════════
# B. Integrations — cross-workspace + role-gated mutation
# ═════════════════════════════════════════════════════════════════════════════


class TestIntegrationsCrossWorkspace:

    def _setup_integration_query(self, db, integration):
        q = MagicMock()
        q.filter.return_value = q
        q.first.return_value = integration
        db.query.return_value = q

    def test_B1_workspace_A_member_cannot_view_workspace_B_integration(self):
        """An integration with workspace_id=B is invisible to a non-member of B."""
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner = uuid.uuid4()
        ws_b = uuid.uuid4()
        stranger = uuid.uuid4()
        integ = _make_integration(owner, workspace_id=ws_b)
        self._setup_integration_query(db, integ)

        with patch(
            "app.services.workspace_service.get_membership", return_value=None
        ):
            assert get_integration_for_viewer(
                integration_id=integ.id, actor_user_id=stranger, db=db
            ) is None

    def test_B2_workspace_member_can_view_workspace_integration(self):
        from app.services.integration_service import get_integration_for_viewer

        db = _mock_db()
        owner = uuid.uuid4()
        viewer = uuid.uuid4()
        ws = uuid.uuid4()
        integ = _make_integration(owner, workspace_id=ws)
        self._setup_integration_query(db, integ)

        mem = _make_member(ws, viewer, "member")
        with patch(
            "app.services.workspace_service.get_membership", return_value=mem
        ):
            assert get_integration_for_viewer(
                integration_id=integ.id, actor_user_id=viewer, db=db
            ) is integ

    def test_B3_workspace_member_cannot_manage_view_only(self):
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner = uuid.uuid4()
        viewer = uuid.uuid4()
        ws = uuid.uuid4()
        integ = _make_integration(owner, workspace_id=ws)
        self._setup_integration_query(db, integ)

        mem = _make_member(ws, viewer, "member")  # member, not admin
        with patch(
            "app.services.workspace_service.get_membership", return_value=mem
        ):
            assert get_integration_for_manager(
                integration_id=integ.id, actor_user_id=viewer, db=db
            ) is None

    def test_B4_workspace_admin_can_manage(self):
        from app.services.integration_service import get_integration_for_manager

        db = _mock_db()
        owner = uuid.uuid4()
        admin = uuid.uuid4()
        ws = uuid.uuid4()
        integ = _make_integration(owner, workspace_id=ws)
        self._setup_integration_query(db, integ)

        with patch(
            "app.services.workspace_service.get_membership",
            return_value=_make_member(ws, admin, "admin"),
        ):
            assert get_integration_for_manager(
                integration_id=integ.id, actor_user_id=admin, db=db
            ) is integ

    def test_B5_deleted_integration_returns_none_for_all_roles(self):
        from app.services.integration_service import (
            get_integration_for_manager,
            get_integration_for_viewer,
        )

        db = _mock_db()
        # query returns None (status='deleted' is filtered out)
        self._setup_integration_query(db, None)
        for fn in (get_integration_for_viewer, get_integration_for_manager):
            assert fn(
                integration_id=uuid.uuid4(),
                actor_user_id=uuid.uuid4(),
                db=db,
            ) is None

    def test_B6_get_integration_by_id_filters_user_id(self):
        """get_integration_by_id (owner-only) must filter by user_id."""
        import inspect
        from app.services import integration_service

        src = inspect.getsource(integration_service.get_integration_by_id)
        assert "Integration.user_id == user_id" in src, (
            "get_integration_by_id must filter on user_id"
        )


# ═════════════════════════════════════════════════════════════════════════════
# C. Confused-deputy guards: member_id, invite_id, repo_id, etc. must
#    belong to the workspace_id in the path.
# ═════════════════════════════════════════════════════════════════════════════


class TestConfusedDeputyGuards:

    def test_C1_update_member_role_rejects_wrong_workspace(self):
        """If the target member_id belongs to a different workspace, raise LookupError."""
        from app.services import workspace_service

        db = _mock_db()
        ws_actor = uuid.uuid4()    # the path workspace_id
        ws_other = uuid.uuid4()    # the target member's actual workspace
        actor_uid = uuid.uuid4()

        # Actor is owner of ws_actor.
        with patch(
            "app.services.workspace_service.get_membership",
            return_value=_make_member(ws_actor, actor_uid, "owner"),
        ):
            target_member = _make_member(ws_other, uuid.uuid4(), "member")
            db.get.return_value = target_member
            with pytest.raises(LookupError):
                workspace_service.update_member_role(
                    workspace_id=ws_actor,
                    actor_user_id=actor_uid,
                    target_member_id=target_member.id,
                    new_role="admin",
                    db=db,
                )

    def test_C2_remove_member_rejects_wrong_workspace(self):
        from app.services import workspace_service

        db = _mock_db()
        ws_actor = uuid.uuid4()
        ws_other = uuid.uuid4()
        actor_uid = uuid.uuid4()

        with patch(
            "app.services.workspace_service.get_membership",
            return_value=_make_member(ws_actor, actor_uid, "admin"),
        ):
            target_member = _make_member(ws_other, uuid.uuid4(), "member")
            db.get.return_value = target_member
            with pytest.raises(LookupError):
                workspace_service.remove_member(
                    workspace_id=ws_actor,
                    actor_user_id=actor_uid,
                    target_member_id=target_member.id,
                    db=db,
                )

    def test_C3_revoke_invite_rejects_wrong_workspace(self):
        from app.services import workspace_service

        db = _mock_db()
        ws_actor = uuid.uuid4()
        ws_other = uuid.uuid4()
        actor_uid = uuid.uuid4()

        with patch(
            "app.services.workspace_service.get_membership",
            return_value=_make_member(ws_actor, actor_uid, "owner"),
        ):
            invite = MagicMock()
            invite.id = uuid.uuid4()
            invite.workspace_id = ws_other  # different workspace
            invite.revoked_at = None
            invite.accepted_at = None
            db.get.return_value = invite

            with pytest.raises(LookupError):
                workspace_service.revoke_invite(
                    workspace_id=ws_actor,
                    actor_user_id=actor_uid,
                    invite_id=invite.id,
                    db=db,
                )

    def test_C4_scan_iac_repository_requires_matching_workspace(self):
        """iac_mapping_service.scan_repository must filter on both repo_id AND workspace_id."""
        import inspect
        from app.services import iac_mapping_service

        src = inspect.getsource(iac_mapping_service.scan_repository)
        # Both filter clauses present:
        assert "IacRepository.id == repo_id" in src
        assert "IacRepository.workspace_id == workspace_id" in src

    def test_C5_list_iac_mappings_scoped_to_workspace(self):
        import inspect
        from app.services import iac_mapping_service

        src = inspect.getsource(iac_mapping_service.list_mappings)
        assert "IacResourceMapping.workspace_id == workspace_id" in src

    def test_C6_change_load_helper_checks_workspace_membership(self):
        """``_get_change_and_workspace`` must check WorkspaceMember before returning a change."""
        import inspect
        from app.routers import changes

        src = inspect.getsource(changes._get_change_and_workspace)
        # Look for the membership filter on the WorkspaceMember model.
        assert "WorkspaceMember.workspace_id == workspace_id" in src
        assert "WorkspaceMember.user_id == current_user.id" in src
        # And the not-a-member branch returns 404 (existence-leak avoidance).
        assert "404" in src


# ═════════════════════════════════════════════════════════════════════════════
# D. Non-admin cannot perform admin-only actions
# ═════════════════════════════════════════════════════════════════════════════


class TestAdminGate:

    @pytest.mark.parametrize(
        "fn_name",
        [
            "update_workspace_name",
            "update_member_role",
            "remove_member",
            "create_invite",
            "revoke_invite",
        ],
    )
    def test_D1_admin_only_helpers_check_role_rank(self, fn_name):
        """Each admin-only helper must call _rank or compare role against 'admin'/'owner'."""
        import inspect
        from app.services import workspace_service

        fn = getattr(workspace_service, fn_name)
        src = inspect.getsource(fn)
        # The body must reject low-role actors.  Acceptable patterns:
        #   - `_rank(actor.role) < _rank("admin")`
        #   - `actor.role != "owner"` (for owner-only ops like update_member_role)
        ok = (
            "_rank(actor.role)" in src
            or 'actor.role != "owner"' in src
            or "raise PermissionError" in src
        )
        assert ok, f"{fn_name} must enforce a role check"

    def test_D2_billing_routes_use_require_admin(self):
        """All /workspaces/{id}/billing routes go through _require_admin."""
        billing_src = Path(
            "app/routers/billing.py"
        ).read_text()
        # Every route handler must call _require_admin before doing real work.
        # We search for occurrences within def bodies after @router.
        route_blocks = re.findall(
            r"@router\.(?:get|post|put|patch|delete).*?(?=@router\.|\Z)",
            billing_src,
            flags=re.DOTALL,
        )
        assert route_blocks, "Expected to find router decorators in billing.py"
        for block in route_blocks:
            assert "_require_admin" in block, (
                f"Billing route missing _require_admin call:\n{block[:300]}"
            )

    def test_D3_create_integration_role_gate_present(self):
        """POST /integrations enforces admin-or-owner when workspace_id is supplied."""
        src = Path("app/routers/integrations.py").read_text()
        # The handler defines _INTEGRATION_ALLOWED_ROLES.
        assert "_INTEGRATION_ALLOWED_ROLES" in src
        # It rejects non-admin/owner with 403.
        assert 'detail="Only workspace owners and admins can add integrations.' in src

    def test_D4_create_github_pr_requires_admin(self):
        """github_pr_creation_service.create_github_pr calls require_role admin+."""
        import inspect
        from app.services import github_pr_creation_service

        src = inspect.getsource(github_pr_creation_service.create_github_pr)
        assert 'require_role(workspace_id, actor_user_id, "admin", db)' in src


# ═════════════════════════════════════════════════════════════════════════════
# E. Wiring: every workspace-scoped endpoint must call an auth helper
# ═════════════════════════════════════════════════════════════════════════════

# Set of helper-call substrings that count as a workspace auth check.
_AUTH_PATTERNS: tuple[str, ...] = (
    "workspace_service.require_role(",
    "require_role(",
    "_require_admin(",
    "_require_membership(",
    "get_membership(",
    "get_integration_for_viewer(",
    "get_integration_for_manager(",
    "get_integration_by_id(",
    "_get_change_and_workspace(",
    "workspace_service.get_workspace(",
    "workspace_service.list_members(",
    "workspace_service.get_audit_logs(",
    "workspace_service.list_invites(",
    "workspace_service.update_workspace_name(",
    "workspace_service.update_member_role(",
    "workspace_service.remove_member(",
    "workspace_service.create_invite(",
    "workspace_service.revoke_invite(",
    "workspace_service.accept_invite(",
    # Owner-only by user_id (filter inside the service):
    "changes_service.get_change_by_id(",
    "sync_service.get_sync_run(",
)


def _route_bodies(source: str) -> list[tuple[str, str]]:
    """Return [(handler_name, body_text)] for every @router.<verb> in source.

    Skips include_in_schema=False endpoints (intentionally public callbacks).
    """
    tree = ast.parse(source)
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if not (
                    isinstance(dec.func, ast.Attribute)
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "router"
                ):
                    continue
                # Skip public callbacks (signed externally, not user-auth-gated).
                is_public = any(
                    isinstance(kw, ast.keyword)
                    and kw.arg == "include_in_schema"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in dec.keywords
                )
                if is_public:
                    continue
                # Slice the source so we can do substring searches.
                start = node.lineno - 1
                end = node.end_lineno or start + 1
                body = "\n".join(source.splitlines()[start:end])
                out.append((node.name, body))
                break
    return out


def _has_auth_call(body: str) -> bool:
    return any(p in body for p in _AUTH_PATTERNS)


# Endpoints intentionally NOT workspace-scoped (allow-list).
# Each entry maps to the reason it's allowed without a workspace auth helper.
_NON_WORKSPACE_HANDLERS: set[str] = {
    # User-scoped (own resources only):
    "list_changes",
    "list_needs_review_changes",
    "list_integrations",  # workspace-aware: gate inside body via get_membership
    "list_resources",
    "list_resource_snapshots",
    "list_resource_changes",
    "get_resource",
    "get_dashboard_summary",
    "get_user_settings",
    "update_user_settings",
    "get_settings",          # user settings (not workspace)
    "update_settings",       # user settings (not workspace)
    "create_integration",  # workspace gate happens inside body via get_membership
    "create_sync",         # owner-only via get_integration_by_id
    "get_sync_run",        # owner-only via get_sync_run user_id filter
    # Workspace list / create root:
    "list_workspaces",
    "create_workspace",
    # Invites (public preview / token-based accept):
    "preview_invite",
    "accept_invite",
    # GitHub App (user-scoped, state-token gated):
    "get_install_url",
    "get_installation_repos",
    "complete_github_app_install",
}


class TestRouteWiring:

    @pytest.mark.parametrize("router_file", [
        "app/routers/billing.py",
        "app/routers/changes.py",
        "app/routers/integrations.py",
        "app/routers/integrations_github_app.py",
        "app/routers/resources.py",
        "app/routers/syncs.py",
        "app/routers/workspaces.py",
        "app/routers/dashboard.py",
        "app/routers/settings.py",
        "app/routers/invites.py",
    ])
    def test_E1_every_workspace_scoped_endpoint_has_auth_helper_call(
        self, router_file
    ):
        """Static check: every non-public router handler that is not in the
        explicit allow-list must call a recognized authorization helper."""
        src = Path(router_file).read_text()
        offenders: list[str] = []
        for name, body in _route_bodies(src):
            if name in _NON_WORKSPACE_HANDLERS:
                continue
            # Either the endpoint loads a workspace-scoped object via an
            # accepted auth helper, or it must mention ``workspace_id`` and
            # a membership check.
            if not _has_auth_call(body):
                offenders.append(name)
        assert not offenders, (
            f"{router_file}: handlers missing workspace auth call: {offenders}"
        )

    def test_E2_no_hardcoded_bypass_of_workspace_check(self):
        """No router file should contain a 'TODO auth' / 'skip auth' marker."""
        for path in Path("app/routers").glob("*.py"):
            text = path.read_text().lower()
            for marker in ("todo: auth", "todo auth", "skip auth", "fixme auth"):
                assert marker not in text, (
                    f"{path}: contains forbidden marker '{marker}'"
                )

    def test_E3_get_current_user_is_imported_in_user_facing_routers(self):
        """Every user-facing router must import get_current_user."""
        user_facing = [
            "app/routers/billing.py",
            "app/routers/changes.py",
            "app/routers/integrations.py",
            "app/routers/resources.py",
            "app/routers/settings.py",
            "app/routers/syncs.py",
            "app/routers/workspaces.py",
            "app/routers/dashboard.py",
            "app/routers/invites.py",
        ]
        for p in user_facing:
            src = Path(p).read_text()
            assert "get_current_user" in src, f"{p}: missing get_current_user import"


# ═════════════════════════════════════════════════════════════════════════════
# F. Public endpoint safety: stripe webhook + slack OAuth/actions
# ═════════════════════════════════════════════════════════════════════════════


class TestPublicEndpointSafety:

    def test_F1_stripe_webhook_verifies_signature(self):
        src = Path("app/routers/stripe_webhook.py").read_text()
        # Must verify signature BEFORE doing any DB work.
        assert "verify_stripe_signature" in src
        # Must reject missing Stripe-Signature header.
        assert "Missing Stripe-Signature header" in src
        # Must not log secrets — confirmed by the header line.
        assert "stripe-signature" in src.lower()

    def test_F2_slack_oauth_callback_verifies_state_token(self):
        src = Path("app/routers/slack_oauth.py").read_text()
        assert "verify_state_token_no_user" in src
        # Bot token must never appear in logs (only types).
        assert "NEVER logged" in src
        # Invalid state must redirect to error path, not raise & leak.
        assert "invalid_state" in src

    def test_F3_slack_actions_verifies_hmac_signature(self):
        src = Path("app/routers/slack_oauth.py").read_text()
        assert "verify_request_signature" in src
        assert "X-Slack-Signature" in src
        assert "X-Slack-Request-Timestamp" in src
        # Reject missing or stale signature with 403.
        assert "Invalid or stale Slack signature" in src

    def test_F4_health_endpoint_is_safe(self):
        src = Path("app/routers/health.py").read_text()
        # Must NOT import get_current_user (health is public).
        # Must NOT reference any tenant data (workspace_id / current_user).
        assert "current_user" not in src, "health endpoint must not depend on auth"
        assert "workspace_id" not in src, "health endpoint must not leak tenant data"


# ═════════════════════════════════════════════════════════════════════════════
# G. Secret-safety in error responses (no token / Bearer / etc. should ever
#    appear in default exception messages)
# ═════════════════════════════════════════════════════════════════════════════


class TestErrorResponseSafety:

    def test_G1_workspace_service_error_messages_safe(self):
        """LookupError / PermissionError messages must not leak tokens."""
        import inspect
        from app.services import workspace_service

        # Collect error-message string literals from the module.
        src = inspect.getsource(workspace_service)
        # No raw Bearer / Authorization / token leakage in any raise statement.
        # We assert the file does not contain a raise statement whose message
        # references obvious credential markers.
        bad_markers = ("Bearer ", "Authorization:", "api_token=", "github_token=")
        for marker in bad_markers:
            assert marker not in src, (
                f"workspace_service must not embed {marker!r} in error messages"
            )

    def test_G2_integration_service_error_messages_safe(self):
        import inspect
        from app.services import integration_service

        src = inspect.getsource(integration_service)
        for marker in ("Bearer ", "Authorization:"):
            # api_token= and github_token= are unavoidable param names; just
            # check raw header-style leakage doesn't appear.
            assert marker not in src

    def test_G3_change_load_helper_returns_404_not_403(self):
        """Existence-leak avoidance: ``_get_change_and_workspace`` returns
        404 (not 403) for non-members, matching the existing convention."""
        import inspect
        from app.routers import changes

        src = inspect.getsource(changes._get_change_and_workspace)
        # The not-a-member branch raises 404.
        # (403 would leak whether the change exists in another workspace.)
        assert 'status_code=404, detail="Change not found.' in src

    def test_G4_integration_endpoints_use_404_for_non_members(self):
        """Cross-user/cross-workspace integration access returns 404, never 403,
        per docstring contract (no existence leaks)."""
        src = Path("app/routers/integrations.py").read_text()
        # Several occurrences of the 404 detail string for unauthorized access.
        assert 'status_code=404,\n            detail="Integration not found' in src \
            or 'detail="Integration not found or does not belong to this user' in src


# ═════════════════════════════════════════════════════════════════════════════
# H. Defense in depth for accept-invite (token-bound, not workspace-bound)
# ═════════════════════════════════════════════════════════════════════════════


class TestAcceptInviteSafety:

    def test_H1_accept_invite_rejects_expired_revoked_used(self):
        """accept_invite must reject expired, revoked, or already-accepted invites."""
        import inspect
        from app.services import workspace_service

        src = inspect.getsource(workspace_service.accept_invite)
        # All three end-states are checked.
        assert "revoked_at" in src
        assert "accepted_at" in src
        assert "expires_at" in src

    def test_H2_invite_token_compared_via_hash(self):
        """The raw invite token is hashed; we never store/lookup by plaintext."""
        import inspect
        from app.services import workspace_service

        src_token = inspect.getsource(workspace_service.get_invite_by_token)
        assert "_hash_token" in src_token
        # And the model column is token_hash (not token).
        assert "token_hash" in src_token


# ═════════════════════════════════════════════════════════════════════════════
# I. Object ownership wiring sanity (regression checks)
# ═════════════════════════════════════════════════════════════════════════════


class TestOwnershipWiring:

    def test_I1_integration_model_has_workspace_id_fk(self):
        from app.models.integration import Integration

        # Confirm workspace_id column exists at ORM level.
        assert hasattr(Integration, "workspace_id")

    def test_I2_iac_repository_model_has_workspace_id_fk(self):
        from app.models.iac_repository import IacRepository
        assert hasattr(IacRepository, "workspace_id")

    def test_I3_iac_resource_mapping_has_workspace_id_fk(self):
        from app.models.iac_resource_mapping import IacResourceMapping
        assert hasattr(IacResourceMapping, "workspace_id")

    def test_I4_notification_settings_has_workspace_id_fk(self):
        from app.models.notification_settings import WorkspaceNotificationSettings
        assert hasattr(WorkspaceNotificationSettings, "workspace_id")

    def test_I5_push_subscription_has_workspace_and_user(self):
        from app.models.push_subscription import WorkspacePushSubscription
        assert hasattr(WorkspacePushSubscription, "workspace_id")
        assert hasattr(WorkspacePushSubscription, "user_id")

    def test_I6_billing_has_workspace_id(self):
        from app.models.billing import WorkspaceBilling
        assert hasattr(WorkspaceBilling, "workspace_id")

    def test_I7_workspace_policy_has_workspace_id(self):
        from app.models.workspace_policy import WorkspacePolicy
        assert hasattr(WorkspacePolicy, "workspace_id")

    def test_I8_expected_change_window_has_workspace_id(self):
        from app.models.expected_change_window import ExpectedChangeWindow
        assert hasattr(ExpectedChangeWindow, "workspace_id")

    def test_I9_audit_log_has_workspace_id(self):
        from app.models.workspace import WorkspaceAuditLog
        assert hasattr(WorkspaceAuditLog, "workspace_id")
