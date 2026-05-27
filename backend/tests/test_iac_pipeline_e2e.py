"""TEMPORARY local-only verification of the IaC pipeline.

Filename starts with `_tmp_` so pytest collection picks it up only when
explicitly named on the command line. This file is intentionally NOT
collected by default test runs and is meant to be deleted (or kept as a
permanent regression test, with the user's approval) after one-shot
verification.

Scope: exercises the full IaC pipeline end-to-end against the actual
Terraform written in /Users/rohan/Downloads/configtrace-iac-demo/terraform/
without touching the network, the database, GitHub, or Cloudflare.

Pipeline stages exercised:
  1. iac_mapping_service.scan_terraform_content    (Terraform parsing)
  2. _get_tf_candidates_for_change                  (record-type → tf-type)
  3. _compute_match_confidence                      (mapping ↔ change)
  4. terraform_fix_suggestion_service.get_terraform_fix_preview
                                                    (suggestion generator)
  5. github_pr_draft_service.get_github_pr_draft    (draft assembler)
  6. iac_mapping_service.get_iac_context            (change-page context)

Scenarios covered (matches the verification brief):
  A. CNAME exists in Terraform + Cloudflare 'removed' change   → match + fix preview + PR draft
  B. CNAME exists in Terraform + Cloudflare 'modified' change  → match + fix preview
  C. No IaC repo registered for workspace                      → clean empty-state response, no exception
  D. Terraform file has no resource matching the change        → low/no confidence, no false confident match
"""

from __future__ import annotations

import os
import sys
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest


# Path to the customer-shaped IaC repo we authored alongside the product.
_IAC_DEMO_TF = "/Users/rohan/Downloads/configtrace-iac-demo/terraform/cloudflare.tf"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_tf(path: str = _IAC_DEMO_TF) -> str:
    if not os.path.isfile(path):
        pytest.skip(f"Terraform demo file not found at {path} — skipping.")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _fake_change(
    *,
    provider: str = "cloudflare",
    record_type: str = "cloudflare_record",
    record_identifier: str,
    change_type: str = "modified",
    field_path: str = "content",
    risk_level: str = "high",
    risk_reason: str = "DNS routing changed",
    workspace_id: uuid.UUID | None = None,
    integration_id: uuid.UUID | None = None,
) -> MagicMock:
    c = MagicMock(name="Change")
    c.id                 = uuid.uuid4()
    c.workspace_id       = workspace_id or uuid.uuid4()
    c.integration_id     = integration_id or uuid.uuid4()
    c.provider           = provider
    c.record_type        = record_type
    c.record_identifier  = record_identifier
    c.change_type        = change_type
    c.field_path         = field_path
    c.risk_level         = risk_level
    c.risk_reason        = risk_reason
    # Mirrors how connectors populate provider_metadata: a dict with at least
    # `record_type`. The fix-preview service reads this exact path.
    c.provider_metadata  = {"record_type": record_type}
    return c


def _fake_mapping(
    *,
    workspace_id: uuid.UUID,
    iac_repository_id: uuid.UUID,
    terraform_resource_type: str,
    terraform_resource_name: str,
    cloud_resource_identifier: str,
    file_path: str = "terraform/cloudflare.tf",
    line_start: int = 1,
    line_end: int = 10,
    confidence: str = "medium",
    provider: str = "cloudflare",
    resource_type: str = "cname",
    cloud_resource_name: str | None = None,
    match_reason: str = "scanned from terraform file",
) -> MagicMock:
    m = MagicMock(name="IacResourceMapping")
    m.id                          = uuid.uuid4()
    m.workspace_id                = workspace_id
    m.iac_repository_id           = iac_repository_id
    m.provider                    = provider
    m.resource_type               = resource_type
    m.terraform_resource_type     = terraform_resource_type
    m.terraform_resource_name     = terraform_resource_name
    m.file_path                   = file_path
    m.line_start                  = line_start
    m.line_end                    = line_end
    m.cloud_resource_identifier   = cloud_resource_identifier
    m.cloud_resource_name         = cloud_resource_name
    m.match_confidence            = confidence
    m.match_reason                = match_reason
    m.mapping_source              = "scanner"
    return m


def _query_chain_returning(*, change=None, mappings=None, repo_count=0, mapping_count=None):
    """Build a MagicMock SQLAlchemy session whose query/filter chain returns
    pre-staged answers depending on the model being queried.

    We can't easily distinguish queries by model identity here because
    db.query(Model) is called with the class itself. We use a model-aware
    side_effect that inspects the first positional arg.
    """
    from app.models.change                import Change
    from app.models.iac_repository         import IacRepository
    from app.models.iac_resource_mapping   import IacResourceMapping

    def _query(model):
        chain = MagicMock()
        # `.filter(...).first()` and `.filter(...).count()` and `.all()`
        # all need to be wired.
        chain.filter.return_value = chain
        if model is Change:
            chain.first.return_value = change
        elif model is IacRepository:
            chain.first.return_value = None
            chain.count.return_value = repo_count
        elif model is IacResourceMapping:
            chain.first.return_value = (mappings or [None])[0]
            chain.all.return_value   = mappings or []
            chain.count.return_value = (
                mapping_count if mapping_count is not None else len(mappings or [])
            )
        else:
            chain.first.return_value = None
            chain.all.return_value   = []
            chain.count.return_value = 0
        return chain

    db = MagicMock(name="Session")
    db.query.side_effect = _query
    return db


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1 — Terraform parser produces the expected blocks
# ─────────────────────────────────────────────────────────────────────────────

def test_stage1_terraform_scanner_parses_three_cnames():
    """The demo Terraform must parse to exactly 3 cloudflare_record blocks
    with the expected names: www, api, demo_alerts."""
    from app.services.iac_mapping_service import scan_terraform_content

    blocks = scan_terraform_content(
        content=_load_tf(),
        file_path="terraform/cloudflare.tf",
    )

    cf_records = [b for b in blocks if b.resource_type == "cloudflare_record"]
    names = sorted(b.resource_name for b in cf_records)
    assert names == ["api", "demo_alerts", "www"], (
        f"Expected 3 cloudflare_record blocks named api/demo_alerts/www; got {names}"
    )

    # Each block should carry safe attrs — name and type, at least.
    by_name = {b.resource_name: b for b in cf_records}
    for n in ("api", "www", "demo_alerts"):
        b = by_name[n]
        assert "name" in b.safe_attrs or "type" in b.safe_attrs, (
            f"Block {n!r} should have at least one safe attr captured; got {b.safe_attrs}"
        )

    # Defence-in-depth — never store the API token value (sensitive var ref is OK
    # but no literal token-looking strings should slip through).
    all_attr_values = " ".join(
        v for b in cf_records for v in b.safe_attrs.values()
    )
    assert "REPLACE_WITH" not in all_attr_values.upper()


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2 — Candidate Terraform types match Cloudflare DNS changes
# ─────────────────────────────────────────────────────────────────────────────

def test_stage2_change_record_type_maps_to_cloudflare_record():
    """A Cloudflare CNAME change must propose cloudflare_record as a candidate."""
    from app.services.iac_mapping_service import _get_tf_candidates_for_change

    change = _fake_change(record_identifier="api.configtrace.org")
    candidates = _get_tf_candidates_for_change(change)
    assert "cloudflare_record" in candidates, (
        f"Cloudflare CNAME change must include 'cloudflare_record' candidate; "
        f"got {candidates}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO A — CNAME removed; mapping exists. Expect high-confidence match
# and an available Terraform fix preview + PR draft.
# ─────────────────────────────────────────────────────────────────────────────

def test_scenario_A_cname_removed_matches_terraform_resource(monkeypatch):
    """Cloudflare 'removed' change against api.configtrace.org should match
    cloudflare_record.api with high confidence."""
    from app.services.iac_mapping_service import _compute_match_confidence

    workspace_id = uuid.uuid4()
    iac_repo_id  = uuid.uuid4()

    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="removed",
        field_path=None,
        risk_level="critical",
        risk_reason="CNAME for api.configtrace.org was removed",
        workspace_id=workspace_id,
    )
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=iac_repo_id,
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api",
        cloud_resource_identifier="api.configtrace.org",
        cloud_resource_name="api",
    )

    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence == "high", (
        f"Exact cloud_resource_identifier match must produce 'high' confidence; "
        f"got {confidence!r}. Reason: {reason!r}"
    )
    assert "api.configtrace.org" in reason


def test_scenario_A_cname_removed_fix_preview_is_available(monkeypatch):
    """The Terraform fix preview should be available and offer at least one
    suggestion for a removed Cloudflare CNAME with a matching mapping."""
    from app.services import terraform_fix_suggestion_service

    workspace_id = uuid.uuid4()
    iac_repo_id  = uuid.uuid4()

    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="removed",
        field_path=None,
        risk_level="critical",
        risk_reason="CNAME removed",
        workspace_id=workspace_id,
    )
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=iac_repo_id,
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api",
        cloud_resource_identifier="api.configtrace.org",
        cloud_resource_name="api",
    )

    db = _query_chain_returning(change=change, mappings=[mapping])

    result = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change.id,
        workspace_id=workspace_id,
        db=db,
    )

    assert result.available is True, f"Fix preview should be available; got {result}"
    # PERMANENT SAFETY INVARIANTS — must NEVER be True.
    assert result.execution_enabled is False
    assert result.pr_available is False
    assert len(result.suggestions) >= 1


def test_scenario_A_pr_draft_is_safe_and_does_not_call_github(monkeypatch):
    """The PR-draft assembler must NOT make any network call, and the returned
    draft must carry the safety flags forbidding side effects."""
    from app.services import github_pr_draft_service, terraform_fix_suggestion_service

    workspace_id = uuid.uuid4()
    iac_repo_id  = uuid.uuid4()
    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="removed",
        field_path=None,
        risk_level="critical",
        risk_reason="CNAME removed",
        workspace_id=workspace_id,
    )
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=iac_repo_id,
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api",
        cloud_resource_identifier="api.configtrace.org",
        cloud_resource_name="api",
    )

    db = _query_chain_returning(change=change, mappings=[mapping])

    # Patch httpx.post + .get on the off chance the assembler ever reaches out.
    # (It should not in M58.20 — verified by call_count assertion below.)
    import httpx
    network_calls = {"count": 0}

    def _trap(*a, **kw):
        network_calls["count"] += 1
        raise AssertionError(
            "github_pr_draft_service must not perform real HTTP requests."
        )
    monkeypatch.setattr(httpx, "post", _trap, raising=True)
    monkeypatch.setattr(httpx, "get",  _trap, raising=True)

    draft = github_pr_draft_service.get_github_pr_draft(
        change_id=change.id,
        workspace_id=workspace_id,
        db=db,
    )

    assert network_calls["count"] == 0, "PR-draft assembler must be offline."

    # Either available with a draft payload, or unavailable with a reason —
    # never a partial / silently-failed object.
    assert isinstance(draft.available, bool)
    if draft.available:
        # The draft must carry the safety constants enforced by M58.20.
        assert getattr(draft, "creates_branch", False) is False
        assert getattr(draft, "commits_code",   False) is False
        assert getattr(draft, "opens_pr",       False) is False
        assert getattr(draft, "executes_terraform", False) is False


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO B — CNAME modified (content + proxied changed); mapping exists.
# ─────────────────────────────────────────────────────────────────────────────

def test_scenario_B_cname_modified_value_matches_and_yields_preview():
    from app.services import terraform_fix_suggestion_service
    from app.services.iac_mapping_service import _compute_match_confidence

    workspace_id = uuid.uuid4()
    iac_repo_id  = uuid.uuid4()

    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="modified",
        field_path="content",
        risk_level="high",
        risk_reason="CNAME rerouted to a new target",
        workspace_id=workspace_id,
    )
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=iac_repo_id,
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api",
        cloud_resource_identifier="api.configtrace.org",
        cloud_resource_name="api",
    )

    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence == "high", f"got {confidence}: {reason}"

    db = _query_chain_returning(change=change, mappings=[mapping])
    result = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change.id,
        workspace_id=workspace_id,
        db=db,
    )
    assert result.available is True
    assert result.execution_enabled is False
    assert result.pr_available     is False


def test_scenario_B_cname_proxied_toggle_matches_and_yields_preview():
    """Same mapping; this time the change is on the proxied attribute."""
    from app.services import terraform_fix_suggestion_service

    workspace_id = uuid.uuid4()
    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="modified",
        field_path="proxied",
        risk_level="high",
        risk_reason="Cloudflare proxy disabled, origin IP may be exposed",
        workspace_id=workspace_id,
    )
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=uuid.uuid4(),
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="api",
        cloud_resource_identifier="api.configtrace.org",
    )

    db = _query_chain_returning(change=change, mappings=[mapping])
    result = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change.id,
        workspace_id=workspace_id,
        db=db,
    )
    assert result.available is True


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO C — No IaC repo registered. Expect a clean empty-state response.
# ─────────────────────────────────────────────────────────────────────────────

def test_scenario_C_no_iac_repo_returns_clean_empty_state():
    from app.services import iac_mapping_service

    workspace_id = uuid.uuid4()
    change = _fake_change(record_identifier="api.configtrace.org", workspace_id=workspace_id)
    db = _query_chain_returning(change=change, mappings=[], repo_count=0)

    ctx = iac_mapping_service.get_iac_context(
        change_id=change.id,
        workspace_id=workspace_id,
        db=db,
    )
    assert ctx.available is False
    assert ctx.mappings == []
    assert "no iac repositor" in ctx.summary.lower() or "register" in ctx.summary.lower(), (
        f"Empty-state summary should be helpful, not an error trace; got {ctx.summary!r}"
    )


def test_scenario_C_fix_preview_also_empty_state_when_no_mappings():
    from app.services import terraform_fix_suggestion_service

    workspace_id = uuid.uuid4()
    change = _fake_change(record_identifier="api.configtrace.org", workspace_id=workspace_id)
    db = _query_chain_returning(change=change, mappings=[])

    res = terraform_fix_suggestion_service.get_terraform_fix_preview(
        change_id=change.id, workspace_id=workspace_id, db=db,
    )
    assert res.available is False
    assert res.execution_enabled is False
    assert res.pr_available     is False
    # Summary must be friendly, not an exception or stack trace.
    assert "scanned" in (res.summary or "").lower() or "no iac" in (res.summary or "").lower()


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO D — Terraform has no matching resource for the change. Expect
# low or no confident match — must NOT claim a confident match.
# ─────────────────────────────────────────────────────────────────────────────

def test_scenario_D_no_matching_terraform_resource_does_not_falsely_claim_high_confidence():
    """If the only mapping in the workspace is for a *different* hostname,
    the confidence must NOT be 'high'."""
    from app.services.iac_mapping_service import _compute_match_confidence

    workspace_id = uuid.uuid4()
    change = _fake_change(
        record_identifier="api.configtrace.org",
        change_type="modified",
        workspace_id=workspace_id,
    )
    # Mapping points at a totally different hostname (e.g. a different zone).
    mapping = _fake_mapping(
        workspace_id=workspace_id,
        iac_repository_id=uuid.uuid4(),
        terraform_resource_type="cloudflare_record",
        terraform_resource_name="unrelated_marketing_domain",
        cloud_resource_identifier="totally-different.example.com",
        cloud_resource_name="unrelated_marketing_domain",
        match_reason="scanner found cloudflare_record",
    )

    confidence, reason = _compute_match_confidence(mapping, change)
    assert confidence != "high", (
        f"Mapping for a different hostname must NOT be 'high' confidence; "
        f"got {confidence}: {reason}"
    )
    assert confidence in ("low", "medium")


def test_scenario_D_pr_draft_unavailable_when_no_mapping():
    from app.services import github_pr_draft_service

    workspace_id = uuid.uuid4()
    change = _fake_change(record_identifier="api.configtrace.org", workspace_id=workspace_id)
    db = _query_chain_returning(change=change, mappings=[])

    draft = github_pr_draft_service.get_github_pr_draft(
        change_id=change.id, workspace_id=workspace_id, db=db,
    )
    assert draft.available is False
    # No silent partial state: an unavailable draft must explain itself.
    # The unavailable field is `reason` (see GitHubPrDraftResponse schema).
    message = (getattr(draft, "reason", None) or getattr(draft, "summary", None) or "").strip()
    assert message, "Unavailable draft must carry a reason or summary."


# ─────────────────────────────────────────────────────────────────────────────
# Safety invariants — repeat as a tripwire even though M58.19/.20/.21 cover them
# ─────────────────────────────────────────────────────────────────────────────

def test_safety_no_shell_or_subprocess_invocation_in_iac_services():
    """Sanity check — the IaC services must not shell out to terraform or any
    other CLI. We look for *actual* runtime invocation patterns, not for the
    string 'terraform apply' (which legitimately appears in docstrings that
    explain what we DO NOT do).
    """
    import ast

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    forbidden_modules = {"subprocess", "pty"}                  # shell/process spawns
    forbidden_calls   = {"os.system", "os.popen", "os.execv"}  # exec-y stdlib

    for fname in (
        "app/services/iac_mapping_service.py",
        "app/services/terraform_fix_suggestion_service.py",
        "app/services/github_pr_draft_service.py",
    ):
        path = os.path.join(base, fname)
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden_modules, (
                        f"{fname}: forbidden import {alias.name!r} — would enable "
                        "shelling out to terraform / external CLIs."
                    )
            if isinstance(node, ast.ImportFrom):
                if node.module in forbidden_modules:
                    raise AssertionError(
                        f"{fname}: forbidden import from {node.module!r}."
                    )
            if isinstance(node, ast.Call):
                # Match `os.system(...)`, `os.popen(...)`, etc.
                if isinstance(node.func, ast.Attribute) and isinstance(
                    node.func.value, ast.Name
                ):
                    name = f"{node.func.value.id}.{node.func.attr}"
                    assert name not in forbidden_calls, (
                        f"{fname}: forbidden call {name!r}"
                    )
