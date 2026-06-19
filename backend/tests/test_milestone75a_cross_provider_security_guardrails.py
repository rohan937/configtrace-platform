"""M75A — Cross-provider security product QA guardrails.

Durable, deterministic guardrails that prove the full multi-provider security
spine stays coherent across every completed provider arc (github, aws,
cloudflare, vercel, supabase, firebase, stripe, shopify). Three layers:

  1. Backend provider matrix — each completed provider declares the surfaces
     it should ship and they map to real, callable backend functions
     (demo seed/clear/status, correlation generator, demo case-source marker).
     Provider label maps include every provider.

  2. Demo lifecycle smoke — for each provider with a demo, the
     status→seed→status→report/timeline/graph→clear→status round-trip works,
     uses the right provider label, never emits forbidden claim wording, and
     clear preserves a real non-demo finding for the same provider.

  3. Frontend source guardrails (skip if frontend tree absent) — the activity,
     signals, correlations, and cases pages, the demo script, and the API
     helper all surface every completed provider where the matrix says they
     should.

  4. Privacy allowlist guardrails — the three shared metadata allowlists
     (activity events, incident signals, signal correlations) do not contain
     any of the broad dangerous EXACT keys (``raw``, ``payload``, ``headers``,
     ``body``, ``token``, ``secret``, ``value``, ``email``,
     ``customer_email``, ``card``, ``payment_method``, ``charge``,
     ``invoice``, ``order``, ``checkout``, ``cart``, ``authorization``,
     ``private_key``, ``access_token``, ``refresh_token``). Specific safe
     namespaced keys (e.g. ``webhook_endpoint_domain``, ``payment_link_id``,
     ``domain_host``, ``policy_type``, ``auth_setting_name``) are allowed.

This file adds NO product code — it is a regression net only.
"""

from __future__ import annotations

import inspect
import json
import re
import uuid
from pathlib import Path

import pytest

from app.core.encryption import encrypt_credentials
from app.models.integration import Integration
from app.models.resource import Resource
from app.models.security_case import SecurityCase
from app.models.security_finding import SecurityFinding
from app.services import security_activity_event_service as activity_svc
from app.services import security_case_report_service as report_svc
from app.services import security_finding_service as finding_svc
from app.services import security_incident_demo_service as demo
from app.services import security_incident_signal_service as signal_svc
from app.services import security_signal_correlation_service as corr_svc
from app.services import workspace_service


# ── Forbidden claim wording (exact phrases — M75A set) ───────────────────────
FORBIDDEN_PHRASES = [
    "compromise confirmed",
    "secret leaked",
    "data leaked",
    "customer data leaked",
    "payment fraud detected",
    "attacker found",
    "someone has access",
    "unauthorized access confirmed",
    "breach detected",
    "attack detected",
    "orders exposed",
    "card data exposed",
]


# ── Provider matrix ──────────────────────────────────────────────────────────
# (provider, label, has_correlations, has_demo, demo seed fn, demo clear fn,
#  demo status fn, demo case_source marker)
PROVIDERS = [
    ("github",     "GitHub",     True, True,
     demo.seed,           demo.clear,           demo.get_status,
     demo.DEMO_CASE_SOURCE),
    ("aws",        "AWS",        True, True,
     demo.seed_aws,       demo.clear_aws,       demo.get_aws_status,
     demo.AWS_DEMO_CASE_SOURCE),
    ("cloudflare", "Cloudflare", True, True,
     demo.seed_cloudflare, demo.clear_cloudflare, demo.get_cloudflare_status,
     demo.CF_DEMO_CASE_SOURCE),
    ("vercel",     "Vercel",     True, True,
     demo.seed_vercel,    demo.clear_vercel,    demo.get_vercel_status,
     demo.VERCEL_DEMO_CASE_SOURCE),
    ("supabase",   "Supabase",   True, True,
     demo.seed_supabase,  demo.clear_supabase,  demo.get_supabase_status,
     demo.SUPABASE_DEMO_CASE_SOURCE),
    ("firebase",   "Firebase",   True, True,
     demo.seed_firebase,  demo.clear_firebase,  demo.get_firebase_status,
     demo.FIREBASE_DEMO_CASE_SOURCE),
    ("stripe",     "Stripe",     True, True,
     demo.seed_stripe,    demo.clear_stripe,    demo.get_stripe_status,
     demo.STRIPE_DEMO_CASE_SOURCE),
    ("shopify",    "Shopify",    True, True,
     demo.seed_shopify,   demo.clear_shopify,   demo.get_shopify_status,
     demo.SHOPIFY_DEMO_CASE_SOURCE),
]
PROVIDER_KEYS = [p[0] for p in PROVIDERS]
PROVIDER_LABELS_EXPECTED = {p[0]: p[1] for p in PROVIDERS}


def _ws(user, db):
    return workspace_service.get_or_create_default_workspace(
        user_id=user.id, user_display_name=user.display_name or "M75A", db=db)


def _demo_case(db, ws_id, source):
    return db.query(SecurityCase).filter(
        SecurityCase.workspace_id == ws_id,
        SecurityCase.case_metadata["source"].astext == source,
    ).first()


def _assert_no_forbidden(payload, where):
    low = json.dumps(payload, default=str).lower()
    for phrase in FORBIDDEN_PHRASES:
        assert phrase not in low, f"forbidden phrase {phrase!r} in {where}"


def _frontend_src() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "frontend" / "src"
        if candidate.is_dir():
            return candidate
    return None


def _read_fe(rel: str) -> str:
    src = _frontend_src()
    if src is None:
        pytest.skip("frontend/src not mounted in this environment")
    path = src / rel
    if not path.is_file():
        pytest.skip(f"frontend file not found: {rel}")
    return path.read_text(encoding="utf-8")


# ════════════════════════════════════════════════════════════════════════════
# Layer 1 — backend provider matrix
# ════════════════════════════════════════════════════════════════════════════


def test_completed_provider_set_is_canonical():
    """The set of completed providers is exactly these eight."""
    assert set(PROVIDER_KEYS) == {
        "github", "aws", "cloudflare", "vercel", "supabase", "firebase",
        "stripe", "shopify",
    }


@pytest.mark.parametrize(
    "provider,label,_has_corr,has_demo,seed_fn,clear_fn,status_fn,source",
    PROVIDERS,
)
def test_demo_surfaces_callable(
    provider, label, _has_corr, has_demo, seed_fn, clear_fn, status_fn, source,
):
    """If the matrix says the provider has a demo, the seed/clear/status
    functions are real callables and the case_source marker is a non-empty
    string. Marker uniqueness is asserted separately."""
    assert has_demo is True, f"matrix expected demo for {provider}"
    assert callable(seed_fn), f"{provider} seed not callable"
    assert callable(clear_fn), f"{provider} clear not callable"
    assert callable(status_fn), f"{provider} status not callable"
    assert isinstance(source, str) and source.strip(), (
        f"{provider} case-source marker is empty"
    )


def test_demo_case_source_markers_are_distinct():
    sources = [p[7] for p in PROVIDERS]
    assert len(set(sources)) == len(sources), "demo case-source markers collide"


@pytest.mark.parametrize(
    "provider,_label,has_corr,_has_demo,_seed,_clear,_status,_source",
    PROVIDERS,
)
def test_correlation_generator_exists(
    provider, _label, has_corr, _has_demo, _seed, _clear, _status, _source,
):
    """Each provider with correlations exposes a ``generate_<p>_correlations``
    on the shared service that accepts ``workspace_id`` + ``db``."""
    assert has_corr is True
    fn = getattr(corr_svc, f"generate_{provider}_correlations", None)
    assert callable(fn), f"correlation generator missing for {provider}"
    params = inspect.signature(fn).parameters
    assert "workspace_id" in params and "db" in params


def test_provider_labels_canonical():
    """The canonical label map carries every completed provider with the
    expected display label. ``_TIMELINE_PROVIDER_LABELS`` is the source of
    truth used by both ``build_case_report`` and ``build_case_evidence_timeline``.

    M77G added Azure to the label map (demo-ready Azure security review flow).
    Azure is NOT in the canonical 8 dual-stack-complete provider set, but its
    label is required so case timelines/graphs render "Azure" correctly.
    """
    actual = report_svc._TIMELINE_PROVIDER_LABELS
    # The canonical 8 dual-stack-complete providers must all be present with
    # their expected labels.
    for key, label in PROVIDER_LABELS_EXPECTED.items():
        assert actual.get(key) == label, (
            f"canonical provider {key!r} label mismatch in _TIMELINE_PROVIDER_LABELS"
        )
    # Azure was added in M77G — partial provider, but appears in the label map.
    assert actual.get("azure") == "Azure", (
        "Azure label missing from _TIMELINE_PROVIDER_LABELS (M77G demo-ready)"
    )


# ════════════════════════════════════════════════════════════════════════════
# Layer 2 — demo lifecycle smoke (parametrized per provider)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    "provider,label,_has_corr,_has_demo,seed_fn,clear_fn,status_fn,source",
    PROVIDERS,
)
def test_demo_lifecycle_round_trip(
    provider, label, _has_corr, _has_demo, seed_fn, clear_fn, status_fn,
    source, test_user, db_session,
):
    """status→seed→status→report+timeline+graph→clear→status round-trip,
    with provider-label correctness, no forbidden wording, and a real
    non-demo finding preserved across clear."""
    ws = _ws(test_user, db_session)

    # A real (non-demo) finding for this provider that must survive clear.
    real_provider = "github" if provider == "github" else provider
    ct, iv = encrypt_credentials({"demo_smoke": True, "provider": real_provider})
    real_integ = Integration(
        user_id=test_user.id, workspace_id=ws.id, provider=real_provider,
        display_name=f"real-{provider}", encrypted_credentials=ct,
        credential_iv=iv, status="active",
    )
    db_session.add(real_integ); db_session.commit(); db_session.refresh(real_integ)
    real_res = Resource(
        integration_id=real_integ.id, user_id=test_user.id,
        provider_resource_type=f"{provider}_resource",
        provider_resource_id=f"real-{provider}-{uuid.uuid4().hex[:6]}",
        display_name="real-resource", is_active=True,
    )
    db_session.add(real_res); db_session.commit(); db_session.refresh(real_res)
    real = finding_svc.upsert_active_finding(
        db=db_session, workspace_id=ws.id, integration_id=real_integ.id,
        provider=real_provider,
        finding_key=f"real_{provider}_finding:{real_res.provider_resource_id}",
        severity="medium", title=f"Real {label} finding (keep)",
        resource_id=real_res.id,
        description="Non-demo finding asserted to survive demo clear.",
        evidence={"rule": f"real_{provider}_finding"},
        remediation={"summary": "n/a"},
    )
    real_id = real.id

    try:
        # 1. status starts unseeded (or at least returns a status response).
        s0 = status_fn(ws.id, db_session)
        assert isinstance(s0, dict)
        assert s0.get("seeded") is False, f"{provider} status not initially unseeded"

        # 2. seed creates a case.
        res = seed_fn(workspace_id=ws.id, actor_user_id=test_user.id, db=db_session)
        assert isinstance(res, dict) and res.get("case_id"), (
            f"{provider} seed did not return a case_id"
        )

        # 3. status reflects seeded state with the same case id.
        s1 = status_fn(ws.id, db_session)
        assert s1.get("seeded") is True
        assert s1.get("case_id") == res["case_id"]

        # 4. report + timeline + graph build with the right label.
        case = _demo_case(db_session, ws.id, source)
        assert case is not None and (case.provider or "").lower() == provider

        report = report_svc.build_case_report(case=case, db=db_session)
        assert label in report["executive_summary"]
        for key in (
            "evidence_timeline", "evidence_graph", "timeline",
            "signals", "risks", "activity_events", "correlations",
            "review_checklist", "limitations",
        ):
            assert key in report, f"{provider} report missing {key}"

        timeline = report_svc.build_case_evidence_timeline(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert timeline["provider"] == label
        assert timeline["total"] >= 1
        ts = [it["timestamp"] for it in timeline["timeline_items"] if it["timestamp"]]
        assert ts == sorted(ts), f"{provider} timeline not chronological"

        graph = report_svc.build_case_evidence_graph(
            case_id=case.id, workspace_id=ws.id, db=db_session)
        assert graph["counts_by_node_type"].get("case", 0) == 1
        assert len(graph["nodes"]) >= 2
        node_ids = {n["id"] for n in graph["nodes"]}
        for e in graph["edges"]:
            assert e["source_node_id"] in node_ids
            assert e["target_node_id"] in node_ids

        # 5. No forbidden wording in any of the three payloads.
        _assert_no_forbidden(report, f"{provider} report")
        _assert_no_forbidden(timeline, f"{provider} timeline")
        _assert_no_forbidden(graph, f"{provider} graph")

        # 6. clear removes the demo case but preserves the real finding.
        clear_fn(workspace_id=ws.id, db=db_session)
        assert _demo_case(db_session, ws.id, source) is None
        assert status_fn(ws.id, db_session).get("seeded") is False
        survivor = db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id).first()
        assert survivor is not None, (
            f"{provider} demo clear removed a non-demo finding"
        )
    finally:
        # Always ensure the demo is cleared even if assertions fired.
        try:
            clear_fn(workspace_id=ws.id, db=db_session)
        except Exception:
            db_session.rollback()
        db_session.query(SecurityFinding).filter(
            SecurityFinding.id == real_id).delete(synchronize_session=False)
        db_session.query(Resource).filter(
            Resource.id == real_res.id).delete(synchronize_session=False)
        db_session.query(Integration).filter(
            Integration.id == real_integ.id).delete(synchronize_session=False)
        db_session.commit()


# ════════════════════════════════════════════════════════════════════════════
# Layer 3 — frontend source guardrails
# ════════════════════════════════════════════════════════════════════════════

_SEC = "app/(app)/security"

# Providers expected on each /security/<surface> provider selector. The
# selectors are the canonical literal arrays in the page source.
_ACTIVITY_PROVIDERS = [
    "github", "aws", "cloudflare", "vercel", "supabase", "firebase",
    "stripe", "shopify",
    # M77D added Azure activity ingestion.
    "azure",
    # M78D added Google Cloud Audit Log ingestion.
    "google_cloud",
    # M79D added Twilio Monitor activity ingestion.
    "twilio",
    # M80D added SendGrid config-state activity ingestion.
    "sendgrid",
    # M81D added Auth0 config-state activity ingestion.
    "auth0",
    # M82D added Datadog config-state activity ingestion.
    "datadog",
    # M83D added Clerk config-state activity ingestion.
    "clerk",
]
# Datadog activity signals landed in M82E; correlations landed in M82F.
# Clerk activity signals landed in M83E; correlations landed in M83F.
_SIGNALS_PROVIDERS = _ACTIVITY_PROVIDERS[:]
_CORRELATIONS_PROVIDERS = _ACTIVITY_PROVIDERS[:]


def _provider_selector_array(text: str) -> list[str] | None:
    """Extract the first ``options={["a","b",...]}`` provider selector array.

    M78D added ``google_cloud`` which contains an underscore.
    M81D added ``auth0`` which contains a digit — accept ``[a-z0-9_]+``.
    """
    m = re.search(
        r"options=\{\s*\[\s*((?:\"[a-z0-9_]+\"\s*,?\s*)+)\]\s*\}", text)
    if not m:
        return None
    return re.findall(r"\"([a-z0-9_]+)\"", m.group(1))


def test_fe_activity_provider_selector_has_all():
    text = _read_fe(f"{_SEC}/activity/page.tsx")
    arr = _provider_selector_array(text)
    assert arr is not None, "activity provider selector not found"
    assert arr == _ACTIVITY_PROVIDERS, (
        f"activity provider selector drift: {arr}"
    )


def test_fe_signals_provider_selector_has_all():
    text = _read_fe(f"{_SEC}/signals/page.tsx")
    arr = _provider_selector_array(text)
    assert arr is not None, "signals provider selector not found"
    assert arr == _SIGNALS_PROVIDERS, f"signals provider selector drift: {arr}"


def test_fe_correlations_provider_selector_has_all():
    text = _read_fe(f"{_SEC}/correlations/page.tsx")
    # Correlations page may declare ``PROVIDER_OPTIONS`` OR inline the
    # options list directly on the <Select> — accept either shape. ``[a-z_]+``
    # accommodates ``google_cloud``.
    m = re.search(
        r"const\s+PROVIDER_OPTIONS\s*=\s*\[\s*((?:\"[a-z0-9_]+\"\s*,?\s*)+)\]", text)
    if m is None:
        m = re.search(
            r"options=\{\s*\[\s*((?:\"[a-z0-9_]+\"\s*,?\s*)+)\]\s*\}", text)
    assert m is not None, "PROVIDER_OPTIONS / inline literal not found on correlations page"
    arr = re.findall(r"\"([a-z0-9_]+)\"", m.group(1))
    assert arr == _CORRELATIONS_PROVIDERS, (
        f"correlations PROVIDER_OPTIONS drift: {arr}"
    )


def test_fe_cases_has_each_demo_provider_label():
    """Each provider with a demo gets a banner card on /security/cases.

    M75B refactored the page to render banners from a single
    ``PROVIDER_DEMO_CARDS`` array via ``.map(card => ... onSeedDemo(card.provider))``
    instead of hand-rolled inline ``onSeedDemo("<provider>")`` calls. We pin
    that each provider id and CTA label is present in the array.
    """
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    for provider, label, *_ in PROVIDERS:
        if provider == "github":
            assert "Load GitHub incident demo" in text
        else:
            assert f"Load {label} security demo" in text, (
                f"cases page missing '{label}' security demo CTA"
            )
        assert f'provider: "{provider}"' in text, (
            f"cases page missing demo card for {provider!r}"
        )
    # Sanity: cards are dispatched through the array map (not inline calls).
    assert 'onSeedDemo(card.provider)' in text
    assert 'onClearDemo(card.provider)' in text


def test_fe_api_demo_provider_union_has_all():
    """The frontend api.ts demo helpers' provider unions list every provider."""
    text = _read_fe("lib/api.ts")
    # Three helper unions exist verbatim: getIncidentDemoStatus,
    # seedIncidentDemo, clearIncidentDemo. Confirm every provider appears in
    # all of them.
    for provider, *_ in PROVIDERS:
        # The union token is the bare quoted lowercase provider name.
        assert text.count(f'"{provider}"') >= 3, (
            f"api.ts demo unions missing 3 mentions of '{provider}'"
        )


def test_fe_demo_script_mentions_every_provider():
    """``securityDemoScript`` mentions every provider somewhere in its talk
    track. Some providers may appear under just their display label."""
    text = _read_fe("lib/securityDemoScript.ts")
    for _provider, label, *_ in PROVIDERS:
        assert label in text, f"demo script missing provider label {label!r}"


def test_fe_demo_script_forbidden_only_in_allowed_contexts():
    """Forbidden phrases in the demo script may appear only in negated
    narration, presenter ``avoid:`` guidance, or the explicit blocklist
    constant — never as a customer-facing claim. Mirrors M69.8B's check but
    against the wider M75A forbidden set."""
    text = _read_fe("lib/securityDemoScript.ts")
    allowed_markers = (
        "avoid", "never", "not ", "n't", "forbidden", "don't",
        "does not", "without", "no ",
    )
    for phrase in FORBIDDEN_PHRASES:
        for line in text.splitlines():
            if phrase not in line.lower():
                continue
            low = line.lower()
            is_blocklist_entry = re.match(r'^\s*"[^"]+",?\s*$', line) is not None
            assert is_blocklist_entry or any(m in low for m in allowed_markers), (
                f"forbidden phrase {phrase!r} used as a claim: {line.strip()!r}"
            )


# ════════════════════════════════════════════════════════════════════════════
# Layer 4 — privacy allowlist guardrail (shared metadata allowlists)
# ════════════════════════════════════════════════════════════════════════════


_BROAD_DANGEROUS_KEYS = frozenset({
    "raw",
    "payload",
    "headers",
    "body",
    "token",
    "secret",
    "value",
    "email",
    "customer_email",
    "card",
    "payment_method",
    "charge",
    "invoice",
    "order",
    "checkout",
    "cart",
    "authorization",
    "private_key",
    "access_token",
    "refresh_token",
})

# Namespaced safe keys that explicitly carry one of the dangerous fragments
# as a suffix or stand alone. These MUST appear in at least one allowlist —
# their presence proves we keep working safe NAME-level fields available.
_REQUIRED_SAFE_NAMESPACED_KEYS = frozenset({
    "webhook_endpoint_domain",
    "webhook_endpoint_scheme",
    "payment_link_id",
    "domain_host",
    "policy_type",
    "auth_setting_name",
})


def _all_allowlists() -> dict[str, frozenset[str]]:
    return {
        "activity": activity_svc.ALLOWED_METADATA_KEYS,
        "signal": signal_svc.ALLOWED_METADATA_KEYS,
        "correlation": corr_svc.ALLOWED_METADATA_KEYS,
    }


def test_shared_allowlists_no_broad_dangerous_keys():
    """No allowlist carries any of the broad-dangerous EXACT keys. Match is
    strict equality — ``webhook_endpoint_domain`` is fine; bare ``domain``
    would not be."""
    failures: dict[str, set[str]] = {}
    for name, allowlist in _all_allowlists().items():
        bad = set(allowlist) & _BROAD_DANGEROUS_KEYS
        if bad:
            failures[name] = bad
    assert not failures, (
        f"shared allowlists carry broad dangerous keys: {failures}"
    )


def test_shared_allowlists_keep_safe_namespaced_keys():
    """The deliberately-safe namespaced keys are still in at least one
    allowlist somewhere. This pins that we have not over-corrected and
    accidentally dropped a working safe key during a guardrail tightening."""
    union: set[str] = set()
    for allowlist in _all_allowlists().values():
        union |= set(allowlist)
    missing = _REQUIRED_SAFE_NAMESPACED_KEYS - union
    assert not missing, (
        f"required safe namespaced keys missing from every allowlist: {missing}"
    )
