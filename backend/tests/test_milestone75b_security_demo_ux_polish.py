"""M75B — Cross-provider security demo UX polish guardrails.

Pins the polished cross-provider demo / activity / signals / correlations
copy so a future edit cannot silently regress the operator experience.

Three layers (all static frontend reads + one backend label check):

  1. Cases page — admin-only demo banners now render from a single
     ``PROVIDER_DEMO_CARDS`` array. Every completed provider appears once,
     each card carries the standardized intro/description shape, every
     seed/clear button is wired to the right ``DemoProvider`` literal, and
     none of the copy contains forbidden claim wording.

  2. Activity / signals / correlations pages — each surface mentions every
     completed provider label and carries the review-safe helper phrase
     for its surface ("Sync" / "Generate review signals" / "Correlate").

  3. Case detail page + case-report markdown export — both use evidence /
     review framing and never call the case an "attack chain", "confirmed
     incident", "breach path", or "proof".

  4. Backend label map remains canonical (mirrors M75A's pin so a coupled
     break is caught here too).

Frontend assertions skip cleanly when the frontend tree isn't mounted
(matches M69.8B / M75A's CI-tolerant pattern).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services import security_case_report_service as report_svc


# ── Forbidden claim wording (M75B set — same 12 phrases as M75A) ─────────────
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

# Wording that frames a case as proof / certainty rather than evidence.
_CERTAINTY_PHRASES = [
    "attack chain",
    "confirmed incident",
    "breach path",
    "proof of compromise",
    "proof of breach",
]

# Canonical completed-provider matrix (mirrors M75A's PROVIDERS).
PROVIDERS: list[tuple[str, str]] = [
    ("github", "GitHub"),
    ("aws", "AWS"),
    ("cloudflare", "Cloudflare"),
    ("vercel", "Vercel"),
    ("supabase", "Supabase"),
    ("firebase", "Firebase"),
    ("stripe", "Stripe"),
    ("shopify", "Shopify"),
]


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


def _assert_no_forbidden(text: str, where: str, *, allowed_markers=()) -> None:
    """Each forbidden phrase in ``text`` must be inside an explicit denylist
    constant or carry a negated / avoidance marker on the same line."""
    default_markers = (
        "avoid", "never", "not ", "n't", "forbidden", "don't",
        "does not", "without", "no ",
    )
    markers = tuple(default_markers) + tuple(allowed_markers)
    low_lines = text.splitlines()
    for phrase in FORBIDDEN_PHRASES:
        for line in low_lines:
            if phrase not in line.lower():
                continue
            low = line.lower()
            is_blocklist_entry = re.match(r'^\s*"[^"]+",?\s*$', line) is not None
            assert is_blocklist_entry or any(m in low for m in markers), (
                f"forbidden phrase {phrase!r} used as a claim in {where}: "
                f"{line.strip()!r}"
            )


_SEC = "app/(app)/security"


# ════════════════════════════════════════════════════════════════════════════
# Layer 1 — cases page demo cards
# ════════════════════════════════════════════════════════════════════════════


def test_cases_page_uses_provider_demo_cards_array():
    """The cases page declares a single ``PROVIDER_DEMO_CARDS`` array and
    renders banners from it — not 8 hand-rolled inline cards."""
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    assert "PROVIDER_DEMO_CARDS" in text, "PROVIDER_DEMO_CARDS array not found"
    # The array is mapped to <div> banners.
    assert re.search(r"PROVIDER_DEMO_CARDS\.map\(", text) is not None
    # Standardized shape: every entry has intro, description, seedButton,
    # clearButton, seedColor.
    for key in ("intro:", "description:", "seedButton:", "clearButton:", "seedColor:"):
        assert key in text, f"PROVIDER_DEMO_CARDS missing {key} field"
    # No "Try the …:" intro string is hand-rolled outside the array map.
    # The array carries one entry per provider with a demo: 8 canonical
    # providers plus Azure (M77G) plus Google Cloud (M78G) plus Twilio
    # (M79G) plus SendGrid (M80G) = 12. Sanity-check by counting the
    # ``intro: "Try the `` literal (filters out comments / prose).
    assert text.count('intro: "Try the ') == 12, (
        "expected exactly 12 PROVIDER_DEMO_CARDS intros"
    )


def test_cases_page_demo_cards_cover_every_provider():
    """Every completed provider's CTA appears on the cases page with the
    M75A button labels and an ``onSeedDemo`` / ``onClearDemo`` call."""
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    for provider, label in PROVIDERS:
        assert f'provider: "{provider}"' in text, (
            f"PROVIDER_DEMO_CARDS missing provider={provider!r}"
        )
        assert f'label: "{label}"' in text
        if provider == "github":
            assert "Load GitHub incident demo" in text
        else:
            assert f"Load {label} security demo" in text
        assert f'onSeedDemo(card.provider)' in text  # rendered via map
        assert f'onClearDemo(card.provider)' in text


def test_cases_page_demo_cards_have_consistent_intro_shape():
    """Each card's intro reads "Try the <Label> (incident|security) demo:"."""
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    for provider, label in PROVIDERS:
        if provider == "github":
            assert f'intro: "Try the {label} incident demo:"' in text
        else:
            assert f'intro: "Try the {label} security demo:"' in text


def test_cases_page_demo_descriptions_are_short_and_safe():
    """Each card's description mentions the evidence-chain shape and stays
    review-safe. Also: forbidden phrases never appear as customer-facing
    claims (mirrors M69.8B's check)."""
    text = _read_fe(f"{_SEC}/cases/page.tsx")
    # Each description names the four evidence kinds the demo seeds.
    for keyword in ("activity", "signals", "correlations", "case report"):
        # The keyword must appear at least once per provider in the description
        # block; 8 providers ⇒ at least 8 mentions across the file.
        assert text.lower().count(keyword.lower()) >= 8, (
            f"cases page descriptions under-mention {keyword!r}"
        )
    _assert_no_forbidden(text, "cases/page.tsx")


# ════════════════════════════════════════════════════════════════════════════
# Layer 2 — activity / signals / correlations pages
# ════════════════════════════════════════════════════════════════════════════


def test_activity_page_has_review_safe_helper_phrase():
    text = _read_fe(f"{_SEC}/activity/page.tsx")
    for _provider, label in PROVIDERS:
        assert label in text, f"activity page missing provider label {label!r}"
    assert "review-safe" in text.lower() or "evidence for review" in text.lower(), (
        "activity page helper copy missing review-safe framing"
    )
    _assert_no_forbidden(text, "activity/page.tsx")


def test_signals_page_has_review_signal_phrase():
    text = _read_fe(f"{_SEC}/signals/page.tsx")
    for _provider, label in PROVIDERS:
        assert label in text, f"signals page missing provider label {label!r}"
    # Each provider's generate-helper copy says "Generate review signals from
    # <Provider> ... activity evidence" — sanity-check the shared verb.
    assert text.count("Generate review signals from") >= 5, (
        "signals page generate helper copy too thin"
    )
    _assert_no_forbidden(text, "signals/page.tsx")


def test_correlations_page_has_review_window_phrase():
    text = _read_fe(f"{_SEC}/correlations/page.tsx")
    for _provider, label in PROVIDERS:
        assert label in text, f"correlations page missing provider label {label!r}"
    # Every per-provider blurb names "review window" so the cross-provider
    # narrative converges.
    assert "review window" in text.lower(), (
        "correlations page missing 'review window' framing"
    )
    _assert_no_forbidden(text, "correlations/page.tsx")


# ════════════════════════════════════════════════════════════════════════════
# Layer 3 — case detail page + markdown export
# ════════════════════════════════════════════════════════════════════════════


def test_case_detail_uses_evidence_framing_not_certainty():
    text = _read_fe(f"{_SEC}/cases/[id]/page.tsx")
    low = text.lower()
    for phrase in _CERTAINTY_PHRASES:
        assert phrase not in low, (
            f"case detail page uses certainty wording: {phrase!r}"
        )
    # Positive framing must remain — at least one of these per surface.
    for required in ("evidence timeline", "evidence relationship map"):
        assert required in low, f"case detail page missing {required!r}"
    _assert_no_forbidden(text, "cases/[id]/page.tsx")


def test_case_report_export_uses_evidence_framing_not_certainty():
    text = _read_fe("lib/caseReportExport.ts")
    low = text.lower()
    for phrase in _CERTAINTY_PHRASES:
        assert phrase not in low, (
            f"caseReportExport.ts uses certainty wording: {phrase!r}"
        )
    # Markdown sections still title evidence content.
    assert "chronological evidence timeline" in low
    assert "metadata-only evidence" in low or "evidence for review" in low
    _assert_no_forbidden(text, "lib/caseReportExport.ts")


# ════════════════════════════════════════════════════════════════════════════
# Layer 4 — demo script + backend label map
# ════════════════════════════════════════════════════════════════════════════


def test_demo_script_uses_review_window_and_does_not_confirm():
    text = _read_fe("lib/securityDemoScript.ts")
    low = text.lower()
    # Required positive framing.
    for required in ("review window", "evidence for review"):
        assert required in low, f"demo script missing required framing: {required!r}"
    # ConfigTrace's standing disclaimer — accept any of the conventional
    # "does not ___" surfaces (we don't pin one wording verbatim because
    # different scenes lean on slightly different verbs).
    assert any(p in low for p in (
        "does not confirm", "does not claim", "does not mean",
        "never confirms",
    )), "demo script missing 'ConfigTrace does not …' framing"
    for _provider, label in PROVIDERS:
        assert label in text, f"demo script missing provider label {label!r}"
    # M75A already pins forbidden-wording allowed-context discipline; do not
    # re-run that here to avoid duplicate failure modes.


def test_backend_provider_label_map_remains_canonical():
    """Belt-and-suspenders pin on top of M75A's same check, so a future copy
    change cannot break the cross-page label story without this file failing.

    M77G added Azure and M78G added Google Cloud to the canonical map
    (demo-ready security review flow). Both remain tracked as partial
    providers in the capability matrix but appear in the timeline label
    map so case timelines/graphs render their friendly labels as the
    dominant-provider label.
    """
    assert report_svc._TIMELINE_PROVIDER_LABELS == {
        "github": "GitHub", "aws": "AWS", "cloudflare": "Cloudflare",
        "vercel": "Vercel", "supabase": "Supabase", "firebase": "Firebase",
        "stripe": "Stripe", "shopify": "Shopify", "azure": "Azure",
        "google_cloud": "Google Cloud", "twilio": "Twilio",
    }
