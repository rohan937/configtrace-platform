"""Stale flat-Team-price detection (Commercial Infrastructure message 1).

Scans commercial-relevant frontend/backend surfaces for outdated flat-Team
pricing references ($50/month, 5000 cents, TEAM_PRICE=50-style constants,
"$40/month" display copy) that should have been replaced by the new
$30-base + $5/seat presentation. An explicit allowlist covers files that
legitimately still describe the OLD price for historical/migration
documentation purposes (this message's own message-1 report, the
compatibility PLAN_LIMITS dict which intentionally keeps the legacy flat
Stripe price alive for the existing checkout flow per message-1 spec
item 6/14).
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND_ROOT = _REPO_ROOT / "backend"
_FRONTEND_ROOT = _REPO_ROOT / "frontend"

_TEAM_PRICING_DISPLAY_FILE = _FRONTEND_ROOT / "src/app/(app)/settings/workspace/billing/page.tsx"

# Files legitimately allowed to mention the OLD flat price:
#   * billing_service.py — the compatibility PLAN_LIMITS dict intentionally
#     keeps monthly_price_usd=40 for the EXISTING Stripe checkout flow,
#     which this message does not rewire to seat-based pricing (message-1
#     spec item 14: isolation, not rewrite). It is not a "stale" reference,
#     it is the documented, still-live legacy value.
#   * test_milestone58_25.py — pins the existing (unchanged) compatibility
#     behavior; a genuine regression test, not stale product copy.
#   * this test file, and the message-1 reports that document the
#     before/after change for historical record.
_ALLOWLISTED_PATHS = {
    _BACKEND_ROOT / "app/services/billing_service.py",
    _BACKEND_ROOT / "tests/test_milestone58_25.py",
    _BACKEND_ROOT / "tests/test_commercial_stale_team_price.py",
}


def _is_allowlisted(path: Path) -> bool:
    if path in _ALLOWLISTED_PATHS:
        return True
    if "commercial_infrastructure" in path.name:  # message-1 reports
        return True
    return False


class TestFrontendTeamPricingDisplayIsUpdated:
    def test_billing_page_no_longer_shows_flat_40_dollar_team_price(self):
        text = _TEAM_PRICING_DISPLAY_FILE.read_text()
        assert '"$40"' not in text, "stale flat $40 Team price string found in billing page.tsx"
        assert "Then $40/month" not in text

    def test_billing_page_no_longer_shows_flat_50_dollar_team_price(self):
        text = _TEAM_PRICING_DISPLAY_FILE.read_text()
        assert '"$50"' not in text
        assert "$50/month" not in text

    def test_billing_page_shows_new_base_price_and_included_seats_copy(self):
        text = _TEAM_PRICING_DISPLAY_FILE.read_text()
        assert "$30" in text
        assert "20" in text  # included-seats count appears somewhere in the copy
        assert "$5" in text  # additional-seat price appears in the copy

    def test_billing_page_never_says_dollars_per_member_for_base_price(self):
        text = _TEAM_PRICING_DISPLAY_FILE.read_text()
        assert "$30 per member" not in text
        assert "$30/member" not in text


class TestNoStale5000CentsAsTeamBase:
    def test_no_5000_cents_team_base_reference_outside_allowlist(self):
        pattern = re.compile(r"\b5000\b")
        offenders = []
        for path in _BACKEND_ROOT.rglob("app/billing/**/*.py"):
            pass  # placeholder to keep rglob usage explicit below
        for path in (_BACKEND_ROOT / "app" / "billing").rglob("*.py"):
            if _is_allowlisted(path):
                continue
            text = path.read_text()
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line) and "team" in text.lower():
                    # Only flag if genuinely presented as a team-base amount,
                    # not an unrelated numeric literal.
                    if "5000" in line and ("team" in line.lower() or "base" in line.lower()):
                        offenders.append(f"{path}:{lineno}: {line.strip()}")
        assert offenders == [], f"stale 5000-cent Team base reference(s): {offenders}"

    def test_pricing_module_base_constant_is_3000_not_5000(self):
        from app.billing.pricing import TEAM_BASE_MONTHLY_CENTS

        assert TEAM_BASE_MONTHLY_CENTS == 3000
        assert TEAM_BASE_MONTHLY_CENTS != 5000


class TestNoStaleTeamPriceEnvConstant:
    def test_no_team_price_equals_50_env_style_constant_anywhere(self):
        pattern = re.compile(r"TEAM_PRICE\s*=\s*50\b")
        offenders = []
        for root in (_BACKEND_ROOT / "app", _FRONTEND_ROOT / "src"):
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix not in (".py", ".ts", ".tsx"):
                    continue
                if _is_allowlisted(path):
                    continue
                text = path.read_text(errors="ignore")
                if pattern.search(text):
                    offenders.append(str(path))
        assert offenders == [], f"stale TEAM_PRICE=50 constant found in: {offenders}"


class TestNoUnrelatedDuplicatePriceConstants:
    def test_pricing_py_is_the_single_source_of_truth_for_team_base_amount(self):
        """No other module in app/billing/ redefines TEAM_BASE_MONTHLY_CENTS
        with a different literal value."""
        pricing_source = (_BACKEND_ROOT / "app/billing/pricing.py").read_text()
        assert "TEAM_BASE_MONTHLY_CENTS = 3000" in pricing_source

        for path in (_BACKEND_ROOT / "app" / "billing").rglob("*.py"):
            if path.name == "pricing.py":
                continue
            text = path.read_text()
            assert "TEAM_BASE_MONTHLY_CENTS = " not in text, (
                f"{path} redefines TEAM_BASE_MONTHLY_CENTS instead of importing it"
            )
