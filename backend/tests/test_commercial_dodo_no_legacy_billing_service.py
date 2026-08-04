"""Guard against accidental use of the stale legacy Team $40 pricing path
(Dodo Payments message 1, Phase 1 requirement 7).

``app.services.billing_service.PLAN_LIMITS`` is a SEPARATE, older,
Stripe-only pricing table (Team = $40/month flat, no seat component) that
predates the provider-neutral commercial-infrastructure domain. No Dodo
module may import from it, and no Dodo module may reference the stale
$40 figure.
"""

from __future__ import annotations

import ast
from pathlib import Path

_APP_BILLING_DIR = Path(__file__).parent.parent / "app" / "billing"
_DODO_FILES = sorted(_APP_BILLING_DIR.glob("dodo_*.py")) + sorted((_APP_BILLING_DIR / "adapters").glob("dodo.py"))


class TestNoLegacyBillingServiceImport:
    def test_dodo_files_exist_to_check(self):
        assert len(_DODO_FILES) >= 5, f"expected at least 5 dodo_* files, found {_DODO_FILES}"

    def test_no_dodo_module_imports_billing_service(self):
        offenders = []
        for path in _DODO_FILES:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and "billing_service" in node.module:
                    offenders.append(str(path))
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if "billing_service" in alias.name:
                            offenders.append(str(path))
        assert offenders == [], f"Dodo modules must never import billing_service: {offenders}"

    def test_no_dodo_module_references_stale_forty_dollar_team_price(self):
        """4000 (cents) is the legacy, stale Team price — never a valid
        value in any Dodo-specific source file."""
        offenders = []
        for path in _DODO_FILES:
            text = path.read_text()
            if "4000" in text:
                offenders.append(str(path))
        assert offenders == [], f"Dodo modules must never reference the stale $40 (4000 cents) Team price: {offenders}"

    def test_no_dodo_module_imports_plan_limits(self):
        offenders = []
        for path in _DODO_FILES:
            if "PLAN_LIMITS" in path.read_text():
                offenders.append(str(path))
        assert offenders == [], f"Dodo modules must never reference the legacy PLAN_LIMITS table: {offenders}"


class TestCanonicalTeamPriceIsThirtyDollars:
    def test_team_base_monthly_cents_is_3000_not_4000(self):
        from app.billing.pricing import TEAM_BASE_MONTHLY_CENTS

        assert TEAM_BASE_MONTHLY_CENTS == 3000

    def test_dodo_adapter_seat_math_reuses_the_canonical_seat_reconciliation_module(self):
        """The Dodo adapter must derive its seat math from
        app.billing.seat_reconciliation (which itself derives from
        app.billing.pricing's canonical $30 formula), never re-deriving
        or hardcoding a seat threshold independently."""
        import ast

        adapter_path = _APP_BILLING_DIR / "adapters" / "dodo.py"
        tree = ast.parse(adapter_path.read_text())
        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.billing.seat_reconciliation":
                imported_names.update(alias.name for alias in node.names)
        assert "calculate_desired_additional_quantity" in imported_names
