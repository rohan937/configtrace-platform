"""Optional, explicitly opt-in Dodo Test Mode smoke tests (Dodo Payments
message 1).

SKIPPED BY DEFAULT. Never runs in ordinary CI. Requires:

  RUN_DODO_SANDBOX_TESTS=1
  DODO_ENVIRONMENT=test
  DODO_API_KEY=<real Test Mode key>
  DODO_WEBHOOK_SECRET=<real Test Mode secret>
  DODO_PRO_PRODUCT_ID=<real Test Mode product id>
  DODO_TEAM_PRODUCT_ID=<real Test Mode product id>
  DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID=<real Test Mode addon id>

If ``DODO_ENVIRONMENT`` is ``live`` these tests refuse to run at all,
even with the opt-in flag set — never a live transaction from a test run.
No checkout, subscription, or charge is ever created by this file — the
only real call made is a read-only ``GET /products/{id}`` catalog check.
"""

from __future__ import annotations

import os

import pytest

_OPT_IN = os.environ.get("RUN_DODO_SANDBOX_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not _OPT_IN,
    reason="RUN_DODO_SANDBOX_TESTS=1 not set — Dodo Test Mode smoke tests are opt-in only, skipped by default.",
)


def _test_mode_client_or_skip():
    from app.billing.dodo_client import DodoAPIClient, DodoClientConfig
    from app.config import settings

    if settings.dodo_environment_normalized == "live":
        pytest.fail("Refusing to run Dodo smoke tests against DODO_ENVIRONMENT=live.")
    if settings.dodo_environment_normalized != "test":
        pytest.skip("DODO_ENVIRONMENT is not 'test' — cannot run Dodo Test Mode smoke tests.")
    if not settings.DODO_API_KEY:
        pytest.skip("DODO_API_KEY is not set — cannot run Dodo Test Mode smoke tests.")
    return DodoAPIClient(DodoClientConfig(environment="test", api_key=settings.DODO_API_KEY))


class TestSandboxCatalogVerification:
    """Calls the real Dodo Test Mode API (read-only) to verify the
    configured Pro/Team product IDs actually resolve to real products."""

    def test_pro_product_id_resolves(self):
        from app.config import settings

        client = _test_mode_client_or_skip()
        product_id = settings.DODO_PRO_PRODUCT_ID
        if not product_id:
            pytest.skip("DODO_PRO_PRODUCT_ID is not configured.")
        result = client.get_product(product_id)
        assert result.get("product_id") == product_id or result.get("id") == product_id

    def test_team_product_id_resolves(self):
        from app.config import settings

        client = _test_mode_client_or_skip()
        product_id = settings.DODO_TEAM_PRODUCT_ID
        if not product_id:
            pytest.skip("DODO_TEAM_PRODUCT_ID is not configured.")
        result = client.get_product(product_id)
        assert result.get("product_id") == product_id or result.get("id") == product_id


class TestSandboxSignatureRoundTrip:
    """Documents that a real Dodo Test Mode webhook delivery has NOT been
    exercised against this implementation in this message — this is the
    honest, explicit placeholder for that verification step, not a
    fabricated PASS."""

    def test_documented_as_not_yet_run_against_a_real_test_mode_delivery(self):
        pytest.skip(
            "This message did not receive a real Dodo Test Mode webhook delivery. "
            "Configure a Test Mode webhook endpoint pointed at a reachable test "
            "server, trigger a real event (e.g. via a real Test Mode checkout), "
            "then replace this skip with a real assertion against the captured "
            "payload's signature and event shape."
        )


class TestSandboxChangePlanAddonQuantitySemantics:
    """Documents that this message's assumptions about add-on quantity
    multiplication and zero-quantity omission (see adapters/dodo.py's
    module docstring) have NOT been verified against a real change-plan
    call in this message."""

    def test_documented_as_not_yet_verified(self):
        pytest.skip(
            "This message did not verify, against a real Dodo Test Mode "
            "subscription, whether add-on quantity multiplies the add-on's "
            "unit price, or whether a zero-quantity add-on must be omitted "
            "vs explicitly sent as quantity:0. See adapters/dodo.py's module "
            "docstring for the exact assumptions made."
        )
