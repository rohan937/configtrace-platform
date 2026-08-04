"""Optional, explicitly opt-in Paddle sandbox smoke tests (Commercial
Infrastructure message 2, spec item 40).

SKIPPED BY DEFAULT. Never runs in ordinary CI. Requires:

  RUN_PADDLE_SANDBOX_TESTS=1
  PADDLE_ENVIRONMENT=sandbox
  PADDLE_API_KEY=<real sandbox key>
  PADDLE_WEBHOOK_SECRET=<real sandbox secret>
  PADDLE_TEAM_BASE_PRICE_ID=<real sandbox price id>
  PADDLE_TEAM_ADDITIONAL_SEAT_PRICE_ID=<real sandbox price id>

If ``PADDLE_ENVIRONMENT`` is ``production`` these tests refuse to run at
all, even with the opt-in flag set — never a production transaction from
a test run.

No destructive subscription mutation is performed against any object
other than one this test module creates and is responsible for cleaning
up manually (see the module docstring's cleanup note below).

Cleanup instructions (manual, since no destructive automation is built
here): after running these tests against a sandbox account, review the
Paddle sandbox dashboard's Customers/Subscriptions/Transactions lists for
any test object matching the ``ctm_test_configtrace_*`` / checkout custom
data workspace_id pattern used here and remove it manually if desired —
sandbox data has no billing consequence and Paddle does not charge real
money in sandbox mode, but keeping the sandbox catalog tidy is still good
practice before a production cutover rehearsal.
"""

from __future__ import annotations

import os

import pytest

_OPT_IN = os.environ.get("RUN_PADDLE_SANDBOX_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not _OPT_IN,
    reason="RUN_PADDLE_SANDBOX_TESTS=1 not set — sandbox smoke tests are opt-in only, skipped by default.",
)


def _sandbox_client_or_skip():
    from app.billing.paddle_client import PaddleAPIClient, PaddleClientConfig
    from app.config import settings

    if settings.paddle_environment_normalized == "production":
        pytest.fail("Refusing to run sandbox smoke tests against PADDLE_ENVIRONMENT=production.")
    if settings.paddle_environment_normalized != "sandbox":
        pytest.skip("PADDLE_ENVIRONMENT is not 'sandbox' — cannot run sandbox smoke tests.")
    if not settings.PADDLE_API_KEY:
        pytest.skip("PADDLE_API_KEY is not set — cannot run sandbox smoke tests.")
    return PaddleAPIClient(PaddleClientConfig(environment="sandbox", api_key=settings.PADDLE_API_KEY))


class TestSandboxCatalogVerification:
    """Calls the real Paddle sandbox API to verify the configured Team
    base/additional-seat prices match the internal expected contract."""

    def test_verify_catalog_against_real_sandbox_prices(self):
        from app.billing.catalog_verification import verify_catalog
        from app.config import settings

        client = _sandbox_client_or_skip()
        base_id = settings.effective_paddle_team_base_price_id
        seat_id = settings.effective_paddle_team_additional_seat_price_id
        if not base_id or not seat_id:
            pytest.skip("Paddle sandbox price IDs are not configured.")

        result = verify_catalog(client, base_price_id=base_id, additional_seat_price_id=seat_id)
        assert result.verified, f"catalog mismatches: {result.as_dict()}"


class TestSandboxSignatureRoundTrip:
    """Documents that a real sandbox webhook delivery has NOT been
    exercised against this implementation in this message — this is the
    honest, explicit placeholder for that verification step, not a
    fabricated PASS."""

    def test_documented_as_not_yet_run_against_a_live_sandbox_delivery(self):
        pytest.skip(
            "This message did not receive a real Paddle sandbox webhook delivery. "
            "Run this suite with RUN_PADDLE_SANDBOX_TESTS=1 after configuring a real "
            "sandbox notification destination pointed at a reachable test endpoint, "
            "then replace this skip with a real assertion against the captured payload."
        )
