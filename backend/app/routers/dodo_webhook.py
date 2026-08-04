"""Dodo Payments webhook receiver (Dodo Payments message 1).

Mirrors ``app/routers/stripe_webhook.py`` and ``app/routers/paddle_webhook.py``'s
raw-body handling pattern exactly: the raw body is read BEFORE any JSON
parsing, so the exact byte sequence is what gets signature-verified —
never a re-serialized representation.

Security
--------
* Missing/invalid signature -> HTTP 400, before any DB work.
* Always returns HTTP 200 for a signature-VALID event, even unhandled
  event types — a non-2xx response would cause Dodo to retry repeatedly
  (Dodo documents up to 8 retry attempts over ~10 hours with exponential
  backoff — matches the existing Stripe/Paddle webhooks' documented
  behavior of always acknowledging a verified delivery).
* No authentication token is required (Dodo cannot supply one);
  authenticity is proved entirely by the Standard Webhooks signature.
* The raw body is never logged.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.billing.dodo_webhook_service import DodoWebhookProcessingError, process_dodo_webhook
from app.billing.dodo_webhooks import DodoSignatureError, verify_dodo_signature
from app.config import settings
from app.database import SessionLocal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dodo", tags=["dodo-webhook"])


@router.post("/webhook", include_in_schema=False)
async def dodo_webhook(request: Request) -> JSONResponse:
    raw_body = await request.body()

    webhook_id = request.headers.get("webhook-id", "")
    webhook_timestamp = request.headers.get("webhook-timestamp", "")
    webhook_signature = request.headers.get("webhook-signature", "")
    if not webhook_id or not webhook_timestamp or not webhook_signature:
        logger.warning("Dodo webhook received without required Standard Webhooks headers.")
        raise HTTPException(status_code=400, detail="Missing required webhook signature headers.")

    webhook_secret = settings.DODO_WEBHOOK_SECRET
    if not webhook_secret:
        logger.warning("Dodo webhook received but DODO_WEBHOOK_SECRET is not configured.")
        raise HTTPException(status_code=503, detail="Dodo webhooks are not configured on this server.")

    headers = {
        "webhook-id": webhook_id,
        "webhook-timestamp": webhook_timestamp,
        "webhook-signature": webhook_signature,
    }
    try:
        event = verify_dodo_signature(raw_body, headers, webhook_secret)
    except DodoSignatureError as exc:
        logger.warning("Dodo webhook signature verification failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    db = SessionLocal()
    try:
        status = process_dodo_webhook(event, webhook_id, db)
        db.commit()
        logger.info("Dodo webhook processed: %s (%s)", event.get("type"), status)
    except DodoWebhookProcessingError:
        db.rollback()
        logger.exception("Error processing Dodo webhook event: %s", event.get("type"))
        # Still return 200 — a 5xx would cause Dodo to retry and hammer
        # the endpoint; the failed row is retryable via reconciliation.
        return JSONResponse({"status": "error"}, status_code=200)
    finally:
        db.close()

    return JSONResponse({"status": "ok"})
