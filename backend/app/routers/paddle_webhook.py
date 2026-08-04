"""Paddle webhook receiver (Commercial Infrastructure message 2).

Mirrors ``app/routers/stripe_webhook.py``'s raw-body handling pattern
exactly: the raw body is read BEFORE any JSON parsing, so the exact byte
sequence is what gets signature-verified — never a re-serialized
representation.

Security
--------
* Missing/invalid signature -> HTTP 400, before any DB work.
* Always returns HTTP 200 for a signature-VALID event, even unhandled
  event types — a non-2xx response would cause Paddle to retry
  indefinitely (matches the existing Stripe webhook's documented
  behavior).
* No authentication token is required (Paddle cannot supply one);
  authenticity is proved entirely by the webhook signature.
* The raw body is never logged.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.billing.paddle_webhook_service import PaddleWebhookProcessingError, process_paddle_webhook
from app.billing.paddle_webhooks import PaddleSignatureError, verify_paddle_signature
from app.config import settings
from app.database import SessionLocal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/paddle", tags=["paddle-webhook"])


@router.post("/webhook", include_in_schema=False)
async def paddle_webhook(request: Request) -> JSONResponse:
    raw_body = await request.body()

    sig_header = request.headers.get("paddle-signature", "")
    if not sig_header:
        logger.warning("Paddle webhook received without Paddle-Signature header.")
        raise HTTPException(status_code=400, detail="Missing Paddle-Signature header.")

    webhook_secret = settings.PADDLE_WEBHOOK_SECRET
    if not webhook_secret:
        logger.warning("Paddle webhook received but PADDLE_WEBHOOK_SECRET is not configured.")
        raise HTTPException(status_code=503, detail="Paddle webhooks are not configured on this server.")

    try:
        event = verify_paddle_signature(raw_body, sig_header, webhook_secret)
    except PaddleSignatureError as exc:
        logger.warning("Paddle webhook signature verification failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    db = SessionLocal()
    try:
        status = process_paddle_webhook(event, db)
        db.commit()
        logger.info("Paddle webhook processed: %s (%s)", event.get("event_type"), status)
    except PaddleWebhookProcessingError:
        db.rollback()
        logger.exception("Error processing Paddle webhook event: %s", event.get("event_type"))
        # Still return 200 — a 5xx would cause Paddle to retry and hammer
        # the endpoint; the failed row is retryable via reconciliation.
        return JSONResponse({"status": "error"}, status_code=200)
    finally:
        db.close()

    return JSONResponse({"status": "ok"})
