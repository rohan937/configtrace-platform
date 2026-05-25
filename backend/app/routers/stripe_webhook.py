"""Stripe webhook receiver — M52: Billing + Usage Limits.

Routes
------
POST /stripe/webhook   — receive and process Stripe events (public endpoint)

Security
--------
* The endpoint reads the raw request body before any JSON parsing so the exact
  byte sequence can be used for HMAC-SHA256 signature verification.
* Requests with an invalid or missing Stripe-Signature header are rejected with
  HTTP 400 before any DB work is done.
* The endpoint always returns HTTP 200 to Stripe even for event types we don't
  handle — returning non-2xx would cause Stripe to retry indefinitely.
* No authentication token is required (Stripe cannot supply one); authenticity
  is proved entirely by the webhook signature.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.database import SessionLocal
from app.services import billing_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/stripe", tags=["stripe-webhook"])


@router.post("/webhook", include_in_schema=False)
async def stripe_webhook(
    request: Request,
) -> JSONResponse:
    """Process an inbound Stripe webhook event.

    The route reads the raw body, verifies the Stripe-Signature header, then
    dispatches to billing_service.handle_webhook_event.

    Returns HTTP 200 for all successfully verified events (even unhandled ones)
    so Stripe does not retry unnecessarily.
    """
    raw_body = await request.body()

    sig_header = request.headers.get("stripe-signature", "")
    if not sig_header:
        logger.warning("Stripe webhook received without Stripe-Signature header.")
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header.")

    try:
        event = billing_service.verify_stripe_signature(raw_body, sig_header)
    except ValueError as exc:
        logger.warning("Stripe webhook signature verification failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))

    # Process the event with a fresh DB session.
    # Use SessionLocal() directly (not next(get_db())) so we own the lifecycle
    # explicitly — the generator approach leaks the generator if not exhausted.
    db = SessionLocal()
    try:
        billing_service.handle_webhook_event(event, db)
        db.commit()
        logger.info("Stripe webhook processed: %s", event.get("type"))
    except Exception:
        db.rollback()
        logger.exception("Error processing Stripe webhook event: %s", event.get("type"))
        # Still return 200 — a 5xx would cause Stripe to retry and hammer the endpoint.
        return JSONResponse({"status": "error"}, status_code=200)
    finally:
        db.close()

    return JSONResponse({"status": "ok"})
