# Commercial Infrastructure — Paddle Webhook Matrix (message 2)

Covers signature verification, event normalization, and end-to-end
processing (idempotency, staleness/ordering, state transitions, audit).
Every row maps to a real, currently-passing test.

## Signature verification (19 tests)

| # | Case | Test |
|---|---|---|
| 1 | Valid signature returns the parsed event | `test_commercial_paddle_signature.py::TestValidSignature::test_valid_signature_returns_parsed_event` |
| 2 | Wrong HMAC is rejected | `TestInvalidHmac::test_wrong_hmac_rejected` |
| 3 | Body modified after signing is rejected | `TestModifiedBody::test_modified_body_after_signing_rejected` |
| 4 | Wrong secret is rejected | `TestWrongSecret::test_wrong_secret_rejected` |
| 5 | Empty/missing header is rejected | `TestMissingHeader::test_empty_header_rejected` |
| 6 | Header missing `ts=` is rejected | `TestMalformedHeader::test_header_without_ts_rejected` |
| 7 | Header missing `h1=` is rejected | `TestMalformedHeader::test_header_without_h1_rejected` |
| 8 | Non-integer timestamp is rejected | `TestMalformedHeader::test_non_integer_timestamp_rejected` |
| 9 | Completely malformed header is rejected | `TestMalformedHeader::test_completely_malformed_header_rejected` |
| 10 | Timestamp too old (beyond tolerance) is rejected | `TestStaleTimestamp::test_timestamp_too_old_rejected` |
| 11 | Timestamp too far in the future is rejected | `TestStaleTimestamp::test_timestamp_too_far_in_future_rejected` |
| 12 | Custom tolerance window is respected | `TestStaleTimestamp::test_custom_tolerance_respected` |
| 13 | Multiple `h1` values: any match accepted (secret rotation) | `TestMultipleSignatures::test_multiple_h1_values_accepted_if_any_matches` |
| 14 | Multiple `h1` values: rejected if none match | `TestMultipleSignatures::test_multiple_h1_values_rejected_if_none_matches` |
| 15 | Whitespace-only body difference breaks the signature (byte sensitivity) | `TestExactRawBodyPreservation::test_whitespace_difference_breaks_signature` |
| 16 | Exact original bytes verify successfully | `TestExactRawBodyPreservation::test_exact_original_bytes_verify` |
| 17 | Error message never contains the raw body content | `TestNoBodyLogging::test_signature_error_message_never_contains_body_content` |
| 18 | Error message never contains the webhook secret | `TestNoBodyLogging::test_signature_error_never_contains_secret` |
| 19 | Empty webhook secret is rejected outright | `TestMissingWebhookSecret::test_empty_secret_rejected` |

## Event normalization (16 tests)

| # | Case | Test |
|---|---|---|
| 20 | `subscription.created` normalizes correctly | `test_commercial_paddle_webhooks.py::TestFixturesNormalizeCorrectly::test_subscription_created` |
| 21 | `subscription.updated` normalizes correctly | `::test_subscription_updated` |
| 22 | `subscription.canceled` normalizes correctly | `::test_subscription_canceled` |
| 23 | `subscription.paused` normalizes correctly | `::test_subscription_paused` |
| 24 | `subscription.resumed` normalizes correctly | `::test_subscription_resumed` |
| 25 | `transaction.completed` normalizes correctly | `::test_transaction_completed` |
| 26 | `transaction.payment_failed` normalizes correctly | `::test_transaction_payment_failed` |
| 27 | `customer.updated` normalizes correctly | `::test_customer_updated` |
| 28 | `subscription.past_due` maps to `PAYMENT_PAST_DUE` | `TestSubscriptionPastDue::test_subscription_past_due_maps_to_payment_past_due` |
| 29 | Unrecognized event name maps to `UNKNOWN` (safe default) | `TestUnknownEventsSafelyAcknowledged::test_unrecognized_event_name_maps_to_unknown` |
| 30 | Unknown event still carries the raw event name for audit purposes | `::test_unknown_event_still_carries_raw_event_name_for_audit` |
| 31 | Fixture IDs are obviously synthetic (no accidental real-data reuse) | `TestNoRealCustomerDataInFixtures::test_fixture_ids_are_obviously_synthetic` |
| 32 | Valid ISO `occurred_at` is parsed | `TestOccurredAtParsing::test_iso_timestamp_parsed` |
| 33 | Missing `occurred_at` yields `None`, not an exception | `::test_missing_occurred_at_yields_none` |
| 34 | Malformed `occurred_at` yields `None`, not an exception | `::test_malformed_occurred_at_yields_none_not_exception` |
| 35 | Normalized payload never carries a customer email | `TestNormalizedPayloadIsSmallAndSafe::test_normalized_payload_never_carries_email` |

## End-to-end processing (8 tests, real Postgres-backed rows)

| # | Case | Test |
|---|---|---|
| 36 | First delivery of `subscription.created` updates local subscription status | `TestFirstDeliveryProcessed::test_subscription_created_updates_local_status` |
| 37 | Duplicate delivery does not reapply the event or error | `TestDuplicateDeliveryReturnsSuccessNoDuplicateMutation::test_duplicate_delivery_does_not_reapply_or_error` |
| 38 | Duplicate delivery does not create a duplicate audit entry | `::test_duplicate_delivery_does_not_create_duplicate_audit_entry` |
| 39 | Unknown event type leaves the subscription untouched | `TestUnknownEventNeverMutatesState::test_unknown_event_leaves_subscription_untouched` |
| 40 | An older "active" event delivered after a newer cancellation is ignored (ordering/staleness protection) | `TestOlderActiveEventAfterCancellation::test_stale_active_event_after_newer_cancellation_is_ignored` |
| 41 | Event referencing an unknown subscription reference is a safe no-op | `TestWrongWorkspaceCustomData::test_event_for_unknown_subscription_reference_is_a_safe_no_op` |
| 42 | Payment failure sets `past_due` + a `grace_period_end` | `TestPaymentFailureAndRecovery::test_payment_failed_sets_past_due_and_grace_period` |
| 43 | A subsequent successful transaction recovers the subscription from `past_due` | `::test_successful_transaction_recovers_from_past_due` |

## Route-level behavior (by direct inspection of `app/routers/paddle_webhook.py`, mirrors the existing `stripe_webhook.py` pattern; not independently re-tested in this file set)

| # | Case | Basis |
|---|---|---|
| 44 | Raw body is read before any JSON parsing | Direct inspection — `await request.body()` precedes `verify_paddle_signature` call |
| 45 | Route always returns HTTP 200 even when processing raises, to prevent Paddle retry storms | Direct inspection, mirrors `stripe_webhook.py` |
| 46 | Route returns 503 if `PADDLE_WEBHOOK_SECRET` is unset | Direct inspection |
| 47 | Route returns 400 for a missing or invalid signature header | Direct inspection |

**Total: 43 executed test cases + 4 direct-inspection route-contract notes = 47 rows.**
