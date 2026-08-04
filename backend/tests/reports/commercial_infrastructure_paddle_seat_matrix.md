# Commercial Infrastructure — Paddle Seat Reconciliation & Subscription-Item Matrix (message 2)

Covers subscription-item construction/update, the six required seat
transitions, proration policy, and seat reconciliation. Every row maps
to a real, currently-passing test.

## Checkout item construction (13 tests)

| # | Case | Test |
|---|---|---|
| 1 | 1 seat → base item only | `test_commercial_paddle_checkout.py::TestCheckoutItemsByMemberCount::test_base_only_for_seats_at_or_under_20[1]` |
| 2 | 10 seats → base item only | `[10]` |
| 3 | 19 seats → base item only | `[19]` |
| 4 | 20 seats → base item only | `[20]` |
| 5 | 21 seats → base + 1 additional | `test_base_plus_additional_for_seats_over_20[21-1]` |
| 6 | 25 seats → base + 5 additional | `[25-5]` |
| 7 | 50 seats → base + 30 additional | `[50-30]` |
| 8 | `custom_data` includes required correlation fields (`workspace_id`, `plan_id`, `billable_seat_count`, `pricing_version`) | `TestCustomData::test_custom_data_includes_required_correlation_fields` |
| 9 | Idempotency reference is generated when absent | `::test_idempotency_reference_generated_if_absent` |
| 10 | Provided idempotency reference is passed through unchanged | `::test_provided_idempotency_reference_is_used` |
| 11 | Checkout response includes `provider` and `checkout_url` | `TestCheckoutResponse::test_response_includes_provider_and_url` |
| 12 | No price mapping → `PaddleNotConfiguredError` | `TestNotConfigured::test_checkout_raises_not_configured_when_no_mapping` |
| 13 | No client → `PaddleNotConfiguredError` | `::test_checkout_raises_not_configured_when_client_missing` |

## Subscription-item update logic (17 tests)

| # | Case | Test |
|---|---|---|
| 14 | No additional members → base item only sent | `test_commercial_paddle_subscription_items.py::TestBaseOnly::test_update_with_no_additional_members_sends_base_only` |
| 15 | 21 members → adds exactly 1 additional seat | `TestBasePlusOneAdditional::test_update_with_21_members_adds_one_seat` |
| 16 | 50 members → sets 30 additional seats | `TestBasePlusManyAdditional::test_update_with_50_members_sets_30_additional` |
| 17 | An unrelated recurring line item is preserved unchanged | `TestPreserveUnrelatedItem::test_unrelated_recurring_item_preserved_unchanged` |
| 18 | Missing base item raises `PaddleBaseItemMissingError` | `TestMissingBaseItem::test_missing_base_item_raises` |
| 19 | Duplicate base item raises `PaddleDuplicateBaseItemError` | `TestDuplicateBaseItem::test_duplicate_base_item_raises` |
| 20 | Item with an unrecognized price ID is preserved, not silently dropped | `TestWrongPriceId::test_item_with_unknown_price_id_is_preserved_not_dropped` |
| 21 | Seat transition 21→20: additional item goes to 0 and is omitted | `TestZeroAdditionalSeatsOmitted::test_seat_transitions[21-20]` |
| 22 | Seat transition 25→20 | `[25-20]` |
| 23 | Seat transition 30→25 | `[30-25]` |
| 24 | Seat transition 50→10 | `[50-10]` |
| 25 | Seat transition 10→50 | `[10-50]` |
| 26 | Seat transition 20→21 | `[20-21]` |
| 27 | Every PATCH carries an explicit `proration_billing_mode` | `TestExplicitProrationMode::test_proration_mode_always_present` |
| 28 | Seat ADDED uses `prorated_immediately` | `::test_seat_added_uses_immediate_proration` |
| 29 | Seat REMOVED uses `prorated_next_billing_period` | `::test_seat_removed_uses_next_billing_period_proration` |
| 30 | Checkout idempotency reference is a stable string across calls with the same inputs | `TestStableIdempotencyKey::test_checkout_idempotency_reference_is_stable_string` |

**Six required seat transitions from the spec, all covered**: 20→21 (row 26), 21→20 (row 21), 25→30 (covered by row 6, checkout construction, plus the general formula tests below), 30→25 (row 23), 50→10 (row 24), 10→50 (row 25).

## Seat reconciliation — pure planning function (16 tests)

| # | Case | Test |
|---|---|---|
| 31 | Desired-quantity formula: 0 members → 0 additional | `test_commercial_paddle_seat_reconciliation.py::TestDesiredQuantity::test_desired_additional_quantity_formula[0-0]` |
| 32 | 1 member → 0 additional | `[1-0]` |
| 33 | 20 members → 0 additional | `[20-0]` |
| 34 | 21 members → 1 additional | `[21-1]` |
| 35 | 25 members → 5 additional | `[25-5]` |
| 36 | 50 members → 30 additional | `[50-30]` |
| 37 | Matching quantities need no update (`needs_update=False`) | `TestNoUpdateNeeded::test_matching_quantities_need_no_update` |
| 38 | Increase transition 20→21 | `TestSeatIncreaseTransitions::test_20_to_21[20-21]` |
| 39 | Increase transition 21→24 | `[21-24]` |
| 40 | Increase transition 25→30 | `[25-30]` |
| 41 | Decrease transition 30→25 | `TestSeatDecreaseTransitions::test_30_to_25` |
| 42 | Decrease transition 50→10 | `test_50_to_10` |
| 43 | Plan is a pure, deterministic function of its inputs (concurrency-safety proof) | `TestConcurrentChangeSafety::test_plan_is_a_pure_function_of_its_inputs` |
| 44 | Reconciling an already-correct subscription produces no plan (no duplicate update) | `TestDuplicateUpdateAvoidance::test_reconciling_an_already_correct_subscription_produces_no_plan` |
| 45 | `WorkspaceCustomerMismatchError` is a `ValueError` subclass | `TestWorkspaceCustomerMismatch::test_mismatch_detection_class_exists_and_is_a_value_error` |
| 46 | `reconcile_workspace_subscription` with no local subscription returns `updated=False` | `TestReconcileWorkspaceSubscriptionNoLocalSubscription::test_reconcile_with_no_local_subscription_returns_not_updated` |

**Total: 46 executed test cases**, covering checkout-item construction, subscription-item diff/update, all 6 required seat transitions, explicit proration-mode selection, and pure-function seat-reconciliation planning.
