# Commercial Infrastructure Test Matrix (message 1)

Total rows: **182** (minimum required: 180). Every row maps to a real, currently-passing test.

Columns: Case | File | Test


## Pricing calculation (36 rows)

| # | Case | File | Test |
|---|---|---|---|
| 1 | negative rejected: negative one raises | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestNegativeRejected::test_negative_one_raises` |
| 2 | negative rejected: large negative raises | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestNegativeRejected::test_large_negative_raises` |
| 3 | zero members: zero members is base price not free | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestZeroMembers::test_zero_members_is_base_price_not_free` |
| 4 | boundary values: boundary value[1-3000-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[1-3000-0]` |
| 5 | boundary values: boundary value[2-3000-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[2-3000-0]` |
| 6 | boundary values: boundary value[10-3000-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[10-3000-0]` |
| 7 | boundary values: boundary value[19-3000-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[19-3000-0]` |
| 8 | boundary values: boundary value[20-3000-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[20-3000-0]` |
| 9 | boundary values: boundary value[21-3500-1] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[21-3500-1]` |
| 10 | boundary values: boundary value[22-4000-2] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[22-4000-2]` |
| 11 | boundary values: boundary value[25-5500-5] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[25-5500-5]` |
| 12 | boundary values: boundary value[30-8000-10] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[30-8000-10]` |
| 13 | boundary values: boundary value[50-18000-30] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[50-18000-30]` |
| 14 | boundary values: boundary value[100-43000-80] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_boundary_value[100-43000-80]` |
| 15 | boundary values: spec examples match dollar amounts | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundaryValues::test_spec_examples_match_dollar_amounts` |
| 16 | very large count: very large count stays integer and correct | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestVeryLargeCount::test_very_large_count_stays_integer_and_correct` |
| 17 | bounded loop property: formula holds for every n in range | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestBoundedLoopProperty::test_formula_holds_for_every_n_in_range` |
| 18 | integer minor units: total is int never float | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestIntegerMinorUnits::test_total_is_int_never_float` |
| 19 | deterministic breakdown: repeated calls produce identical breakdown | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestDeterministicBreakdown::test_repeated_calls_produce_identical_breakdown` |
| 20 | deterministic breakdown: breakdown as dict is json serializable | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestDeterministicBreakdown::test_breakdown_as_dict_is_json_serializable` |
| 21 | component quantities: base quantity always one[0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[0]` |
| 22 | component quantities: base quantity always one[1] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[1]` |
| 23 | component quantities: base quantity always one[20] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[20]` |
| 24 | component quantities: base quantity always one[21] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[21]` |
| 25 | component quantities: base quantity always one[25] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[25]` |
| 26 | component quantities: base quantity always one[50] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[50]` |
| 27 | component quantities: base quantity always one[100] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_base_quantity_always_one[100]` |
| 28 | component quantities: additional quantity is max zero seats minus 20[0-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[0-0]` |
| 29 | component quantities: additional quantity is max zero seats minus 20[1-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[1-0]` |
| 30 | component quantities: additional quantity is max zero seats minus 20[20-0] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[20-0]` |
| 31 | component quantities: additional quantity is max zero seats minus 20[21-1] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[21-1]` |
| 32 | component quantities: additional quantity is max zero seats minus 20[25-5] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[25-5]` |
| 33 | component quantities: additional quantity is max zero seats minus 20[50-30] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[50-30]` |
| 34 | component quantities: additional quantity is max zero seats minus 20[100-80] | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestComponentQuantities::test_additional_quantity_is_max_zero_seats_minus_20[100-80]` |
| 35 | currency and interval: currency is usd | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestCurrencyAndInterval::test_currency_is_usd` |
| 36 | currency and interval: interval is month | `tests/test_commercial_pricing.py` | `tests/test_commercial_pricing.py::TestCurrencyAndInterval::test_interval_is_month` |

## Billable-seat definition (14 rows)

| # | Case | File | Test |
|---|---|---|---|
| 37 | owner alone counts: owner only counts as one | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestOwnerAloneCounts::test_owner_only_counts_as_one` |
| 38 | admin and member count: admin counts | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestAdminAndMemberCount::test_admin_counts` |
| 39 | admin and member count: ordinary member counts | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestAdminAndMemberCount::test_ordinary_member_counts` |
| 40 | admin and member count: owner admin and member all count | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestAdminAndMemberCount::test_owner_admin_and_member_all_count` |
| 41 | pending invites not counted: pending invite is not a billable member | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestPendingInvitesNotCounted::test_pending_invite_is_not_a_billable_member` |
| 42 | accepted invite becomes member: accepting an invite creates a real billable member | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestAcceptedInviteBecomesMember::test_accepting_an_invite_creates_a_real_billable_member` |
| 43 | member removal: removing a member decreases the count | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestMemberRemoval::test_removing_a_member_decreases_the_count` |
| 44 | member role change: promoting member to admin does not change count | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestMemberRoleChange::test_promoting_member_to_admin_does_not_change_count` |
| 45 | duplicate membership: duplicate membership rejected by unique constraint | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestDuplicateMembership::test_duplicate_membership_rejected_by_unique_constraint` |
| 46 | no service account concept: no deactivated or service account role exists | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestNoServiceAccountConcept::test_no_deactivated_or_service_account_role_exists` |
| 47 | workspace has no owner: workspace with no owner raises | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestWorkspaceHasNoOwner::test_workspace_with_no_owner_raises` |
| 48 | workspace has no owner: in memory variant also requires an owner | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestWorkspaceHasNoOwner::test_in_memory_variant_also_requires_an_owner` |
| 49 | workspace has no owner: in memory variant counts correctly with owner | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestWorkspaceHasNoOwner::test_in_memory_variant_counts_correctly_with_owner` |
| 50 | concurrent invite acceptance: two invites accepted for different users both count | `tests/test_commercial_billable_seats.py` | `tests/test_commercial_billable_seats.py::TestConcurrentInviteAcceptance::test_two_invites_accepted_for_different_users_both_count` |

## Provider abstraction (12 rows)

| # | Case | File | Test |
|---|---|---|---|
| 51 | stripe selected: default provider is stripe | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestStripeSelected::test_default_provider_is_stripe` |
| 52 | stripe selected: explicit stripe override | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestStripeSelected::test_explicit_stripe_override` |
| 53 | paddle selected but not activated: paddle without price mapping fails closed | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestPaddleSelectedButNotActivated::test_paddle_without_price_mapping_fails_closed` |
| 54 | paddle selected but not activated: paddle configured adapter is returned but unsupported | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestPaddleSelectedButNotActivated::test_paddle_configured_adapter_is_returned_but_unsupported` |
| 55 | unknown provider rejected: unknown provider string raises | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestUnknownProviderRejected::test_unknown_provider_string_raises` |
| 56 | provider neutral types: checkout request is plain dataclass | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestProviderNeutralTypes::test_checkout_request_is_plain_dataclass` |
| 57 | provider neutral types: checkout request fields are primitives or enums only | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestProviderNeutralTypes::test_checkout_request_fields_are_primitives_or_enums_only` |
| 58 | no stripe object leakage: stripe adapter module never imports stripe sdk | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestNoStripeObjectLeakage::test_stripe_adapter_module_never_imports_stripe_sdk` |
| 59 | no stripe object leakage: provider module has no stripe or paddle import statement | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestNoStripeObjectLeakage::test_provider_module_has_no_stripe_or_paddle_import_statement` |
| 60 | registry deterministic: same provider override returns same adapter type every time | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestRegistryDeterministic::test_same_provider_override_returns_same_adapter_type_every_time` |
| 61 | no silent provider fallback: paddle not configured never returns a stripe adapter | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestNoSilentProviderFallback::test_paddle_not_configured_never_returns_a_stripe_adapter` |
| 62 | paddle price mapping configuration: price mapping is configured only with both ids | `tests/test_commercial_provider_registry.py` | `tests/test_commercial_provider_registry.py::TestPaddlePriceMappingConfiguration::test_price_mapping_is_configured_only_with_both_ids` |

## Entitlement normalization (32 rows)

| # | Case | File | Test |
|---|---|---|---|
| 63 | normalize stripe status: known stripe statuses map correctly[trialing-trialing] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[trialing-trialing]` |
| 64 | normalize stripe status: known stripe statuses map correctly[active-active] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[active-active]` |
| 65 | normalize stripe status: known stripe statuses map correctly[past due-past due] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[past_due-past_due]` |
| 66 | normalize stripe status: known stripe statuses map correctly[canceled-canceled] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[canceled-canceled]` |
| 67 | normalize stripe status: known stripe statuses map correctly[unpaid-expired] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[unpaid-expired]` |
| 68 | normalize stripe status: known stripe statuses map correctly[incomplete-incomplete] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[incomplete-incomplete]` |
| 69 | normalize stripe status: known stripe statuses map correctly[incomplete expired-expired] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[incomplete_expired-expired]` |
| 70 | normalize stripe status: known stripe statuses map correctly[paused-paused] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_known_stripe_statuses_map_correctly[paused-paused]` |
| 71 | normalize stripe status: unknown stripe status maps to incomplete not active | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestNormalizeStripeStatus::test_unknown_stripe_status_maps_to_incomplete_not_active` |
| 72 | every normalized status: paid access by status[active-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[active-True]` |
| 73 | every normalized status: paid access by status[trialing-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[trialing-True]` |
| 74 | every normalized status: paid access by status[past due-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[past_due-True]` |
| 75 | every normalized status: paid access by status[grace period-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[grace_period-True]` |
| 76 | every normalized status: paid access by status[paused-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[paused-False]` |
| 77 | every normalized status: paid access by status[canceled-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[canceled-False]` |
| 78 | every normalized status: paid access by status[expired-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[expired-False]` |
| 79 | every normalized status: paid access by status[incomplete-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_paid_access_by_status[incomplete-False]` |
| 80 | every normalized status: active team gets team entitlements | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_active_team_gets_team_entitlements` |
| 81 | every normalized status: canceled team falls back to free entitlements | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_canceled_team_falls_back_to_free_entitlements` |
| 82 | every normalized status: past due still gets team entitlements during grace | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEveryNormalizedStatus::test_past_due_still_gets_team_entitlements_during_grace` |
| 83 | management availability: billing management availability[active-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[active-True]` |
| 84 | management availability: billing management availability[trialing-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[trialing-True]` |
| 85 | management availability: billing management availability[past due-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[past_due-True]` |
| 86 | management availability: billing management availability[grace period-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[grace_period-True]` |
| 87 | management availability: billing management availability[paused-True] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[paused-True]` |
| 88 | management availability: billing management availability[canceled-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[canceled-False]` |
| 89 | management availability: billing management availability[expired-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[expired-False]` |
| 90 | management availability: billing management availability[incomplete-False] | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestManagementAvailability::test_billing_management_availability[incomplete-False]` |
| 91 | feature gates never read raw provider strings: decide entitlements signature takes normalized status enum | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestFeatureGatesNeverReadRawProviderStrings::test_decide_entitlements_signature_takes_normalized_status_enum` |
| 92 | feature gates never read raw provider strings: entitlement decision never stores a raw provider status field | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestFeatureGatesNeverReadRawProviderStrings::test_entitlement_decision_never_stores_a_raw_provider_status_field` |
| 93 | entitlement decision serializable: as dict is json serializable | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEntitlementDecisionSerializable::test_as_dict_is_json_serializable` |
| 94 | entitlement decision serializable: source provider none serializes to none | `tests/test_commercial_entitlements.py` | `tests/test_commercial_entitlements.py::TestEntitlementDecisionSerializable::test_source_provider_none_serializes_to_none` |

## Webhook event normalization (17 rows)

| # | Case | File | Test |
|---|---|---|---|
| 95 | normalized event types: stripe event type maps correctly[checkout.session.completed-subscription created] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[checkout.session.completed-subscription_created]` |
| 96 | normalized event types: stripe event type maps correctly[customer.subscription.created-subscription created] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.subscription.created-subscription_created]` |
| 97 | normalized event types: stripe event type maps correctly[customer.subscription.updated-subscription updated] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.subscription.updated-subscription_updated]` |
| 98 | normalized event types: stripe event type maps correctly[customer.subscription.deleted-subscription canceled] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.subscription.deleted-subscription_canceled]` |
| 99 | normalized event types: stripe event type maps correctly[customer.subscription.paused-subscription paused] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.subscription.paused-subscription_paused]` |
| 100 | normalized event types: stripe event type maps correctly[customer.subscription.resumed-subscription resumed] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.subscription.resumed-subscription_resumed]` |
| 101 | normalized event types: stripe event type maps correctly[invoice.payment failed-transaction failed] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[invoice.payment_failed-transaction_failed]` |
| 102 | normalized event types: stripe event type maps correctly[invoice.payment succeeded-transaction completed] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[invoice.payment_succeeded-transaction_completed]` |
| 103 | normalized event types: stripe event type maps correctly[invoice.paid-transaction completed] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[invoice.paid-transaction_completed]` |
| 104 | normalized event types: stripe event type maps correctly[customer.updated-customer updated] | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_stripe_event_type_maps_correctly[customer.updated-customer_updated]` |
| 105 | normalized event types: unrecognized stripe event type maps to unknown | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNormalizedEventTypes::test_unrecognized_stripe_event_type_maps_to_unknown` |
| 106 | reference extraction: subscription event extracts subscription and customer reference | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestReferenceExtraction::test_subscription_event_extracts_subscription_and_customer_reference` |
| 107 | reference extraction: invoice event extracts transaction reference | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestReferenceExtraction::test_invoice_event_extracts_transaction_reference` |
| 108 | occurred at: created timestamp converted to utc datetime | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestOccurredAt::test_created_timestamp_converted_to_utc_datetime` |
| 109 | occurred at: missing created timestamp yields none | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestOccurredAt::test_missing_created_timestamp_yields_none` |
| 110 | no raw payload persisted: normalized payload is small allowlisted summary not full object | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestNoRawPayloadPersisted::test_normalized_payload_is_small_allowlisted_summary_not_full_object` |
| 111 | external event id: external event id extracted | `tests/test_commercial_webhook_events.py` | `tests/test_commercial_webhook_events.py::TestExternalEventId::test_external_event_id_extracted` |

## Webhook idempotency (12 rows)

| # | Case | File | Test |
|---|---|---|---|
| 112 | first delivery: first delivery creates a pending row | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestFirstDelivery::test_first_delivery_creates_a_pending_row` |
| 113 | duplicate delivery: duplicate delivery returns existing row not a new one | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestDuplicateDelivery::test_duplicate_delivery_returns_existing_row_not_a_new_one` |
| 114 | duplicate delivery: duplicate after success is detected and marked | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestDuplicateDelivery::test_duplicate_after_success_is_detected_and_marked` |
| 115 | failed delivery retry: failed event can be retried and then succeed | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestFailedDeliveryRetry::test_failed_event_can_be_retried_and_then_succeed` |
| 116 | same external id different providers: same external event id from different providers does not collide | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestSameExternalIdDifferentProviders::test_same_external_event_id_from_different_providers_does_not_collide` |
| 117 | out of order and stale events: older event after newer update is flagged stale | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestOutOfOrderAndStaleEvents::test_older_event_after_newer_update_is_flagged_stale` |
| 118 | out of order and stale events: cancellation followed by older active event is stale | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestOutOfOrderAndStaleEvents::test_cancellation_followed_by_older_active_event_is_stale` |
| 119 | out of order and stale events: no timestamp is never considered stale | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestOutOfOrderAndStaleEvents::test_no_timestamp_is_never_considered_stale` |
| 120 | out of order and stale events: no existing subscription is never considered stale | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestOutOfOrderAndStaleEvents::test_no_existing_subscription_is_never_considered_stale` |
| 121 | audit entry emitted once: duplicate webhook delivery emits exactly one duplicate audit entry | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestAuditEntryEmittedOnce::test_duplicate_webhook_delivery_emits_exactly_one_duplicate_audit_entry` |
| 122 | no secret or raw payload leakage: normalized payload never contains credential shaped keys | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestNoSecretOrRawPayloadLeakage::test_normalized_payload_never_contains_credential_shaped_keys` |
| 123 | no secret or raw payload leakage: audit details are filtered to allowlist | `tests/test_commercial_webhook_idempotency.py` | `tests/test_commercial_webhook_idempotency.py::TestNoSecretOrRawPayloadLeakage::test_audit_details_are_filtered_to_allowlist` |

## Stripe compatibility adapter (8 rows)

| # | Case | File | Test |
|---|---|---|---|
| 124 | create checkout through adapter: checkout returns provider neutral response | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestCreateCheckoutThroughAdapter::test_checkout_returns_provider_neutral_response` |
| 125 | create portal through adapter: portal returns provider neutral response | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestCreatePortalThroughAdapter::test_portal_returns_provider_neutral_response` |
| 126 | create portal through adapter: portal without stripe customer raises 400 | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestCreatePortalThroughAdapter::test_portal_without_stripe_customer_raises_400` |
| 127 | webhook normalization equivalence: parse webhook delegates to existing verify signature | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestWebhookNormalizationEquivalence::test_parse_webhook_delegates_to_existing_verify_signature` |
| 128 | webhook normalization equivalence: parse webhook rejects bad signature | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestWebhookNormalizationEquivalence::test_parse_webhook_rejects_bad_signature` |
| 129 | update and cancel unsupported: update subscription returns unsupported before m2 | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestUpdateAndCancelUnsupported::test_update_subscription_returns_unsupported_before_m2` |
| 130 | update and cancel unsupported: cancel subscription documents portal only cancellation | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestUpdateAndCancelUnsupported::test_cancel_subscription_documents_portal_only_cancellation` |
| 131 | no external calls in adapter construction: constructing adapter makes no network call | `tests/test_commercial_stripe_adapter.py` | `tests/test_commercial_stripe_adapter.py::TestNoExternalCallsInAdapterConstruction::test_constructing_adapter_makes_no_network_call` |

## Paddle adapter contract (18 rows)

| # | Case | File | Test |
|---|---|---|---|
| 132 | price mapping contract: unconfigured mapping is not configured | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestPriceMappingContract::test_unconfigured_mapping_is_not_configured` |
| 133 | price mapping contract: fully configured mapping is configured | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestPriceMappingContract::test_fully_configured_mapping_is_configured` |
| 134 | price mapping contract: environment field distinguishes sandbox and live | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestPriceMappingContract::test_environment_field_distinguishes_sandbox_and_live` |
| 135 | adapter not configured: no mapping raises not configured | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterNotConfigured::test_no_mapping_raises_not_configured` |
| 136 | adapter not configured: empty mapping raises not configured | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterNotConfigured::test_empty_mapping_raises_not_configured` |
| 137 | adapter not configured: not configured never silently returns none | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterNotConfigured::test_not_configured_never_silently_returns_none` |
| 138 | adapter configured but unsupported: create checkout raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_create_checkout_raises_unsupported` |
| 139 | adapter configured but unsupported: create portal raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_create_portal_raises_unsupported` |
| 140 | adapter configured but unsupported: get customer raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_get_customer_raises_unsupported` |
| 141 | adapter configured but unsupported: get subscription raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_get_subscription_raises_unsupported` |
| 142 | adapter configured but unsupported: parse webhook raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_parse_webhook_raises_unsupported` |
| 143 | adapter configured but unsupported: reconcile raises unsupported | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_reconcile_raises_unsupported` |
| 144 | adapter configured but unsupported: update subscription returns typed result not exception | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_update_subscription_returns_typed_result_not_exception` |
| 145 | adapter configured but unsupported: cancel subscription returns typed result not exception | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestAdapterConfiguredButUnsupported::test_cancel_subscription_returns_typed_result_not_exception` |
| 146 | never falls back to stripe: paddle adapter provider is always paddle | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestNeverFallsBackToStripe::test_paddle_adapter_provider_is_always_paddle` |
| 147 | never falls back to stripe: paddle adapter module never imports stripe | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestNeverFallsBackToStripe::test_paddle_adapter_module_never_imports_stripe` |
| 148 | planned seat representation: base quantity is always one never combinatorial | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestPlannedSeatRepresentation::test_base_quantity_is_always_one_never_combinatorial` |
| 149 | planned seat representation: additional seat quantity matches formula | `tests/test_commercial_paddle_contract.py` | `tests/test_commercial_paddle_contract.py::TestPlannedSeatRepresentation::test_additional_seat_quantity_matches_formula` |

## Deployment configuration (12 rows)

| # | Case | File | Test |
|---|---|---|---|
| 150 | settings schema supports paddle: billing provider field exists and defaults to stripe | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestSettingsSchemaSupportsPaddle::test_billing_provider_field_exists_and_defaults_to_stripe` |
| 151 | settings schema supports paddle: paddle fields exist and default to none | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestSettingsSchemaSupportsPaddle::test_paddle_fields_exist_and_default_to_none` |
| 152 | settings schema supports paddle: existing stripe fields unchanged | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestSettingsSchemaSupportsPaddle::test_existing_stripe_fields_unchanged` |
| 153 | env example has paddle placeholders: env example file exists | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestEnvExampleHasPaddlePlaceholders::test_env_example_file_exists` |
| 154 | env example has paddle placeholders: env example declares paddle variables | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestEnvExampleHasPaddlePlaceholders::test_env_example_declares_paddle_variables` |
| 155 | env example has paddle placeholders: env example declares no real paddle secret values | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestEnvExampleHasPaddlePlaceholders::test_env_example_declares_no_real_paddle_secret_values` |
| 156 | fail closed provider selection: paddle without mapping never returns a usable adapter | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestFailClosedProviderSelection::test_paddle_without_mapping_never_returns_a_usable_adapter` |
| 157 | no secret in a p i response models: billing response model has no paddle or stripe secret fields | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestNoSecretInAPIResponseModels::test_billing_response_model_has_no_paddle_or_stripe_secret_fields` |
| 158 | no secret in a p i response models: pricing breakdown as dict has no secret fields | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestNoSecretInAPIResponseModels::test_pricing_breakdown_as_dict_has_no_secret_fields` |
| 159 | paddle secrets backend only: paddle settings are not next public prefixed | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestPaddleSecretsBackendOnly::test_paddle_settings_are_not_next_public_prefixed` |
| 160 | paddle secrets backend only: stripe secret key is not next public prefixed | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestPaddleSecretsBackendOnly::test_stripe_secret_key_is_not_next_public_prefixed` |
| 161 | hosted environments untouched by this message: no render yaml modification evidence of paddle env injection | `tests/test_commercial_deployment_config.py` | `tests/test_commercial_deployment_config.py::TestHostedEnvironmentsUntouchedByThisMessage::test_no_render_yaml_modification_evidence_of_paddle_env_injection` |

## Stale-price detection (8 rows)

| # | Case | File | Test |
|---|---|---|---|
| 162 | frontend team pricing display is updated: billing page no longer shows flat 40 dollar team price | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestFrontendTeamPricingDisplayIsUpdated::test_billing_page_no_longer_shows_flat_40_dollar_team_price` |
| 163 | frontend team pricing display is updated: billing page no longer shows flat 50 dollar team price | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestFrontendTeamPricingDisplayIsUpdated::test_billing_page_no_longer_shows_flat_50_dollar_team_price` |
| 164 | frontend team pricing display is updated: billing page shows new base price and included seats copy | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestFrontendTeamPricingDisplayIsUpdated::test_billing_page_shows_new_base_price_and_included_seats_copy` |
| 165 | frontend team pricing display is updated: billing page never says dollars per member for base price | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestFrontendTeamPricingDisplayIsUpdated::test_billing_page_never_says_dollars_per_member_for_base_price` |
| 166 | no stale5000 cents as team base: no 5000 cents team base reference outside allowlist | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestNoStale5000CentsAsTeamBase::test_no_5000_cents_team_base_reference_outside_allowlist` |
| 167 | no stale5000 cents as team base: pricing module base constant is 3000 not 5000 | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestNoStale5000CentsAsTeamBase::test_pricing_module_base_constant_is_3000_not_5000` |
| 168 | no stale team price env constant: no team price equals 50 env style constant anywhere | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestNoStaleTeamPriceEnvConstant::test_no_team_price_equals_50_env_style_constant_anywhere` |
| 169 | no unrelated duplicate price constants: pricing py is the single source of truth for team base amount | `tests/test_commercial_stale_team_price.py` | `tests/test_commercial_stale_team_price.py::TestNoUnrelatedDuplicatePriceConstants::test_pricing_py_is_the_single_source_of_truth_for_team_base_amount` |

## Message-1 reports (13 rows)

| # | Case | File | Test |
|---|---|---|---|
| 170 | all required reports exist: every required report file exists | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestAllRequiredReportsExist::test_every_required_report_file_exists` |
| 171 | all required reports exist: every report is non trivial | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestAllRequiredReportsExist::test_every_report_is_non_trivial` |
| 172 | stripe inventory report: mentions provider neutral scope distinction | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestStripeInventoryReport::test_mentions_provider_neutral_scope_distinction` |
| 173 | stripe inventory report: documents actual current team price not the spec assumption | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestStripeInventoryReport::test_documents_actual_current_team_price_not_the_spec_assumption` |
| 174 | deployment inventory report: documents paddle env vars planned not deployed | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestDeploymentInventoryReport::test_documents_paddle_env_vars_planned_not_deployed` |
| 175 | deployment inventory report: documents existing stripe env vars | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestDeploymentInventoryReport::test_documents_existing_stripe_env_vars` |
| 176 | paddle cutover report: has all five phases | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestPaddleCutoverReport::test_has_all_five_phases` |
| 177 | paddle cutover report: documents rollback strategy | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestPaddleCutoverReport::test_documents_rollback_strategy` |
| 178 | message1 report: states provider neutral architecture | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestMessage1Report::test_states_provider_neutral_architecture` |
| 179 | message1 report: documents zero member decision | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestMessage1Report::test_documents_zero_member_decision` |
| 180 | message1 report: does not claim paddle api was called | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestMessage1Report::test_does_not_claim_paddle_api_was_called` |
| 181 | pricing matrix report: has at least boundary rows | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestPricingMatrixReport::test_has_at_least_boundary_rows` |
| 182 | test matrix report: has at least 180 rows | `tests/test_commercial_message1_reports.py` | `tests/test_commercial_message1_reports.py::TestTestMatrixReport::test_has_at_least_180_rows` |
