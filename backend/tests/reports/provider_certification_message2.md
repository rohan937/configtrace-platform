# Provider Certification Framework — Message 2 Certification Report

## Objective

Expand the Provider Certification Framework (message 1) to two more
providers — Okta and Microsoft Entra ID — proving it generalizes across
four distinct authentication/API shapes (REST + org-token, SQL API +
PAT, REST + API-token, Microsoft Graph + tenant/client-secret), then
begin safely consolidating a small number of duplicated certification
assertions now that the framework is authoritative for the exact
invariants they checked.

## Providers added

- **Okta** (`manifests/okta.py`, `OKTA_MANIFEST`) — `provider_id="okta"`,
  category `auth`, maturity `partial`. 16 record types, 30 Security
  Finding rule IDs, 2 credential fields (`okta_org_url`,
  `okta_api_token` — token marked sensitive), reconnect required,
  public/connectable/Live.
- **Microsoft Entra ID** (`manifests/entra.py`, `ENTRA_MANIFEST`) —
  canonical `provider_id="entra"` (confirmed via
  `provider_capability_matrix_service.get_provider_capability`, not
  memory), category `auth`, maturity `partial`. 19 record types, 45
  Security Finding rule IDs, 3 credential fields (`entra_tenant_id`,
  `entra_client_id`, `entra_client_secret` — secret marked sensitive),
  reconnect required, public/connectable/Live.

Both manifests were built by independently re-deriving every field from
discovered repository state (schema record-type constants, the
registry/confidence/pack/coverage dicts, `diff_service`'s tracked-fields
dict and removal-suppression function, the capability-matrix entry) —
never copied from `okta_provider_certification.md` /
`entra_provider_certification.md` or from memory. See
`test_provider_certification_okta.py::TestOktaDiscoveryIndependentlyConfirmsManifest`
and the Entra equivalent for the tests that prove this.

## Discovery changes

None required. Generic `discovery.py` from message 1 already handles
both providers correctly:

- Okta's `risk_rules/okta.py` dispatches on raw string literals — the
  same pattern already proven for Sentry.
- Entra's `risk_rules/entra.py` dispatch was independently re-verified
  to resolve correctly against `entra_schema.py`'s named constants where
  used, the same named-constant-resolution logic already proven for
  Snowflake in message 1.
- `discover_diff_tracked_fields_dict` and
  `discover_schema_record_type_constants` returned exact matches for
  both providers on the first attempt — no record-type-constant
  precision bug (the `ACTION_CATEGORY_SENTRY_APP`-style false positive
  found for Sentry in message 1) exists for either Okta or Entra.

## Adapter changes

Added `adapters.py` (`ProviderDiscoveryAdapter`, `resolve_set()`,
adapter registry) and `gates.gate_adapter_consistency`. No adapter is
registered for any of the four pilot providers — generic discovery is
sufficient for all of them. The mechanism itself is proven with
synthetic (non-production) adapters in
`test_provider_certification_adapters.py` (16 tests): agreement,
augmentation (adapter is a strict superset of generic discovery — the
union is used), and contradiction (anything else — the generic result
is kept and the disagreement is surfaced as an explicit `fail`, never
silently resolved).

## Global gates

Added `cross_manifest.py` with five gates attached to every provider's
result (`gate_provider_expansion_freeze`'s pattern, extended):
`cross_manifest_identity`, `cross_manifest_capability_consistency`,
`cross_manifest_finding_uniqueness`, `cross_manifest_catalog_consistency`,
`cross_manifest_live_freeze`. All five pass for the real four-provider
manifest set; each has a negative-mutation test proving it fails under
simulated drift (`test_provider_certification_cross_manifest.py`, 21
tests).

Alias audit: this repository has no `microsoft_entra_id` or `azure_ad`
alias for Entra anywhere (backend sync list, frontend provider lists,
capability matrix, security coverage) — confirmed via direct grep and
via `test_provider_certification_entra.py::test_no_alias_provider_id_registered`.
Per the explicit "only if the repository already has real aliases"
instruction, no alias-normalization mechanism was built; the
cross-manifest identity gate's case/separator-collision check is the
proportionate guard against future alias drift.

## Consolidation performed

12 assertions removed total (within the 5-20 target):

| File | Removed | Before → After |
|---|---|---|
| `test_sentry_security_finding_parity.py` | `TestRegistryParity` (2 tests), `TestFrontendParity::test_every_registered_sentry_rule_in_frontend_catalog` + `test_no_frontend_only_sentry_rules` (2), `TestFullCrossLayerParity` (2 tests) | 39 → 33 |
| `test_snowflake_security_finding_parity.py` | Same 6 categories, Snowflake equivalents | 37 → 31 |

Every removed assertion was a pure module/registry/frontend-catalog
SET-EQUALITY check with zero additional semantic value beyond what
`gate_security_finding_registry_parity` already proves against real
discovered state. Nothing semantic was removed.

## Tests removed / retained

Removed: 12 (see above). Retained (deliberately, explicitly NOT
consolidated this message): confidence-value validity, guard-reason
presence, pack severity validity, pack manifest self-check, pack
summary/category coverage, capability-matrix flag checks,
`provider_of`/`_expected_record_types` resolution, frontend
provider-field/severity-match checks, all "no forbidden wording" guards,
and all `TestFindingVsChangeSeverityParity` cases — these require
provider-specific semantic knowledge (exact severity values, exact
forbidden phrase lists, exact Change-vs-Finding pairings) the generic
framework does not and should not attempt to encode. Okta's and Entra's
own legacy parity/depth-QA test files were NOT edited this message — see
`tests/reports/provider_certification_duplication_inventory.md` (80
rows) for the full per-provider, per-category audit and the message-3
recommendation to consolidate their equivalents next.

## Negative mutation coverage

Added across four test files: Okta record-type-missing-classifier,
Okta secret-field-rendered-unmasked, Okta backend/frontend drift, Okta
completeness-scope-without-suppression, Okta reconnect-router-missing,
Okta tracked-field-missing; Entra Finding-missing-from-confidence-map,
Entra backend/frontend drift, Entra Live-but-capability-matrix-planned,
Entra completeness-scope-without-suppression, Entra reconnect-function-missing,
Entra tracked-field-missing; five cross-manifest negative mutations
(duplicate provider ID, capability-matrix maturity disagreement, a
pilot reappearing in the future queue, sync-service catalog drift,
cross-provider Finding-ID duplicate); four adapter-mechanism mutations
(agreement, augmentation, contradiction — both symmetric cases).

## Deterministic reports

`backend/tests/reports/provider_certification/{sentry,snowflake,okta,entra,summary}.json`
generated via `runner.write_report()` / `runner.write_summary_report()`.
Proven byte-identical: same process (repeated calls), a separate Python
process (subprocess), and under reversed manifest-registration order
(`test_provider_certification_reports.py`). No timestamps, no
environment-specific absolute paths.

## Limitations

- Adapter mechanism is unexercised by any real provider — it is proven
  correct via synthetic tests only, not by a genuine production case.
- Okta's and Entra's own legacy test-file duplication (12+ analogous
  assertions each, per the duplication inventory) remains unconsolidated.
- Cross-manifest gates operate only over the four registered pilots —
  they say nothing about the ~40 other launched providers that remain
  outside this framework.

## Certification result

**PASS.** All four pilot providers (`sentry`, `snowflake`, `okta`,
`entra`) certify `overall_status == "pass"`. See
`provider_certification_framework.md` §21 for the full gate table.
