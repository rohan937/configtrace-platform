# Provider Certification Framework (Message 1 + Message 2)

**Message 2 update**: see §17-21 below for Okta/Entra manifests, the
discovery-adapter model, cross-manifest global gates, and the
consolidation performed. Sections 1-16 are message 1's original content,
left unmodified except where explicitly noted.

Provider expansion is frozen. This message does not launch, migrate, or
add any provider — it converts the repeated certification patterns from
the Snowflake and Sentry eight-message launch arcs into a reusable,
executable, provider-agnostic framework.

## 1. Objective

Answer, mechanically and reproducibly: **is provider X certified for
its declared maturity and capabilities?** The framework evaluates a
provider's DECLARED contract (a `ProviderCertificationManifest`) against
ACTUAL repository wiring (discovered via static introspection of real
backend modules and frontend source text) — it never trusts a manifest
declaration, or a hand-written Markdown report, as evidence by itself.

## 2. Non-goals (explicitly out of scope for message 1)

- Migrating every launched provider onto the framework (Kubernetes,
  Okta, Microsoft Entra ID remain on their existing provider-specific
  QA suites — no manifest was written for them this message).
- Deleting any existing provider-specific test file, reliability
  matrix, or certification report. Every file from the Sentry/Snowflake
  eight-message arcs remains untouched and is referenced as evidence.
- A Live Validation CLI that calls real provider APIs with real
  credentials.
- Snapshot mutation/replay tooling.
- Security Finding lifecycle work.
- Adding another provider. Provider expansion stays frozen.

## 3. Architecture

```
backend/app/provider_certification/
  __init__.py         schema_version constant
  models.py            typed dataclasses: manifest, gate, evidence, result,
                        status/maturity/dimension taxonomies, manifest
                        __post_init__ contradiction validation
  discovery.py          read-only introspection of real repository state —
                        imports backend modules, parses frontend source
                        text with regex; never network, never DB, never a
                        live connector instance
  gates.py              one gate_* function per certification dimension;
                        pure functions comparing manifest declarations
                        against discovery.py results
  runner.py             certify_provider()/certify_all_providers()/
                        write_report(); manifest registry
  manifests/
    __init__.py
    sentry.py            SENTRY_MANIFEST (pilot)
    snowflake.py         SNOWFLAKE_MANIFEST (pilot)
```

No policy engine, no YAML configuration framework, no graph database, no
templating engine, no new CLI library. Standard library (`dataclasses`,
`re`, `pathlib`, `json`) plus the repository's existing Pydantic models
(read via `.model_fields` for schema introspection) — nothing else was
added.

## 4. Maturity semantics (certification meaning)

Audited from `provider_capability_matrix_service.MATURITY_LEVELS`
(`{"planned", "partial", "complete"}`) — not reinterpreted, only given a
certification meaning:

| Maturity | Certification meaning |
|---|---|
| `planned` | Internal groundwork only. Non-connectable, non-public, non-Live. Most gates resolve `not_applicable`/`deferred`; only identity/backend-registration gates are meaningfully evaluated. |
| `partial` | Launched provider — drift + Security Findings required end-to-end. Activity ingestion, incident signals, risk×activity correlations, and demo/case tooling are explicitly NOT required (`deferred` is acceptable only for these named dimensions). |
| `complete` | Only for a provider where the FULL dual-stack capability model is implemented. No dimension may be `deferred`; every dual-stack capability (`security_findings`, `activity_ingestion`, `activity_signals`, `risk_activity_correlations`, `demo_case_reporting`) must be declared supported, and the manifest itself rejects a `complete` manifest with a capability gap at construction time. |

`PARTIAL_ALLOWED_DEFERRED_DIMENSIONS` in `models.py` is the single,
explicit list of dimensions a `partial` provider may defer — every other
dimension deferring blocks overall PASS.

## 5. Certification dimensions

34 stable string IDs live in `models.DIMENSIONS` (never renumbered —
evidence and historical reports reference these), covering identity,
backend/frontend registration, credentials, creation/reconnect
dispatch, sync/worker dispatch, connector contract, record inventory,
diff tracked fields, Change classifier coverage, Security Finding
registry/confidence/pack/coverage/reachability/Finding-vs-Change
parity, sensitive-data controls, capability-matrix/security-coverage/
frontend parity, public/connectable/Live consistency, dependency/env-var
audit, known limitations, test evidence, the four optional dual-stack
dimensions, exhaustive change-classification proof, and the global
provider-expansion-freeze dimension.

## 6. Manifest model

`ProviderCertificationManifest` (frozen dataclass, `models.py`) is
provider-owned DECLARED INTENT. `__post_init__` rejects, at construction
time, every contradiction enumerated in the message-1 task spec:
Live+non-connectable, connectable+non-public, planned+public,
security_findings+zero-rule-IDs (both directions), duplicate record
types/Finding IDs/derived types, a Finding ID with the wrong provider
prefix, a secret-looking credential field not marked sensitive, a
declared-sensitive field absent from `credential_fields`,
Live+no-reconnect, connectable+no-frontend-form, a capability declared
both supported and unsupported, `complete` maturity with a capability
gap, a dependency/env-var declared both allowed/required AND prohibited,
and a `derived_record_types` entry not present in `expected_record_types`.
See `tests/test_provider_certification_models.py` for one test per
contradiction.

## 7. Discovery model

`discovery.py` never trusts the manifest — it re-derives reality:

- **Backend**: imports `sync_service`, `security_coverage_service`,
  `security_rule_registry`/`_confidence`/`_pack`, `security_finding_evaluator`,
  `provider_capability_matrix_service`, `integration_service`,
  `diff_service`, `risk_service`, `app.schemas.integration`, and the
  provider's own `<provider>.py`/`<provider>_schema.py` connector
  modules — then reflects on their real module-level attributes.
- **Frontend**: reads `providers.ts`, the integration-creation
  dispatcher page, `securityRuleCatalog.ts`, and the demo-script
  future-provider queue as plain text, parsed with regex — never
  imported as JS/TS, never executed.
- **Record-type precision fix (found during message 1)**: a naive "any
  uppercase constant whose string value starts with the provider
  prefix" heuristic wrongly counted `ACTION_CATEGORY_SENTRY_APP =
  "sentry_app"` as a Sentry record type. Fixed by requiring the
  constant's OWN NAME to equal its value uppercased (`SENTRY_ORGANIZATION
  = "sentry_organization"` passes; `ACTION_CATEGORY_SENTRY_APP =
  "sentry_app"` does not) — see
  `discovery.discover_schema_record_type_constants` and
  `test_provider_certification_discovery.py::TestRecordTypes::test_sentry_record_types_excludes_action_category_constants`.
- **Classifier-dispatch resolution (found during message 1)**: Sentry's
  `risk_rules/sentry.py` dispatches on raw string literals
  (`record_type == "sentry_organization"`); Snowflake's
  `risk_rules/snowflake.py` dispatches on named constants imported from
  its schema module (`record_type == SNOWFLAKE_ACCOUNT`). Discovery
  handles both by additionally resolving any matched
  `record_type == UPPER_NAME` constant back to its string value via the
  provider's schema module — see
  `discovery.discover_classifier_record_type_dispatch` and
  `test_provider_certification_discovery.py::TestClassifierDispatch::test_snowflake_classifier_resolves_named_constants`.

## 8. Gate model

`gates.py` has one `gate_*` function per dimension. Each takes a
manifest, calls one or more `discovery.py` functions, and returns a
single `CertificationGate`. No arbitrary executable code is ever
persisted in JSON — gates are trusted Python; only their structured
RESULT (status/details/evidence) is serialized. `ALL_PROVIDER_GATE_FUNCS`
is the ordered tuple the runner iterates; `gate_provider_expansion_freeze()`
is called separately and attached to every result since it is a
repository-wide invariant, not a per-provider capability.

## 9. Result / status model

Bounded taxonomy (`models.STATUS_VALUES`): `pass`, `fail`, `warning`,
`not_applicable`, `deferred`, `unknown`. `deferred` is never silently
treated as `pass` — `runner._overall_status()` computes overall PASS
only when every blocking gate passes or is `not_applicable`, no
blocking gate is `unknown`, no blocking gate `fail`s, and any blocking
`deferred` gate is on a dimension the provider's maturity is explicitly
allowed to defer (see §4).

## 10. Evidence model

`CertificationEvidence` is typed and bounded to one of 7
`EVIDENCE_TYPES` (`discovered_symbol`, `test_file`, `test_node_id`,
`report`, `source_grep`, `capability_matrix_entry`,
`manifest_declaration`) — never arbitrary prose alone. Gates attach
evidence pointing at the exact discovered symbol/expected/observed
values that produced their verdict.

## 11. Deterministic JSON output

`CertificationResult.to_json()` sorts gates by `gate_id` and dumps with
`sort_keys=True` — two calls against the same repository state produce
byte-identical output (pinned by
`test_provider_certification_runner.py::TestDeterminism`). Reports live
at `backend/tests/reports/provider_certification/<provider>.json`
(generated by `runner.write_report()`; committed this message for
Sentry and Snowflake).

## 12. Pilot providers

Sentry and Snowflake — the newest, most complete eight-message launch
arcs; they cover REST (Sentry) and SQL-API (Snowflake) authentication
patterns; and they exercise different completeness/false-removal models
(Sentry: organization-wide + per-team + per-project + derived records;
Snowflake: account-wide + per-database + per-role + per-detail-family +
derived records). No third provider was added, per the task's explicit
scope limit.

## 13. Trust boundaries

Certification NEVER: calls an external provider API, mutates an
integration row, reads a customer's encrypted credential or decrypts
one, writes non-report DB state, triggers a sync, instantiates a
connector, or reads a global customer-credential env var
(`SENTRY_AUTH_TOKEN`, `SNOWFLAKE_ACCOUNT`, etc.). Proven by
`test_provider_certification_runner.py::TestNoProductionSideEffects`,
which monkeypatches `httpx.Client.__init__`, `sqlalchemy.orm.Session.__init__`,
`os.environ.get`, both pilot connector `__init__`s, and
`encryption.decrypt_credentials`, then asserts zero calls across a full
`certify_all_providers()` run.

## 14. Limitations (explicit, message-1-critical to state)

- Change-classification coverage is verified STATICALLY (dispatch
  branch exists; every expected record type has an explicit
  `record_type ==` check) but is NOT claimed to exhaustively prove every
  transition — that requires the real `compute_diff()`-pipeline parity
  tests referenced via `evidence_test_files` (see
  `gate_change_classification_exhaustive_proof`, which is `deferred`,
  not `pass`, when no evidence is referenced for a `partial` provider).
- Read-only behavior (allowed HTTP methods / SQL statement allowlists)
  is NOT independently re-verified by a generic mechanism this message
  — the framework consumes each provider's own message-7 reliability
  evidence files rather than attempting one grep pattern that fits both
  a REST connector and a SQL-statement-based connector.
- Only Sentry and Snowflake have manifests. Kubernetes, Okta, and
  Microsoft Entra ID are NOT certified by this framework yet — they
  keep their existing provider-specific QA suites unchanged.
- The frontend discovery functions gracefully return `None`/`not_applicable`
  when the frontend tree isn't mounted in a given execution environment
  — certification does not hard-fail in a backend-only sandbox.

## 15. Migration roadmap (message 2 recommendation)

Recommended next steps, NOT started this message: (1) write manifests
for Kubernetes, Okta, and Microsoft Entra ID and run their existing
provider-depth/reliability test suites as `evidence_test_files`; (2)
add a `Finding-vs-Change parity` gate that statically compares
`security_rule_pack._RULE_META` severities against
`risk_rules.<provider>` classifier output for representative cases,
generalizing the pattern already proven in
`test_sentry_change_parity.py`; (3) only after every launched provider
has a manifest, consider whether provider-specific QA files can be
trimmed in favor of framework-driven evidence — never before message 1's
explicit "do not delete existing tests" boundary is lifted by a future
message.

## 16. Certification status after message 1

| Gate | Result |
|---|---|
| Sentry pilot manifest certifies PASS | PASS |
| Snowflake pilot manifest certifies PASS | PASS |
| Global provider-expansion-freeze gate passes | PASS |
| Model validation (all 16+ contradictions rejected) | PASS |
| Discovery matches real repository state (61 discovery tests) | PASS |
| Gate layer has passing + failing + not-applicable cases for every gate | PASS |
| Negative mutation tests prove gates check reality, not manifests | PASS |
| No network/DB/credential access during certification | PASS |
| Deterministic JSON output | PASS |
| Framework matrix ≥ 140 rows | PASS (212 rows) |
| Full backend test suite has no framework-caused regression | PASS |

## 17. Message 2 — Okta and Entra manifests

`manifests/okta.py` (`OKTA_MANIFEST`) and `manifests/entra.py`
(`ENTRA_MANIFEST`) were added, proving the framework generalizes to two
more authentication/API shapes beyond Sentry's org-token REST and
Snowflake's PAT-based SQL API:

- **Okta** — REST identity provider, `api_token` auth
  (`okta_org_url` + `okta_api_token`, the token marked sensitive). 16
  record types (2 derived: `okta_privileged_identity`,
  `okta_privileged_group`), 30 Security Finding rule IDs — every count
  independently re-derived via discovery, not copied from
  `okta_provider_certification.md` or memory (see
  `test_provider_certification_okta.py::TestOktaDiscoveryIndependentlyConfirmsManifest`).
- **Entra** — Microsoft Graph identity provider, `oauth2_client_credentials`
  auth (`entra_tenant_id` + `entra_client_id` + `entra_client_secret`,
  the secret marked sensitive; tenant/client IDs are GUIDs, not secrets).
  Canonical `provider_id="entra"` confirmed via
  `provider_capability_matrix_service.get_provider_capability("entra")`
  — this repository has no `microsoft_entra_id`/`azure_ad` alias. 19
  record types (3 derived: `entra_privileged_identity`,
  `entra_privileged_group`, `entra_privileged_service_principal`), 45
  Security Finding rule IDs.

Both manifests certify `pass` with the EXISTING gate/discovery code from
message 1 — no discovery-precision bug was found for either provider
(generic discovery already handled Okta's literal `record_type ==`
dispatch and Entra's mixed literal/constant dispatch correctly, matching
the pattern already proven for Sentry/Snowflake respectively).

## 18. Discovery adapter model (message 2)

`adapters.py` adds `ProviderDiscoveryAdapter` — a typed, optionally
registered, per-provider augmentation hook for the rare case where
generic discovery genuinely cannot follow a provider's pattern (dispatch
via a shared registration helper, generated metadata, frontend
indirection). **No pilot provider needs one** — Sentry, Snowflake, Okta,
and Entra all follow the same naming conventions generic discovery
already expects. The mechanism is proven with synthetic adapters in
`test_provider_certification_adapters.py`: `adapt.resolve_set()`
distinguishes agreement, augmentation (adapter is a strict superset —
the union is used), and CONTRADICTION (adapter and generic disagree in
any other way — the generic result is kept as the safe default and the
disagreement is surfaced, never silently resolved by picking a side).
`gate_adapter_consistency` wires this into the per-provider gate set,
resolving `not_applicable` for all four pilots today.

## 19. Cross-manifest global gates (message 2)

`cross_manifest.py` adds five gates that operate over every registered
manifest at once (attached to every provider's result, the same pattern
`gate_provider_expansion_freeze` already established in message 1):
`cross_manifest_identity` (unique provider IDs, no alias/case-variant
collisions — audited against real repository state: this codebase has
no `microsoft_entra_id`/`azure_ad` alias for Entra, so no
alias-normalization mechanism was built, per the explicit
"only if the repository already has real aliases" instruction),
`cross_manifest_capability_consistency` (maturity + dual-stack
capability flags agree with the discovered capability-matrix entry for
every manifest), `cross_manifest_finding_uniqueness` (no Security
Finding rule ID declared by more than one manifest), `cross_manifest_catalog_consistency`
(every manifest agrees with backend sync/coverage lists and frontend
provider/connectable lists), and `cross_manifest_live_freeze` (every
Live-declared manifest absent from both future-provider queues).

## 20. Consolidation performed (message 2)

12 duplicated static parity assertions were removed — 6 from
`test_sentry_security_finding_parity.py` and 6 from
`test_snowflake_security_finding_parity.py` (both files' `TestRegistryParity`
and `TestFullCrossLayerParity` classes, plus the two frontend-catalog
set-equality checks in each `TestFrontendParity` class). Every removed
assertion was a pure module/registry/frontend-catalog SET-EQUALITY check
now proven, against real discovery (not just the manifest reflecting
itself), by `gate_security_finding_registry_parity` — see
`test_provider_certification_consolidation.py` for proof the gate still
fails under the exact drift the removed assertions used to catch, and
that every provider-specific semantic test (confidence values, guard
reasons, pack severities, frontend wording guards, Finding-vs-Change
severity parity) was left untouched. Okta's and Entra's equivalent
legacy duplication was deliberately NOT touched this message — see
`tests/reports/provider_certification_duplication_inventory.md` (80
rows) for the full audit and the message-3 recommendation.

## 21. Certification status after message 2

| Gate | Result |
|---|---|
| Sentry pilot manifest certifies PASS | PASS |
| Snowflake pilot manifest certifies PASS | PASS |
| Okta pilot manifest certifies PASS | PASS |
| Entra pilot manifest certifies PASS | PASS |
| `certify_all_providers()` deterministic ordering (4 providers) | PASS |
| Global provider-expansion-freeze gate passes for all 4 | PASS |
| Cross-manifest global gates (identity/capability/finding/catalog/live-freeze) all PASS | PASS |
| Discovery adapter mechanism proven via synthetic adapters | PASS |
| Consolidation: 12 assertions removed, all proven safe | PASS |
| No network/DB/credential access during certification (4 providers) | PASS |
| Deterministic JSON output (same process, separate process, shuffled registration) | PASS |
| Framework matrix ≥ 220 rows | PASS (336 rows) |
| Duplication inventory ≥ 80 rows | PASS (80 rows) |
| Full backend test suite has no framework-caused regression | PASS |

**FRAMEWORK CERTIFICATION STATUS: PASS.**
