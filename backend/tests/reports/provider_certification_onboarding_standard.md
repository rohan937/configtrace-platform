# Provider Certification — Onboarding Standard

This is the authoritative process for adding a provider certification
manifest. It codifies the pattern used across all eleven certified
providers (Sentry, Snowflake, Okta, Microsoft Entra ID, Kubernetes,
GitHub, GitLab, Cloudflare, Supabase, Firebase, Stripe) and is the
reference to follow for any future provider — subject always to the
provider-expansion freeze (see §20).

## 1. Prerequisites

- Provider expansion must be explicitly unfrozen for THIS provider by a
  separate, explicit roadmap decision — this standard existing is not
  itself such a decision (see §20).
- The provider's connector, schema module, risk-rules module, and (if
  Live) reconnect/creation-validation wiring must already exist and be
  covered by their own provider-specific semantic test suite. This
  framework certifies EXISTING implementations; it does not build them.
- `graphify update .` should be run if the graph predates the commit
  you're certifying against.

## 2. Canonical identity

Derive the exact `provider_id` from code — never assume it matches the
display name, a marketing name, or a package name. Verify it is
identical across every one of these surfaces before writing a single
line of the manifest:

- the manifest you are about to write (this is what you're deriving)
- backend sync-provider list (`discover_backend_sync_provider_ids`)
- backend connectable list / frontend connectable list
- frontend provider list (`providers.ts`)
- capability matrix (`PROVIDER_CAPABILITIES` / `PROVIDER_CAPABILITIES_PARTIAL`)
- security coverage list
- sync dispatch / reconnect dispatch (worker + router)
- future-provider queues (must be ABSENT once launched)

Reject alias drift: if any surface uses a different literal string for
the same provider, that is a real repository inconsistency to flag, not
something to paper over in the manifest.

## 3. Maturity selection

Choose `planned` / `partial` / `complete` based on what is ACTUALLY
implemented, never to make certification pass:

- `planned`: internal groundwork only, non-public/non-connectable/non-Live.
- `partial`: connectable, may lack one or more of the five dual-stack
  capabilities (activity_ingestion, activity_signals,
  risk_activity_correlations, demo_case_reporting) or a completeness
  model — GitLab is the reference case (partial, no reconnect, no
  parity evidence, all honest).
- `complete`: requires ALL FIVE dual-stack capabilities declared
  supported (models.py enforces this) — Cloudflare/Supabase/Firebase/
  Stripe and Sentry/Snowflake/Okta/Entra/Kubernetes/GitHub are the
  reference cases.

## 4. Credential declaration

Run generic discovery FIRST:
`discovery.discover_credential_schema_fields(provider_id)`. If it
returns fields, declare `credential_fields` to match exactly. If it
returns empty but the provider genuinely has credentials (e.g.
Cloudflare's unprefixed `api_token`/`zone_id`, Kubernetes'
`kubeconfig`/`context`), that is a real "original-era naming
convention" case requiring a `ProviderDiscoveryAdapter` with a
`discover_credential_fields` hook — never invent a generic-discovery
special case for one provider.

Mark every secret-looking field (token/key/secret/password/json/
credential) in `sensitive_credential_fields`. Never mark non-secret
identifiers (zone_id, project_ref, account_id) as sensitive.

## 5. Record inventory discovery

Run `discovery.discover_schema_record_type_constants(provider_id)`
BEFORE writing `expected_record_types`. Use the exact discovered set —
never a manually guessed count. Cross-check against
`discover_schema_record_type_identity_constants` to find any
schema-declared-but-unwired constants (Stripe: 11 of 17; GitHub: 6 of
17; Cloudflare: the DNS constant) and explicitly document why each is
excluded in `known_limitations` — "unimplemented" and "dynamically-
valued, can't be represented as a fixed constant" are both legitimate,
different reasons; state which applies.

## 6. Tracked/classifier parity

Confirm `discover_diff_tracked_fields_dict(provider_id)` has no
missing keys for your declared record types, and that
`discover_classifier_record_type_dispatch(provider_id)` (plus any
adapter augmentation) covers every declared type. Cloudflare's
`cloudflare_ruleset` — dispatched from a SECOND risk-rules module via
`risk_service.py`, not the single module the generic scan imports — is
the reference case requiring an adapter for this dimension specifically.

## 7. Completeness model

Declare `completeness_scopes`/`false_removal_scopes` (legacy string
form) and/or typed `completeness_scope_declarations`
(`CompletenessScopeDeclaration`, message 4) ONLY if a real
`_<provider>_removal_suppressed` function exists
(`discovery.discover_removal_suppression_exists`) AND is actually wired
(`discover_removal_suppression_wired` — called beyond its own `def`
site, not dead code). If no such function exists yet, declare both
empty — this is honest and does not block certification (the gate
resolves `warning`, not `fail`). Cloudflare/Supabase/Firebase/Stripe are
the reference case for "honestly empty."

Use `COMPLETENESS_SCOPE_GRANULARITIES` (family, account, organization,
project, repository, group, cluster, namespace, zone, parent_resource,
detail, derived_dependency) — never invent a provider-named granularity.

## 8. False-removal model

If you declare a `suppression_symbol` on a typed
`CompletenessScopeDeclaration`, it must resolve on `diff_service`
(`gate_completeness_scope_declarations` checks this) — a dead or
misspelled symbol name fails certification. Declaring
`parent_record_type` on a scope requires that type to be a real,
declared record type (or derived type). `derived_dependents` must be a
subset of `derived_record_types`.

## 9. Security Finding parity

Run `discovery.discover_registry_rule_ids(provider_id)` and set
`security_finding_rule_ids` to the exact discovered set. Declaring
`security_findings` in `supported_capabilities` requires a non-empty
rule-ID set, and vice versa (models.py enforces both directions).

## 10. Reachability evidence

MANDATORY, at manifest-construction time: every declared Finding rule
ID must be covered by `reachability_evidence` (direct or grouped) or an
explicit `ReachabilityExemption` with a durable, non-empty reason. Each
evidence entry's `test_file` must be a REAL file under `tests/` — the
gate (not construction) checks it exists on disk and that its
`test_selector` (or the whole file, if empty) matches at least
`minimum_test_count` real tests via pure static counting. Never create
a broad exemption merely to force PASS — an exemption is a genuine,
reviewed limitation, not a shortcut.

## 11. Finding-vs-Change evidence

NOT mandatory — a provider with zero `change_parity_evidence` and zero
`change_parity_exceptions` legitimately resolves `deferred`
(non-blocking). Never fabricate complete parity. If you do have direct
Change-severity-transition tests, reference them as evidence; if a
transition is intentionally less severe than the static Finding, use an
explicit `ParityException` with `static_severity`/`transition_severity`
(from the fixed severity enum), a durable `rationale`, and a real
`evidence_test`.

## 12. Frontend parity

Declare `expected_frontend_form` as the exact `.tsx` filename. If the
provider's secret can't be a single-line password input (e.g.
Kubernetes' multi-line `kubeconfig`), a masked `<textarea>` also
satisfies the sensitive-data-controls gate.

## 13. Reconnect

Set `expected_reconnect=True` only if reconnect is genuinely wired —
either a named `reconnect_credentials_<provider>` function
(Supabase/Firebase/Sentry/Snowflake/Okta/Entra/Kubernetes) or the
shared generic dispatcher (GitHub/Cloudflare/Stripe — the "original-
era" pattern). `expected_live=True` requires `expected_reconnect=True`
(models.py enforces this).

## 14. Sensitive-data boundary

Explicitly document, in `known_limitations`, every category of data
the provider does NOT ingest that a reasonable reader might assume it
does — table rows, auth-user records, document/object contents, payment
transactions, webhook payloads, traffic/request analytics. No silent
ambiguity: say what's supported AND what's excluded, in the same place.

## 15. Capability declaration

Use only the five generic capability strings
(`security_findings`, `activity_ingestion`, `activity_signals`,
`risk_activity_correlations`, `demo_case_reporting`) — every concept
audited in message 4 (configuration drift, identity/effective access,
alerting, repositories, database/network/storage/application security,
event/incident ingestion) already maps onto these five plus
`known_limitations`/completeness declarations. Do not invent a new
capability ID without first proving none of the existing five (plus
`known_limitations`) can express it.

## 16. Known limitations

Every manifest must declare at least one. If you can't think of any,
you haven't audited the provider closely enough.

## 17. Deterministic reports

After the manifest constructs and all gates resolve, regenerate
`tests/reports/provider_certification/<provider>.json` and
`summary.json` via `runner.write_report()` /
`runner.write_summary_report()`. Verify byte-identical output across
same-process, separate-process, and reversed-registration-order runs.

## 18. Required tests

At minimum, one `test_provider_certification_<provider>.py` with:
manifest-shape assertions, discovery-vs-manifest parity assertions
(independently re-deriving every manifest claim from real source — not
merely trusting the manifest), full certification
(`overall_status == "pass"`), and at least 2 negative-mutation tests
for the provider's most distinctive discovery pattern.

## 19. Approval criteria

`certify_provider(provider_id).overall_status == "pass"`, with:

- no blocking gate `fail`
- no blocking gate `unknown`
- every `deferred` blocking gate permitted by the declared maturity
- no capability contradiction (§13-14 of message 4's task spec)
- no completeness contradiction (§12 of message 4's task spec)
- no future-queue contradiction

## 20. Prohibition on provider expansion while freeze is active

This standard is a PROCESS document. It does not, by itself, authorize
adding a new provider. `gate_provider_expansion_freeze` remains a
blocking gate on every certification result, and the future-provider
queues remain the single source of truth for what MAY be added next —
only an explicit roadmap decision (outside this framework) unfreezes
expansion for a specific named provider. Following this checklist for a
provider that hasn't been explicitly greenlit is out of scope, even if
every other step would otherwise succeed.

## 21. Repository-wide manifest coverage requirement (message 5)

Every provider `discover_launched_provider_ids()` finds MUST have
either a registered certification manifest or an explicit entry in
`migration_allowlist.MIGRATION_ALLOWLIST` — `gate_provider_manifest_coverage`
enforces this as a blocking, repository-wide gate attached to every
certification result. A provider that is neither certified nor
allowlisted is a silent gap this gate exists specifically to prevent.

## 22. Migration allowlist rules

`UncertifiedProviderMigrationEntry` requires a non-empty `reason` and a
`planned_framework_message >= 1` referencing a future message number
(not a calendar date, matching this project's message-numbered
convention). Duplicate `provider_id` entries are rejected at import
time. An entry for a provider `discover_launched_provider_ids()` does
not recognize as launched is rejected at import time. A provider that
already has a registered manifest MUST NOT also appear in the
allowlist — `gate_provider_manifest_coverage` fails this as
`certified_and_allowlisted`. Once a provider is certified, its
allowlist entry must be removed in the same message.

## 23. Stale-inventory / Finding-set / credential-drift detection

`gate_record_inventory`, `gate_security_finding_registry_parity`,
`gate_credential_schema`, and `gate_sensitive_data_controls` already
detect drift between a manifest's declarations and live repository
discovery (missing → `fail`, undeclared extra → `warning`). Message 5
adds regression coverage (`test_provider_certification_staleness.py`)
proving each of these genuinely catches drift — via monkeypatched
discovery, not manifest mutation, since expected_record_types and
security_finding_rule_ids are cross-referenced by other typed
declarations whose own validation would otherwise fire first.

## 24. Capability evidence declarations

A `supported_capabilities` entry MAY optionally carry a
`CapabilityEvidenceDeclaration` naming the real record types, Finding
rule IDs, and test files that back the claim. `gate_capability_evidence`
is `not_applicable` (non-blocking) when a manifest declares none, and
otherwise fails if any declared `evidence_tests` file is missing from
disk. Evidence is optional strengthening, not a requirement for every
capability — a capability may remain supported without a
`CapabilityEvidenceDeclaration`.

## 25. Retirement / removal process

Should a certified provider ever be removed from the repository
(connector deleted, capability-matrix entry removed), its manifest
must be unregistered in the same change and its provider_id removed
from `PILOT_PROVIDERS` — leaving a stale manifest for a provider that
no longer exists would trip `gate_provider_manifest_coverage`'s orphan
check (`manifest_id_set - launched - planned_ids`).

## 26. Manifest update requirements when record types or Findings change

Any change to a provider's schema record-type constants or Finding
rule IDs (adding, removing, or renaming) MUST be accompanied by the
matching manifest update in the same change — `gate_record_inventory`
and `gate_security_finding_registry_parity` will otherwise report
drift on the very next certification run.

## 32. Every launched provider requires a manifest (message 6)

As of message 6, 100% of launched providers are certified — there is
no longer any launched provider without a manifest. Any newly LAUNCHED
provider (an already-existing repository concept: backend sync +
frontend connectable + capability-matrix registered, per
`discover_launched_provider_ids()`) MUST receive a certification
manifest in the same message it becomes launched, or be added to
`MIGRATION_ALLOWLIST` with a concrete `reason` and
`planned_framework_message` as a temporary, tracked exception — never
silently.

## 33. No migration allowlist for ordinary launched providers

The migration allowlist exists for genuinely temporary, controlled
migration windows only — not as a permanent parking spot. As of
message 6 it is empty and MUST remain empty for any provider that is
an ordinary launched sync provider with no unusual circumstance
justifying deferral. `gate_provider_manifest_coverage` fails if a
certified provider reappears in the allowlist, and
`test_provider_certification_migration_allowlist.py` proves the
mechanism's validation rules (duplicate/unknown/certified-provider
rejection, required reason, required planned milestone) independent
of whether the real allowlist currently holds any entries.

## 34. Certification failure blocks provider metadata drift

Message 6 confirms this is now framework-wide, not aspirational:
record/Finding changes must update the manifest in the SAME pull
request that makes the change — `gate_record_inventory` and
`gate_security_finding_registry_parity` will report drift (`fail` for
missing, `warning` for undeclared extras) on the very next
certification run otherwise, and `certify_provider()` never silently
passes a provider whose manifest has drifted from real discovery.
Provider-specific semantic tests (connector normalization, pagination/
retry, partial-sync/false-removal, Change-classification, Finding
reachability, reconnect-mismatch) remain mandatory and are never
superseded by the certification framework, which only proves static
repository WIRING.

## 35. CI enforcement pull-request checklist (message 7)

Message 7 wires this framework into CI (see
`.github/workflows/provider-certification.yml` and
`backend/app/provider_certification/README.md`). Before opening or
updating any pull request that touches a provider-affecting or shared
certification-relevant file, run:

1. **Impact analysis** — `python -m app.provider_certification.cli affected --base <base-sha> --head <head-sha>`
   to see which providers are directly affected and whether the diff
   forces full-catalog certification.
2. **Focused or full certification** — `certify-provider <id>` for each
   directly affected provider, or `certify-all` if impact analysis (or
   CI) says full-catalog is required. Never skip this because "it's a
   small change."
3. **Update the manifest** the moment a provider's record types,
   Finding IDs, credential fields, capabilities, completeness model, or
   launch state (public/connectable/live/reconnect) change — in the
   SAME change, never a follow-up.
4. **Regenerate reports** — `python -m app.provider_certification.cli generate-reports`
   — and commit the resulting diff. `check-reports` is what CI runs to
   catch a forgotten regeneration; running `generate-reports` yourself
   first avoids a CI round-trip.
5. **Run provider-specific semantic tests** for anything touched (see
   §34) — the certification framework only proves static wiring, never
   a substitute for real connector/Finding/diff tests.
6. **Never weaken a gate to make CI pass.** A failing gate means the
   manifest, the implementation, or both are out of sync with reality —
   fix the actual drift, don't loosen the check.

CI (`provider-certification-impact` → `provider-certification` →
`provider-certification-reports`) re-runs impact analysis, certification,
and report-drift checking independently of local runs — it is the
source of truth, not a formality.
