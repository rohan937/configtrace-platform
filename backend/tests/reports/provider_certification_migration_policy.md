# Provider Certification — Migration & Ownership Policy

Status: message 3 of N. This document is the durable reference for
**who owns what** across the provider-certification framework and the
per-provider semantic test suites it does *not* replace, plus the rules
governing when the framework may absorb more of a provider's assertions.

## 1. Framework-owned static invariants

These are checked identically for every provider via `gates.py` /
`cross_manifest.py`, driven entirely by a provider's declarative
manifest (`manifests/<provider>.py`) cross-checked against `discovery.py`.
No provider-specific code lives here.

- Record-type / Finding-ID / capability declaration parity (manifest vs.
  discovered schema, registry, capability matrix).
- Credential-field schema and sensitive-field masking (backend + frontend).
- Public / connectable / Live / reconnect-required consistency.
- Connector class resolution and constructor contract.
- Frontend form existence and dispatcher wiring.
- Dependency / env-var allow/prohibit lists.
- Change-classifier coverage (does every declared record type reach a
  classifier dispatch, direct or grouped).
- False-removal / completeness-scope declaration presence.
- **Security Finding reachability** (message 3): every declared Finding
  rule ID has direct/grouped evidence or an explicit exemption.
- **Finding-vs-Change parity** (message 3): every declared Finding rule
  ID has parity evidence or an explicit, rationale-backed severity
  exception — or the gate legitimately defers (non-blocking) if the
  provider has declared neither.
- Cross-manifest invariants: unique provider IDs, no Finding-ID
  collisions, maturity/capability consistency, future-queue exclusion
  for already-launched providers, schema-version compatibility.

## 2. Provider-owned semantic invariants (never framework-owned)

These require running the provider's own connector/normalizer/risk-rule
code against realistic (mocked-API, not handcrafted-in-test) data, and
must remain in each provider's own test files:

- Pagination, retry, and rate-limit handling.
- Field normalization correctness (tri-state booleans, unknown/absent
  values, timestamp formats, nested-object flattening).
- Partial-sync and false-removal *suppression logic* itself (the static
  gate only checks that a suppression function *exists* — it does not
  re-derive or replay its branching logic).
- Reconnect credential-mismatch protection (tenant/account/org identity
  checks).
- Change-severity classification correctness for each transition.
- Effective-access / privilege-derivation graph traversal.
- Scale and N+1-query reliability.
- Sensitive-payload exclusion at the connector layer (not just "is the
  frontend field masked").

**The framework must never delete these.** A provider passing all
framework gates says nothing about whether its own semantic tests are
still present or passing — they are a separate, mandatory axis.

## 3. Evidence requirements (message 3)

- `reachability_evidence` / `reachability_exemptions`: MANDATORY full
  coverage. Every `security_finding_rule_ids` entry must resolve via
  evidence or an exemption at manifest-construction time — a
  manifest that leaves a rule ID uncovered fails to construct at all,
  not merely fails a gate.
- `change_parity_evidence` / `change_parity_exceptions`: NOT mandatory
  at construction time. A provider with declared Finding rule IDs but
  no parity evidence/exceptions is legitimate — the
  `finding_change_parity` gate resolves `deferred` (non-blocking), never
  a fabricated `pass`. This reflects that parity work may reasonably
  lag reachability work during a provider's certification rollout.
- Every evidence entry's `test_file` must live under `tests/`, must
  exist on disk (checked at gate time, since construction-time
  validation cannot see the filesystem), and must independently satisfy
  its declared `minimum_test_count` via pure static counting
  (`gates._count_matching_tests`) — never a pytest/subprocess
  invocation.
- Evidence declaring a `provider_id` different from the manifest's own
  is rejected outright (no shared-evidence allowance exists yet; a
  future message may add one explicitly, never implicitly).

## 4. Deletion criteria

A duplicated static assertion (see
`provider_certification_duplication_inventory.md`) may be removed from
a provider's own legacy test file **only if all of the following hold**:

1. It is a pure structural/registry/catalog set-equality check with a
   1:1 framework gate already covering the identical invariant.
2. Removing it does not reduce the provider's own semantic test count
   below its pre-message-3 baseline for anything except that one
   duplicated class.
3. A corresponding framework **negative-mutation test** exists proving
   the framework gate actually fails when the invariant is violated
   (never assume the framework gate as ground truth without proving it
   can fail).
4. The removal is recorded in this message's report
   (`provider_certification_message3.md`) with a before/after test count.

Semantic tests (connector fixtures, normalizer tests, reachability
tests, severity/parity tests, removal-suppression tests, retry tests,
scale tests, sensitive-payload tests) are **never** eligible for
deletion under this policy, regardless of any apparent overlap with a
framework gate.

## 5. Deprecation lifecycle

1. **Candidate**: identified in the duplication inventory as
   `remove-now` eligible per §4.
2. **Consolidated**: removed from the provider file, replaced with a
   one-line `NOTE` comment pointing at the framework gate ID that now
   owns the invariant.
3. **Guarded**: a framework negative-mutation test exists that fails
   when the invariant breaks, so the coverage loss is provably zero.
4. **Retired**: once every pilot + all onboarded providers have reached
   step 2 for a given duplicate-assertion class, the class is removed
   from the "candidate" pool of the duplication inventory entirely (not
   yet reached for any class as of message 3 — Kubernetes/GitHub/GitLab
   are newly onboarded and intentionally NOT touched this message; see
   `provider_certification_message3.md` for the rationale).

## 6. Negative-mutation requirement

Every framework gate that could plausibly mask a real regression (i.e.
every blocking gate) must have at least one test that mutates the
discovered/declared state to a known-bad value and asserts the gate
produces `fail` (or `warning` where a soft failure is the documented
correct behavior). This is enforced ad hoc per gate today (see the
`TestXNegativeMutations` classes across `test_provider_certification_*`);
it is not yet automatically verified that *every* gate has one — a
candidate item for a future message, not undertaken here since it would
require touching gate-coverage tooling.

## 7. Rollback policy

If a framework gate produces a false positive (fails a genuinely correct
provider state) after being merged:

1. The gate is reverted to its prior behavior in a follow-up commit,
   never patched with a provider-specific carve-out embedded in the
   gate function itself.
2. The provider manifest is left declaring its true, intended state
   (the manifest is not adjusted to work around a broken gate).
3. If the false positive stemmed from an incorrect blanket assumption
   (as happened this message with `PROVIDER_CAPABILITIES_PARTIAL`
   membership), the fix is generalized across all providers, not
   special-cased for the one that surfaced it.

## 8. Provider onboarding checklist

For a new provider to be added to `PILOT_PROVIDERS` / registered via
`_ensure_manifests_loaded()`:

1. Confirm the provider's canonical `provider_id` from code (dispatch
   tables, capability matrix keys, connector class name) — never assume
   it matches the display name or PyPI/CLI naming.
2. Run generic discovery first (`discovery.py`'s existing generic
   functions) before writing any provider-specific
   `ProviderDiscoveryAdapter`. An adapter is justified only when
   generic discovery genuinely cannot resolve a real, verified pattern
   (see `adapters.py`'s Kubernetes adapter for the credential-field and
   grouped-classifier-dispatch precedent).
3. Write the manifest (`manifests/<provider>.py`) declaring only
   verified-true state — a manifest field must never be set to "make
   the gate pass" if the underlying repository state doesn't actually
   support it (e.g. GitLab honestly declares `expected_live=False`,
   `expected_reconnect=False`, empty `change_parity_evidence`).
4. Populate `reachability_evidence`/`reachability_exemptions` for every
   declared Finding rule ID (mandatory) before the manifest will even
   construct.
5. Populate `change_parity_evidence`/`change_parity_exceptions` if the
   provider has them; otherwise leave both empty and accept the
   `deferred` gate result — do not fabricate evidence.
6. Add the provider to `PILOT_PROVIDERS` and `_ensure_manifests_loaded()`
   in `runner.py`.
7. Write a `test_provider_certification_<provider>.py` file with, at
   minimum: manifest-shape assertions, discovery-vs-manifest parity
   assertions (proving the framework independently re-derives the
   manifest's claims from real source, not merely trusting it), full
   certification (`overall_status == "pass"`), and negative-mutation
   tests for at least the provider's most distinctive discovery pattern.
8. Never delete or weaken that provider's own semantic test files as
   part of onboarding — onboarding only ADDS the certification layer.
9. Regenerate the provider's JSON report and `summary.json`.
10. Update the duplication inventory and framework matrix with the new
    provider's rows.

## 9. Message-4 additions: completeness/capability/evidence-quality migration

### 9.1 Manifest onboarding procedure (formalized)

Superseded by the dedicated `provider_certification_onboarding_standard.md`
document, which is now the single authoritative process reference. This
migration-policy document retains §1-8 as the historical framework-owned
vs. provider-owned invariant record; the onboarding STANDARD document is
the step-by-step checklist to actually follow.

### 9.2 Completeness declaration migration

The legacy free-form `completeness_scopes`/`false_removal_scopes` string
tuples are NOT deprecated or removed — they remain the primary,
lightweight declaration surface, and all eleven manifests still use
them. The new typed `completeness_scope_declarations` field
(`CompletenessScopeDeclaration`) is strictly additive: a provider MAY
use it for detail the string form can't express (a specific
`suppression_symbol`, a `parent_record_type`, `derived_dependents`),
but is never required to. Migrating an existing manifest from the
string form to the typed form is optional and may be done incrementally,
scope by scope, with no schema-version implication (see §9.5).

### 9.3 Capability declaration migration

No migration needed. The five-string capability vocabulary
(`security_findings`, `activity_ingestion`, `activity_signals`,
`risk_activity_correlations`, `demo_case_reporting`) established in
message 1 was audited in message 4 against a much larger candidate list
(configuration_drift, identity_access, effective_access, alerting,
ownership_routing, repositories, integrations, database_security,
network_security, storage_security, application_security,
event_ingestion, incident_ingestion) and found sufficient for all
eleven real providers — every one of those concepts already maps onto
the existing five plus a manifest's `known_limitations`. No manifest
needs to change its capability declarations because of this audit.

### 9.4 Evidence-quality requirements

`FindingReachabilityEvidence`/`FindingChangeParityEvidence` gained a
`quality` field (message 4): `direct`, `grouped`, or `static_only`
(validated against a fixed enum; `deferred` is deliberately excluded —
it describes the absence of evidence, not a property evidence itself
can carry). Existing evidence entries default to `quality="direct"`,
which is accurate for every evidence entry declared by all eleven
providers as of this message — no existing entry needed reclassifying.
A future provider whose evidence only proves predicates evaluate
correctly against HANDCRAFTED records (not real connector-shaped ones)
should declare `quality="static_only"` and pair it with a
`ReachabilityExemption`, never leave it as `direct`.

### 9.5 Schema-version migration

Message 4 assessed whether the new `completeness_scope_declarations`
field and the `quality` field on evidence types constitute a
"meaningful" schema change requiring `SCHEMA_VERSION = 2`. Decision:
**no bump**. Both additions are purely additive dataclass fields with
safe defaults (`completeness_scope_declarations=()`,
`quality="direct"`) — every one of the seven pre-existing manifests
constructs and certifies identically with or without referencing the
new fields, and their persisted JSON reports simply gain new keys
(`completeness_scope_declarations: []`, `quality: "direct"` on each
evidence entry) rather than losing or reinterpreting any existing key.
This is the textbook "cosmetic/additive, don't bump" case the original
message-3 schema-version guidance anticipated. If a FUTURE change ever
removes a field, changes a field's meaning, or makes a previously
optional field required, THAT is when `SCHEMA_VERSION` must become 2,
with mixed-schema rejection and full seven-manifest (now
eleven-manifest) migration as described in the original §21 guidance
this policy inherits from message 3's task spec.

### 9.6 When an adapter is permitted

Unchanged from the Kubernetes/GitHub/GitLab precedent (message 3),
reaffirmed by message 4's Cloudflare case: an adapter is permitted ONLY
when generic discovery, run first and confirmed insufficient, cannot
resolve a genuinely different, verified architectural pattern —
unprefixed credential fields (Kubernetes, Cloudflare), grouped
classifier dispatch (Kubernetes), or classifier logic split across two
risk-rules modules the generic single-module scan can't see
(Cloudflare's `cloudflare_ruleset` route through
`risk_rules/cloudflare_dns.py`). An adapter must never be added merely
to make a gate pass without confirming the underlying pattern is real.

### 9.7 When legacy static assertions may be removed

Unchanged from message 2/3 policy (§4 above): only pure static
registry/catalog/set-equality duplication with a 1:1 framework gate
already covering it, never in the same milestone a provider is
onboarded, always paired with a framework negative-mutation test, and
capped at a conservative per-message budget (message 4: at most 20
additional assertions, actually removed: 4, from Kubernetes'
`test_kubernetes_security_rule_parity.py` — an already-certified
provider, per the explicit "prefer existing certified providers"
instruction, not one of the four newly onboarded this message. Message
5: at most 24 additional assertions, actually removed: 2 —
`test_okta_in_connectable_providers_list` /
`test_entra_in_connectable_providers_list`, each an exact duplicate of
`gate_security_coverage_parity`'s `security_coverage_service.PROVIDERS`
membership check, from Okta/Entra — already-certified providers, not
the six newly onboarded this message. The sibling
`PROVIDER_SURFACES`-membership assertions were deliberately kept since
no gate currently proves that distinct invariant.)

## 10. Repository-wide adoption tracking (message 5)

`runner.adoption_report()` / `write_adoption_report()` produce a
deterministic, timestamp-free JSON snapshot
(`tests/reports/provider_certification_adoption.json`) of
launched-vs-certified-vs-allowlisted-vs-orphan provider-ID sets and a
coverage percentage. This is the authoritative place to check overall
framework adoption without re-deriving it from individual manifests.

## 11. Migration allowlist exit criteria

A provider leaves `MIGRATION_ALLOWLIST` the moment it receives a
registered certification manifest — `gate_provider_manifest_coverage`
actively fails (`certified_and_allowlisted`) if a certified provider's
allowlist entry is not removed in the same change. There is no grace
period; the allowlist and the manifest registry are mutually
exclusive for a given `provider_id`.

## 12. Stale-manifest failure policy

A manifest whose `expected_record_types` or `security_finding_rule_ids`
drifts from live discovery is not silently tolerated: missing entries
`fail` (`gate_record_inventory` / `gate_security_finding_registry_parity`),
undeclared extras `warning` (never silently `pass`). A credential field
the manifest still declares but the backend schema no longer has
`fail`s `gate_credential_schema`; a new backend credential field absent
from the manifest `warning`s it, surfacing the drift without blocking
an otherwise-passing provider.

## 13. Capability-evidence migration

`CapabilityEvidenceDeclaration` is additive and optional — providers
certified before message 5 are not required to retroactively add
evidence declarations for already-declared capabilities. New manifests
onboarded from message 5 onward are encouraged, not required, to
declare evidence for `security_findings` at minimum, following the
AWS/Datadog precedent set this message.

## 14. When provider certification becomes required for PR merge

Not yet — this remains a voluntary, additive framework as of message 5.
No CI gate currently blocks a PR on `certify_provider()` results. A
future message may propose wiring this framework into required CI
checks; that decision is explicitly out of scope for message 5.

## 15. Preserving semantic provider tests

Nothing in this message's staleness-detection or capability-evidence
work touches a certified provider's own semantic connector tests
(normalization, pagination/retry, partial-sync/false-removal,
Change-classification, Finding reachability, reconnect-mismatch) — the
framework verifies static repository WIRING only, and every
consolidation this message (§9.7) was scoped to pure registry/catalog
set-equality duplication with a verified 1:1 framework-gate
equivalent, never a semantic behavioral test.

## 16. 100% adoption reached — allowlist exit is complete (message 6)

The migration allowlist held exactly 9 entries after message 5, all
for genuinely launched-but-uncertified providers. Message 6 certified
all 9 (Auth0, Azure, Clerk, Google Cloud, Linear, SendGrid, Shopify,
Terraform Cloud, Twilio) and removed every one of their entries — the
allowlist is now the empty tuple `()`. Repository-wide adoption
coverage is exactly 100.0%: every launched provider has a
certification manifest, with zero exceptions. This is a genuine
milestone, not a target adjusted to force a PASS — the underlying
`gate_provider_manifest_coverage` gate was not weakened to reach it;
all 9 new providers independently passed every blocking gate on their
own merits (see `provider_certification_message6.md`).

## 17. Ordinary launched providers may never remain allowlisted

Going forward, the allowlist is reserved for genuinely temporary,
controlled migration windows — e.g. a provider that becomes launched
mid-message, with certification explicitly deferred one message with a
concrete reason and milestone. It must never become a permanent
parking spot for provider debt. `gate_provider_manifest_coverage`
actively fails if a certified provider reappears in the allowlist,
and `discover_launched_provider_ids()` gates entry eligibility — an
allowlist entry for a provider that isn't genuinely launched is
rejected at import time.

## 18. Runtime defect fixed during message 6 certification

Terraform Cloud's `creation_validation` gate exposed a genuine,
pre-existing production defect: `routers/integrations.py`'s
`_build_credentials()` had no dispatch branch for
`provider == "terraform_cloud"` at all, meaning credentials were
silently dropped (`{}`) on integration creation. This was fixed by
adding the missing branch, mirroring the existing GitLab
optional-base-URL pattern — the one runtime change this message made,
justified exclusively by a certification-uncovered genuine defect, not
by any attempt to force a gate to pass through means other than fixing
the underlying gap.
