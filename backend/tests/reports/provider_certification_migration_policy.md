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
