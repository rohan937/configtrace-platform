# Provider Certification Framework — Message 4

## 1. Objective

Expand the Provider Certification Framework (messages 1-3, covering
Sentry/Snowflake/Okta/Entra/Kubernetes/GitHub/GitLab) to four new pilot
providers — **Cloudflare, Supabase, Firebase, Stripe** — formalize the
provider-onboarding standard, and strengthen completeness, capability,
and evidence normalization across all eleven providers.

## 2. Graphify results and freshness

All four queries succeeded. The graph was stale (built from message-2
commit `937d2f77`; current HEAD was `9fe1c87`, message 3's commit) —
`graphify update .` was run and rebuilt the graph (45408 nodes, 105313
edges, 1728 communities) before rerunning the queries. Direct reads and
tests remained authoritative throughout, per instruction. The rebuilt
graph confirmed Cloudflare/Supabase/Firebase/Stripe are pre-existing,
fully-implemented, launched providers (connectors, schemas, risk-rules
modules, frontend forms, and many prior milestone test files already
exist) — this message only writes their certification manifests,
exactly like Okta/Entra (message 2) and Kubernetes/GitHub/GitLab
(message 3).

## 3. Cloudflare manifest summary

8 record types (`CLOUDFLARE_DNS_RECORD` is declared but never assigned
— DNS records use the raw DNS RR type as their dynamic `record_type`
value instead), 12 Finding IDs, unprefixed `api_token`/`zone_id`
credentials, zone-scoped only (no account-level family), `maturity="complete"`,
Live/connectable/reconnect (via the shared generic dispatcher), honestly
empty completeness declarations (no suppression function exists),
documented boundary against traffic/request analytics ingestion.

## 4. Supabase manifest summary

10 record types, 10 Finding IDs, prefixed `supabase_access_token`/
`supabase_project_ref` credentials, `maturity="complete"`, reconnect via
a named function, project-scoped configuration metadata only —
documented boundary against table-row and auth-user data ingestion.

## 5. Firebase manifest summary

13 record types, 8 Finding IDs, single `firebase_service_account_json`
credential, `maturity="complete"`, reconnect via a named function,
project/service configuration and security-rule TEXT only — documented
boundary against Firestore document, Storage object, auth-user record,
and function-source-code ingestion.

## 6. Stripe manifest summary

6 real record types (11 of 17 schema-declared constants are genuinely
unimplemented — confirmed by grep, not a discovery gap), 8 Finding IDs,
single `stripe_api_key` credential, `maturity="complete"`, reconnect via
the shared generic dispatcher (not a named function) — documented
boundary against payment-transaction, customer-data, and webhook-
payload ingestion.

## 7. Generic discovery results before adapters

Run first, for all four, before any manifest was written:

| Provider | Discovered record types | Classifier coverage | Credential fields | Reconnect | Capability-matrix state |
|---|---|---|---|---|---|
| Cloudflare | 8/9 wired (DNS excluded) | 7/8 direct (ruleset missing) | 0 discovered (unprefixed) | generic dispatch | complete, in `PROVIDER_CAPABILITIES` |
| Supabase | 10/10 wired | 10/10 direct | 2/2 discovered | named function | complete, in `PROVIDER_CAPABILITIES` |
| Firebase | 13/13 wired | 13/13 direct | 1/1 discovered | named function | complete, in `PROVIDER_CAPABILITIES` |
| Stripe | 6/17 wired (11 unimplemented) | 17/17 direct (classifier is aspirational for the unwired 11) | 1/1 discovered | generic dispatch | complete, in `PROVIDER_CAPABILITIES` |

Every discrepancy was classified:

- Cloudflare's DNS constant: **discovery limitation** — the connector's
  architecture uses a dynamically-valued `record_type` for DNS, which
  static single-constant discovery cannot represent. Documented in
  `known_limitations`, not forced into `expected_record_types`.
- Cloudflare's credential fields (0 discovered): **provider-specific
  architecture requiring adapter** — unprefixed original-era naming.
- Cloudflare's `cloudflare_ruleset` classifier gap: **provider-specific
  architecture requiring adapter** — dispatch is split across a second
  risk-rules module (`risk_rules/cloudflare_dns.py`) the generic
  single-module scan can't see; confirmed real via `risk_service.py`.
- Stripe's 11 unwired record-type constants: **real provider defect...
  no** — re-classified after direct grep as **obsolete/aspirational
  schema declarations, genuinely unimplemented on both the connector
  and (functionally) the classifier side** — not a bug to fix, a fact
  to document.
- Supabase/Firebase: no discrepancies — generic discovery fully
  sufficient.

## 8. Adapters added and justification

One new adapter: `_CLOUDFLARE_ADAPTER` (in `manifests/cloudflare.py`),
providing `discover_credential_fields` (resolves `api_token`/`zone_id`)
and `discover_classifier_record_types` (adds the `cloudflare_ruleset`
route confirmed real via `risk_service.py`'s source). No adapter was
added for Supabase, Firebase, or Stripe — generic discovery was
confirmed sufficient for all three before writing their manifests, per
the "run generic discovery first, don't add adapters prematurely"
instruction.

## 9. Completeness taxonomy

New typed `CompletenessScopeDeclaration` (scope_id, record_types,
granularity, parent_record_type, status_field, suppression_symbol,
derived_dependents, note) and `COMPLETENESS_SCOPE_GRANULARITIES` (12
generic values: family, account, organization, project, repository,
group, cluster, namespace, zone, parent_resource, detail,
derived_dependency — no provider names encoded). Purely additive to the
manifest — the legacy `completeness_scopes`/`false_removal_scopes`
string tuples are unchanged and still primary. Construction-time
validation rejects unknown record/parent/derived types and duplicate
scope IDs; a new gate (`gate_completeness_scope_declarations`) checks
`suppression_symbol` discoverability at certification time.

## 10. False-removal discovery strengthening

`discover_removal_suppression_wired` counts symbol occurrences in
`diff_service`'s source: >1 proves a call site exists beyond the `def`
line (not dead code). Confirmed wired for all 5 providers with a
suppression function (Sentry, Snowflake, Okta, Entra, Kubernetes).
`gate_false_removal_protection` now resolves three ways: `pass`
(wired), `warning` (exists but not provably wired), `fail` (doesn't
exist).

## 11. Capability taxonomy

Audited the existing 5-string vocabulary against 13 candidate IDs
suggested by the task spec. Finding: all 13 concepts already map onto
the existing 5 plus `known_limitations`. No new capability IDs were
introduced — see `test_provider_certification_capabilities.py`.

## 12. Supported/unsupported boundaries

Every one of the 4 new manifests explicitly documents, in
`known_limitations`, what it does NOT ingest (Cloudflare: traffic
analytics; Supabase: table rows/auth-user data; Firebase: document/
object/user data; Stripe: payment transactions/customer data/webhook
payloads) alongside what it does support.

## 13. Schema-version decision

**Not bumped.** Both message-4 additions
(`completeness_scope_declarations`, evidence `quality`) are purely
additive dataclass fields with safe defaults — every existing manifest
constructs and certifies identically whether or not it references
them. See `provider_certification_migration_policy.md` §9.5 for the
full reasoning.

## 14. All eleven certification results

All eleven resolve `overall_status == "pass"`: sentry, snowflake, okta,
entra, kubernetes, github, gitlab, cloudflare, supabase, firebase,
stripe.

## 15. Record/Finding counts

| Provider | Records | Findings |
|---|---|---|
| Cloudflare | 8 | 12 |
| Supabase | 10 | 10 |
| Firebase | 13 | 8 |
| Stripe | 6 | 8 |

## 16. Reachability coverage

100% mandatory coverage for all four new providers (direct evidence,
`quality="direct"`), backed by real existing test files
(`test_milestone60_4_3_cloudflare_rules.py`,
`test_milestone71a_supabase_security_provider_foundation.py`,
`test_milestone72a_firebase_security_provider_foundation.py`,
`test_milestone73a_stripe_security_provider_foundation.py`).

## 17. Parity coverage and exceptions

All four declare direct `change_parity_evidence` (not deferred),
backed by real existing change-classification-QA test files. No
`ParityException` was needed for any of the four — none of them has a
transition intentionally less severe than its static Finding severity.

## 18. Deterministic reports

All eleven providers' JSON reports plus `summary.json` regenerated via
`runner.write_report()`/`write_summary_report()`. Verified byte-
identical across same-process and reversed-registration-order runs (the
existing `test_provider_certification_reports.py` determinism suite
covers this and still passes unmodified in behavior).

## 19. Onboarding-standard summary

`provider_certification_onboarding_standard.md` created — 20 sections
(prerequisites through the provider-expansion-freeze prohibition),
codifying the exact pattern used across all eleven certified providers.
Pinned by `test_provider_certification_onboarding.py` (section
presence, order, and that the standard does not itself authorize
expansion).

## 20. Migration-policy updates

`provider_certification_migration_policy.md` §9 added: manifest
onboarding procedure (now delegated to the dedicated standard doc),
completeness-declaration migration (optional, additive), capability-
declaration migration (none needed), evidence-quality requirements,
the schema-version decision, when an adapter is permitted, and when
legacy static assertions may be removed.

## 21. Duplication inventory

Expanded from 140 to 220 rows (minimum met exactly): rows 141-220 cover
Cloudflare/Supabase/Firebase/Stripe across the same 20 categories,
marked `Defer to message 5` per the onboarding-milestone rule.

## 22. Assertions removed

4, from Kubernetes' own `test_kubernetes_security_rule_parity.py`
(`TestRegistryParity`'s 2 module-keys-vs-registry checks, plus 2 more
from `TestFrontendParity`/`TestFullCrossLayerParity`'s set-equality/
all-layers-identical checks) — an already-certified provider, per the
explicit "prefer existing certified providers, not the four being
onboarded" instruction. Running framework-wide consolidation total: 28.

## 23. Assertions retained

Every provider-owned semantic test file for all eleven providers was
left untouched: API normalization, retry/pagination, false-removal
scenarios, reconnect mismatch, Change severities, Finding predicates,
connector reachability, secret redaction, scale/call-count tests.

## 24. Negative mutation coverage

New negative-mutation tests cover: Cloudflare's ruleset classifier
route removed, Cloudflare's credential adapter removed, dead/unwired
`suppression_symbol` (multiple scopes), `gate_false_removal_protection`'s
three-way status (exists-but-not-wired vs. wired vs. absent), invalid
evidence `quality` values (both reachability and parity), Stripe's
reconnect-dispatcher-branch removal, Stripe's record-inventory gaining
an unexpected type, Firebase's registry losing a Finding ID, Firebase's
parity-evidence file going missing, plus the message-3-precedent
negative mutations retained unmodified.

## 25. No-network/no-credential proof

Confirmed via direct grep of every file in `app/provider_certification/`
and `app/provider_certification/manifests/`: no
`requests.`/`httpx.`/`urlopen`/`socket.`/`aiohttp`, no
`Session`/`sessionmaker`/`get_db`/`.query(`, no
`decrypt`/`ENCRYPTION_KEY`/`os.environ[...KEY/SECRET/TOKEN]`, and no
`subprocess`/`pytest.main`/`os.system` (the one grep hit is a docstring
explaining the design, not an actual call).

## 26. Framework matrix

Expanded from 501 to 751 rows (minimum 750 met).

## 27. Message-4 certification status

**PASS** — see `provider_certification_framework.md` §33 for the full
gate table.

## 28. Exact framework test count

794 tests across all `test_provider_certification_*.py` files plus
`test_provider_expansion_freeze_certification.py` (up from 545 before
this message) — all passing.

## 29. Narrow-filter results

All 8 required filters (`cloudflare`, `supabase`, `firebase`, `stripe`,
`completeness`, `capabilities`, `onboarding`, `eleven_provider`), each
scoped `and provider_certification`: 46, 34, 35, 34, 55, 29, 11, 17
tests respectively — all non-zero, all passing.

## 30. Provider regressions

Focused exact regressions across all eleven providers (depth-QA,
security-finding/reachability/parity, change-classification-QA, plus
the modified `test_kubernetes_security_rule_parity.py`, expansion
freeze): **1949 tests passed, 1 skipped** (excluding 1 failure + 5
errors in `test_milestone87b_gitlab_core_security_foundation.py`,
`test_milestone60_4_1_github_rules.py`, and
`test_milestone75c_provider_capability_matrix.py` — confirmed via `git diff`
that none of these files or the code they exercise were touched this
message; this is the same pre-existing "no live Postgres in this
environment" limitation documented in message 3, not a message-4
regression).

## 31. TypeScript

Not run — no frontend files were read or modified this message (all
four providers' frontend forms already existed and were certified via
static discovery only).

## 32. Dependencies

No changes — confirmed via `git diff --stat` on
`backend/requirements.txt`, `backend/requirements-dev.txt`, and
`frontend/package.json`.

## 33. Message-5 recommendation

Not started, and not begun as part of this message. Candidate items:
promote the `Defer to message 5` duplication-inventory rows for
Cloudflare/Supabase/Firebase/Stripe now that they are no longer newly
onboarded; consider migrating one or two more existing providers'
legacy `completeness_scopes` strings to the typed
`CompletenessScopeDeclaration` form as a worked example beyond
Kubernetes' single representative entry; consider whether any future
provider's evidence genuinely needs `quality="static_only"` paired
with an exemption.

**Not safe to push without explicit user instruction — no push was
performed as part of this message.**
