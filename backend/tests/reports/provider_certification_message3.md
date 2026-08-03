# Provider Certification Framework — Message 3

## 1. Objective

Extend the Provider Certification Framework (messages 1-2, covering
Sentry/Snowflake/Okta/Entra) to three new pilot providers —
**Kubernetes, GitHub, GitLab** — and add two new generalized
certification capabilities: a **Finding-reachability evidence gate**
(`security_finding_reachability`) and a **Finding-vs-Change parity
evidence gate** (`finding_change_parity`), while continuing
conservative, limited consolidation of duplicated static assertions.

## 2. Providers added

| Provider | Record types | Finding IDs | Maturity | Live | Reconnect | Notes |
|---|---|---|---|---|---|---|
| Kubernetes | 36 (+4 derived) | 59 | complete | yes | yes | Grouped classifier dispatch via a dedicated discovery adapter |
| GitHub | 11 | 25 | complete | yes | yes | Reconnect via shared generic dispatcher, not a named function |
| GitLab | 9 | 25 | partial | no | no | Honest `expected_live=False`/`expected_reconnect=False`; parity gate `deferred` |

Canonical `provider_id`s were verified from code (dispatch tables,
capability-matrix keys, connector class names) before writing each
manifest — `kubernetes`, `github`, `gitlab` all matched their real
repository identifiers exactly; no alias drift was found.

## 3. Discovery-precision refinements

- `discover_schema_record_type_constants` rewritten to cross-check
  identity constants (`NAME == VALUE.upper()`) against real connector
  wiring via a 200-character window search after every
  `record_type["']?\s*[:=]` site, matching either the constant NAME or
  the literal quoted VALUE. This correctly:
  - excludes 3 phantom Kubernetes constants (39 → 36) never referenced
    anywhere in `kubernetes.py`,
  - excludes 6 unwired GitHub constants (17 → 11),
  - includes all 9 real GitLab types via literal-value matching, since
    GitLab's connector never imports its own schema constants by name
    (the name-based check alone found zero).
- `discover_classifier_grouped_dispatch` (new): resolves
  `record_type in _SOME_FROZENSET_CONSTANT` grouped-dispatch patterns,
  needed because Kubernetes' risk-rule classifier dispatches many types
  via grouped frozenset membership rather than one-name-at-a-time.
- `discover_generic_reconnect_dispatch` / `discover_router_create_dispatch`
  (new): recognize that GitHub/GitLab wire reconnect/creation through a
  shared dispatcher or inline router branch, not per-provider named
  functions — an "original-8-era" pattern the message-1/2 discovery
  functions didn't anticipate.
- `discover_connector_class_any_capitalization` (new): resolves
  `GitHubConnector`/`GitLabConnector`'s irregular internal
  capitalization against the naive `GithubConnector`/`GitlabConnector`
  guess.
- `discover_frontend_form_uses_masked_multiline_input` (new): accepts
  `<textarea>` as an alternative to `type="password"`, needed for
  Kubernetes' multi-line `kubeconfig` field.
- `discover_frontend_form_wired_into_dispatcher` extended with an
  optional `form_component_name` fallback, needed for GitHub's implicit
  default-case wiring.

## 4. Adapter changes

`manifests/kubernetes.py` registers `_KUBERNETES_ADAPTER`, a
`ProviderDiscoveryAdapter` providing `discover_credential_fields`
(resolves the four unprefixed credential fields) and
`discover_classifier_record_types` (combines direct + grouped dispatch
resolution to reach full 36/36 coverage). No adapter was needed for
GitHub or GitLab — generic discovery, once extended per §3, resolved
their real state without a provider-specific adapter.

## 5. Global gate additions

`gate_security_finding_reachability` and `gate_finding_change_parity`
(both in `gates.py`, added to `ALL_PROVIDER_GATE_FUNCS`) — see
`provider_certification_framework.md` §23 for the full design. Both are
purely static: evidence-file existence is checked via `Path.is_file()`,
and minimum-test-count satisfaction is checked via
`gates._count_matching_tests` (regex-bounded `def test_` counting) —
**the framework runner never invokes pytest or a subprocess during
certification**, confirmed by grep (`app/provider_certification/*.py`
contains no `subprocess`, `pytest.main`, or `os.system` call outside
this file's own docstring explaining the design).

## 6. Evidence-test discovery and non-zero-test verification

Every reachability/parity evidence entry declares a real `test_file`
and (optionally) a `test_selector`. `_count_matching_tests` parses the
referenced file's text directly — no test collection machinery, no
process spawn — and the gate fails if the count is below the declared
`minimum_test_count`. This was proven both positively (all seven
providers' real evidence files satisfy their declared minimums) and
negatively (`TestZeroSelectedTests`, `TestMissingEvidenceFile` in
`test_provider_certification_reachability.py` / `_change_parity.py`).

## 7. Manifest-validation strengthening

`ProviderCertificationManifest.__post_init__` now rejects:
reachability/parity evidence for unknown rule IDs; a rule ID covered by
neither reachability evidence nor an exemption (parity has no such
requirement — see §8); parity exceptions lacking a rationale or
evidence_test, or with an invalid severity value; `minimum_test_count < 1`;
evidence files outside `tests/`; evidence declaring a different
`provider_id` than the manifest's own (no shared-evidence allowance is
configured); duplicate `(test_file, test_selector)` evidence identity.

## 8. Reachability vs. parity: mandatory vs. deferred

Reachability coverage is mandatory at construction time — a manifest
with an uncovered Finding rule ID fails to construct at all. Parity
coverage is deliberately NOT mandatory: `gate_finding_change_parity`
resolves `deferred` (non-blocking) when a manifest declares zero
`change_parity_evidence` and zero `change_parity_exceptions`. This
reflects that parity work may legitimately lag reachability work, and
GitLab is the concrete proof — it declares no parity evidence or
exceptions, and its gate result is `deferred`, never a fabricated
`pass`.

## 9. Cross-manifest extensions

All five existing cross-manifest gates (`cross_manifest_identity`,
`cross_manifest_capability_consistency`, `cross_manifest_finding_uniqueness`,
`cross_manifest_catalog_consistency`, `cross_manifest_live_freeze`) were
verified to run correctly, and identically in structure, across all
seven providers — `TestCrossManifestGatesAcrossAllSevenProviders` in
`test_provider_certification_cross_manifest.py` pins this. No new
cross-manifest gate specific to reachability/parity evidence was
needed; each provider's own reachability/parity gates already cover the
per-provider requirement, and no cross-provider Finding-ID collision was
found among the newly added Kubernetes/GitHub/GitLab rule IDs (pinned by
the pre-existing `cross_manifest_finding_uniqueness` gate).

## 10. Capability/completeness normalization

No new provider-specific capability strings were introduced — Kubernetes,
GitHub, and GitLab all declare `supported_capabilities` drawn from the
same fixed five-capability vocabulary (`security_findings`,
`activity_ingestion`, `activity_signals`, `risk_activity_correlations`,
`demo_case_reporting`) used by Sentry/Snowflake/Okta/Entra. Completeness
scopes are declared per-provider using whatever granularity is real for
that provider — Kubernetes declares `cluster_wide_family_completeness`
and a namespace-scoped removal-suppression scope; GitLab honestly
declares `completeness_scopes=()` / `false_removal_scopes=()` since no
family-completeness reporting or removal-suppression function exists
for it yet. No vocabulary was forced onto a provider that doesn't
genuinely have it.

## 11. Manifest validation strengthening (deeper detail)

See §7 above and `test_provider_certification_evidence.py` for the
dedicated cross-check tests proving these rules are enforced
consistently for BOTH reachability and parity evidence, not just
whichever one a given provider happens to use first.

## 12. Deterministic reports

All seven providers' JSON reports (`kubernetes.json`, `github.json`,
`gitlab.json`, plus the four pre-existing) and `summary.json` were
regenerated via `runner.write_report()` / `runner.write_summary_report()`.
`certification_summary()` was enhanced with per-provider
`reachability_evidence_coverage`, `parity_evidence_coverage`,
`exemption_count`, `warnings`, and `deferred_gates` fields — all sorted
deterministically, with no timestamps or absolute paths, verified by
`test_provider_certification_seven_provider_summary.py`.

## 13. Duplication inventory

Expanded from 80 to 140 rows (see
`provider_certification_duplication_inventory.md`), adding
Kubernetes/GitHub/GitLab across the same 20 duplication categories used
for the original four pilots. Every framework-superseded category for
the three new providers is marked `Defer to message 4`, matching the
precedent set for Okta/Entra in message 2 — their own depth-QA/legacy
test files were not touched this message.

## 14. Consolidation performed

12 assertions removed from `test_okta_security_finding_parity.py` and
`test_entra_security_finding_parity.py` (Okta: 30 → 24 tests, Entra:
39 → 33 tests) — the same category removed from Sentry/Snowflake in
message 2 (`TestRegistryParity`, two frontend-catalog set-equality
methods, `TestFullCrossLayerParity`), now extended to the two providers
deliberately left untouched then. Combined 57 tests verified passing
across both files. No Kubernetes/GitHub/GitLab test was deleted this
message.

## 15. Negative-mutation coverage

Every new gate and every new generic discovery function has at least
one negative-mutation test proving it can actually fail under a broken
condition — not merely proving it passes on real state. See
`TestKubernetesNegativeMutations`, `TestGitHubNegativeMutations`,
`TestGitLabNegativeMutations` in the three new provider test files, and
`TestGateCapabilityMatrixParityAcceptsPartialListMembership`,
`TestGateConnectorContractCapitalizationFallback`,
`TestGateReconnectRotationGenericDispatchFallback` in
`test_provider_certification_gates.py` for the four generic bug fixes
from §24 of the framework report.

## 16. No network/DB/credential access

Confirmed via direct grep of every file in
`app/provider_certification/` and `app/provider_certification/manifests/`:
no `requests.`/`httpx.`/`urlopen`/`socket.`/`aiohttp`, no
`Session`/`sessionmaker`/`get_db`/`.query(`, no `decrypt`/`ENCRYPTION_KEY`/
`os.environ[...KEY]`/`os.environ[...SECRET]`/`os.environ[...TOKEN]`, and
no `subprocess`/`pytest.main`/`os.system` (the one grep hit is a
docstring explaining the design, not an actual call).

## 17. No new production dependencies

`git diff --stat` on `backend/requirements.txt`,
`backend/requirements-dev.txt`, and `frontend/package.json` shows no
changes.

## 18. Test totals

- Framework test suite (all `test_provider_certification_*.py` +
  `test_provider_expansion_freeze_certification.py`): **544 tests, all
  passing**.
- Seven narrow `-k` filters (`kubernetes`, `github`, `gitlab`,
  `reachability`, `change_parity`, `evidence`, `seven_provider`), each
  scoped to `and provider_certification`: 30, 25, 25, 28, 17, 36, 19
  tests respectively — all non-zero, all passing.
- Focused provider regressions (Kubernetes/GitHub/GitLab/Okta/Entra/
  Sentry/Snowflake depth-QA, security-finding/reachability/parity
  suites, GitHub change-classification QA, GitLab depth QA, provider
  expansion freeze): **1029 tests, all passing** (excluding 6 tests in
  `test_milestone75c_provider_capability_matrix.py`,
  `test_milestone60_4_1_github_rules.py`, and
  `test_milestone87b_gitlab_core_security_foundation.py` that require a
  live Postgres connection unavailable in this environment — confirmed
  via `git diff` that none of the files those tests exercise were
  touched this message, so these are a pre-existing environment
  limitation, not a message-3 regression).

## 19. Frontend

No frontend files were read or modified this message (Kubernetes',
GitHub's, and GitLab's frontend forms already existed and were
certified via static discovery only) — `npx tsc --noEmit` was not run,
per the "only if frontend files changed" instruction.

## 20. Certification result

**Framework certification: PASS for all seven providers.** See
`provider_certification_framework.md` §27 for the full gate table.

## 21. Message 4 recommendation

Not started, and not begun as part of this message. Candidate items for
a future message: promote the `Defer to message 4` duplication-inventory
rows to actual consolidation for Kubernetes/GitHub/GitLab now that they
are no longer newly onboarded; add `change_parity_evidence` for GitLab
once a dedicated parity test file exists; consider a shared-evidence
allowance mechanism if cross-provider evidence sharing becomes
necessary; automatically verify every blocking gate has a
negative-mutation test rather than auditing this ad hoc.

**Not safe to push without explicit user instruction — no push was
performed as part of this message.**
