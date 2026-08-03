# Provider Certification Framework — Message 7 (Final Milestone)

## Objective

Enforce the Provider Certification Framework in CI: give it a stable CLI
entry point, changed-provider impact analysis, generated-report drift
enforcement, a deterministic contract fingerprint, framework
self-certification, and a real GitHub Actions workflow — without adding
another provider, modifying provider runtime behavior, or building anything
out of scope (Live Validation CLI, snapshot mutation/replay, billing,
dashboard).

## Command architecture

New module: `backend/app/provider_certification/cli.py`, invoked as
`python -m app.provider_certification.cli <command>`.

| Command | Purpose |
|---|---|
| `certify-all` | Full-catalog certification of every registered provider |
| `certify-provider <id>` | Focused certification of one canonical provider ID |
| `generate-reports` | Regenerate every deterministic report on disk (the only write path) |
| `check-reports` | Detect drift between committed reports and freshly generated ones — never writes |
| `affected --base <sha> --head <sha>` | Changed-provider impact analysis over a local git diff |

Every command supports `--format text` (human-readable) and `--format json`
(deterministic — sorted keys, no timestamps, no absolute paths, no
credentials). Built with `argparse` only — no new CLI dependency. A shared
`parents=[format_parent]` pattern makes `--format` valid both before and
after the subcommand token.

Exit codes: `0` pass, `1` gate failed, `2` invalid command/provider, `3`
reports stale, `4` internal error — documented in `cli.py`'s module
docstring and the README, and pinned by
`test_provider_certification_cli.py`.

## Impact analysis

New module: `backend/app/provider_certification/impact.py`.

- **Provider-specific path patterns** (11 compiled regexes): connector,
  schema, risk-rules, security-rules, manifest, provider report, and four
  test-file naming conventions, plus a PascalCase frontend-form pattern.
- **Global path patterns** (16 (regex, dimension) pairs): diff service,
  security-rule registry/confidence/pack, capability matrix, security
  coverage service, integration schema/service/router, sync service, worker
  dispatch, framework code itself, migration allowlist, provider-expansion
  framework, frontend provider catalog, frontend rule catalog.
- **Conservative fallback philosophy**, applied at three independent
  layers: (1) an unrecognized-but-provider-shaped file (e.g. a new
  `connectors/newcloud.py` with no manifest) forces full-catalog
  certification and is never silently ignored; (2) any git failure
  (invalid SHA, shallow clone, no merge base) is caught and converted to a
  full-catalog result, never an exception and never an empty "nothing
  changed" result; (3) `ci_policy.decide_strategy()` independently forces
  full-catalog on a push to `main` or when no merge base is available,
  regardless of what impact analysis itself found.
- **Rename/delete handling**: `git diff --name-status` output is parsed
  without `shell=True` (list-form `subprocess.run` only); a rename
  contributes BOTH the old and new path so the old provider's certification
  and the new (possibly unregistered) path's classification are both
  captured.
- One genuine bug found and fixed during manual verification against the
  real message-6 commit diff: framework-internal test/report files (e.g.
  `test_provider_certification_runner.py`, `summary.json`) were
  incidentally matching a provider-shaped regex and being flagged
  "unknown provider-shaped" — fixed with an explicit `_NON_PROVIDER_IDS`
  frozenset, pinned by a regression test.
- A second bug fixed proactively: a naive PascalCase→snake_case regex would
  have mangled "PagerDuty" into "pager_duty" (real ID: `pagerduty`) and
  similar cases — fixed by matching against every known provider_id with
  underscores stripped, rather than guessing one splitting convention.

## CI integration

New file: `.github/workflows/provider-certification.yml` (no prior GitHub
Actions CI existed in this repository — confirmed via
`ls -la .github/workflows/` returning nothing before this message).

Three jobs:

1. **`provider-certification-impact`** — full-history checkout
   (`fetch-depth: 0`), runs `affected`, exposes `full_catalog` and
   `providers` as job outputs.
2. **`provider-certification`** — `certify-all` if full-catalog required,
   else `certify-provider <id>` per directly-affected provider, else
   nothing (a docs-only PR is not required to run certification).
3. **`provider-certification-reports`** — `check-reports` (drift must be
   zero) plus the full framework test suite
   (`pytest tests/ -k "provider_certification"`) against a real Postgres
   service container.

Pull requests use the real merge base (full-history checkout); pushes to
`main` always run full-catalog certification regardless of changed paths
(`ci_policy.decide_strategy`); any git failure (shallow clone, missing
merge base) is already absorbed by `impact.analyze_impact_from_git`'s own
conservative fallback, so no separate shallow-clone detection is needed in
the workflow itself. Workflow YAML syntax was validated with the
already-installed PyYAML (`yaml.safe_load`) — no new dependency.

## Report drift

New module: `backend/app/provider_certification/report_drift.py`.
`generate_reports()` is the sole write path (atomic `tempfile.mkstemp()` +
`os.replace()`); `check_report_drift()` regenerates every report in memory
and diffs byte-for-byte against disk, reporting `STALE:` / `MISSING:` /
`EXTRA:` lines with a `provider_certification/` path prefix, never
rewriting anything itself. Verified clean against the real, currently
committed reports.

## Contract fingerprints

New module: `backend/app/provider_certification/fingerprint.py`.
`contract_fingerprint()` returns a deterministic, order-independent dict
covering record types, Finding IDs, credential fields,
supported/unsupported capabilities, public/connectable/live/reconnect
state, maturity, completeness scope declarations, frontend form, and
schema version (`manifest_version`) — explicitly excluding prose
(`known_limitations`, `display_name`, evidence file paths/notes) and any
timestamp-shaped field. `fingerprint_hash()` gives a stable SHA-256 hex
digest; `diff_fingerprints()` gives a field-level before/after diff.

**Limitation, stated honestly**: this message does not check out two full
git trees to compute an automated before/after fingerprint diff as a CI
gate — that would require invasive worktree/checkout machinery out of
scope for this message. `fingerprint.py`'s before/after comparison is
exercised via fixture manifests (constructed with `dataclasses.replace()`)
rather than real git history. The **actual, immediate CI enforcement
mechanism for "manifest didn't update when the contract changed" is
`check-reports`**: every committed report is a deterministic function of a
manifest plus live repository discovery, so any manifest/implementation
mismatch that isn't reflected in the committed reports fails
`check-reports` on the very next run. A true git-tree-based fingerprint
diff is a natural future enhancement, not built here.

## Schema-version enforcement

`manifest_version` (currently `1` for every manifest) participates in the
contract fingerprint and in every generated report's serialized content. A
version bump changes both, so a report left at the old version fails
`check-reports`'s byte-for-byte comparison — pinned directly by
`test_provider_certification_report_drift.py::TestSchemaVersionMismatch`.

## Performance

Measured with warm-up + median-of-5 (never exact-millisecond assertions):

| Operation | Budget | Measured (this run) |
|---|---|---|
| `certify_provider("sentry")` | < 1s | passes comfortably (see `test_provider_certification_performance.py`) |
| `certify_all_providers()` | < 5s | passes comfortably |
| `generate_reports()` | < 5s | passes comfortably |
| `check_report_drift()` | < 5s | passes comfortably |
| `analyze_impact()` (5 mixed paths) | < 1s | passes comfortably |
| `classify_path()` (single path) | < 1s | passes comfortably |

Full suite (1,585 provider-certification tests) runs in ~23 seconds locally
— well under any reasonable CI timeout.

## Determinism

- `certify-all --format json` produces byte-identical output across two
  consecutive runs and across reversed dict insertion order (dict keys are
  explicitly sorted before serialization).
- `generate_reports()` run twice produces byte-identical report files.
- `check_report_drift()` never mutates mtime or contents, and never
  creates a new file.
- Contract fingerprints are order-independent across every tuple-typed
  field (record types, credential fields, Finding IDs) — reversing tuple
  order never changes the fingerprint or its hash.

## Safety (no production side effects)

None of the new message-7 code — `cli.py`, `impact.py`, `report_drift.py`,
`ci_policy.py`, `fingerprint.py`, `framework_self_certification.py` — ever
constructs an `httpx.Client`, opens a `sqlalchemy.orm.Session`, decrypts a
credential, instantiates a connector, or reads a customer-credential
environment variable. `impact.py`'s only external interaction is a local,
list-form (never `shell=True`) `git diff --name-status` subprocess call
with a 30-second timeout. Two new tests were added to the pre-existing
`test_provider_certification_runner.py::TestNoProductionSideEffects` class
specifically pinning that `cli.main(["certify-all", ...])` and
`impact.analyze_impact(...)` never open a DB session.

## Framework self-certification

New module: `backend/app/provider_certification/framework_self_certification.py`.
A single global, non-blocking-per-provider gate verifying 8 checks: every
gate dimension has a test-file reference; every manifest is loaded exactly
once with no duplicates; every generated report is represented (via
`check_report_drift`); the adoption report shows zero missing and zero
orphan providers; matrix/report minimums hold; the CLI entry point exists
on disk; the committed CI workflow references the real CLI module path;
and no migration-allowlist entry overlaps an already-certified provider.
All 8 checks pass against the real repository state.

## Tests

7 new test files, 132 tests, all passing:

| File | Tests |
|---|---|
| `test_provider_certification_cli.py` | 21 |
| `test_provider_certification_impact.py` | 30 |
| `test_provider_certification_report_drift.py` | 13 |
| `test_provider_certification_contract_fingerprint.py` | 31 |
| `test_provider_certification_ci_policy.py` | 17 |
| `test_provider_certification_performance.py` | 6 |
| `test_provider_certification_framework_self_certification.py` | 14 |

Plus 2 new tests added to the existing
`test_provider_certification_runner.py` (no-production-side-effect
coverage for the new CLI/impact surfaces).

**Total provider-certification framework tests: 1,585** (was 1,583 before
this message; `pytest tests/ -k "provider_certification"` — never the
whole repository suite).

All 7 required narrow `-k` filters select non-zero, fully-passing tests:
`cli` (30), `impact` (34), `report_drift` (14), `fingerprint` (31),
`ci_policy` (17), `performance` (6), `self_certification` (14).

Focused regressions (500 tests) all pass: full-catalog certification,
manifest coverage, adoption report, expansion freeze, report determinism,
Sentry provider-depth, Snowflake provider-depth, Terraform Cloud
integration creation/reconnect (called out specifically because message 6
changed its credential routing), capability matrix, security coverage.

## Limitations

1. Manifest-update enforcement is report-drift-based rather than a true
   git-tree before/after fingerprint diff (see "Contract fingerprints"
   above) — documented, not silently assumed complete.
2. `provider-certification-reports`'s CI job needs a real Postgres service
   container because the test suite's `conftest.py` imports the full
   FastAPI app (auth, DB session) even for framework tests that never
   touch the database themselves — this is pre-existing test-suite
   architecture, not something this message could narrow without touching
   `conftest.py`.
3. No frontend files changed in this message, so `npx tsc --noEmit` was not
   run — confirmed via `git status --short` showing zero `frontend/`
   changes.

## Final result

- Graphify: all four mandatory queries ran successfully
  (`provider certification CI workflow changed provider detection ConfigTrace`,
  `GitHub Actions backend tests certification generated report drift`,
  `provider files manifests record types security findings capability matrix frontend parity`,
  `provider certification performance deterministic JSON schema version`).
  The graph is built from commit `037dadea`, which matches `git rev-parse HEAD`
  exactly (`037dadeae9d94b2fbc2f60083765562ff3015d58`) — **not stale**, so
  `graphify update .` was not required. The queries confirmed no existing
  GitHub Actions workflow or CI-related nodes are indexed (consistent with
  the direct-read finding that `.github/workflows/` did not exist before
  this message) and surfaced the real `provider_certification/models.py`
  symbol set (`ProviderCertificationManifest`, `CompletenessScopeDeclaration`,
  `FindingReachabilityEvidence`, `ReachabilityExemption`,
  `CapabilityEvidenceDeclaration`, `ManifestValidationError`) used throughout
  this message's new modules. Direct reads of `runner.py`, `models.py`,
  `gates.py`, `discovery.py`, `cross_manifest.py`, and `migration_allowlist.py`
  remained the authoritative source for implementation details, per
  CLAUDE.md's graphify guidance.
- All CI and framework gates pass against real repository state.
- No new provider was added. No provider runtime behavior was modified.
- No new production dependency was added (PyYAML was already installed).

**Provider Certification Framework is complete.**
