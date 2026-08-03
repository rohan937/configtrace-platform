# Provider Certification Framework

Pure, read-only, deterministic certification of every provider integration's
repository-level wiring: credential schema, record inventory, diff/Change
classifier coverage, Security Finding registry parity, capability-matrix
parity, frontend parity, completeness/false-removal declarations, and more.
It never calls a provider API, opens a DB session, decrypts a credential, or
instantiates a connector — see `test_provider_certification_runner.py::TestNoProductionSideEffects`.

As of message 7, the framework is enforced in CI on every pull request and
every push to `main` (see [CI behavior](#ci-behavior) below). This message did
not add another provider — provider expansion remains frozen (see
`provider_certification_onboarding_standard.md` §20).

## Architecture

| Module | Responsibility |
|---|---|
| `models.py` | Typed, frozen manifest/gate/result dataclasses. Manifest construction validates internal consistency (`__post_init__`) — a contradictory manifest fails immediately. |
| `discovery.py` | Pure repository introspection (AST/regex/import-based) — record types, credential fields, dispatch wiring, etc. Never trusts a manifest's claims; gates compare declared vs. discovered. |
| `gates.py` | One evaluator function per certification dimension (identity, credential schema, record inventory, Finding parity, …). Each returns a `CertificationGate` with status/evidence/remediation. |
| `cross_manifest.py` | Global (repository-wide) gates: no duplicate provider IDs, no Finding-ID collisions, capability-matrix/frontend/security-coverage catalog consistency across every registered manifest. |
| `runner.py` | `certify_provider()` / `certify_all_providers()` — the pure entry points. Loads every manifest exactly once, runs every applicable gate, computes overall pass/fail. |
| `manifests/<provider_id>.py` | One declarative manifest per certified provider. Declared intent only — never itself certification evidence. |
| `migration_allowlist.py` | Tracked, reason-required exceptions for a launched-but-not-yet-certified provider. Empty as of message 6 and expected to stay empty for ordinary providers. |
| `fingerprint.py` *(message 7)* | Deterministic, order-independent "contract fingerprint" of a manifest — record types, Finding IDs, credential fields, capabilities, completeness, reconnect/launch state, frontend form, schema version. Excludes prose (limitations text, display names, evidence notes) and timestamps. |
| `impact.py` *(message 7)* | Changed-path → changed-provider impact analysis. Classifies each changed path as provider-specific, shared/global, or unknown-provider-shaped, and conservatively decides whether full-catalog certification is required. |
| `report_drift.py` *(message 7)* | Generates every committed certification report deterministically and detects drift (stale/missing/extra) against what's on disk. `generate_reports()` is the only write path — always atomic (`os.replace()`). |
| `ci_policy.py` *(message 7)* | Pure decision logic combining impact analysis + CI event context into a certification strategy, and combining certification/report-drift/manifest-coverage/framework-test results into a single merge-blocking decision. |
| `framework_self_certification.py` *(message 7)* | The framework certifying itself: every gate has test coverage, every manifest loads exactly once, every generated report is current, the adoption report reflects real repository state, the CI entry point and workflow exist and agree, no migration-allowlist entry has gone stale. |
| `cli.py` *(message 7)* | The stable CI/developer entry point — see below. |

## CLI commands

```bash
cd backend
python -m app.provider_certification.cli certify-all
python -m app.provider_certification.cli certify-provider sentry
python -m app.provider_certification.cli generate-reports
python -m app.provider_certification.cli check-reports
python -m app.provider_certification.cli affected --base <base-sha> --head <head-sha>
```

Every command accepts `--format text` (default, human-readable) or
`--format json` (deterministic — sorted keys, no timestamps, no absolute
paths, no credentials; safe to diff or pipe to `jq`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Certification passed / command succeeded |
| 1 | A certification gate failed (`certify-all` / `certify-provider`) |
| 2 | Invalid command, missing argument, or unknown provider |
| 3 | Generated reports are stale (`check-reports`) |
| 4 | Internal framework error (unexpected exception — never used to mean "certification failed") |

Every JSON envelope carries `exit_code_category` (`"pass"` / `"gate_failed"`
/ `"invalid_command"` / `"reports_stale"` / `"internal_error"`) so CI tooling
never has to hardcode the integer mapping.

## Adding or updating a manifest

Follow `provider_certification_onboarding_standard.md` (§1-26 for manifest
construction, §35 for the message-7 CI checklist). In short: derive
`provider_id`/record types/credential fields/Finding IDs from real discovery,
never from assumption; declare `known_limitations` honestly; regenerate
reports; run the provider's own semantic test suite. Provider expansion
itself (adding a new provider) remains frozen — this document only governs
existing certified providers.

## Running focused certification

```bash
python -m app.provider_certification.cli certify-provider sentry --format json
```

Rejects unknown/alias provider IDs (exit 2) — only the canonical
`provider_id` a manifest is registered under is accepted.

## Regenerating reports

```bash
python -m app.provider_certification.cli generate-reports
```

Writes every provider's `tests/reports/provider_certification/<id>.json`,
`tests/reports/provider_certification/summary.json`, and
`tests/reports/provider_certification_adoption.json`, deterministically (no
timestamps, sorted keys) and atomically. **These three report locations are
generated files — never hand-edit them.** Any manual edit will immediately
be flagged as drift by `check-reports`.

## Resolving drift failures

```bash
python -m app.provider_certification.cli check-reports
```

Regenerates every report **in memory** (never touching disk) and compares
byte-for-byte against what's committed. On failure it prints one line per
problem:

```
STALE: provider_certification/sentry.json
MISSING: provider_certification/newprovider.json
EXTRA: provider_certification/removed_provider.json
```

Fix by running `generate-reports` and committing the resulting diff — never
by hand-editing a report to match, and never by weakening a gate to avoid
the underlying drift.

## Impact-analysis behavior

`affected --base <sha> --head <sha>` runs `git diff --name-status
<base>...<head>` locally (no network, never `shell=True`) and classifies
every changed path (including both sides of a rename):

- **Provider-specific** paths (a connector, schema, risk-rules module,
  security-rules module, manifest, or provider-specific test/report/frontend
  form for a *known* provider) narrow the affected-provider set.
- **Shared/global** paths (diff service, security-rule registry/confidence/
  pack, capability matrix, security coverage service, integration
  schema/service/router, sync service, worker dispatch, framework code
  itself, migration allowlist, provider-expansion framework, frontend
  provider catalog) force full-catalog certification.
- **Unknown provider-shaped** paths (a connector-shaped file whose name
  doesn't match any registered manifest — a genuinely new or renamed
  provider) force full-catalog certification and are never silently
  ignored.
- Any git failure (missing merge base, shallow clone, invalid SHA) also
  forces full-catalog certification — uncertainty is never resolved by
  skipping certification.

## CI behavior

`.github/workflows/provider-certification.yml` runs three jobs on every pull
request into `main` and every push to `main`:

1. **`provider-certification-impact`** — checks out full history
   (`fetch-depth: 0`), runs `affected`, and exposes `full_catalog`
   (true/false) and the comma-joined `providers` list as job outputs.
2. **`provider-certification`** — runs `certify-all` if full-catalog is
   required, or `certify-provider <id>` for each directly affected provider
   otherwise. If neither shared nor provider-affecting paths changed (e.g. a
   docs-only PR), certification is skipped for that run.
3. **`provider-certification-reports`** — runs `check-reports` (drift must
   be zero) and the full Provider Certification Framework test suite
   (`pytest tests/ -k "provider_certification"`) against a Postgres service
   container.

**Push events to `main` always run full-catalog certification**, regardless
of which paths changed — see `ci_policy.decide_strategy`. Pull-request
events use the real merge base when available (fetch-depth 0); if a merge
base can't be determined (a genuinely unrelated-history diff, or a git
failure), impact analysis's own conservative fallback already forces
full-catalog certification, so `ci_policy` doesn't need separate
shallow-clone detection.

## Exit codes reference

See the table above — every CLI command uses this same fixed mapping, and
CI treats any non-zero exit from `provider-certification` or
`provider-certification-reports` as a merge-blocking failure.

## Safety boundaries

No command in this package — CLI, impact analysis, report generation, or
report-drift checking — ever:

- makes a network call or instantiates an HTTP client
- opens a database session
- decrypts an encrypted credential
- instantiates a connector class
- reads a customer-credential environment variable
- triggers a sync or mutates an integration

See `test_provider_certification_runner.py::TestNoProductionSideEffects` and
`test_provider_certification_cli.py::TestNoSecretOutput` for the tests
pinning this.

## Provider-expansion freeze

Certifying, testing, or wiring CI for this framework does **not** itself
authorize adding a new provider. `gate_provider_expansion_freeze` remains a
blocking gate on every certification result; the future-provider queues
remain the single source of truth for what may be added next. See
`provider_certification_onboarding_standard.md` §20.

## Known limitations (message 7)

- **Manifest-update enforcement is report-drift-based, not a true
  before/after contract diff.** `fingerprint.py` can compute a deterministic
  contract fingerprint for any single manifest and diff two fingerprints,
  but this message does not check out the pre-change tree to compute an
  automatic "did the contract change without a manifest update" CI gate.
  The immediate, real CI enforcement mechanism is `check-reports`: since
  every report is a deterministic function of a manifest plus discovered
  repository state, a manifest/implementation mismatch that isn't reflected
  in the committed reports fails `check-reports` on the very next run.
  `fingerprint.py`'s before/after comparison is fixture-based only for now
  (see `test_provider_certification_contract_fingerprint.py`) — a genuine
  git-tree-checkout-based fingerprint diff is a natural, but not yet built,
  future enhancement.
- Schema-version enforcement relies on `manifest_version` /
  `SCHEMA_VERSION` participating in the contract fingerprint and the
  generated report content — a version bump changes both, and
  `check-reports` catches any report left at the old version.
