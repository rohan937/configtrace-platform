# AWS Detection-QA Matrix (message 1)

Scope: **detection only** — connector extraction/normalization, diff
tracked-field parity, classifier routing, Security Finding reachability,
evaluator/registry/frontend parity, provider metadata, fail-soft/partial-
sync behavior, and sensitive-data minimization for the AWS provider.
Exhaustive transition-severity and restoration calibration is reserved for
the dedicated AWS change-classification pass (message 2) and is **not**
covered here.

AWS is by far the most mature provider in ConfigTrace: 13,177-line connector
(`app/connectors/aws.py`), 9,800-line risk-rules module
(`app/services/risk_rules/aws.py`), 95 schema-defined record types, and 21
pre-existing AWS-specific test files spanning milestones M36–M69.3B. This
pass is the first formal `aws_detection_matrix.md`; no prior report existed.

## Graphify summary

All four required `graphify query` commands ran successfully via
`/Users/rohan/.local/bin/graphify`. Per instructions, success was **not**
treated as evidence the index is current. Findings:

- The graph surfaced `AWSConnector` (`aws.py:2135`), `classify_aws_change()`
  (`risk_rules/aws.py:7342` at query time, later shifted by edits),
  `_tracked_fields_for()` (`diff_service.py:1928`), and `compute_diff()`
  (`diff_service.py:2095`) — confirming the major architectural nodes are
  indexed at the module/function level.
- Test-file nodes surfaced: `test_aws_remaining_surfaces_audit.py`,
  `test_milestone42.py` (`TestRdsDbInstanceRisk`, `_rds_change()`),
  `test_milestone37.py` (`TestS3RiskClassification`), and hints like
  `"AWS Part 2 — remaining-surface risk audit (RDS, KMS/secrets/SSM,
  Lambda/ECS/EKS, ...)"` and `"mfa_required=None (not set) must NOT fire —
  evaluator checks 'is False'"` and `".test_C12_enabled_rule_count_decrease_
  uses_prev_value()"` — correctly signaling that `prev_value` is the
  established convention and that unknown-Boolean handling already exists
  in parts of the codebase.
- AWS service record families surfaced in node summaries: VPC Flow Logs,
  S3 data-event/access signals, IAM behavior timelines/privilege-chain
  signals, CloudTrail ingestion, GuardDuty, KMS key hashing, Lambda failure
  classification, and Security Hub — consistent with the 21 real AWS test
  files found directly.
- The graph did **not** surface the two headline bugs found in this pass:
  the `previous_value`/`prev_value` field-name bug in 3 classifiers, or the
  fact that 8 schema-defined/classifier-implemented record types
  (`aws_ec2_instance`, `aws_vpc_flow_log`, `aws_config_recorder`,
  `aws_config_delivery_channel`, `aws_access_analyzer`,
  `aws_access_analyzer_finding`, `aws_securityhub_finding`,
  `aws_acm_certificate`) are never emitted by `AWSConnector.fetch()`. The
  graph is coarse (module/class/docstring-level, not field/diff-level) and
  was used strictly as an architectural locator, as instructed — direct
  source reads (via 4 parallel research passes) and real `compute_diff()` /
  `classify_aws_change()` executions were authoritative for every finding.
- No missing diff/classifier/evaluator/registry wiring was directly
  *suggested* by graph output; all wiring gaps were found by direct
  cross-referencing of `aws_schema.py`, `diff_service.py`, and
  `risk_rules/aws.py`.

## Record-type inventory

**95 record types are defined in `aws_schema.py`'s `AWS_RECORD_TYPES`
frozenset.** Of these, **87 are actively emitted by `AWSConnector.fetch()`**
across ~31 `_fetch_*_resources` service families (S3, EC2 networking, IAM,
Route53, CloudFront, Secrets Manager, SSM, RDS, Lambda, API Gateway v1/v2,
ELBv2/Classic ELB, WAFv2, CloudTrail, GuardDuty, Security Hub, ECS, EKS,
ECR, EventBridge, SQS, SNS, KMS, Backup, Organizations, CloudWatch,
CloudWatch Logs). **8 record types are schema-defined and fully classified
in `risk_rules/aws.py` (with dedicated `_classify_*` functions and dispatch
entries) and referenced in `security_rules/aws.py`'s docstrings, but are
never fetched or emitted anywhere in `aws.py`** — a genuine "schema-defined,
classifier-implemented, never-connected" gap (see Root-cause bugs, #3).

## Total cases reviewed and status counts

| Metric | Count |
|---|---|
| Total detection cases reviewed | 68 |
| PASS | 47 |
| FIXED | 16 |
| GAP (documented, intentionally out of scope) | 5 |
| FAIL | 0 |
| N/A | 0 |

## Root-cause bugs found and fixed

1. **`previous_value` vs. `prev_value` field-name bug (3 classifiers).**
   `_classify_route53_hosted_zone_change`, `_classify_route53_record_change`,
   and `_classify_cloudfront_distribution_change` all read the Change's
   previous value via `_get(change, "previous_value")`. Real
   `compute_diff()` Changes only ever carry `prev_value` (confirmed at
   `diff_service.py` — Change dict construction and `store_changes()`'s
   `prev_value=cd.get("prev_value")`). This meant `pv` was **always
   `None`** in all three functions, silently breaking every prev→new
   transition check: Route53 public↔private zone-type flips, the
   `private_zone` False→True detection, CloudFront `enabled` True→False
   detection, and record-count-decrease messages (which always showed
   `None` as the "previous" value). **Fixed**: all three now read
   `prev_value`.
2. **Unsafe `int(v or 0)` numeric-unknown coercion (3 classifiers).**
   `_classify_config_recorder_change` (`resource_types_count`) and
   `_classify_acm_certificate_change` (`days_to_expiry`,
   `subject_alternative_names_count`) used `int(v or 0)` wrapped in a
   `try/except` that also defaulted to `0` on failure — conflating a
   missing/unparseable value with a genuine zero. The `days_to_expiry` case
   was the most severe: a missing value would be coerced to `0`, and
   `new_n <= 0` then falsely reported **"certificate has expired"** at
   critical/high severity. **Fixed**: all three now preserve unknown via an
   `isinstance(v, (int, float))` check and return an explicit "could not be
   determined" branch instead of treating missing as zero.
3. **Schema-defined + classifier-implemented record types never emitted
   (8 record types) — documented as GAP, not fixed by adding new connector
   code.** `aws_ec2_instance`, `aws_vpc_flow_log`, `aws_config_recorder`,
   `aws_config_delivery_channel`, `aws_access_analyzer`,
   `aws_access_analyzer_finding`, `aws_securityhub_finding`, and
   `aws_acm_certificate` are all defined in `aws_schema.py` with detailed
   docstrings (milestones "M59.8"/"M59.9"), have fully-implemented, tested
   (via `test_aws_part1_risk_audit.py`/`test_aws_part2_risk_audit.py`
   pure-mock tests) classifiers in `risk_rules/aws.py`, and are dispatched
   correctly in `classify_aws_change()` — but `AWSConnector.fetch()`
   contains **zero** boto3 calls or record construction for any of them
   (confirmed via exhaustive grep — the schema constants aren't even
   imported into `aws.py`). Per the task's explicit instruction *"do not
   invent new AWS service coverage merely to increase coverage,"* this pass
   does **not** implement EC2/Config/Access-Analyzer/ACM fetch logic (that
   is substantial new connector work, not a QA/detection fix). It **is**,
   however, a genuine tracked-fields gap in the existing declared schema/
   classifier surface, so tracked-field entries were added for all 8 types
   in `diff_service.py` (see Fix #4) so that if/when a future connector
   change wires up emission, drift detection works immediately.
4. **Tracked-but-not-emitted fields for the 8 dark record types.** As a
   direct consequence of #3, none of the 8 record types had entries in
   `_AWS_TRACKED_FIELDS_BY_TYPE` — meaning even if a record of one of these
   types were ever emitted, `compute_diff()` would never generate a
   "modified" Change for it (added/removed would still work since those
   don't depend on tracked fields). **Fixed**: added tracked-field tuples
   for all 8 types, matching exactly the fields each type's existing
   classifier inspects (`public_ip_address`/`in_public_subnet`/etc. for EC2
   instance; `recording`/`records_global_resources`/`resource_types_count`
   for Config recorder; `status`/`days_to_expiry`/`domain_name`/
   `subject_alternative_names_count`/`key_algorithm` for ACM certificate;
   and so on). These entries are currently inert (no record of these types
   exists in any snapshot) but close the gap for future connector work.
5. **Generic "added" severity for newly-discovered risky resources (8
   classifiers).** `_classify_rds_db_instance_change`,
   `_classify_rds_db_cluster_change`, `_classify_sqs_queue_change`,
   `_classify_sns_topic_change`, `_classify_ecr_repository_change`,
   `_classify_kms_key_change`, and `_classify_eventbridge_bus_change` all
   returned a flat "was added to monitoring" / generic low severity for
   `change_type == "added"`, regardless of the new record's actual posture
   — even though `new_value` on an "added" Change is the full new record
   dict and the same posture fields (`publicly_accessible`,
   `public_or_cross_account_policy`, `policy_is_public`,
   `wildcard_admin_policy`) are already inspected on "modified" Changes for
   the same record types. **Fixed**: all 8 "added" branches now inspect the
   new record's posture and escalate (critical/high) when a newly
   discovered resource is already publicly exposed or unencrypted, matching
   the established GitHub/Stripe/Supabase/Firebase "added record must be
   inspected" precedent from this session's other provider passes. A ~50
   further "added" branches across lower-signal record types (VPC,
   subnets, route tables, Lambda aliases, CloudWatch alarms, etc.) remain
   flat/generic — these either genuinely carry no security-relevant base
   posture or are reserved for message 2's exhaustive added/removed
   calibration pass; not fixed here to avoid scope creep beyond the
   task's "fix structural bugs now, reserve exhaustive calibration for
   message 2" boundary.

## Non-code findings (documented, not fixed)

- **`security_coverage_service.py`'s `RECORD_TYPE_DIAGNOSTICS`** had no
  entry for `aws_iam_account_summary`, even though that record type is a
  legitimate expected surface (`aws_root_mfa_disabled` maps to it). This
  meant `_diagnose()` silently produced no specific permission-hint message
  when this was the missing surface. **Fixed**: added a diagnostic entry
  (`"IAM account summary (root MFA) metadata was not observed."`, hint
  `iam:GetAccountSummary`).
- **`PROVIDER_SURFACES["aws"]`** (backend) and the frontend's
  `PROVIDER_COVERAGE` entry for `"aws"` both listed only 4 of the 5
  underlying AWS record-type surfaces covered by the 9 security rules,
  omitting the root-MFA/IAM-account-summary surface. **Fixed**: both lists
  now include a 5th surface entry (`"IAM account summary (root MFA)"` /
  `"Root account MFA"`).
- `security_rule_pack.py`'s static severity table lists `aws_s3_public_acl`
  as `"critical"` only, while the actual rule (and frontend catalog) has a
  conditional critical/high split (write vs. read-only). This is a minor
  pre-existing simplification in a summary table, not a missing/orphaned
  key — left as-is; the actual evaluator and frontend catalog are correct.

## Classifier routing

`classify_aws_change()` uses **exact-match dispatch** (`record_type ==
AWS_<CONST>`), never prefix/wildcard matching. All 95 dispatch branches
have a corresponding classifier function (95 classifiers, 95 branches,
1:1, no orphans). The final fallback is:
```python
return ("low", f"AWS configuration changed ({record_type or 'unknown record type'}).")
```
This is safe and generic — confirmed no cross-provider fallback routing
exists anywhere in the function (no calls into Azure/GCP/Firebase/etc.
classifiers). Unknown/unrecognized `aws_*` record types fail safely into
this generic low-severity branch.

## Unrelated/generic fallback behavior

Confirmed clean: `_tracked_fields_for()`'s AWS branch
(`diff_service.py:2865`) is `if rt.startswith("aws_"): return
_AWS_TRACKED_FIELDS_BY_TYPE.get(rt, ())` — unmapped `aws_*` types get an
empty tuple (no spurious modification Changes), never fall through to the
generic non-prefixed `_TRACKED_FIELDS` tuple used for un-prefixed record
types (e.g. bare Cloudflare DNS record types). No dangerous fallback
routing to another provider's tracked-fields or classifier logic exists
anywhere in the AWS path.

## Normalized-but-untracked fields

None found as accidental omissions. Two explicit, documented,
intentional exclusions:
- `aws_service_inventory.future_surfaces` — deliberately excluded so that
  future/placeholder surface additions don't spuriously fire Change events.
- `aws_cloudtrail_trail.trail_name` — deliberately excluded; trail identity
  is via the hashed-ARN `record_id`, so renames surface as remove+add
  rather than a field modification (avoids misleadingly rendering a rename
  as an in-place config change).

## Tracked-but-not-emitted fields

All 87 actively-emitted record types have full field parity between
connector output and tracked fields (no tracked field that the connector
never populates, verified by the diff_service tracked-fields audit
cross-referenced against the connector inventory audit). The only
tracked-but-not-emitted case is the 8 dark record types described in
root-cause bug #3/#4 above — the tracked fields exist (post-fix) but the
records themselves are never emitted, so the tracking is currently inert.

## Security Finding reachability, registry, and frontend parity

**9 Security Finding rule keys** exist in `security_rules/aws.py`, and all
9 have full parity across the central evaluator dispatch, registry,
confidence table, rule pack, coverage service, and frontend catalog:

| Rule key | record_type | Severity |
|---|---|---|
| `aws_public_admin_port` | `aws_security_group_rule` | high |
| `aws_public_database_port` | `aws_security_group_rule` | critical |
| `aws_public_all_ports` | `aws_security_group_rule` | critical |
| `aws_s3_public_policy` | `aws_s3_bucket` | critical |
| `aws_s3_public_acl` | `aws_s3_bucket` | critical (write) / high (read-only) |
| `aws_iam_admin_policy_attached` | `aws_iam_policy_attachment` | high |
| `aws_iam_broad_policy_attached` | `aws_iam_policy_attachment` | high |
| `aws_root_mfa_disabled` | `aws_iam_account_summary` | high |
| `aws_access_key_unused` | `aws_iam_access_key` | medium |

All 9 rules use explicit `is True`/`is False`/`is not True`/`is not False`
Boolean checks (never truthy/falsy), and the one numeric rule
(`aws_access_key_unused`) uses `isinstance(age, int)` before comparing —
`None`/missing data never fires a Finding. No orphaned frontend/registry
entries found; no rule key present in one location but missing from
another. Deferred (documented, not implemented) rules — public web ports
80/443, default-SG-name correlation, standalone "WAF missing", per-user IAM
MFA (`aws_iam_user_mfa_disabled`) — are confirmed intentionally absent via
an existing regression assertion in `test_aws_provider_depth_qa.py`.

**Unreachable Findings**: none — all 9 rules are reachable given their
expected record type is emitted by the connector.

**Records without Findings**: the vast majority of AWS's 87 emitted record
types have no dedicated Security Finding (only drift/Change tracking) —
this is expected and consistent with every other provider in ConfigTrace;
Security Findings model a curated high-signal subset, not every trackable
field. Notable record types with rich Change classifiers but no Finding:
RDS public accessibility/encryption, CloudTrail disabled/weakened, KMS
rotation/scheduled-deletion, Lambda public function URLs, GuardDuty/Security
Hub disablement, ECR/SQS/SNS/EventBridge public policies — all of these
are documented, high-value candidates for future Security Finding
expansion but are out of scope to add in this detection-QA pass (adding
new Finding rules is new coverage, not a fix).

## Boolean/numeric/list unknown handling

- **Boolean**: audited the entire 9,800-line file for the unsafe
  "unconditional else with no `is None` guard" pattern — **zero matches**.
  114 occurrences of the safe explicit `is True`/`is False` pattern were
  found; the codebase already consistently avoids truthy/falsy coercion for
  Boolean fields.
- **Numeric**: found and fixed 3 unsafe `int(v or 0)` sites (see root-cause
  bug #2). No other numeric-to-zero coercion patterns found.
- **List**: `.get(..., [])` — zero matches in `risk_rules/aws.py`. List/set
  fields (`tag_keys`, `subnet_ids`, `security_group_ids`, etc.) are tracked
  as whole-value comparisons in `diff_service.py`; no accidental
  empty-list-as-unknown coercion found.

## Fail-soft and partial-sync behavior

`fetch()` itself (`aws.py:2625`) has no top-level try/except — it is a flat
sequence of ~31 `_fetch_*_resources` calls. All fail-soft behavior is
delegated to each individual method, which (verified across S3, EC2
networking, IAM, and every M40–M49 family) consistently wraps its own
boto3 calls in per-region/per-sub-call `try/except ConnectorError`/`except
Exception` blocks — a single bad bucket, region, or sub-resource never
aborts the whole service family or `fetch()` as a whole. This is a
convention, not enforced by `fetch()` itself. No custom retry/backoff
exists; `Throttling*` errors translate to `RateLimitError` and are deferred
to the next scheduled sync (no local exponential-backoff loop). Pagination
is unbounded (`while True:`/`NextToken`/`Marker` loops) across all ~30
paginated fetch methods — no artificial page caps found on inventory
fetches (separate, intentionally-bounded methods exist for
finding/event/log-object lookups, which are NOT called from `fetch()`).
"Service disabled" vs. "permission denied" vs. "empty result" is
distinguished in some but not all paths — best example:
`_fetch_iam_account_summary`'s password-policy fetch explicitly checks for
`NoSuchEntity` (valid "no policy configured" state) vs. other error codes;
GuardDuty/Security-Hub/Access-Analyzer treat an empty list result as "not
enabled," which is documented but doesn't separately distinguish "enabled
with zero resources." No evidence of one failed service producing mass
false removals or synthetic records — 403s on S3/IAM/etc. sub-calls
produce a `config_fetch_warnings` string and a `None`-valued field rather
than a fabricated posture.

## Sensitive-data minimization

Confirmed clean across the entire connector: **zero calls** to
`GetSecretValue`, `GetParameter`/`GetParameters`/`GetParameterHistory`,
`DownloadDBLogFilePortion`, Lambda `GetFunction` (source), KMS
`Decrypt`/`Encrypt`/`GenerateDataKey`, CloudWatch Logs `GetLogEvents`/
`FilterLogEvents`, GuardDuty/SecurityHub `GetFindings` (within `fetch()`),
or any EC2 user-data/RDS-credential/S3-object-content API. IAM/S3/SNS/SQS/
KMS/EventBridge/SCP policy documents are parsed in-memory only
(`_analyze_policy_document`) and reduced to a SHA-256 hash + derived
boolean/count summary — raw policy JSON is never persisted. Lambda/ECS
environment variables store **key names and counts only**, never values.
ARNs, DNS names, KMS key IDs, dashboard bodies, log-group names, filter
patterns, event patterns, SNS/SQS endpoints, and account emails are hashed
(not stored raw) in the M40+ modules. Access keys store only the public
`access_key_id`; secret key material is never in scope of any API called.

## Provider metadata

`_build_provider_metadata()` includes 2 AWS-specific stanzas:
`aws_route53_record` (adds `dns_record_type`, `zone_name`,
`dns_record_name` for classifier/UI use) and `aws_cloudtrail_trail` (adds
`is_organization_trail`, `is_multi_region_trail` to let the classifier
escalate org/multi-region logging-disabled events to critical). Real
`provider_metadata` is confirmed via this pass's new tests
(`test_aws_detection_qa.py`) to correctly carry `record_id`, `record_type`,
`record_name` for every classified Change — no test in this new file or
the pre-existing suite relies on `MagicMock`-injected metadata that would
mask an absent production value; every pre-existing AWS test file's
`_change()`/`_make_change()` helper builds a realistic `provider_metadata`
dict (not an empty/default MagicMock passthrough), and several
(`test_aws_risk_audit.py`, `test_aws_remaining_surfaces_audit.py`)
defensively set both `prev_value` and `old_value` to the same value —
confirmed via direct inspection of `Change` model (`app/models/change.py`)
that only `prev_value` is real; `old_value` never appears in production
code.

## Unsupported-capability review

| Capability | Status |
|---|---|
| AWS Organizations inventories | Partial — org/account/OU/SCP metadata emitted; SCP raw policy documents never stored (only derived summary) |
| SCP contents | GAP — only derived booleans/counts (`denies_full_admin_escape`, `wildcard_action_present`, etc.), never raw JSON |
| IAM Access Analyzer findings | GAP — schema+classifier exist, never emitted (see root-cause #3) |
| Credential-report raw data | N/A — not modeled; IAM data comes from `list_users`/`list_access_keys`, not `GenerateCredentialReport` |
| Raw CloudTrail events | N/A — never called (`LookupEvents` intentionally excluded from `fetch()`; a separate bounded `lookup_cloudtrail_events` helper exists but is not part of `fetch()`) |
| GuardDuty findings | GAP — detector/publishing-destination metadata emitted; `GetFindings` never called from `fetch()` (a separate bounded `list_guardduty_findings` helper exists outside `fetch()`) |
| Security Hub findings | Partial — `aws_securityhub_finding` schema+classifier exist but never emitted from `fetch()` (see root-cause #3); a separate bounded `list_security_hub_findings` helper exists outside `fetch()` |
| Inspector findings | N/A — not modeled at all |
| Macie findings | N/A — not modeled at all |
| Detective graphs | N/A — not modeled at all |
| Raw Config snapshots | N/A — `aws_config_recorder`/`aws_config_delivery_channel` schema+classifier exist but never emitted (see root-cause #3); no raw Config snapshot/history API ever called |
| Secrets Manager contents | GAP by design — `GetSecretValue` never called; only metadata |
| SSM secure-string contents | GAP by design — `GetParameter`/`GetParameters` never called; only metadata |
| Lambda source | N/A — `GetFunction`/code download never called |
| EC2 user data | N/A — `aws_ec2_instance` schema+classifier exist but never emitted (see root-cause #3); user data is never fetched regardless |
| RDS credentials | N/A — master username presence only (boolean), never the actual username/password/connection string |
| S3 object inventories | N/A — object listing/contents never accessed |
| ECR images | N/A — image pull/scan-result contents never accessed |
| EKS secrets | N/A — Kubernetes API never called |
| CloudWatch logs | GAP by design — log group/stream metadata only; `GetLogEvents`/`FilterLogEvents` never called |
| Application payloads | N/A — not modeled |
| Billing and cost data | N/A — not modeled at all |

## Tests run

- Exact AWS test files (22 files including this pass's new
  `test_aws_detection_qa.py`, 558 tests total): **558 passed**, 0 failed.
- `-k "aws and iam"`: 89 passed.
- `-k "aws and s3"`: 73 passed.
- `-k "aws and security_group"`: 6 passed.
- `-k "aws and rds"`: 26 passed.
- `-k "aws and cloudtrail"`: 13 passed.
- `-k "aws and kms"`: 20 passed.
- `-k "aws and lambda"`: 8 passed.
- `-k "aws and diff"`: 24 passed.
- `-k "aws and risk"`: 326 passed.

No timeouts, no zero-selection filters. `npx tsc --noEmit` was run because
`frontend/src/lib/securityRuleCatalog.ts` changed (PROVIDER_COVERAGE
surface-list fix) — **clean, no errors**.

## Detection matrix

Severity scale where applicable: `low` < `medium` < `high` < `critical`.

| Case | Category | Record type | Source API | Field(s) | Change/posture simulated | Connector emits evidence? | Detected by `compute_diff`? | Classifier route | Security Finding key | Finding reachable? | Registry/frontend parity | Test coverage | Status | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Root MFA | `aws_iam_account_summary` | IAM `GetAccountSummary` | `mfa_enabled_for_root` | disabled→enabled / enabled→disabled | Yes | Yes | `_classify_iam_account_summary_change` | `aws_root_mfa_disabled` | Yes | Full | `test_aws_risk_audit.py`, `test_aws_provider_depth_qa.py` | PASS | Explicit `is False` gate; None never fires |
| B | Root access key | `aws_iam_account_summary` | IAM `GetAccountSummary` | `root_access_keys_present` | present/absent | Yes | Yes | `_classify_iam_account_summary_change` | — (no dedicated Finding) | N/A | N/A | `test_aws_risk_audit.py` | GAP | Change-tracked, no Finding rule modeled; candidate for future expansion |
| C | Password policy | `aws_iam_account_summary` | IAM `GetAccountPasswordPolicy` | `password_min_length`, `password_reuse_prevention`, etc. | weakened/strengthened | Yes | Yes | `_classify_iam_account_summary_change` | — (no dedicated Finding) | N/A | N/A | `test_aws_risk_audit.py` | GAP | `NoSuchEntity` distinguished from other errors (valid "no policy" state) |
| D | IAM user MFA | `aws_iam_user` | IAM `ListMFADevices` | `mfa_enabled` | enabled/disabled | Yes | Yes | `_classify_iam_user_change` | — (per-user MFA rule intentionally deferred) | N/A | Confirmed via regression assertion in `test_aws_provider_depth_qa.py` | `test_aws_risk_audit.py` | PASS (GAP for Finding) | `aws_iam_user_mfa_disabled` intentionally not implemented |
| E | IAM access key active/inactive | `aws_iam_access_key` | IAM `ListAccessKeys`+`GetAccessKeyLastUsed` | `status`, `last_used_age_days` | active↔inactive, age crossing threshold | Yes | Yes | `_classify_iam_access_key_change` | `aws_access_key_unused` | Yes | Full | `test_aws_risk_audit.py` | PASS | `isinstance(age, int)` guard; None never fires |
| F | Broad IAM policy | `aws_iam_policy_attachment` | IAM `ListAttached*Policies` | `policy_arn` | AdministratorAccess / PowerUserAccess / IAMFullAccess attached | Yes | Yes | `_classify_iam_policy_attachment_change` | `aws_iam_admin_policy_attached`, `aws_iam_broad_policy_attached` | Yes | Full | `test_aws_provider_depth_qa.py` | PASS | Exact-ARN allowlist match, no truthy issue |
| G | S3 public/private | `aws_s3_bucket` | S3 `GetBucketPolicyStatus`/`GetBucketAcl` | `policy_status_is_public`, `acl_all_users_*` | public→private / private→public | Yes | Yes | `_classify_s3_change` | `aws_s3_public_policy`, `aws_s3_public_acl` | Yes | Full | `test_milestone37.py`, `test_aws_risk_audit.py` | PASS | Explicit `is True` checks |
| H | S3 public-access block | `aws_s3_bucket` | S3 `GetPublicAccessBlock` | `public_access_block_configured`, `block_public_acls` etc. | configured/removed | Yes | Yes | `_classify_s3_change` | (contributes to `aws_s3_public_*`) | Yes | Full | `test_milestone37.py` | PASS | Missing endpoint → `None`, not "public" |
| I | S3 encryption | `aws_s3_bucket` | S3 `GetBucketEncryption` | `encryption_enabled`, `encryption_algorithm` | enabled/disabled | Yes | Yes | `_classify_s3_change` | — (no dedicated Finding) | N/A | N/A | `test_milestone37.py` | GAP | Change-tracked, no Finding rule |
| J | S3 versioning | `aws_s3_bucket` | S3 `GetBucketVersioning` | `versioning_status` | enabled/suspended | Yes | Yes | `_classify_s3_change` | — | N/A | N/A | `test_milestone37.py` | PASS (low-signal) | |
| K | SG public SSH | `aws_security_group_rule` | EC2 `DescribeSecurityGroups` | `is_public`, `port_category="admin"` | 0.0.0.0/0:22 added/removed | Yes | Yes | `_classify_security_group_rule_change` | `aws_public_admin_port` | Yes | Full | `test_aws_risk_audit.py` | PASS | |
| L | SG public RDP | `aws_security_group_rule` | EC2 `DescribeSecurityGroups` | `is_public`, `port_category="admin"` | 0.0.0.0/0:3389 added/removed | Yes | Yes | `_classify_security_group_rule_change` | `aws_public_admin_port` | Yes | Full | `test_aws_risk_audit.py` | PASS | |
| M | SG public DB port | `aws_security_group_rule` | EC2 `DescribeSecurityGroups` | `is_public`, `port_category="database"` | 0.0.0.0/0:3306/5432/6379/9200/27017 | Yes | Yes | `_classify_security_group_rule_change` | `aws_public_database_port` | Yes | Full | `test_aws_risk_audit.py` | PASS | Severity `critical` |
| N | SG all ports/protocols | `aws_security_group_rule` | EC2 `DescribeSecurityGroups` | `port_category="all"`, protocol `-1` | full open added | Yes | Yes | `_classify_security_group_rule_change` | `aws_public_all_ports` | Yes | Full | `test_aws_risk_audit.py` | PASS | Severity `critical` |
| O | IPv6 public ingress | `aws_security_group_rule` | EC2 `DescribeSecurityGroups` | `cidr_ipv6`, `is_public` | `::/0` added | Yes | Yes | `_classify_security_group_rule_change` | same 3 SG rules | Yes | Full | `test_aws_risk_audit.py` | PASS | IPv4 and IPv6 both feed `is_public` |
| P | RDS public accessibility | `aws_rds_db_instance`/`aws_rds_db_cluster` | RDS `DescribeDBInstances`/`DescribeDBClusters` | `publicly_accessible` | False→True | Yes | Yes | `_classify_rds_db_instance_change`/`_classify_rds_db_cluster_change` | — (no dedicated Finding) | N/A | N/A | `test_milestone42.py`, `test_aws_remaining_surfaces_audit.py` | GAP (Finding); FIXED (added-branch) | "Added" branch now also inspects posture — see root-cause #5 |
| Q | RDS encryption | `aws_rds_db_instance` | RDS `DescribeDBInstances` | `storage_encrypted` | True→False | Yes | Yes | `_classify_rds_db_instance_change` | — | N/A | N/A | `test_milestone42.py` | GAP (Finding) | Change severity `critical` regardless |
| R | RDS deletion protection | `aws_rds_db_instance` | RDS `DescribeDBInstances` | `deletion_protection` | enabled/disabled | Yes | Yes | `_classify_rds_db_instance_change` | — | N/A | N/A | `test_milestone42.py` | PASS | |
| S | CloudTrail enabled/disabled | `aws_cloudtrail_trail` | CloudTrail `GetTrailStatus` | `is_logging` | True→False | Yes | Yes | `_classify_cloudtrail_trail_change` | — (no dedicated Finding) | N/A | N/A | `test_milestone67_5_aws_cloudtrail.py` | GAP (Finding) | Uses `is_organization_trail`/`is_multi_region_trail` metadata to escalate severity |
| T | CloudTrail multi-region | `aws_cloudtrail_trail` | CloudTrail `DescribeTrails` | `is_multi_region_trail` | True→False | Yes | Yes | `_classify_cloudtrail_trail_change` | — | N/A | N/A | `test_milestone67_5_aws_cloudtrail.py` | PASS | |
| U | CloudTrail log validation | `aws_cloudtrail_trail` | CloudTrail `DescribeTrails` | `log_file_validation_enabled` | True→False | Yes | Yes | `_classify_cloudtrail_trail_change` | — | N/A | N/A | `test_milestone67_5_aws_cloudtrail.py` | PASS | |
| V | AWS Config recorder | `aws_config_recorder` | Config `DescribeConfigurationRecorders` | `recording` | True→False | **No** (schema+classifier only) | Would be, if emitted | `_classify_config_recorder_change` | — | N/A | N/A | `test_aws_part2_risk_audit.py` (mock-only) | GAP | Root-cause #3 — never emitted by `fetch()` |
| W | GuardDuty enabled/disabled | `aws_guardduty_detector` | GuardDuty `GetDetector` | `status` | ENABLED→DISABLED | Yes | Yes | `_classify_guardduty_detector_change` | — (no dedicated Finding) | N/A | N/A | `test_milestone67_7_aws_security_hub.py` (adjacent) | GAP (Finding) | Empty `list_detectors` result = "not enabled," documented |
| X | KMS rotation | `aws_kms_key` | KMS `GetKeyRotationStatus` | `rotation_enabled` | True→False | Yes | Yes | `_classify_kms_key_change` | — (no dedicated Finding) | N/A | N/A | `test_milestone48*`-family, `test_aws_remaining_surfaces_audit.py` | GAP (Finding) | |
| Y | KMS scheduled deletion | `aws_kms_key` | KMS `DescribeKey` | `key_state`, `deletion_date_present` | ENABLED→PENDINGDELETION | Yes | Yes | `_classify_kms_key_change` | — | N/A | N/A | `test_aws_remaining_surfaces_audit.py` | PASS | Severity `critical`/`high` by sensitivity heuristic |
| Z | Lambda function URL public/private | `aws_lambda_function_url` | Lambda `GetFunctionUrlConfig` | `auth_type` | NONE↔AWS_IAM | Yes | Yes | `_classify_lambda_function_url_change` | — (no dedicated Finding) | N/A | N/A | `test_aws_part1_risk_audit.py` | GAP (Finding) | Missing config distinguished from denied access |
| AA | Lambda environment count only | `aws_lambda_function` | Lambda `ListFunctions` | `environment_key_count`, `environment_key_names` | count changed | Yes | Yes | `_classify_lambda_function_change` | — | N/A | N/A | `test_aws_part1_risk_audit.py` | PASS | Values never stored, only key names/counts |
| AB | Resource added already risky | `aws_rds_db_instance`, `aws_sqs_queue`, `aws_sns_topic`, `aws_ecr_repository`, `aws_kms_key`, `aws_eventbridge_event_bus`, `aws_rds_db_cluster` | various | `publicly_accessible`/`public_or_cross_account_policy`/`policy_is_public`/`wildcard_admin_policy` | new record already public/unencrypted | Yes | Yes | 7 classifiers | varies (none of these 7 have dedicated Findings) | N/A | N/A | `test_aws_detection_qa.py` (new) | **FIXED** | Root-cause #5 — "added" branches now inspect posture instead of flat "low" |
| AC | Protective resource removed | `aws_cloudtrail_trail`, `aws_guardduty_detector`, `aws_kms_key` | various | change_type=removed | trail/detector/key removed | Yes | Yes | respective classifiers | varies | varies | varies | `test_aws_risk_audit.py`, `test_aws_remaining_surfaces_audit.py` | PASS | Removal severity already escalates independent of prior posture |
| AD | Unknown Boolean | `aws_route53_hosted_zone` `private_zone`, `aws_cloudfront_distribution` `enabled`, others | various | boolean fields | value→`None` | Yes | Yes | Route53/CloudFront classifiers | — | N/A | N/A | `test_aws_detection_qa.py` (new) | PASS | Zero unconditional-else-without-`is None` patterns found file-wide |
| AE | Unknown numeric count | `aws_config_recorder` `resource_types_count`, `aws_acm_certificate` `days_to_expiry`/`subject_alternative_names_count` | various | numeric fields | value→`None` | Yes (post-fix, tracked) | Yes (post-fix) | Config recorder / ACM classifiers | — | N/A | N/A | `test_aws_detection_qa.py` (new) | **FIXED** | Root-cause #2 — `int(v or 0)` replaced with unknown-preserving check |
| AF | Unknown list vs. empty | `aws_iam_user` `tag_keys`, `aws_security_group` etc. | various | list fields | `None` vs `[]` | Yes | Yes | various | — | N/A | N/A | pre-existing suite | PASS | Whole-value list/set comparison; no `.get(..., [])` coercion found |
| AG | AccessDenied optional endpoint | `aws_s3_bucket` policy/ACL/encryption sub-calls | S3 | `config_fetch_warnings` | 403 on one sub-call | Yes | N/A (per-field warning, not a Change) | n/a | n/a | n/a | `test_milestone37.py` | PASS | Per-field `try/except`; bucket record still emitted with `None` for that field |
| AH | Unsupported region | `aws_region` | EC2 `DescribeRegions` | `opt_in_status` | 403 on describe-regions | Yes | Yes | `_classify_region_change` | — | N/A | N/A | connector-level test | PASS | Falls back to `source="selected"`, `opt_in_status="unknown"` |
| AI | Throttling behavior | (any paginated fetch) | various | n/a | `Throttling`/`RequestLimitExceeded` | Yes (translated) | n/a | n/a | n/a | n/a | connector-level (`_call_aws` error-code map) | PASS (documented) | No local retry/backoff; deferred to next scheduled sync — not a Change/Finding-pipeline concern |
| AJ | Real account/region provider metadata | all emitted types | various | `account_id`/`region` in `provider_metadata` | n/a | Yes | Yes | all classifiers | n/a | n/a | `test_aws_detection_qa.py` (new), pre-existing suite | PASS | Verified via real `compute_diff()`; no MagicMock-injected metadata masking absence |
| AK | Normalized-but-untracked field | `aws_service_inventory.future_surfaces`, `aws_cloudtrail_trail.trail_name` | n/a | n/a | intentionally excluded from tracked fields | Yes | No (by design) | n/a | n/a | n/a | diff_service audit | PASS | Both exclusions documented in-line with rationale |
| AL | Tracked-but-not-emitted field | 8 dark record types (EC2 instance, VPC flow log, Config recorder/delivery channel, Access Analyzer, Access Analyzer finding, SecurityHub finding, ACM certificate) | n/a | n/a | n/a | **No** | No (record never appears in any snapshot) | classifiers exist, unreachable | n/a | n/a | mock-only tests in `test_aws_part1/part2_risk_audit.py` | **FIXED** (tracking) / GAP (emission) | Root-cause #3/#4 |
| AM | Unreachable Finding | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `test_aws_provider_depth_qa.py` | PASS | None found — all 9 rules reachable given their record type is emitted |
| AN | Record without Finding | most of the 87 emitted types | various | various | various | Yes | Yes | various | none | N/A | N/A | pre-existing suite | PASS (documented GAP list) | Expected — Findings model a curated subset, not every field |
| AO | Registry/evaluator/frontend parity | all 9 rule keys | n/a | n/a | n/a | n/a | n/a | n/a | n/a | Full, pre- and post-fix | `test_aws_provider_depth_qa.py` | **FIXED** (2 diagnostics/surface-list gaps) | See Non-code findings |
| AP | Sensitive-data minimization | all 87 emitted types | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | connector-level audit + 2 safety greps | PASS | Zero secret-value/raw-policy/raw-log-content storage found |
| AQ | Runtime/security-event data separated from drift | GuardDuty/SecurityHub findings, CloudTrail events, CloudWatch logs | n/a | n/a | n/a | Partial (detector/hub metadata yes; findings/events/logs no) | n/a | n/a | n/a | n/a | connector-level audit | PASS (by design) | Findings/events/log-content APIs intentionally never called from `fetch()`; separate bounded helper methods exist outside `fetch()` for incident-signal correlation use cases |

## Files changed

- `app/services/risk_rules/aws.py` — 3 `previous_value`→`prev_value` fixes,
  3 unsafe-`int(v or 0)` fixes, 8 "added"-branch posture-inspection fixes.
- `app/services/diff_service.py` — added tracked-field entries for 8
  schema-defined/classifier-implemented-but-never-emitted record types.
- `app/services/security_coverage_service.py` — added
  `aws_iam_account_summary` diagnostic entry; added 5th surface to
  `PROVIDER_SURFACES["aws"]`.
- `frontend/src/lib/securityRuleCatalog.ts` — added 5th surface to
  `PROVIDER_COVERAGE`'s `"aws"` entry.
- `tests/test_aws_detection_qa.py` — new file, 18 tests exercising the real
  `compute_diff()` → `classify_aws_change()` pipeline for every fix above.
- `tests/reports/aws_detection_matrix.md` — this report.

## Live-validation recommendation

Recommend validating against a real AWS account with: (a) a Route53
public↔private hosted-zone toggle and a CloudFront `Enabled=false` update,
to confirm the `prev_value` fix now correctly detects these transitions in
production (previously silently broken); (b) an ACM certificate approaching
expiry alongside a temporary IAM permission gap that makes
`days_to_expiry` briefly unavailable, to confirm no false "certificate
expired" alert fires; (c) creation of a new public SQS queue / SNS topic /
ECR repository / KMS key with an already-public resource policy, to confirm
the new "added" posture-inspection branches fire at the correct elevated
severity in a live sync.

## Safe to push?

Yes, contingent on the same reviewer/CI gates as prior message-1 passes.
Do **not** push per this task's explicit instruction — commit only.
