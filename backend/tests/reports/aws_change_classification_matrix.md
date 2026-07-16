# AWS Change-Classification QA Matrix (message 2)

Scope: **exact Change classification correctness** for the 87 AWS record
types currently emitted by `AWSConnector.fetch()`. Detection/routing/
tracking-field structural correctness was covered in message 1 (committed
`667396c`, see `aws_detection_matrix.md`) and is not re-litigated here,
except where classification bugs required a corresponding structural note.
The 8 schema-defined/classifier-implemented-but-never-emitted record types
(`aws_ec2_instance`, `aws_vpc_flow_log`, `aws_config_recorder`,
`aws_config_delivery_channel`, `aws_access_analyzer`,
`aws_access_analyzer_finding`, `aws_securityhub_finding`,
`aws_acm_certificate`) remain documented GAPs — no endpoint coverage was
added for them in this pass.

## Graphify summary

All four required `graphify query` commands ran successfully via
`/Users/rohan/.local/bin/graphify`. The graph surfaced `classify_aws_change()`
(`risk_rules/aws.py`), `compute_diff()` (`diff_service.py`), `AWSConnector`,
`evaluate_record()`, and pre-existing test nodes (`TestACMCertificate`,
`TestS3RiskClassification`, `_rds_change()`, "CloudTrail/Route53 403 ->
fail-soft empty list"). The `prev_value` fixes and added-resource fixes from
`667396c`, and the new `aws_detection_matrix.md`/`test_aws_detection_qa.py`
artifacts, do **not** appear as distinct indexed nodes — confirming the
graph has not been refreshed since that commit and is stale relative to it,
as expected. No specific classification gap was directly suggested by the
graph beyond the architecture already known; it is coarse (module/class-
level only). Direct source reads, four parallel research agents (one of
which completed before an API session-limit interruption), and
programmatic scans of `risk_rules/aws.py` were authoritative for every
finding in this report.

## Total cases reviewed and status counts

| Metric | Count |
|---|---|
| Total classification cases reviewed | 96 |
| PASS (already correct) | 51 |
| FIXED (bug found and corrected) | 40 |
| GAP (documented, out of scope — dark record types or no Finding to compare) | 5 |
| FAIL | 0 |

## Root-cause bugs found and fixed

### 1. Security Finding vs. Change severity parity (5 fixes)

A background research agent (the only one of four parallel audit agents to
complete before an API session-limit interruption) systematically compared
all 9 AWS Security Finding rules against the equivalent `classify_aws_change()`
branch for the same fact pattern. Five cases had a fresh transition into a
bad state rated **below** the equivalent static Finding — meaning a resource
newly becoming risky would show a lower Change severity than a resource
already in that risky state at rest, which is backwards (a transition is at
least as noteworthy as the static condition):

| # | Location | Before | After | Rationale |
|---|---|---|---|---|
| 1 | `_classify_s3_change`, `public_principals_detected` | `critical` if sensitive-named else `high` | `critical` unconditionally | `aws_s3_public_policy` Finding fires critical unconditionally for this signal |
| 2 | `_classify_s3_change`, `acl_authenticated_users_write` | `high` | `critical` | `aws_s3_public_acl` Finding treats authenticated-write same as all-users-write |
| 3 | `_classify_s3_change`, `acl_authenticated_users_read` | `medium` | `high` | Finding treats authenticated-read same as all-users-read |
| 4 | `_classify_iam_policy_attachment_change`, PowerUserAccess/IAMFullAccess attach | `high` if sensitive-named else `medium` | `high` unconditionally | `aws_iam_broad_policy_attached` Finding fires high unconditionally |
| 5 | `_classify_iam_access_key_change`, `last_used_age_days` | `low`, threshold `> 90` | `medium`, threshold `>= 90` | Matches `aws_access_key_unused` Finding's severity and exact threshold (fixes an off-by-one at exactly 90 days) |

Two additional wording-only inconsistencies were reviewed and **not**
changed (severity already correctly Change ≥ Finding, only prose style
differs): `aws_public_admin_port` (Finding says "high" with an explicit
reachability-hedge; Change says "critical" without the hedge) and
`aws_root_mfa_disabled` (Finding uses soft "may require review" language at
high; Change uses "critical security risk" language at critical). Both are
intentional — the Change classifier has access to the specific transition
(a control was actively just weakened) whereas the Finding evaluates a
static snapshot, which supports Change being *at least as severe*, and a
stronger active-weakening framing is defensible. Documented, not fixed.

### 2. Widespread Boolean-unknown-as-restored/enabled bug (30 sites fixed)

A systematic regex + AST-adjacent scan of all 95 classifier functions found
a repeated shape: `if nv is False: <escalate>` followed immediately by an
**unconditional** `return (..., "<feature> was enabled/added/restored")`
with no `nv is None` branch. A missing/unavailable value (e.g. a permission
hiccup on re-fetch, or the field simply not yet observed) would silently
fall into the positive "was enabled"/"was restored" claim — the exact
"unknown described as restored" anti-pattern the task explicitly warns
against. Confirmed and fixed across:

| Service | Fields fixed |
|---|---|
| CloudTrail trail | `is_logging`, `is_multi_region_trail`, `include_global_service_events`, `is_organization_trail`, `log_file_validation_enabled`, `kms_key_id_present`, `sns_topic_name_present`, `cloud_watch_logs_enabled`, `management_events_enabled`/`include_management_events` (9 fields — the entire trail classifier) |
| Security Hub account | `hub_enabled`, `auto_enable_controls`, `finding_aggregator_present` |
| GuardDuty detector | all `_GUARDDUTY_PROTECTION_FEATURES` (s3/eks/malware/rds/lambda/runtime/ebs), `admin_account_present` |
| GuardDuty publishing destination | `kms_key_arn_present`, `destination_arn_present` |
| ECS | `container_insights_enabled` (cluster), `circuit_breaker_enabled`/`circuit_breaker_rollback` (service), `has_privileged_container`/`any_readonly_root_filesystem` (task definition) |
| EKS cluster | `public_access_fully_open`, `endpoint_public_access`, `endpoint_private_access`, `secrets_encryption_enabled`, `has_audit_logging` |
| ECR repository | `policy_is_public`, `scan_on_push`, `tag_immutable` |
| SQS queue | `public_or_cross_account_policy`, `sqs_managed_sse_enabled`, `kms_master_key_id_present`, `redrive_policy_present` |
| SNS topic / subscription | `public_or_cross_account_policy`, `kms_master_key_id_present` (topic); `filter_policy_present`, `redrive_policy_present` (subscription) |
| KMS key | `enabled`, `deletion_date_present`, `public_or_cross_account_policy`, `wildcard_admin_policy` |
| EventBridge rule / target | `schedule_expression_present`, `dlq_target_present`, `retry_policy_present` (rule); `dead_letter_config_present`, `retry_policy_present` (target) |
| Backup vault / recovery point | `locked`, `backup_vault_lock_configuration_present`, `encryption_key_arn_present` (vault); `is_encrypted`, `encryption_key_arn_present`, `lifecycle_present` (recovery point) |
| WAF Web ACL | `logging_enabled` |
| ELBv2 load balancer | `deletion_protection_enabled`, `access_logs_enabled`, `drop_invalid_header_fields_enabled` |
| KMS alias | `target_key_present` |
| Organizations SCP | `wildcard_action_present`/`wildcard_resource_present` |

Each fix adds an explicit `if nv is None: return ("medium"/"low", "Whether
<X> ... could not be determined. Review the current configuration
manually.")` branch, using "medium" for security-relevant fields and "low"
for operational/cosmetic ones, matching the existing severity conventions
in each function.

**Confirmed NOT bugs (three-way branching already correct), reviewed and
left unchanged:** S3's `_BPA_FIELD_LABELS`/`public_access_block_configured`/
`encryption_enabled`/`versioning_status`/`mfa_delete_status`/
`logging_enabled` fields (all already have explicit `is True`/`is False`/
generic-fallback branches), `_classify_subnet_change`'s
`map_public_ip_on_launch`, `_classify_route_table_change`'s
`has_igw_route` (both already three-way branched), and `aws_iam_user`'s
`active_key_count` default (a connector-guaranteed count field, not a
field that's ever legitimately absent from an emitted record).

### 3. Numeric unknown-as-zero (0 new fixes — already fixed in message 1)

Re-verified via fresh grep: zero remaining `int(v or 0)` sites in the file
beyond the 3 already fixed in message 1 (`_classify_config_recorder_change`,
`_classify_acm_certificate_change` ×2 — the latter's record type is one of
the 8 dark ones, fix retained for correctness but currently unreachable in
production).

### 4. Stale Change-field usage (0 remaining, guard added)

Re-verified via fresh grep across the whole file: zero occurrences of
`"old_value"`, `"previous_value"`, or `"prior_value"` in live code (only
the message-1 fix's explanatory comments remain, which reference the
strings in prose, not as dict keys). A permanent regression guard was
added: `TestNoStaleChangeFields.test_risk_rules_aws_never_reads_stale_
previous_value_fields` scans the source file (stripping comment lines) and
fails if any of the three stale field names ever reappear in live code.

## Boolean/numeric/list unknown fixes — summary

- **Boolean**: 30 sites fixed (see table above). All now explicitly handle
  `True`/`False`/`None` and never describe `None` as "enabled"/"disabled"/
  "restored"/"removed" without evidence.
- **Numeric**: 0 new fixes needed (message-1 fixes confirmed still correct
  and complete).
- **List**: reviewed `pv or []`/`nv or []` patterns (EKS `enabled_log_types`)
  — confirmed safe: the `isinstance(pv, list)` guard means a `None` value
  already falls to an empty set via the `else` branch, and the resulting
  "removed log types" diff is empty (not a false "all types removed"
  claim) when the previous state was genuinely unknown. No fix needed.

## IAM classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Root MFA disabled | `mfa_enabled_for_root` | True→False | critical | PASS |
| Root MFA restored | `mfa_enabled_for_root` | False→True | low, "improvement" | PASS |
| Root MFA unknown | `mfa_enabled_for_root` | known→None | medium, generic (no "disabled" claim) | PASS (already safe) |
| Root access key introduced | `root_access_keys_present` | False→True | critical | PASS |
| Root access key removed | `root_access_keys_present` | True→False | low, "improvement" | PASS |
| Password min length decreased | `password_min_length` | 14→8 | medium | PASS |
| Password min length increased | `password_min_length` | 8→14 | low | PASS |
| Password max age removed | `password_max_age` | set→None | medium | PASS |
| Password reuse prevention removed | `password_reuse_prevention` | set→None | medium | PASS |
| IAM user MFA disabled | `mfa_enabled` (`aws_iam_user`) | True→False | reviewed, no dedicated Finding | GAP (documented, per-user MFA rule intentionally deferred) |
| Access key active→inactive | `status` | Active→Inactive | low | PASS |
| Access key inactive→active | `status` | Inactive→Active | medium | PASS |
| Access key age crosses 90d | `last_used_age_days` | 10→90 | medium (was low, `>90`) | **FIXED** |
| Access key age just under threshold | `last_used_age_days` | →89 | low | PASS |
| AdministratorAccess attached | `policy_name` (added) | — | critical | PASS |
| PowerUserAccess attached, non-sensitive | `policy_name` (added) | — | high (was medium) | **FIXED** |
| Broad policy removed | `policy_name` (removed) | — | medium/low by sensitivity | PASS |
| IAM policy/role/user added | change_type=added | — | inspects posture where available | PASS |
| Raw IAM policy content in copy | n/a | n/a | never appears — only `policy_summary` derived booleans | PASS |

## S3 classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Bucket policy public | `policy_status_is_public` | False→True | critical | PASS |
| Bucket policy private | `policy_status_is_public` | True→False | low, improvement | PASS |
| Public principal, sensitive bucket | `public_principals_detected` | False→True | critical | PASS |
| Public principal, non-sensitive bucket | `public_principals_detected` | False→True | critical (was high) | **FIXED** |
| BPA weakened | `block_public_*` fields | True→False | high/medium by sensitivity | PASS |
| BPA config removed entirely | `public_access_block_configured` | True→False | high/medium | PASS |
| ACL all-users write | `acl_all_users_write` | False→True | critical | PASS |
| ACL authenticated-users write | `acl_authenticated_users_write` | False→True | critical (was high) | **FIXED** |
| ACL all-users read | `acl_all_users_read` | False→True | high | PASS |
| ACL authenticated-users read | `acl_authenticated_users_read` | False→True | high (was medium) | **FIXED** |
| ACL status unknown (permission removed) | any ACL field | known→None | low, "unavailable", no false-removal claim | PASS |
| Encryption disabled | `encryption_enabled` | True→False | high/medium by sensitivity | PASS |
| Encryption enabled | `encryption_enabled` | False→True | low, improvement | PASS |
| Encryption unknown | `encryption_enabled` | known→None | medium, generic (no false claim) | PASS (already safe) |
| Versioning suspended | `versioning_status` | Enabled→Suspended | high/medium | PASS |
| Versioning unavailable | `versioning_status` | known→None | low, "unavailable" (explicit guard comment) | PASS |
| Logging disabled | `logging_enabled` | True→False | medium/low | PASS |
| MFA delete disabled | `mfa_delete_status` | Enabled→Disabled | medium | PASS |
| Bucket added already public | change_type=added | — | inspects `policy_status_is_public`/ACLs | PASS (from message 1) |
| Bucket removed | change_type=removed | — | high | PASS |
| Object names/contents in copy | n/a | n/a | never appears | PASS |

## Networking classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Public SSH added | `has_public_ssh`/rule `is_public`+port 22 | — | critical/high | PASS |
| Public RDP added | rule `is_public`+port 3389 | — | critical/high | PASS |
| Public database port | rule `is_public`+port 3306/5432/6379/9200/27017 | — | high | PASS |
| All ports/protocols | `port_category="all"`, protocol -1 | — | critical | PASS |
| IPv6 public ingress | `cidr_ipv6="::/0"` | — | same severity path as IPv4 (`is_public` computed identically for both) | PASS |
| Exposure removed | rule removed/narrowed | — | improvement | PASS |
| Subnet public-IP-on-launch enabled | `map_public_ip_on_launch` | False→True | high | PASS |
| Subnet public-IP-on-launch disabled | `map_public_ip_on_launch` | True→False | low | PASS |
| Subnet field unknown | `map_public_ip_on_launch` | known→None | medium, generic (already 3-way branched) | PASS |
| Route table IGW route added | `has_igw_route` | False→True | high | PASS |
| Route table IGW route removed | `has_igw_route` | True→False | low | PASS |
| Route table field unknown | `has_igw_route` | known→None | medium, generic (already 3-way branched) | PASS |
| VPC/NACL/IGW added/removed | change_type | — | flat low/medium (no inherent risky/safe state) | PASS (intentional generic) |
| Security-group rule identity stable | `record_id` | — | hash of region/group/direction/protocol/ports/CIDR, excludes description | PASS |

## RDS classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Instance publicly accessible | `publicly_accessible` | False→True | critical/high | PASS |
| Instance encryption disabled | `storage_encrypted` | True→False | critical | PASS |
| Instance deletion protection removed | `deletion_protection` | True→False | reviewed (no dedicated Finding) | GAP |
| Instance added already public | change_type=added | — | inspects `publicly_accessible`/`storage_encrypted` | PASS (from message 1) |
| Cluster publicly accessible | `publicly_accessible` | False→True | critical/high (consistent with instance) | PASS |
| Cluster encryption disabled | `storage_encrypted` | True→False | critical (consistent with instance) | PASS |
| Cluster added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| DB subnet group/snapshot public | `publicly_accessible` | — | consistent pattern across all 5 RDS record types | PASS |
| No credentials/connection strings in copy | n/a | n/a | never appears — only presence booleans | PASS |

## CloudTrail / monitoring classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Trail stopped logging | `is_logging` | True→False | critical/high | PASS |
| Trail logging resumed | `is_logging` | False→True | low | PASS |
| Trail logging unknown | `is_logging` | known→None | medium, "could not be determined" (was: falsely "resumed") | **FIXED** |
| Multi-region disabled | `is_multi_region_trail` | True→False | critical/high | PASS |
| Multi-region unknown | `is_multi_region_trail` | known→None | medium (was: falsely "is now multi-region") | **FIXED** |
| Global service events disabled | `include_global_service_events` | True→False | critical/high | PASS |
| Global service events unknown | same field | known→None | medium (was: falsely "now includes") | **FIXED** |
| Organization trail demoted | `is_organization_trail` | True→False | critical | PASS |
| Organization trail unknown | same field | known→None | medium (was: falsely "is now an organization trail") | **FIXED** |
| Log validation disabled | `log_file_validation_enabled` | True→False | critical/high | PASS |
| Log validation unknown | same field | known→None | medium (was: falsely "was enabled") | **FIXED** |
| KMS encryption removed | `kms_key_id_present` | True→False | critical/high | PASS |
| KMS encryption unknown | same field | known→None | medium (was: falsely "was added") | **FIXED** |
| Management events disabled | `management_events_enabled` | True→False | critical/high | PASS |
| Management events unknown | same field | known→None | medium (was: falsely "re-enabled") | **FIXED** |
| GuardDuty protection feature disabled | any `_GUARDDUTY_PROTECTION_FEATURES` | True→False | high/medium | PASS |
| GuardDuty protection unknown | same fields | known→None | medium (was: falsely "was enabled") | **FIXED** |
| GuardDuty admin account removed | `admin_account_present` | True→False | high | PASS |
| Security Hub disabled | `hub_enabled` | True→False | critical/high | PASS |
| Security Hub unknown | `hub_enabled` | known→None | medium (was: falsely "was enabled") | **FIXED** |
| Permission denied vs. disabled | n/a | n/a | distinguished for password policy (`NoSuchEntity`); GuardDuty/SecurityHub empty-list = documented "not enabled" state | PASS (documented from message 1) |
| No log/finding content in copy | n/a | n/a | never appears | PASS |

## KMS classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Key disabled | `enabled` | True→False | critical/high | PASS |
| Key re-enabled | `enabled` | False→True | low | PASS |
| Key enabled-state unknown | `enabled` | known→None | medium (was: falsely "was re-enabled") | **FIXED** |
| Scheduled deletion added | `deletion_date_present` | False→True | critical/high | PASS |
| Scheduled deletion cancelled | `deletion_date_present` | True→False | low | PASS |
| Deletion-date unknown | same field | known→None | medium (was: falsely "was cancelled") | **FIXED** |
| Rotation disabled | `rotation_enabled` | True→False | high/medium | PASS |
| Public/cross-account policy introduced | `public_or_cross_account_policy` | False→True | critical/high | PASS |
| Public policy unknown | same field | known→None | medium (was: falsely "no longer grants") | **FIXED** |
| Wildcard admin policy introduced | `wildcard_admin_policy` | False→True | critical/high | PASS |
| Wildcard admin policy unknown | same field | known→None | medium (was: falsely "was removed") | **FIXED** |
| Key added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| No key material/raw policy in copy | n/a | n/a | never appears | PASS |

## Lambda classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Function URL auth NONE introduced | `auth_type` | AWS_IAM→NONE | critical | PASS |
| Function URL auth restored | `auth_type` | NONE→AWS_IAM | improvement | PASS |
| Environment key count changed | `environment_key_count` | — | reviewed, count-only (no values) | PASS |
| Environment sensitive key count increased | `environment_sensitive_key_count` | — | medium (name-heuristic only) | PASS |
| VPC attachment changed | `vpc_config_present` | — | reviewed | PASS |
| No source/env values/secrets in copy | n/a | n/a | never appears — key names/counts only | PASS |

## Queue / topic / repository / event-bus classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| SQS public policy introduced | `public_or_cross_account_policy` | False→True | critical/high | PASS |
| SQS public policy unknown | same field | known→None | medium (was: falsely "no longer grants") | **FIXED** |
| SQS managed SSE disabled | `sqs_managed_sse_enabled` | True→False | high/medium | PASS |
| SQS SSE unknown | same field | known→None | medium (was: falsely "was enabled") | **FIXED** |
| SQS KMS encryption removed | `kms_master_key_id_present` | True→False | high/medium | PASS |
| SQS KMS unknown | same field | known→None | medium (was: falsely "was enabled") | **FIXED** |
| SQS redrive policy removed | `redrive_policy_present` | True→False | high/medium | PASS |
| SQS redrive unknown | same field | known→None | medium (was: falsely "was added") | **FIXED** |
| SQS queue added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| SNS public policy introduced | `public_or_cross_account_policy` | False→True | critical/high | PASS |
| SNS public policy unknown | same field | known→None | medium (was: falsely "no longer grants") | **FIXED** |
| SNS KMS encryption removed | `kms_master_key_id_present` | True→False | high/medium | PASS |
| SNS topic added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| SNS subscription filter policy removed | `filter_policy_present` | True→False | medium/low | PASS |
| SNS subscription filter unknown | same field | known→None | low (was: falsely "was added") | **FIXED** |
| ECR public policy introduced | `policy_is_public` | False→True | critical/high | PASS |
| ECR public policy unknown | same field | known→None | medium (was: falsely "no longer publicly accessible") | **FIXED** |
| ECR scan-on-push disabled | `scan_on_push` | True→False | medium/low | PASS |
| ECR repository added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| EventBridge public policy introduced | `public_or_cross_account_policy` | False→True | critical/high | PASS |
| EventBridge bus added already public | change_type=added | — | inspects posture (from message 1) | PASS |
| EventBridge rule retry/DLQ removed | `retry_policy_present`/`dlq_target_present` | True→False | medium/low | PASS |
| EventBridge retry/DLQ unknown | same fields | known→None | low (was: falsely "was added"/"has a target") | **FIXED** |

## Route 53 and CloudFront classifications

| Case | Field | Transition | Expected | Result |
|---|---|---|---|---|
| Hosted zone public→private | `zone_type` | public→private | high | PASS (verified `prev_value` fix live) |
| Hosted zone private→public | `zone_type` | private→public | high | PASS |
| `private_zone` False→True | `private_zone` | False→True | high | PASS |
| Record count decreased | `resource_record_set_count` | 10→3 | high, shows real previous value | PASS (verified `prev_value` fix live) |
| TTL changed | `ttl` | 300→60 | low, `prev_value` correctly carries 300 | PASS (verified `prev_value` fix live) |
| Zone added/removed | change_type | — | low/critical | PASS |
| CloudFront `enabled` True→False | `enabled` | True→False | critical/high, `prev_value` correctly detects the transition | PASS (verified `prev_value` fix live — was completely undetectable before message-1 fix) |
| CloudFront `enabled` False→True | `enabled` | False→True | improvement | PASS |
| WAF association removed | `web_acl_id` | set→None | high | PASS |
| Distribution added/removed | change_type | — | low/critical | PASS |
| No classifier reads `previous_value` | n/a | n/a | zero occurrences, regression-guarded | PASS |

## Added/removed posture coverage

Confirmed for all 87 emitted families that added/removed Changes use
full-record shape (`new_value`/`prev_value` is the complete record dict,
never a scalar). Posture-inspecting "added" branches (from message 1,
re-verified): RDS instance/cluster, SQS queue, SNS topic, ECR repository,
KMS key, EventBridge event bus. Remaining "added" branches for lower-signal
record types (VPC, subnets, route tables, Lambda aliases, CloudWatch
alarms/dashboards, most ECS/EKS/Backup/Organizations sub-resources) stay
flat/generic — reviewed and confirmed these either carry no inherent
risky/safe base posture or would require exhaustive per-field calibration
reserved for a future pass; not expanded further in this message to avoid
scope creep beyond the confirmed bug classes above.

"Removed" branches were spot-checked for protective-vs-risky-resource
framing: CloudTrail trail removal (critical/high, escalates by
org/multi-region), GuardDuty detector, KMS key, Security Hub, Backup vault
all escalate consistently regardless of what's known about prior posture
(a protective control disappearing is inherently the higher-severity case
regardless of what state it was in). No case found where removing an
already-risky resource was rated as alarming as removing a healthy
protective one in a way that seemed backwards.

## Intentional generic fields (confirmed, not fixed)

`aws_cloudtrail_trail.trail_name` (excluded from tracked fields — identity
via hashed ARN), `aws_service_inventory.future_surfaces`, S3
`encryption_algorithm`/`versioning_status` fallback branches (generic
"changed" copy for non-boolean-shaped transitions), most CloudWatch
alarm/dashboard fields, ECS/EKS naming and tag fields, Organizations OU
hierarchy fields. All reviewed and confirmed intentionally generic — no
strong safe/unsafe direction exists for these fields.

## Accidental fallthrough fields (all fixed)

The 30-site Boolean-unknown bug (root-cause #2 above) was the only
systematic accidental-fallthrough class found. No other accidental generic
fallback was found beyond what message 1 already fixed (added-branch flat
severity) and what this pass fixed (Boolean unknown, Finding parity).

## Provider-metadata completeness

Re-verified via the new real-pipeline tests (`test_aws_change_
classification_qa.py`): `record_id`, `record_type`, `record_name` survive
correctly for every classified Change across CloudTrail, KMS, Security
Hub, EKS, SQS, ECR, and Backup record types tested. The two existing
AWS-specific `_build_provider_metadata()` stanzas (`aws_route53_record`:
`dns_record_type`/`zone_name`/`dns_record_name`; `aws_cloudtrail_trail`:
`is_organization_trail`/`is_multi_region_trail`) were exercised directly —
the CloudTrail stanza's `is_organization_trail`/`is_multi_region_trail`
correctly drive the trail classifier's `is_critical_trail` escalation
logic in the live tests. No MagicMock-injected metadata was used in any
new test; all built from realistic record dicts run through the real
`compute_diff()` pipeline. A deeper per-field metadata-dependency audit
(originally planned as a 4th parallel research agent) did not complete due
to an API session-limit interruption — flagged as a follow-up for a future
pass, not a known gap based on evidence gathered so far.

## Security Finding parity — final state

All 9 AWS Security Finding rules now have Change-classification severity
that is **equal to or higher than** the equivalent static Finding for the
same fact pattern (5 mismatches found and fixed, verified via the new
`TestS3FindingParity`/`TestIamFindingParity` tests). No risky transition
remains below its equivalent static Finding without a documented reason.

## Tests run

- Exact AWS test files (22 files including this pass's new
  `test_aws_change_classification_qa.py`, 575 tests total): **575 passed**,
  0 failed.
- `-k "aws and iam"`: 91 passed.
- `-k "aws and s3"`: 76 passed.
- `-k "aws and security_group"`: 6 passed.
- `-k "aws and rds"`: 26 passed.
- `-k "aws and cloudtrail"`: 16 passed.
- `-k "aws and kms"`: 21 passed.
- `-k "aws and lambda"`: 8 passed.
- `-k "aws and route53"`: 17 passed.
- `-k "aws and cloudfront"`: 9 passed.
- `-k "aws and diff"`: 24 passed.
- `-k "aws and risk"`: 327 passed.

No timeouts, no zero-selection filters. No frontend files were changed in
this pass, so `npx tsc --noEmit` was not run.

## Files changed

- `app/services/risk_rules/aws.py` — 5 Finding-parity fixes, 30
  Boolean-unknown fixes (see tables above).
- `tests/test_aws_change_classification_qa.py` — new file, 17 tests
  (stale-field regression guard + Finding-parity + Boolean-unknown
  coverage via the real `compute_diff()` pipeline).
- `tests/reports/aws_change_classification_matrix.md` — this report.

## Live-validation recommendation

Recommend validating against a real AWS account with: (a) a CloudTrail
trail whose `GetTrailStatus`/`DescribeTrails` call is temporarily denied
(simulating a permission hiccup) to confirm the Change reports "could not
be determined" rather than falsely "resumed"/"was enabled" for any of the
9 CloudTrail fields fixed in this pass; (b) an S3 bucket ACL granting
authenticated-users write/read access on a bucket without a "sensitive"
name, to confirm the Change now matches the Finding's critical/high
severity; (c) an IAM principal with a non-"sensitive" name receiving
PowerUserAccess, to confirm "high" severity; (d) an access key crossing
exactly the 90-day threshold, to confirm "medium" fires at the boundary.

## Safe to push?

Yes, contingent on the same reviewer/CI gates as prior passes. Do **not**
push per this task's explicit instruction — commit only.
