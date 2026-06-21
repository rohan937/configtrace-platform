"""AWS security exposure rules — M60.4 / expanded in M60.4.1+ (M60.4.2).

Every rule fires only on explicit, reliable normalized fields produced by the
AWS connector (app/connectors/aws.py + aws_schema.py). Evidence is metadata-only:
security-group ids/ports/CIDRs, bucket names + public-access booleans, IAM
policy/principal names, masked access-key ids. No secrets, key material, or
customer data are ever read.

Reachability language
---------------------
A public security-group rule means a resource *may* be exposed IF it is attached
to an internet-reachable resource. We do not have attachment / public-subnet /
public-IP / route context in the flattened rule record, so titles/descriptions
use careful "may expose / reachable from the internet" language and never claim
proven reachability.

Record types consumed
---------------------
- ``aws_security_group_rule``   → public ingress to admin / database / all ports
- ``aws_s3_bucket``             → public bucket policy / public ACL grants
- ``aws_iam_policy_attachment`` → AWS-managed AdministratorAccess /
                                  PowerUserAccess / IAMFullAccess attached
- ``aws_iam_account_summary``   → root account MFA not enabled
- ``aws_iam_access_key``        → active key unused for a long time

Deferred AWS rules (intentionally NOT implemented — see report)
---------------------------------------------------------------
* Public web ports (80/443/8080/8443): the flattened SG-rule record has no
  attachment / resource-name / public-IP context, so we cannot distinguish a
  normal public web server from an exposed internal service. Flagging all
  public 80/443 would be noise. Deferred.
* Default-security-group public ingress: requires joining the rule to its
  parent SG's NAME ("default"), which is on a different record. The evaluator
  processes records independently, so this cross-record correlation is not
  available. Deferred.
* WAF disabled / missing: "missing WAF" is absence-inference (we cannot know a
  resource *should* have a WAF). Deferred.
* IAM access key "never used": ``last_used_age_days is None`` is ambiguous
  (never used vs. last-used fetch failed), so we only flag a concrete stale age.
* S3 Block-Public-Access-not-configured on its own: weaker/noisier than the
  authoritative ``policy_status_is_public`` / ACL public-grant signals we use.
* Per-user IAM MFA disabled: the ``aws_iam_user`` record has ``mfa_enabled`` but
  NO console/login-profile or ``password_enabled`` field, so we cannot tell a
  service principal (legitimately MFA-less) from a console user. Firing on
  ``mfa_enabled=False`` alone would be noise, so this per-user rule is deferred
  until the connector emits console-access state. Root MFA (an unambiguous,
  always-console identity) is covered by ``aws_root_mfa_disabled``.
"""

from __future__ import annotations

from typing import Any

from app.connectors.aws_schema import (
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP_RULE,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule keys ────────────────────────────────────────────────────────────────
# NOTE: M60.4 used a single ``aws_public_admin_port`` key for admin/database/all.
# M60.4.2 splits these into category-specific keys for clearer, well-named
# findings (finding_key = rule_key:record_id, so each SG rule still dedupes
# independently). ``aws_public_admin_port`` is retained for the admin category.
_RULE_PUBLIC_ADMIN = "aws_public_admin_port"
_RULE_PUBLIC_DB = "aws_public_database_port"
_RULE_PUBLIC_ALL = "aws_public_all_ports"
_RULE_S3_PUBLIC_POLICY = "aws_s3_public_policy"
_RULE_S3_PUBLIC_ACL = "aws_s3_public_acl"
_RULE_IAM_ADMIN_ATTACHED = "aws_iam_admin_policy_attached"
_RULE_IAM_BROAD_ATTACHED = "aws_iam_broad_policy_attached"
_RULE_ROOT_MFA_DISABLED = "aws_root_mfa_disabled"
_RULE_ACCESS_KEY_STALE = "aws_access_key_unused"

# AWS-managed AdministratorAccess policy — exact ARN, not a keyword guess.
_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# AWS-managed policies that grant broad (non-AdministratorAccess) privilege.
# Exact ARN match → short policy name. Not keyword guesses.
_BROAD_AWS_MANAGED_POLICIES = {
    "arn:aws:iam::aws:policy/PowerUserAccess": "PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess": "IAMFullAccess",
}

# Admin port → human label (the connector's admin category = {22,3389,5985,5986}).
_ADMIN_PORT_LABELS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}

# Active access key unused for this many days is considered stale.
_STALE_KEY_DAYS = 90


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Dispatch a normalized AWS record to the relevant rule(s)."""
    if not isinstance(record, dict):
        return []
    rtype = record.get("record_type")
    if rtype == AWS_SECURITY_GROUP_RULE:
        return _eval_security_group_rule(record)
    if rtype == AWS_S3_BUCKET:
        return _eval_s3_bucket(record)
    if rtype == AWS_IAM_POLICY_ATTACHMENT:
        return _eval_iam_attachment(record)
    if rtype == AWS_IAM_ACCOUNT_SUMMARY:
        return _eval_iam_account_summary(record)
    if rtype == AWS_IAM_ACCESS_KEY:
        return _eval_access_key(record)
    return []


# ── Security group public ingress (M60.4 expanded) ───────────────────────────


def _eval_security_group_rule(record: dict[str, Any]) -> list[FindingCandidate]:
    if get_str(record, "direction") != "ingress":
        return []
    if record.get("is_public") is not True:
        return []
    category = get_str(record, "port_category")
    # web/other public ingress is intentionally NOT flagged (see deferred notes).
    if category not in ("admin", "database", "all"):
        return []

    cidr = get_str(record, "cidr_ipv4") or get_str(record, "cidr_ipv6")
    group_id = get_str(record, "group_id")
    record_id = get_str(record, "record_id") or None
    from_port = record.get("from_port")
    to_port = record.get("to_port")
    protocol = get_str(record, "protocol")

    if category == "all":
        rule_key = _RULE_PUBLIC_ALL
        severity = "critical"
        what = "all ports"
    elif category == "database":
        rule_key = _RULE_PUBLIC_DB
        severity = "critical"
        what = "database ports"
    else:  # admin
        rule_key = _RULE_PUBLIC_ADMIN
        # High (not critical): admin exposure is severe but reachability is not
        # proven from the rule alone.
        severity = "high"
        what = _admin_label(from_port, to_port)

    evidence: dict[str, Any] = {
        "rule": rule_key,
        "group_id": group_id,
        "direction": "ingress",
        "port_category": category,
        "cidr": cidr,
        "protocol": protocol,
    }
    if isinstance(from_port, int):
        evidence["from_port"] = from_port
    if isinstance(to_port, int):
        evidence["to_port"] = to_port

    return [
        FindingCandidate(
            provider="aws",
            rule_key=rule_key,
            finding_key=make_finding_key(rule_key, record_id),
            severity=severity,
            title=f"AWS security group exposes {what} to the internet",
            description=(
                f"An inbound security group rule allows public access "
                f"({cidr}) to {what}. If this group is attached to an "
                f"internet-reachable resource, those ports are reachable from "
                f"anywhere on the internet."
            ),
            evidence=evidence,
            remediation={
                "summary": "Restrict the rule to trusted source ranges.",
                "steps": [
                    "Replace 0.0.0.0/0 (or ::/0) with specific trusted CIDRs.",
                    "Prefer a bastion host or VPN for administrative access.",
                    "Remove the rule entirely if the exposure is unintended.",
                ],
            },
            record_id=record_id,
        )
    ]


def _admin_label(from_port: Any, to_port: Any) -> str:
    """Human label for an admin-category rule (SSH/RDP/WinRM when pinpointable)."""
    if isinstance(from_port, int) and from_port == to_port:
        return f"{_ADMIN_PORT_LABELS.get(from_port, 'an administrative port')} (port {from_port})"
    return "administrative ports"


# ── S3 public exposure (M60.4.2) ─────────────────────────────────────────────


def _eval_s3_bucket(record: dict[str, Any]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    bucket = get_str(record, "bucket_name") or get_str(record, "name")
    record_id = get_str(record, "record_id") or None

    # Public bucket POLICY — authoritative AWS signal. Only explicit True flags;
    # None means "could not determine" and is never treated as public.
    policy_public = record.get("policy_status_is_public") is True
    principals_public = record.get("public_principals_detected") is True
    if policy_public or principals_public:
        out.append(
            FindingCandidate(
                provider="aws",
                rule_key=_RULE_S3_PUBLIC_POLICY,
                finding_key=make_finding_key(_RULE_S3_PUBLIC_POLICY, record_id),
                severity="critical",
                title="AWS S3 bucket policy allows public access",
                description=(
                    f"The bucket '{bucket}' has a bucket policy that grants "
                    f"public access. Objects may be readable or writable by "
                    f"anyone on the internet."
                ),
                evidence={
                    "rule": _RULE_S3_PUBLIC_POLICY,
                    "bucket": bucket,
                    "policy_status_is_public": policy_public,
                    "public_principals_detected": principals_public,
                    "public_access_block_configured": record.get(
                        "public_access_block_configured"
                    ),
                },
                remediation={
                    "summary": "Remove public grants and enable Block Public Access.",
                    "steps": [
                        "Remove statements granting access to '*' / anonymous principals.",
                        "Enable S3 Block Public Access on the bucket (or account).",
                        "Serve public assets via CloudFront with OAC instead.",
                    ],
                },
                record_id=record_id,
            )
        )

    # Public ACL grants (AllUsers / AuthenticatedUsers). Write is critical.
    acl_write = (
        record.get("acl_all_users_write") is True
        or record.get("acl_authenticated_users_write") is True
    )
    acl_read = (
        record.get("acl_all_users_read") is True
        or record.get("acl_authenticated_users_read") is True
    )
    if acl_write or acl_read:
        out.append(
            FindingCandidate(
                provider="aws",
                rule_key=_RULE_S3_PUBLIC_ACL,
                finding_key=make_finding_key(_RULE_S3_PUBLIC_ACL, record_id),
                severity="critical" if acl_write else "high",
                title="AWS S3 bucket ACL grants public access",
                description=(
                    f"The bucket '{bucket}' has an ACL granting "
                    f"{'write' if acl_write else 'read'} access to all users or "
                    f"any authenticated AWS user."
                ),
                evidence={
                    "rule": _RULE_S3_PUBLIC_ACL,
                    "bucket": bucket,
                    "acl_all_users_read": record.get("acl_all_users_read"),
                    "acl_all_users_write": record.get("acl_all_users_write"),
                    "acl_authenticated_users_read": record.get(
                        "acl_authenticated_users_read"
                    ),
                    "acl_authenticated_users_write": record.get(
                        "acl_authenticated_users_write"
                    ),
                },
                remediation={
                    "summary": "Disable public ACL grants and enable Block Public Access.",
                    "steps": [
                        "Remove AllUsers / AuthenticatedUsers grants from the ACL.",
                        "Prefer bucket policies over ACLs; disable ACLs if possible.",
                        "Enable S3 Block Public Access.",
                    ],
                },
                record_id=record_id,
            )
        )

    return out


# ── IAM AdministratorAccess attachment (M60.4.2) ─────────────────────────────


def _eval_iam_attachment(record: dict[str, Any]) -> list[FindingCandidate]:
    policy_arn = get_str(record, "policy_arn")
    record_id = get_str(record, "record_id") or None
    ptype = get_str(record, "principal_type") or "principal"
    pname = get_str(record, "principal_name") or "an IAM principal"

    if policy_arn == _ADMIN_POLICY_ARN:
        return [
            FindingCandidate(
                provider="aws",
                rule_key=_RULE_IAM_ADMIN_ATTACHED,
                finding_key=make_finding_key(_RULE_IAM_ADMIN_ATTACHED, record_id),
                severity="high",
                title="AWS AdministratorAccess attached to an IAM principal",
                description=(
                    f"The AWS-managed AdministratorAccess policy is attached to the "
                    f"{ptype} '{pname}', granting full control over the account. "
                    f"Over-broad admin grants increase blast radius if the principal "
                    f"is compromised."
                ),
                evidence={
                    "rule": _RULE_IAM_ADMIN_ATTACHED,
                    "principal_type": ptype,
                    "principal_name": pname,
                    "policy_name": get_str(record, "policy_name") or "AdministratorAccess",
                },
                remediation={
                    "summary": "Replace AdministratorAccess with least-privilege policies.",
                    "steps": [
                        "Scope permissions to only what the principal needs.",
                        "Use permission boundaries / SCPs to cap privilege.",
                        "Reserve AdministratorAccess for break-glass roles with MFA.",
                    ],
                },
                record_id=record_id,
            )
        ]

    # Other AWS-managed broad policies (PowerUserAccess, IAMFullAccess). Exact
    # ARN match against an allowlist — never a substring/keyword guess.
    short_name = _BROAD_AWS_MANAGED_POLICIES.get(policy_arn)
    if short_name is not None:
        return [
            FindingCandidate(
                provider="aws",
                rule_key=_RULE_IAM_BROAD_ATTACHED,
                finding_key=make_finding_key(_RULE_IAM_BROAD_ATTACHED, record_id),
                severity="high",
                title="Broad AWS managed policy attached",
                description=(
                    "An AWS managed policy with broad permissions is attached to a "
                    "principal. This configuration may require review."
                ),
                evidence={
                    "rule": _RULE_IAM_BROAD_ATTACHED,
                    "principal_type": ptype,
                    "policy_name": short_name,
                    "broad_policy_category": "aws_managed_broad",
                },
                remediation={
                    "summary": "Replace broad managed policies with least-privilege grants.",
                    "steps": [
                        "Scope permissions to only what the principal needs.",
                        "Use permission boundaries / SCPs to cap privilege.",
                        "Reserve broad grants for narrowly scoped, audited roles.",
                    ],
                },
                record_id=record_id,
            )
        ]

    return []


# ── Root account MFA posture (M60.4.x QA) ────────────────────────────────────


def _eval_iam_account_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    """Flag the AWS root account when MFA is explicitly not enabled.

    Fires only on an explicit ``mfa_enabled_for_root is False``. ``None`` (could
    not determine) is never treated as disabled. Account-level posture only — no
    account id or username is emitted in evidence.
    """
    if record.get("mfa_enabled_for_root") is not False:
        return []

    record_id = get_str(record, "record_id") or None

    return [
        FindingCandidate(
            provider="aws",
            rule_key=_RULE_ROOT_MFA_DISABLED,
            finding_key=make_finding_key(_RULE_ROOT_MFA_DISABLED, record_id),
            severity="high",
            title="Root account MFA not enabled",
            description=(
                "The AWS root account does not have MFA enabled. This "
                "configuration may require review."
            ),
            evidence={
                "rule": _RULE_ROOT_MFA_DISABLED,
                "root_mfa_enabled": False,
            },
            remediation={
                "summary": "Enable MFA on the AWS root account.",
                "steps": [
                    "Sign in as the root user and register a hardware or virtual MFA device.",
                    "Avoid using the root account for day-to-day operations.",
                    "Store root credentials and MFA securely as break-glass only.",
                ],
            },
            record_id=record_id,
        )
    ]


# ── Stale active IAM access key (M60.4.2) ────────────────────────────────────


def _eval_access_key(record: dict[str, Any]) -> list[FindingCandidate]:
    if get_str(record, "status") != "Active":
        return []
    age = record.get("last_used_age_days")
    # Only flag a CONCRETE stale age (None = never-used-or-unknown → skip).
    if not isinstance(age, int) or age < _STALE_KEY_DAYS:
        return []

    record_id = get_str(record, "record_id") or None
    key_id = get_str(record, "access_key_id") or get_str(record, "name")
    username = get_str(record, "username") or "an IAM user"

    return [
        FindingCandidate(
            provider="aws",
            rule_key=_RULE_ACCESS_KEY_STALE,
            finding_key=make_finding_key(_RULE_ACCESS_KEY_STALE, record_id),
            severity="medium",
            title="AWS access key is active but unused",
            description=(
                f"An active access key for '{username}' has not been used in "
                f"{age} days. Long-lived unused keys are an unnecessary standing "
                f"credential that increases exposure if leaked."
            ),
            evidence={
                "rule": _RULE_ACCESS_KEY_STALE,
                "username": username,
                # Show only the last 4 chars of the key id (an identifier, not
                # the secret). Key name avoids the UI's secret-masking heuristic
                # so the suffix stays visible.
                "key_id_last4": key_id[-4:] if len(key_id) >= 4 else key_id,
                "status": "Active",
                "last_used_age_days": age,
            },
            remediation={
                "summary": "Rotate or remove the unused access key.",
                "steps": [
                    "Confirm the key is no longer needed.",
                    "Deactivate it, then delete after a safe window.",
                    "Prefer short-lived role credentials over long-lived keys.",
                ],
            },
            record_id=record_id,
        )
    ]
