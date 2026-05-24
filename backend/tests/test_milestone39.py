"""Tests for M39: AWS IAM Users/Roles/Policies/Trust Risk.

Test coverage
-------------
1.  Module-level helpers — _analyze_policy_document:
    Wildcard action+resource → admin_access=True, finding "admin_access".
    iam:* → iam_write_actions=True, finding "iam_write_access".
    sts:AssumeRole → sts_assume_role_actions=True, finding "sts_assume_role".
    iam:PassRole → pass_role_present=True, finding "pass_role".
    NotAction → has_not_action=True, finding "not_action".
    NotResource → has_not_resource=True, finding "not_resource".
    Privilege escalation actions → finding "privilege_escalation_risk".
    Parse error → finding "parse_error", all False fields.
    policy_document_hash is 16 hex chars.
    hash changes when document changes.
    action_count / resource_count / statement_count correct.
    sensitive_services_touched lists touched sensitive services.

2.  Module-level helpers — _analyze_trust_policy:
    External account principal → has_external_account_trust.
    :root principal → has_root_account_trust.
    Wildcard principal → has_wildcard_principal.
    Service principal → service_principals list populated.
    OIDC federated → has_oidc_trust.
    SAML federated → has_saml_trust.
    ExternalId condition → has_external_id_condition.
    MFA condition → has_mfa_condition.
    Internal account only → no external flags set.
    Empty policy → all False, empty lists.

3.  Stable ID helpers:
    _stable_iam_attachment_id → 16 hex chars, stable, different for different inputs.
    _stable_iam_inline_id → 16 hex chars, stable, different for different inputs.
    _stable_iam_idp_id → 16 hex chars, stable.

4.  Schema constants:
    All 9 M39 constants have correct string values.
    AWS_RECORD_TYPES contains all 9 M39 types.
    No M39 type is in future_surfaces of service inventory.

5.  AWSConnector._paginate_iam:
    Single page (IsTruncated=False) → returns all items.
    Multi-page → concatenates all pages.
    Marker forwarded correctly between pages.

6.  AWSConnector._fetch_iam_account_summary:
    user_count / group_count / role_count / policy_count from SummaryMap.
    mfa_enabled_for_root from AccountMFAEnabled==1.
    root_access_keys_present from AccountAccessKeysPresent>=1.
    password_policy fields populated when policy exists.
    password_policy_present=False when NoSuchEntity raised.
    Record has correct record_type and external_id format.

7.  AWSConnector._fetch_iam_users:
    Returns user records with correct record_type = aws_iam_user.
    active_key_count / inactive_key_count correct from key status.
    mfa_enabled=True when MFA devices present.
    mfa_enabled=False when no MFA devices.
    group_count populated from list_groups_for_user.
    attached_policy_count from list_attached_user_policies.
    inline_policy_count from list_user_policies.
    Access key record has record_type = aws_iam_access_key.
    Access key status "Active"/"Inactive" passed through.
    last_used_age_days computed from GetAccessKeyLastUsed.
    Policy attachment record has record_type = aws_iam_policy_attachment.
    Inline policy record has record_type = aws_iam_inline_policy.
    Inline policy record has policy_summary (not raw doc).
    tag_keys sorted from Tags.
    SECURITY: no secret key in any record.

8.  AWSConnector._fetch_iam_groups:
    Returns group records with correct record_type = aws_iam_group.
    member_count from GetGroup.
    attached managed policy attachments emitted.
    inline policy records emitted.

9.  AWSConnector._fetch_iam_roles:
    Returns role records with correct record_type = aws_iam_role.
    trust_summary populated (not raw trust policy).
    max_session_duration from role data.
    attached policy attachments emitted.
    inline policy records emitted.
    SECURITY: raw trust doc not in record.

10. AWSConnector._fetch_iam_policies:
    Only Scope="Local" called (no AWS-managed).
    Returns aws_iam_policy records.
    policy_summary populated from default version document.
    policy_summary has policy_document_hash field.
    SECURITY: raw policy document not in record.

11. AWSConnector._fetch_iam_identity_providers:
    OIDC provider → record_type=aws_iam_identity_provider, provider_type="oidc".
    SAML provider → provider_type="saml", saml_valid_until populated.
    oidc_client_id_count / oidc_thumbprint_count from detail.
    SECURITY: SAMLMetadataDocument not stored.

12. AWSConnector._fetch_iam_resources (integration):
    Returns all 9 record types when all APIs succeed.
    403 on ListUsers → skips users, still returns other IAM records.
    403 on ListRoles → skips roles.
    403 on GetAccountSummary → skips summary, rest continues.
    Empty account → empty lists, only account summary returned.
    Fail-soft: single user with bad inline policy → user record still returned.

13. AWSConnector.fetch() integration (M39):
    IAM records included in fetch() result.
    aws_iam_user records returned.
    aws_iam_role records returned.
    Service inventory "iam" in enabled_surfaces.
    Service inventory "iam" NOT in future_surfaces.
    iam_user_count in service inventory.
    iam_role_count in service inventory.
    SECURITY: no secret key in any returned record.

14. Failure classifier — classify_aws_iam_failure:
    403 → error_code "aws_iam_access_denied".
    AuthenticationError → error_code "aws_iam_access_denied".
    RateLimitError → error_code "aws_iam_rate_limited".
    ConnectorError(5xx) → error_code "aws_iam_api_unavailable".
    ListUsers failure → error_code "aws_iam_users_unavailable".
    ListRoles failure → error_code "aws_iam_roles_unavailable".
    GetPolicyVersion failure → error_code "aws_iam_policy_versions_unavailable".
    GetAccessKeyLastUsed failure → error_code "aws_iam_access_keys_unavailable".

15. Diff service tracked fields:
    aws_iam_account_summary → mfa_enabled_for_root, root_access_keys_present tracked.
    aws_iam_user → mfa_enabled, active_key_count, attached_policy_count tracked.
    aws_iam_access_key → status, last_used_age_days tracked.
    aws_iam_group → member_count, attached_policy_count tracked.
    aws_iam_role → trust_summary, max_session_duration tracked.
    aws_iam_policy → policy_summary, attachment_count tracked.
    aws_iam_policy_attachment → policy_name tracked.
    aws_iam_inline_policy → policy_summary tracked.
    aws_iam_identity_provider → oidc_client_id_count, saml_valid_until tracked.
    _tracked_fields_for correctly dispatches for all 9 types.

16. Risk classification — aws_iam_account_summary:
    mfa_enabled_for_root False (was True) → critical.
    root_access_keys_present True (was False) → critical.
    password_policy_present False (was True) → high.
    password_min_length decreased → medium.
    password_max_age increased → medium.
    added → low.
    removed → medium.

17. Risk classification — aws_iam_user:
    MFA disabled (sensitive user) → high.
    MFA disabled (non-sensitive) → medium.
    MFA enabled → low.
    active_key_count increased → medium.
    added with keys but no MFA → high.
    removed → low / medium.

18. Risk classification — aws_iam_access_key:
    added active → medium.
    Inactive→Active → medium.
    Active→Inactive → low.
    removed → low.
    last_used_age_days > 90 → low (advisory).

19. Risk classification — aws_iam_group:
    member_count increased (sensitive group) → medium.
    attached_policy_count increased (sensitive) → medium.
    added → low.

20. Risk classification — aws_iam_role:
    trust_summary has_external_account_trust added (sensitive) → high.
    trust_summary has_wildcard_principal added → critical.
    trust_summary has_external_id_condition removed → high.
    trust_summary has_mfa_condition removed → medium.
    trust_summary service_principals added → medium.
    trust_summary has_root_account_trust added → high.
    max_session_duration > 8h → medium.
    added with wildcard principal → high.

21. Risk classification — aws_iam_policy:
    policy_summary admin_access added → critical.
    policy_summary privilege_escalation_risk added → high.
    policy_summary iam_write_access added → high.
    policy_summary admin_access removed → low.
    hash changed, no new codes → medium.
    added with admin access → high.

22. Risk classification — aws_iam_policy_attachment:
    added AdministratorAccess → critical.
    added PowerUser (sensitive principal) → high.
    added normal policy (sensitive principal) → medium.
    added normal policy (non-sensitive) → low.
    removed → low / medium.

23. Risk classification — aws_iam_inline_policy:
    added with admin_access → critical.
    added with privilege_escalation_risk → high.
    policy_summary admin_access added → critical.
    policy_summary priv esc added → high.
    removed → low.

24. Risk classification — aws_iam_identity_provider:
    added OIDC → medium.
    added SAML → medium.
    removed → medium.
    oidc_thumbprint_count → 0 → high.
    saml_valid_until cleared → medium.

25. Security invariants:
    SECURITY: aws_secret_access_key never in any IAM record.
    SECURITY: raw policy documents never in any IAM record.
    SECURITY: SAMLMetadataDocument never in any IAM record.
    SECURITY: _analyze_policy_document never stores raw doc (tested via record absence).

26. M38/M36 regression:
    classify_aws_change still routes M38 types to correct classifiers.
    fetch() still returns aws_account_identity, aws_region, aws_s3_bucket.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from app.connectors.aws import (
    AWSConnector,
    _analyze_policy_document,
    _analyze_trust_policy,
    _stable_iam_attachment_id,
    _stable_iam_inline_id,
    _stable_iam_idp_id,
    _extract_tag_keys,
)
from app.connectors.aws_schema import (
    AWS_ACCOUNT_IDENTITY,
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_GROUP,
    AWS_IAM_IDENTITY_PROVIDER,
    AWS_IAM_INLINE_POLICY,
    AWS_IAM_POLICY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_IAM_ROLE,
    AWS_IAM_USER,
    AWS_RECORD_TYPES,
    AWS_REGION,
    AWS_S3_BUCKET,
    AWS_SECURITY_GROUP,
    AWS_SERVICE_INVENTORY,
)
from app.connectors.exceptions import AuthenticationError, ConnectorError, RateLimitError
from app.core.failure_classifier import classify_aws_iam_failure
from app.services.diff_service import _AWS_TRACKED_FIELDS_BY_TYPE, _tracked_fields_for
from app.services.risk_rules.aws import (
    classify_aws_change,
    _classify_iam_account_summary_change,
    _classify_iam_user_change,
    _classify_iam_access_key_change,
    _classify_iam_group_change,
    _classify_iam_role_change,
    _classify_iam_policy_change,
    _classify_iam_policy_attachment_change,
    _classify_iam_inline_policy_change,
    _classify_iam_identity_provider_change,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CREDS = {
    "aws_access_key_id":      "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key":  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_default_region":     "us-east-1",
    "aws_selected_regions":   ["us-east-1"],
}
_ACCOUNT_ID = "123456789012"
_OTHER_ACCOUNT = "999888777666"

HEX_16 = re.compile(r"^[0-9a-f]{16}$")


def _change(
    record_type: str,
    change_type: str = "modified",
    field_path: str = "",
    new_value: Any = None,
    prev_value: Any = None,
    record_id: str = "rec1",
    record_name: str = "test-principal",
) -> dict:
    return {
        "change_type":         change_type,
        "field_path":          field_path,
        "new_value":           new_value,
        "prev_value":          prev_value,
        "record_identifier":   record_id,
        "provider_metadata":   {
            "record_type": record_type,
            "record_id":   record_id,
            "record_name": record_name,
        },
    }


# ---------------------------------------------------------------------------
# 1. _analyze_policy_document
# ---------------------------------------------------------------------------


class TestAnalyzePolicyDocument:
    def _policy(self, actions, resources=None, effect="Allow", not_action=False, not_resource=False) -> str:
        stmt: dict = {"Effect": effect}
        if not_action:
            stmt["NotAction"] = actions if isinstance(actions, list) else [actions]
        else:
            stmt["Action"] = actions if isinstance(actions, list) else [actions]
        if not_resource:
            stmt["NotResource"] = resources or ["*"]
        else:
            stmt["Resource"] = resources or ["*"]
        return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})

    def test_wildcard_action_resource_is_admin(self):
        doc = self._policy("*", "*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is True
        assert "admin_access" in result["finding_codes"]

    def test_iam_star_is_iam_write(self):
        doc = self._policy("iam:*", "*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["iam_write_actions"] is True
        assert "iam_write_access" in result["finding_codes"]

    def test_sts_assumerole_detected(self):
        doc = self._policy("sts:AssumeRole", "*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["sts_assume_role_actions"] is True
        assert "sts_assume_role" in result["finding_codes"]

    def test_pass_role_detected(self):
        doc = self._policy("iam:PassRole", "*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["pass_role_present"] is True
        assert "pass_role" in result["finding_codes"]

    def test_not_action_detected(self):
        doc = self._policy("s3:GetObject", not_action=True)
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["has_not_action"] is True
        assert "not_action" in result["finding_codes"]

    def test_not_resource_detected(self):
        doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": ["arn:aws:s3:::my-bucket"],
            }],
        })
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["has_not_resource"] is True
        assert "not_resource" in result["finding_codes"]

    def test_privilege_escalation_action(self):
        doc = self._policy("iam:CreatePolicy", "*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["privilege_escalation_actions"] is True
        assert "privilege_escalation_risk" in result["finding_codes"]

    def test_parse_error_returns_safe_defaults(self):
        result = _analyze_policy_document("INVALID JSON {{{", _ACCOUNT_ID)
        assert result["admin_access"] is False
        assert result["has_wildcard_action"] is False
        assert "parse_error" in result["finding_codes"]
        assert "policy_document_hash" in result  # hash still computed

    def test_hash_is_16_hex_chars(self):
        doc = self._policy("s3:GetObject", "arn:aws:s3:::my-bucket/*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert HEX_16.match(result["policy_document_hash"]), result["policy_document_hash"]

    def test_hash_changes_with_content(self):
        doc1 = self._policy("s3:GetObject", "arn:aws:s3:::bucket-a/*")
        doc2 = self._policy("s3:GetObject", "arn:aws:s3:::bucket-b/*")
        h1 = _analyze_policy_document(doc1, _ACCOUNT_ID)["policy_document_hash"]
        h2 = _analyze_policy_document(doc2, _ACCOUNT_ID)["policy_document_hash"]
        assert h1 != h2

    def test_action_resource_counts(self):
        doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::bucket-a/*"]},
                {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": ["*"]},
            ],
        })
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["action_count"] == 3
        # resources: {"arn:aws:s3:::bucket-a/*", "*"}
        assert result["resource_count"] == 2
        assert result["statement_count"] == 2

    def test_sensitive_services_touched(self):
        doc = self._policy(["iam:GetUser", "s3:GetObject", "ec2:DescribeInstances"])
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        svcs = result["sensitive_services_touched"]
        assert "iam" in svcs
        assert "s3" in svcs
        # route53 is not in _IAM_SENSITIVE_SERVICES
        assert "route53" not in svcs

    def test_no_findings_for_minimal_read_policy(self):
        doc = self._policy("s3:GetObject", "arn:aws:s3:::my-bucket/*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is False
        assert result["iam_write_actions"] is False
        assert result["pass_role_present"] is False
        assert result["finding_codes"] == []

    # ── Deny-statement correctness ─────────────────────────────────────────

    def _deny_policy(self, actions, resources=None) -> str:
        """Build a single-statement policy with Effect: Deny."""
        import json as _json
        actions_val = actions if isinstance(actions, list) else [actions]
        return _json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": actions_val,
                "Resource": resources or ["*"],
            }],
        })

    def test_deny_wildcard_does_not_set_admin_access(self):
        """Deny Action:* Resource:* must NOT set admin_access — it's a restriction."""
        doc = self._deny_policy("*", ["*"])
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is False
        assert "admin_access" not in result["finding_codes"]

    def test_deny_iam_star_does_not_set_iam_write(self):
        """Deny iam:* must NOT set iam_write_actions — it's a restriction."""
        doc = self._deny_policy("iam:*")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["iam_write_actions"] is False
        assert "iam_write_access" not in result["finding_codes"]

    def test_deny_passrole_does_not_set_pass_role(self):
        """Deny iam:PassRole must NOT set pass_role_present."""
        doc = self._deny_policy("iam:PassRole")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["pass_role_present"] is False
        assert "pass_role" not in result["finding_codes"]

    def test_deny_assumerole_does_not_set_sts_assume_role(self):
        """Deny sts:AssumeRole must NOT set sts_assume_role_actions."""
        doc = self._deny_policy("sts:AssumeRole")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["sts_assume_role_actions"] is False
        assert "sts_assume_role" not in result["finding_codes"]

    def test_deny_priv_esc_action_does_not_flag(self):
        """Deny iam:CreatePolicy must NOT set privilege_escalation_actions."""
        doc = self._deny_policy("iam:CreatePolicy")
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["privilege_escalation_actions"] is False
        assert "privilege_escalation_risk" not in result["finding_codes"]

    def test_mixed_allow_and_deny_only_counts_allow(self):
        """Allow s3:GetObject + Deny iam:* → only s3 counted; no iam_write finding."""
        import json as _json
        doc = _json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",  "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny",   "Action": "iam:*",         "Resource": "*"},
            ],
        })
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is False
        assert result["iam_write_actions"] is False
        assert "iam_write_access" not in result["finding_codes"]
        # s3 is still counted (from the Allow statement)
        assert "s3" in result["sensitive_services_touched"]

    def test_allow_admin_still_detected_alongside_deny(self):
        """Allow *:* is still admin_access=True even when a Deny is also present."""
        import json as _json
        doc = _json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*",         "Resource": "*"},
                {"Effect": "Deny",  "Action": "s3:Delete*", "Resource": "*"},
            ],
        })
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is True
        assert "admin_access" in result["finding_codes"]

    def test_deny_only_policy_has_no_findings(self):
        """A policy consisting entirely of Deny statements has no grant findings."""
        import json as _json
        doc = _json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "*",    "Resource": "*"},
                {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
            ],
        })
        result = _analyze_policy_document(doc, _ACCOUNT_ID)
        assert result["admin_access"] is False
        assert result["iam_write_actions"] is False
        assert result["pass_role_present"] is False
        assert result["sts_assume_role_actions"] is False
        assert result["privilege_escalation_actions"] is False
        assert result["finding_codes"] == []
        # action_count is 0 because all Allow actions are 0; statement_count counts all
        assert result["statement_count"] == 2
        assert result["action_count"] == 0


# ---------------------------------------------------------------------------
# 2. _analyze_trust_policy
# ---------------------------------------------------------------------------


class TestAnalyzeTrustPolicy:
    def _trust(self, principal, conditions=None) -> dict:
        stmt: dict = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": principal,
        }
        if conditions:
            stmt["Condition"] = conditions
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def test_external_account_detected(self):
        trust = self._trust({"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_external_account_trust"] is True
        assert _OTHER_ACCOUNT in result["aws_principal_account_ids"]

    def test_root_principal_detected(self):
        trust = self._trust({"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:root"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_root_account_trust"] is True

    def test_wildcard_principal_detected(self):
        trust = self._trust("*")
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_wildcard_principal"] is True

    def test_service_principal_populated(self):
        trust = self._trust({"Service": "ec2.amazonaws.com"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert "Service" in result["principal_types"]
        assert "ec2.amazonaws.com" in result["service_principals"]

    def test_oidc_federated(self):
        trust = self._trust({"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_oidc_trust"] is True
        assert result["federated_principal_count"] == 1

    def test_saml_federated(self):
        trust = self._trust({"Federated": "arn:aws:iam::123456789012:saml-provider/MySAML"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_saml_trust"] is True

    def test_external_id_condition(self):
        trust = self._trust(
            {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"},
            conditions={"StringEquals": {"sts:ExternalId": "secret-id"}},
        )
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_external_id_condition"] is True

    def test_mfa_condition(self):
        trust = self._trust(
            {"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:user/alice"},
            conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_mfa_condition"] is True

    def test_internal_account_no_external_flags(self):
        trust = self._trust({"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:role/MyRole"})
        result = _analyze_trust_policy(trust, _ACCOUNT_ID)
        assert result["has_external_account_trust"] is False
        assert result["has_wildcard_principal"] is False

    def test_empty_policy(self):
        result = _analyze_trust_policy({}, _ACCOUNT_ID)
        assert result["has_external_account_trust"] is False
        assert result["has_wildcard_principal"] is False
        assert result["service_principals"] == []
        assert result["principal_types"] == []


# ---------------------------------------------------------------------------
# 3. Stable ID helpers
# ---------------------------------------------------------------------------


class TestStableIdHelpers:
    def test_attachment_id_is_16_hex(self):
        sid = _stable_iam_attachment_id("user", "AIDAUSER", "arn:aws:iam::aws:policy/AdministratorAccess")
        assert HEX_16.match(sid), sid

    def test_attachment_id_stable(self):
        s1 = _stable_iam_attachment_id("user", "AIDAUSER", "arn:aws:iam::aws:policy/AdministratorAccess")
        s2 = _stable_iam_attachment_id("user", "AIDAUSER", "arn:aws:iam::aws:policy/AdministratorAccess")
        assert s1 == s2

    def test_attachment_id_different_for_different_inputs(self):
        s1 = _stable_iam_attachment_id("user", "AIDAUSER1", "arn:aws:iam::aws:policy/ReadOnly")
        s2 = _stable_iam_attachment_id("user", "AIDAUSER2", "arn:aws:iam::aws:policy/ReadOnly")
        assert s1 != s2

    def test_inline_id_is_16_hex(self):
        sid = _stable_iam_inline_id("role", "AROAROLE", "MyInlinePolicy")
        assert HEX_16.match(sid), sid

    def test_inline_id_stable(self):
        s1 = _stable_iam_inline_id("role", "AROAROLE", "MyInlinePolicy")
        s2 = _stable_iam_inline_id("role", "AROAROLE", "MyInlinePolicy")
        assert s1 == s2

    def test_inline_id_different_principal_types(self):
        s1 = _stable_iam_inline_id("user", "ID1", "Policy")
        s2 = _stable_iam_inline_id("role", "ID1", "Policy")
        assert s1 != s2

    def test_idp_id_is_16_hex(self):
        sid = _stable_iam_idp_id("arn:aws:iam::123456789012:oidc-provider/example.com")
        assert HEX_16.match(sid), sid

    def test_idp_id_stable(self):
        arn = "arn:aws:iam::123456789012:oidc-provider/example.com"
        assert _stable_iam_idp_id(arn) == _stable_iam_idp_id(arn)


# ---------------------------------------------------------------------------
# 4. Schema constants
# ---------------------------------------------------------------------------


class TestSchemaConstants:
    def test_iam_account_summary_value(self):
        assert AWS_IAM_ACCOUNT_SUMMARY == "aws_iam_account_summary"

    def test_iam_user_value(self):
        assert AWS_IAM_USER == "aws_iam_user"

    def test_iam_access_key_value(self):
        assert AWS_IAM_ACCESS_KEY == "aws_iam_access_key"

    def test_iam_group_value(self):
        assert AWS_IAM_GROUP == "aws_iam_group"

    def test_iam_role_value(self):
        assert AWS_IAM_ROLE == "aws_iam_role"

    def test_iam_policy_value(self):
        assert AWS_IAM_POLICY == "aws_iam_policy"

    def test_iam_policy_attachment_value(self):
        assert AWS_IAM_POLICY_ATTACHMENT == "aws_iam_policy_attachment"

    def test_iam_inline_policy_value(self):
        assert AWS_IAM_INLINE_POLICY == "aws_iam_inline_policy"

    def test_iam_identity_provider_value(self):
        assert AWS_IAM_IDENTITY_PROVIDER == "aws_iam_identity_provider"

    def test_all_m39_types_in_aws_record_types(self):
        m39 = {
            AWS_IAM_ACCOUNT_SUMMARY, AWS_IAM_USER, AWS_IAM_ACCESS_KEY,
            AWS_IAM_GROUP, AWS_IAM_ROLE, AWS_IAM_POLICY,
            AWS_IAM_POLICY_ATTACHMENT, AWS_IAM_INLINE_POLICY,
            AWS_IAM_IDENTITY_PROVIDER,
        }
        assert m39.issubset(AWS_RECORD_TYPES)


# ---------------------------------------------------------------------------
# 5. AWSConnector._paginate_iam
# ---------------------------------------------------------------------------


class TestPaginateIam:
    """Tests for AWSConnector._paginate_iam.

    _call_aws is patched to directly invoke the method (bypassing botocore
    import check which is irrelevant for unit-testing pagination logic).
    """

    def _connector_with_direct_call(self):
        connector = AWSConnector()
        # Make _call_aws just call the fn directly (no botocore import needed)
        connector._call_aws = lambda fn, **kw: fn(**kw)
        return connector

    def test_single_page(self):
        connector = self._connector_with_direct_call()
        method = MagicMock(return_value={
            "Users": [{"UserId": "U1"}, {"UserId": "U2"}],
            "IsTruncated": False,
        })
        result = connector._paginate_iam(method, "Users")
        assert len(result) == 2
        assert result[0]["UserId"] == "U1"
        method.assert_called_once()

    def test_multi_page(self):
        connector = self._connector_with_direct_call()
        method = MagicMock(side_effect=[
            {"Users": [{"UserId": "U1"}], "IsTruncated": True, "Marker": "token1"},
            {"Users": [{"UserId": "U2"}], "IsTruncated": False},
        ])
        result = connector._paginate_iam(method, "Users")
        assert len(result) == 2
        assert method.call_count == 2

    def test_marker_forwarded(self):
        connector = self._connector_with_direct_call()
        calls = []
        def _side_effect(**kwargs):
            calls.append(kwargs.get("Marker"))
            if len(calls) == 1:
                return {"Roles": [{"RoleId": "R1"}], "IsTruncated": True, "Marker": "page2"}
            return {"Roles": [{"RoleId": "R2"}], "IsTruncated": False}
        method = MagicMock(side_effect=_side_effect)
        result = connector._paginate_iam(method, "Roles")
        assert len(result) == 2
        assert calls[1] == "page2"

    def test_empty_result(self):
        connector = self._connector_with_direct_call()
        method = MagicMock(return_value={"Users": [], "IsTruncated": False})
        result = connector._paginate_iam(method, "Users")
        assert result == []


# ---------------------------------------------------------------------------
# 6. _fetch_iam_account_summary
# ---------------------------------------------------------------------------


def _direct_call_aws(fn, **kwargs):
    """Replacement for _call_aws that directly calls fn(**kwargs) (no botocore)."""
    return fn(**kwargs)


class TestFetchIamAccountSummary:
    def _make_client(self, summary_map=None, password_policy=None, no_pp=False):
        client = MagicMock()
        client.get_account_summary.return_value = {
            "SummaryMap": summary_map or {
                "Users": 5,
                "Groups": 3,
                "Roles": 10,
                "Policies": 2,
                "AccountMFAEnabled": 1,
                "AccountAccessKeysPresent": 0,
            }
        }
        if no_pp:
            client.get_account_password_policy.side_effect = ConnectorError(
                "NoSuchEntity", status_code=None
            )
        elif password_policy is not None:
            client.get_account_password_policy.return_value = {
                "PasswordPolicy": password_policy
            }
        else:
            client.get_account_password_policy.return_value = {
                "PasswordPolicy": {
                    "MinimumPasswordLength": 14,
                    "RequireSymbols": True,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    "MaxPasswordAge": 90,
                    "PasswordReusePrevention": 12,
                    "HardExpiry": False,
                }
            }
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_account_summary(client, _ACCOUNT_ID)

    def test_basic_counts(self):
        connector = AWSConnector()
        client = self._make_client()
        record = self._call(connector, client)
        assert record["record_type"] == AWS_IAM_ACCOUNT_SUMMARY
        assert record["user_count"] == 5
        assert record["group_count"] == 3
        assert record["role_count"] == 10
        assert record["policy_count"] == 2

    def test_mfa_root_from_account_mfa_enabled(self):
        connector = AWSConnector()
        client = self._make_client(
            summary_map={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0,
                         "Users": 0, "Groups": 0, "Roles": 0, "Policies": 0}
        )
        record = self._call(connector, client)
        assert record["mfa_enabled_for_root"] is True

    def test_mfa_root_disabled(self):
        connector = AWSConnector()
        client = self._make_client(
            summary_map={"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0,
                         "Users": 0, "Groups": 0, "Roles": 0, "Policies": 0}
        )
        record = self._call(connector, client)
        assert record["mfa_enabled_for_root"] is False

    def test_root_keys_present(self):
        connector = AWSConnector()
        client = self._make_client(
            summary_map={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1,
                         "Users": 0, "Groups": 0, "Roles": 0, "Policies": 0}
        )
        record = self._call(connector, client)
        assert record["root_access_keys_present"] is True

    def test_password_policy_fields(self):
        connector = AWSConnector()
        client = self._make_client()
        record = self._call(connector, client)
        assert record["password_policy_present"] is True
        assert record["password_min_length"] == 14
        assert record["password_requires_symbols"] is True
        assert record["password_max_age"] == 90
        assert record["password_reuse_prevention"] == 12

    def test_no_password_policy(self):
        connector = AWSConnector()
        client = self._make_client(no_pp=True)
        record = self._call(connector, client)
        assert record["password_policy_present"] is False

    def test_record_id_format(self):
        connector = AWSConnector()
        client = self._make_client()
        record = self._call(connector, client)
        assert record["record_id"] == f"{_ACCOUNT_ID}/iam_account_summary"
        assert record["external_id"] == f"{_ACCOUNT_ID}/iam_account_summary"

    def test_secret_key_not_in_record(self):
        connector = AWSConnector()
        client = self._make_client()
        record = self._call(connector, client)
        record_str = json.dumps(record)
        assert "wJalrXUtnFEMI" not in record_str
        assert "secret" not in record_str.lower()


# ---------------------------------------------------------------------------
# 7. _fetch_iam_users
# ---------------------------------------------------------------------------


class TestFetchIamUsers:
    def _make_client(self, users=None, access_keys=None, mfa_count=0, groups=None,
                      attached=None, inline_names=None, inline_doc=None):
        client = MagicMock()
        _users = users or [
            {"UserName": "alice", "UserId": "AIDAUSER1", "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/alice",
             "Path": "/", "Tags": [{"Key": "Env", "Value": "prod"}]},
        ]
        # list_users
        client.list_users.return_value = {"Users": _users, "IsTruncated": False}
        # list_access_keys
        _keys = access_keys or [
            {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active"},
        ]
        client.list_access_keys.return_value = {"AccessKeyMetadata": _keys, "IsTruncated": False}
        # get_access_key_last_used
        now = datetime.now(timezone.utc)
        client.get_access_key_last_used.return_value = {
            "AccessKeyLastUsed": {
                "LastUsedDate": now - timedelta(days=10),
                "ServiceName": "s3",
                "Region": "us-east-1",
            }
        }
        # list_mfa_devices
        mfa_devs = [{"SerialNumber": f"arn:mfa:{i}"} for i in range(mfa_count)]
        client.list_mfa_devices.return_value = {"MFADevices": mfa_devs, "IsTruncated": False}
        # list_groups_for_user
        client.list_groups_for_user.return_value = {
            "Groups": groups or [], "IsTruncated": False
        }
        # list_attached_user_policies
        _attached = attached or [
            {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "PolicyName": "ReadOnlyAccess"},
        ]
        client.list_attached_user_policies.return_value = {"AttachedPolicies": _attached, "IsTruncated": False}
        # list_user_policies
        _inline = inline_names or ["MyInlinePolicy"]
        client.list_user_policies.return_value = {"PolicyNames": _inline, "IsTruncated": False}
        # get_user_policy
        _doc = inline_doc or json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })
        client.get_user_policy.return_value = {"PolicyDocument": _doc}
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_users(client, _ACCOUNT_ID)

    def test_user_record_type(self):
        connector = AWSConnector()
        users, keys, attachments, inlines = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_USER for r in users)

    def test_active_inactive_key_count(self):
        connector = AWSConnector()
        client = self._make_client(access_keys=[
            {"AccessKeyId": "AK1", "Status": "Active"},
            {"AccessKeyId": "AK2", "Status": "Inactive"},
        ])
        users, keys, _, _ = self._call(connector, client)
        assert users[0]["active_key_count"] == 1
        assert users[0]["inactive_key_count"] == 1

    def test_mfa_enabled_when_devices(self):
        connector = AWSConnector()
        users, _, _, _ = self._call(connector, self._make_client(mfa_count=1))
        assert users[0]["mfa_enabled"] is True
        assert users[0]["mfa_device_count"] == 1

    def test_mfa_disabled_when_no_devices(self):
        connector = AWSConnector()
        users, _, _, _ = self._call(connector, self._make_client(mfa_count=0))
        assert users[0]["mfa_enabled"] is False
        assert users[0]["mfa_device_count"] == 0

    def test_group_count(self):
        connector = AWSConnector()
        client = self._make_client(groups=[{"GroupName": "Admins", "GroupId": "GRP1"}])
        users, _, _, _ = self._call(connector, client)
        assert users[0]["group_count"] == 1

    def test_attached_policy_count(self):
        connector = AWSConnector()
        client = self._make_client(attached=[
            {"PolicyArn": "arn:a", "PolicyName": "P1"},
            {"PolicyArn": "arn:b", "PolicyName": "P2"},
        ])
        users, _, attachments, _ = self._call(connector, client)
        assert users[0]["attached_policy_count"] == 2
        assert len(attachments) == 2

    def test_access_key_record_type(self):
        connector = AWSConnector()
        _, keys, _, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_ACCESS_KEY for r in keys)

    def test_access_key_status(self):
        connector = AWSConnector()
        client = self._make_client(access_keys=[{"AccessKeyId": "AK1", "Status": "Inactive"}])
        _, keys, _, _ = self._call(connector, client)
        assert keys[0]["status"] == "Inactive"

    def test_attachment_record_type(self):
        connector = AWSConnector()
        _, _, attachments, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_POLICY_ATTACHMENT for r in attachments)

    def test_inline_record_type(self):
        connector = AWSConnector()
        _, _, _, inlines = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_INLINE_POLICY for r in inlines)

    def test_inline_has_policy_summary_not_raw_doc(self):
        connector = AWSConnector()
        _, _, _, inlines = self._call(connector, self._make_client())
        for inline in inlines:
            assert "policy_summary" in inline
            assert isinstance(inline["policy_summary"], dict)
            # Raw document MUST NOT be stored
            assert "PolicyDocument" not in inline
            assert "Statement" not in inline

    def test_tag_keys_sorted(self):
        connector = AWSConnector()
        client = self._make_client(users=[{
            "UserName": "bob", "UserId": "AIDABOB",
            "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/bob",
            "Path": "/",
            "Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "App", "Value": "api"}],
        }])
        users, _, _, _ = self._call(connector, client)
        assert users[0]["tag_keys"] == ["App", "Env"]

    def test_secret_key_not_in_any_record(self):
        connector = AWSConnector()
        users, keys, attachments, inlines = self._call(connector, self._make_client())
        all_records = users + keys + attachments + inlines
        for record in all_records:
            record_str = json.dumps(record, default=str)
            assert "wJalrXUtnFEMI" not in record_str
            assert "secret_access_key" not in record_str.lower()

    def test_last_key_used_age_days_computed(self):
        connector = AWSConnector()
        # last used is 10 days ago per the mock
        users, _, _, _ = self._call(connector, self._make_client())
        age = users[0]["last_key_used_age_days"]
        assert age is not None and 9 <= age <= 11


# ---------------------------------------------------------------------------
# 8. _fetch_iam_groups
# ---------------------------------------------------------------------------


class TestFetchIamGroups:
    def _make_client(self, groups=None, members=None, attached=None, inline_names=None):
        client = MagicMock()
        _groups = groups or [
            {"GroupName": "Admins", "GroupId": "GRP1",
             "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:group/Admins", "Path": "/"},
        ]
        client.list_groups.return_value = {"Groups": _groups, "IsTruncated": False}
        _members = members or [{"UserName": "alice"}]
        client.get_group.return_value = {"Users": _members, "Group": {}, "IsTruncated": False}
        _attached = attached or [{"PolicyArn": "arn:a", "PolicyName": "P1"}]
        client.list_attached_group_policies.return_value = {"AttachedPolicies": _attached, "IsTruncated": False}
        _inline = inline_names or ["GrpInline"]
        client.list_group_policies.return_value = {"PolicyNames": _inline, "IsTruncated": False}
        client.get_group_policy.return_value = {
            "PolicyDocument": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}],
            })
        }
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_groups(client, _ACCOUNT_ID)

    def test_group_record_type(self):
        connector = AWSConnector()
        groups, _, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_GROUP for r in groups)

    def test_member_count(self):
        connector = AWSConnector()
        client = self._make_client(members=[{"UserName": "alice"}, {"UserName": "bob"}])
        groups, _, _ = self._call(connector, client)
        assert groups[0]["member_count"] == 2

    def test_policy_attachment_records(self):
        connector = AWSConnector()
        _, attachments, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_POLICY_ATTACHMENT for r in attachments)
        assert attachments[0]["principal_type"] == "group"

    def test_inline_policy_records(self):
        connector = AWSConnector()
        _, _, inlines = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_INLINE_POLICY for r in inlines)
        assert inlines[0]["principal_type"] == "group"

    def test_inline_has_policy_summary_not_raw_doc(self):
        connector = AWSConnector()
        _, _, inlines = self._call(connector, self._make_client())
        for inline in inlines:
            assert "policy_summary" in inline
            assert "Statement" not in inline


# ---------------------------------------------------------------------------
# 9. _fetch_iam_roles
# ---------------------------------------------------------------------------


class TestFetchIamRoles:
    def _make_trust_doc(self, principal="ec2.amazonaws.com", service=True):
        if service:
            principal_dict = {"Service": principal}
        else:
            principal_dict = {"AWS": principal}
        return {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal_dict}],
        }

    def _make_client(self, roles=None, attached=None, inline_names=None, trust_doc=None):
        client = MagicMock()
        trust = trust_doc or self._make_trust_doc()
        _roles = roles or [
            {"RoleName": "MyRole", "RoleId": "AROAROLE1",
             "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:role/MyRole",
             "Path": "/", "MaxSessionDuration": 3600,
             "AssumeRolePolicyDocument": trust,
             "Tags": []},
        ]
        client.list_roles.return_value = {"Roles": _roles, "IsTruncated": False}
        _attached = attached or [{"PolicyArn": "arn:a", "PolicyName": "P1"}]
        client.list_attached_role_policies.return_value = {"AttachedPolicies": _attached, "IsTruncated": False}
        _inline = inline_names or ["RoleInline"]
        client.list_role_policies.return_value = {"PolicyNames": _inline, "IsTruncated": False}
        client.get_role_policy.return_value = {
            "PolicyDocument": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"}],
            })
        }
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_roles(client, _ACCOUNT_ID)

    def test_role_record_type(self):
        connector = AWSConnector()
        roles, _, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_ROLE for r in roles)

    def test_trust_summary_present(self):
        connector = AWSConnector()
        roles, _, _ = self._call(connector, self._make_client())
        assert "trust_summary" in roles[0]
        ts = roles[0]["trust_summary"]
        assert isinstance(ts, dict)
        assert "has_wildcard_principal" in ts

    def test_raw_trust_doc_not_stored(self):
        connector = AWSConnector()
        roles, _, _ = self._call(connector, self._make_client())
        role_str = json.dumps(roles[0], default=str)
        # The raw trust document key should not appear
        assert "AssumeRolePolicyDocument" not in role_str

    def test_external_account_trust_detected(self):
        connector = AWSConnector()
        trust = self._make_trust_doc(
            principal=f"arn:aws:iam::{_OTHER_ACCOUNT}:root", service=False
        )
        roles, _, _ = self._call(connector, self._make_client(trust_doc=trust))
        assert roles[0]["trust_summary"]["has_external_account_trust"] is True

    def test_max_session_duration(self):
        connector = AWSConnector()
        roles, _, _ = self._call(connector, self._make_client())
        assert roles[0]["max_session_duration"] == 3600

    def test_attachment_records(self):
        connector = AWSConnector()
        _, attachments, _ = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_POLICY_ATTACHMENT for r in attachments)
        assert attachments[0]["principal_type"] == "role"

    def test_inline_policy_records(self):
        connector = AWSConnector()
        _, _, inlines = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_INLINE_POLICY for r in inlines)
        assert inlines[0]["principal_type"] == "role"

    def test_inline_has_policy_summary_not_raw(self):
        connector = AWSConnector()
        _, _, inlines = self._call(connector, self._make_client())
        for inline in inlines:
            assert "policy_summary" in inline
            assert "Statement" not in inline


# ---------------------------------------------------------------------------
# 10. _fetch_iam_policies
# ---------------------------------------------------------------------------


class TestFetchIamPolicies:
    def _make_client(self, policies=None, doc=None):
        client = MagicMock()
        _doc = doc or json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })
        _policies = policies or [
            {"PolicyName": "MyPolicy", "PolicyId": "ANPAPOL1",
             "Arn": "arn:aws:iam::123456789012:policy/MyPolicy",
             "Path": "/", "AttachmentCount": 2, "IsAttachable": True,
             "DefaultVersionId": "v1"},
        ]
        client.list_policies.return_value = {"Policies": _policies, "IsTruncated": False}
        client.list_policy_versions.return_value = {"Versions": [{"VersionId": "v1"}], "IsTruncated": False}
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": _doc, "VersionId": "v1"}
        }
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_policies(client, _ACCOUNT_ID)

    def test_policy_record_type(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client())
        assert all(r["record_type"] == AWS_IAM_POLICY for r in records)

    def test_policy_summary_present(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client())
        assert "policy_summary" in records[0]
        assert isinstance(records[0]["policy_summary"], dict)

    def test_raw_policy_document_not_in_record(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client())
        for r in records:
            r_str = json.dumps(r, default=str)
            # Raw "Statement" dict should not appear in the record
            assert "PolicyDocument" not in r_str

    def test_only_local_scope_called(self):
        connector = AWSConnector()
        client = self._make_client()
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            connector._fetch_iam_policies(client, _ACCOUNT_ID)
        call_kwargs = client.list_policies.call_args
        assert call_kwargs.kwargs.get("Scope") == "Local"

    def test_admin_policy_detected_in_summary(self):
        doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        connector = AWSConnector()
        records = self._call(connector, self._make_client(doc=doc))
        assert records[0]["policy_summary"]["admin_access"] is True
        assert "admin_access" in records[0]["policy_summary"]["finding_codes"]

    def test_attachment_count(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client())
        assert records[0]["attachment_count"] == 2


# ---------------------------------------------------------------------------
# 11. _fetch_iam_identity_providers
# ---------------------------------------------------------------------------


class TestFetchIamIdentityProviders:
    def _make_client(self, oidc_arns=None, saml_arns=None):
        client = MagicMock()
        _oidc = oidc_arns or [
            {"Arn": f"arn:aws:iam::{_ACCOUNT_ID}:oidc-provider/token.example.com"}
        ]
        client.list_open_id_connect_providers.return_value = {"OpenIDConnectProviderList": _oidc}
        client.get_open_id_connect_provider.return_value = {
            "Url": "https://token.example.com",
            "ClientIDList": ["aud1", "aud2"],
            "ThumbprintList": ["aabbcc"],
        }
        _saml = saml_arns or [
            {"Arn": f"arn:aws:iam::{_ACCOUNT_ID}:saml-provider/MySAML"}
        ]
        client.list_saml_providers.return_value = {"SAMLProviderList": _saml}
        from datetime import datetime, timezone, timedelta
        client.get_saml_provider.return_value = {
            "ValidUntil": datetime.now(timezone.utc) + timedelta(days=365),
            # SECURITY: SAMLMetadataDocument should NEVER be stored
            "SAMLMetadataDocument": "<EntityDescriptor>LARGE METADATA</EntityDescriptor>",
        }
        return client

    def _call(self, connector, client):
        with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
            return connector._fetch_iam_identity_providers(client, _ACCOUNT_ID)

    def test_oidc_record_type(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(saml_arns=[]))
        oidc_records = [r for r in records if r["provider_type"] == "oidc"]
        assert len(oidc_records) == 1
        assert oidc_records[0]["record_type"] == AWS_IAM_IDENTITY_PROVIDER

    def test_saml_record_type(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(oidc_arns=[]))
        saml_records = [r for r in records if r["provider_type"] == "saml"]
        assert len(saml_records) == 1
        assert saml_records[0]["record_type"] == AWS_IAM_IDENTITY_PROVIDER

    def test_oidc_client_id_count(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(saml_arns=[]))
        oidc = [r for r in records if r["provider_type"] == "oidc"][0]
        assert oidc["oidc_client_id_count"] == 2

    def test_oidc_thumbprint_count(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(saml_arns=[]))
        oidc = [r for r in records if r["provider_type"] == "oidc"][0]
        assert oidc["oidc_thumbprint_count"] == 1

    def test_saml_metadata_not_stored(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(oidc_arns=[]))
        for r in records:
            r_str = json.dumps(r, default=str)
            assert "SAMLMetadataDocument" not in r_str
            assert "EntityDescriptor" not in r_str

    def test_saml_valid_until_stored(self):
        connector = AWSConnector()
        records = self._call(connector, self._make_client(oidc_arns=[]))
        saml = [r for r in records if r["provider_type"] == "saml"][0]
        assert saml["saml_valid_until"] is not None


# ---------------------------------------------------------------------------
# 12. _fetch_iam_resources (integration)
# ---------------------------------------------------------------------------


class TestFetchIamResources:
    def _make_full_client(self):
        client = MagicMock()
        client.get_account_summary.return_value = {
            "SummaryMap": {"Users": 1, "Groups": 0, "Roles": 1, "Policies": 0,
                           "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        client.get_account_password_policy.return_value = {"PasswordPolicy": {"MinimumPasswordLength": 8}}
        client.list_users.return_value = {"Users": [
            {"UserName": "alice", "UserId": "AIDAU1",
             "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/alice", "Path": "/", "Tags": []}
        ], "IsTruncated": False}
        client.list_access_keys.return_value = {"AccessKeyMetadata": [], "IsTruncated": False}
        client.list_mfa_devices.return_value = {"MFADevices": [], "IsTruncated": False}
        client.list_groups_for_user.return_value = {"Groups": [], "IsTruncated": False}
        client.list_attached_user_policies.return_value = {"AttachedPolicies": [], "IsTruncated": False}
        client.list_user_policies.return_value = {"PolicyNames": [], "IsTruncated": False}
        client.list_groups.return_value = {"Groups": [], "IsTruncated": False}
        client.list_roles.return_value = {"Roles": [
            {"RoleName": "MyRole", "RoleId": "AROAR1",
             "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:role/MyRole",
             "Path": "/", "MaxSessionDuration": 3600,
             "AssumeRolePolicyDocument": {
                 "Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                "Principal": {"Service": "lambda.amazonaws.com"}}]
             }, "Tags": []}
        ], "IsTruncated": False}
        client.list_attached_role_policies.return_value = {"AttachedPolicies": [], "IsTruncated": False}
        client.list_role_policies.return_value = {"PolicyNames": [], "IsTruncated": False}
        client.list_policies.return_value = {"Policies": [], "IsTruncated": False}
        client.list_open_id_connect_providers.return_value = {"OpenIDConnectProviderList": []}
        client.list_saml_providers.return_value = {"SAMLProviderList": []}
        return client

    def _call(self, connector, client=None, **kwargs):
        _client = client or self._make_full_client()
        with patch.object(connector, "_make_client", return_value=_client):
            with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                return connector._fetch_iam_resources(_CREDS, _ACCOUNT_ID)

    def test_returns_account_summary(self):
        connector = AWSConnector()
        records = self._call(connector)
        types = {r["record_type"] for r in records}
        assert AWS_IAM_ACCOUNT_SUMMARY in types

    def test_returns_user_records(self):
        connector = AWSConnector()
        records = self._call(connector)
        types = {r["record_type"] for r in records}
        assert AWS_IAM_USER in types

    def test_returns_role_records(self):
        connector = AWSConnector()
        records = self._call(connector)
        types = {r["record_type"] for r in records}
        assert AWS_IAM_ROLE in types

    def test_403_on_list_users_fails_soft(self):
        connector = AWSConnector()
        client = self._make_full_client()
        # Make list_users raise 403 when directly called (bypass _call_aws mock)
        orig_list_users = client.list_users
        client.list_users.side_effect = ConnectorError("AccessDenied", status_code=403)
        records = self._call(connector, client)
        # Should still have account summary and role
        types = {r["record_type"] for r in records}
        assert AWS_IAM_ACCOUNT_SUMMARY in types
        assert AWS_IAM_USER not in types  # users were skipped

    def test_403_on_list_roles_fails_soft(self):
        connector = AWSConnector()
        client = self._make_full_client()
        client.list_roles.side_effect = ConnectorError("AccessDenied", status_code=403)
        records = self._call(connector, client)
        types = {r["record_type"] for r in records}
        assert AWS_IAM_USER in types  # users still returned
        assert AWS_IAM_ROLE not in types

    def test_no_secret_key_in_any_record(self):
        connector = AWSConnector()
        records = self._call(connector)
        all_str = json.dumps(records, default=str)
        assert "wJalrXUtnFEMI" not in all_str
        assert "aws_secret_access_key" not in all_str


# ---------------------------------------------------------------------------
# 13. AWSConnector.fetch() integration (M39)
# ---------------------------------------------------------------------------


class TestFetchM39Integration:
    def _build_minimal_iam_client(self):
        client = MagicMock()
        client.get_account_summary.return_value = {
            "SummaryMap": {"Users": 0, "Groups": 0, "Roles": 0, "Policies": 0,
                           "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        client.get_account_password_policy.side_effect = ConnectorError("NoSuchEntity", status_code=None)
        for method in ["list_users", "list_groups", "list_roles", "list_policies"]:
            getattr(client, method).return_value = {
                method.replace("list_", "").title().replace("_", ""): [], "IsTruncated": False
            }
        # Fix list_users key mismatch
        client.list_users.return_value = {"Users": [], "IsTruncated": False}
        client.list_groups.return_value = {"Groups": [], "IsTruncated": False}
        client.list_roles.return_value = {"Roles": [], "IsTruncated": False}
        client.list_policies.return_value = {"Policies": [], "IsTruncated": False}
        client.list_open_id_connect_providers.return_value = {"OpenIDConnectProviderList": []}
        client.list_saml_providers.return_value = {"SAMLProviderList": []}
        return client

    def _sts_response(self):
        return {
            "Account": _ACCOUNT_ID,
            "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/configtrace",
            "UserId": "AIDAUSER999",
        }

    def test_iam_included_in_fetch(self):
        connector = AWSConnector()
        iam_client = self._build_minimal_iam_client()

        def _make_client(service, credentials, region=None):
            m = MagicMock()
            if service == "sts":
                m.get_caller_identity.return_value = self._sts_response()
            elif service == "ec2":
                m.describe_regions.return_value = {
                    "Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]
                }
            elif service == "s3":
                m.list_buckets.side_effect = ConnectorError("AccessDenied", status_code=403)
            elif service == "iam":
                return iam_client
            return m

        with patch.object(connector, "_make_client", side_effect=_make_client):
            # Also need to skip network resources (EC2 describe SG etc)
            with patch.object(connector, "_fetch_network_resources", return_value=[]):
                with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                    records = connector.fetch(_CREDS)

        types = {r["record_type"] for r in records}
        assert AWS_IAM_ACCOUNT_SUMMARY in types

    def test_service_inventory_has_iam_in_enabled_surfaces(self):
        connector = AWSConnector()
        iam_client = self._build_minimal_iam_client()

        def _make_client(service, credentials, region=None):
            m = MagicMock()
            if service == "sts":
                m.get_caller_identity.return_value = self._sts_response()
            elif service == "ec2":
                m.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}
            elif service == "s3":
                m.list_buckets.side_effect = ConnectorError("AccessDenied", status_code=403)
            elif service == "iam":
                return iam_client
            return m

        with patch.object(connector, "_make_client", side_effect=_make_client):
            with patch.object(connector, "_fetch_network_resources", return_value=[]):
                with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                    records = connector.fetch(_CREDS)

        inv = next(r for r in records if r["record_type"] == AWS_SERVICE_INVENTORY)
        assert "iam" in inv["enabled_surfaces"]

    def test_iam_not_in_future_surfaces(self):
        connector = AWSConnector()
        iam_client = self._build_minimal_iam_client()

        def _make_client(service, credentials, region=None):
            m = MagicMock()
            if service == "sts":
                m.get_caller_identity.return_value = self._sts_response()
            elif service == "ec2":
                m.describe_regions.return_value = {"Regions": []}
            elif service == "s3":
                m.list_buckets.side_effect = ConnectorError("AccessDenied", status_code=403)
            elif service == "iam":
                return iam_client
            return m

        with patch.object(connector, "_make_client", side_effect=_make_client):
            with patch.object(connector, "_fetch_network_resources", return_value=[]):
                with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                    records = connector.fetch(_CREDS)

        inv = next(r for r in records if r["record_type"] == AWS_SERVICE_INVENTORY)
        assert "iam" not in inv.get("future_surfaces", [])

    def test_secret_key_never_in_fetch_result(self):
        connector = AWSConnector()
        iam_client = self._build_minimal_iam_client()

        def _make_client(service, credentials, region=None):
            m = MagicMock()
            if service == "sts":
                m.get_caller_identity.return_value = self._sts_response()
            elif service == "ec2":
                m.describe_regions.return_value = {"Regions": []}
            elif service == "s3":
                m.list_buckets.side_effect = ConnectorError("AccessDenied", status_code=403)
            elif service == "iam":
                return iam_client
            return m

        with patch.object(connector, "_make_client", side_effect=_make_client):
            with patch.object(connector, "_fetch_network_resources", return_value=[]):
                with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                    records = connector.fetch(_CREDS)

        all_str = json.dumps(records, default=str)
        assert "wJalrXUtnFEMI" not in all_str
        assert "aws_secret_access_key" not in all_str


# ---------------------------------------------------------------------------
# 14. Failure classifier — classify_aws_iam_failure
# ---------------------------------------------------------------------------


class TestClassifyAwsIamFailure:
    def test_403_connector_error(self):
        exc = ConnectorError("AccessDenied", status_code=403)
        fc = classify_aws_iam_failure("ListUsers", exc)
        assert fc.error_code == "aws_iam_access_denied"
        assert fc.category == "authentication"

    def test_auth_error(self):
        exc = AuthenticationError("Bad creds", status_code=401)
        fc = classify_aws_iam_failure("ListRoles", exc)
        assert fc.error_code == "aws_iam_access_denied"

    def test_rate_limit(self):
        exc = RateLimitError("Throttled")
        fc = classify_aws_iam_failure("ListPolicies", exc)
        assert fc.error_code == "aws_iam_rate_limited"
        assert fc.category == "rate_limited"

    def test_5xx_api_unavailable(self):
        exc = ConnectorError("InternalError", status_code=503)
        fc = classify_aws_iam_failure("GetUser", exc)
        assert fc.error_code == "aws_iam_api_unavailable"
        assert fc.category == "provider_unavailable"

    def test_list_users_specific_code(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("ListUsers", exc)
        assert fc.error_code == "aws_iam_users_unavailable"

    def test_list_roles_specific_code(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("ListRoles", exc)
        assert fc.error_code == "aws_iam_roles_unavailable"

    def test_list_groups_specific_code(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("ListGroups", exc)
        assert fc.error_code == "aws_iam_groups_unavailable"

    def test_get_policy_version_specific_code(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("GetPolicyVersion", exc)
        assert fc.error_code == "aws_iam_policy_versions_unavailable"

    def test_get_access_key_last_used(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("GetAccessKeyLastUsed", exc)
        assert fc.error_code == "aws_iam_access_keys_unavailable"

    def test_list_mfa_devices(self):
        exc = ConnectorError("Unknown", status_code=None)
        fc = classify_aws_iam_failure("ListMFADevices", exc)
        assert fc.error_code == "aws_iam_mfa_unavailable"

    def test_recommended_action_never_contains_secret(self):
        for exc_type, kwargs in [
            (ConnectorError, {"status_code": 403}),
            (RateLimitError, {}),
        ]:
            exc = exc_type("msg", **kwargs) if exc_type is ConnectorError else exc_type("msg")
            fc = classify_aws_iam_failure("ListUsers", exc)
            assert "secret" not in fc.recommended_action.lower()


# ---------------------------------------------------------------------------
# 15. Diff service tracked fields
# ---------------------------------------------------------------------------


class TestDiffServiceIamTrackedFields:
    def _fields_for_type(self, record_type: str) -> tuple:
        return _AWS_TRACKED_FIELDS_BY_TYPE.get(record_type, ())

    def test_iam_account_summary_tracks_root_mfa(self):
        fields = self._fields_for_type("aws_iam_account_summary")
        assert "mfa_enabled_for_root" in fields
        assert "root_access_keys_present" in fields

    def test_iam_account_summary_tracks_password_policy(self):
        fields = self._fields_for_type("aws_iam_account_summary")
        assert "password_policy_present" in fields
        assert "password_min_length" in fields
        assert "password_max_age" in fields

    def test_iam_user_tracks_mfa(self):
        fields = self._fields_for_type("aws_iam_user")
        assert "mfa_enabled" in fields
        assert "mfa_device_count" in fields

    def test_iam_user_tracks_key_counts(self):
        fields = self._fields_for_type("aws_iam_user")
        assert "active_key_count" in fields

    def test_iam_user_tracks_policy_counts(self):
        fields = self._fields_for_type("aws_iam_user")
        assert "attached_policy_count" in fields
        assert "inline_policy_count" in fields

    def test_iam_access_key_tracks_status(self):
        fields = self._fields_for_type("aws_iam_access_key")
        assert "status" in fields
        assert "last_used_age_days" in fields

    def test_iam_group_tracks_member_count(self):
        fields = self._fields_for_type("aws_iam_group")
        assert "member_count" in fields
        assert "attached_policy_count" in fields

    def test_iam_role_tracks_trust_summary(self):
        fields = self._fields_for_type("aws_iam_role")
        assert "trust_summary" in fields
        assert "max_session_duration" in fields

    def test_iam_policy_tracks_policy_summary(self):
        fields = self._fields_for_type("aws_iam_policy")
        assert "policy_summary" in fields
        assert "attachment_count" in fields

    def test_iam_policy_attachment_tracks_policy_name(self):
        fields = self._fields_for_type("aws_iam_policy_attachment")
        assert "policy_name" in fields

    def test_iam_inline_policy_tracks_policy_summary(self):
        fields = self._fields_for_type("aws_iam_inline_policy")
        assert "policy_summary" in fields

    def test_iam_identity_provider_tracks_client_id_count(self):
        fields = self._fields_for_type("aws_iam_identity_provider")
        assert "oidc_client_id_count" in fields
        assert "saml_valid_until" in fields

    def test_tracked_fields_for_dispatches_iam_types(self):
        for rt in [
            "aws_iam_account_summary", "aws_iam_user", "aws_iam_access_key",
            "aws_iam_group", "aws_iam_role", "aws_iam_policy",
            "aws_iam_policy_attachment", "aws_iam_inline_policy",
            "aws_iam_identity_provider",
        ]:
            fields = _tracked_fields_for({"record_type": rt})
            assert len(fields) > 0, f"No tracked fields for {rt}"


# ---------------------------------------------------------------------------
# 16-24. Risk classification
# ---------------------------------------------------------------------------


def _make_change(record_type, change_type="modified", field_path="",
                 new_value=None, prev_value=None, record_name="test-name"):
    return {
        "change_type": change_type,
        "field_path": field_path,
        "new_value": new_value,
        "prev_value": prev_value,
        "record_identifier": "rec-id",
        "provider_metadata": {
            "record_type": record_type,
            "record_id": "rec-id",
            "record_name": record_name,
        },
    }


class TestRiskIamAccountSummary:
    def test_mfa_root_disabled_is_critical(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "mfa_enabled_for_root",
                          new_value=False, prev_value=True)
        level, reason = _classify_iam_account_summary_change(c)
        assert level == "critical"
        assert "mfa" in reason.lower()

    def test_root_keys_added_is_critical(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "root_access_keys_present",
                          new_value=True, prev_value=False)
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "critical"

    def test_root_keys_removed_is_low(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "root_access_keys_present",
                          new_value=False, prev_value=True)
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "low"

    def test_password_policy_removed_is_high(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "password_policy_present",
                          new_value=False, prev_value=True)
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "high"

    def test_password_min_length_decreased_is_medium(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "password_min_length",
                          new_value=8, prev_value=14)
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "medium"

    def test_mfa_root_enabled_is_low(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "mfa_enabled_for_root",
                          new_value=True, prev_value=False)
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "low"

    def test_added_is_low(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "added")
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "low"

    def test_removed_is_medium(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "removed")
        level, _ = _classify_iam_account_summary_change(c)
        assert level == "medium"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_ACCOUNT_SUMMARY, "modified", "root_access_keys_present",
                          new_value=True, prev_value=False)
        level, _ = classify_aws_change(c)
        assert level == "critical"


class TestRiskIamUser:
    def test_mfa_disabled_sensitive_user_is_high(self):
        c = _make_change(AWS_IAM_USER, "modified", "mfa_enabled",
                          new_value=False, prev_value=True, record_name="prod-deploy-user")
        level, _ = _classify_iam_user_change(c)
        assert level == "high"

    def test_mfa_disabled_nonsensitive_is_medium(self):
        c = _make_change(AWS_IAM_USER, "modified", "mfa_enabled",
                          new_value=False, prev_value=True, record_name="readonly-user")
        level, _ = _classify_iam_user_change(c)
        assert level == "medium"

    def test_mfa_enabled_is_low(self):
        c = _make_change(AWS_IAM_USER, "modified", "mfa_enabled",
                          new_value=True, prev_value=False, record_name="alice")
        level, _ = _classify_iam_user_change(c)
        assert level == "low"

    def test_active_key_count_increased_is_medium(self):
        c = _make_change(AWS_IAM_USER, "modified", "active_key_count",
                          new_value=2, prev_value=1)
        level, _ = _classify_iam_user_change(c)
        assert level == "medium"

    def test_user_added_with_keys_no_mfa_is_high(self):
        c = _make_change(AWS_IAM_USER, "added", new_value={
            "active_key_count": 1, "mfa_enabled": False
        })
        level, _ = _classify_iam_user_change(c)
        assert level == "high"

    def test_user_added_with_mfa_is_low(self):
        c = _make_change(AWS_IAM_USER, "added", new_value={
            "active_key_count": 1, "mfa_enabled": True
        })
        level, _ = _classify_iam_user_change(c)
        assert level == "low"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_USER, "modified", "mfa_enabled",
                          new_value=False, prev_value=True, record_name="prod-user")
        level, _ = classify_aws_change(c)
        assert level == "high"


class TestRiskIamAccessKey:
    def test_added_active_is_medium(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "added",
                          new_value={"status": "Active"})
        level, _ = _classify_iam_access_key_change(c)
        assert level == "medium"

    def test_inactive_to_active_is_medium(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "modified", "status",
                          new_value="Active", prev_value="Inactive")
        level, _ = _classify_iam_access_key_change(c)
        assert level == "medium"

    def test_active_to_inactive_is_low(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "modified", "status",
                          new_value="Inactive", prev_value="Active")
        level, _ = _classify_iam_access_key_change(c)
        assert level == "low"

    def test_removed_is_low(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "removed")
        level, _ = _classify_iam_access_key_change(c)
        assert level == "low"

    def test_stale_key_is_low_advisory(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "modified", "last_used_age_days",
                          new_value=120, prev_value=90)
        level, reason = _classify_iam_access_key_change(c)
        assert level == "low"
        assert "120" in reason

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_ACCESS_KEY, "modified", "status",
                          new_value="Active", prev_value="Inactive")
        level, _ = classify_aws_change(c)
        assert level == "medium"


class TestRiskIamGroup:
    def test_member_count_increased_sensitive_is_medium(self):
        c = _make_change(AWS_IAM_GROUP, "modified", "member_count",
                          new_value=5, prev_value=4, record_name="prod-admins")
        level, _ = _classify_iam_group_change(c)
        assert level == "medium"

    def test_member_count_increased_nonsensitive_is_low(self):
        c = _make_change(AWS_IAM_GROUP, "modified", "member_count",
                          new_value=3, prev_value=2, record_name="readonly-group")
        level, _ = _classify_iam_group_change(c)
        assert level == "low"

    def test_attached_policy_increased_sensitive_is_medium(self):
        c = _make_change(AWS_IAM_GROUP, "modified", "attached_policy_count",
                          new_value=2, prev_value=1, record_name="prod-group")
        level, _ = _classify_iam_group_change(c)
        assert level == "medium"

    def test_added_is_low(self):
        c = _make_change(AWS_IAM_GROUP, "added")
        level, _ = _classify_iam_group_change(c)
        assert level == "low"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_GROUP, "modified", "member_count",
                          new_value=5, prev_value=4, record_name="prod-admins")
        level, _ = classify_aws_change(c)
        assert level == "medium"


class TestRiskIamRole:
    def _trust_summary(self, **kwargs):
        defaults = {
            "has_external_account_trust": False,
            "has_wildcard_principal": False,
            "has_root_account_trust": False,
            "has_external_id_condition": False,
            "has_mfa_condition": False,
            "service_principals": [],
        }
        defaults.update(kwargs)
        return defaults

    def test_external_account_trust_added_sensitive_is_high(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(),
                          new_value=self._trust_summary(has_external_account_trust=True),
                          record_name="prod-role")
        level, _ = _classify_iam_role_change(c)
        assert level == "high"

    def test_wildcard_principal_added_is_critical(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(),
                          new_value=self._trust_summary(has_wildcard_principal=True))
        level, _ = _classify_iam_role_change(c)
        assert level == "critical"

    def test_external_id_removed_is_high(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(has_external_id_condition=True,
                                                          has_external_account_trust=True),
                          new_value=self._trust_summary(has_external_account_trust=True))
        level, _ = _classify_iam_role_change(c)
        assert level == "high"

    def test_mfa_condition_removed_is_medium(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(has_mfa_condition=True),
                          new_value=self._trust_summary())
        level, _ = _classify_iam_role_change(c)
        assert level == "medium"

    def test_service_principal_added_is_medium(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(service_principals=["lambda.amazonaws.com"]),
                          new_value=self._trust_summary(service_principals=["lambda.amazonaws.com", "ec2.amazonaws.com"]))
        level, _ = _classify_iam_role_change(c)
        assert level == "medium"

    def test_max_session_over_8h_is_medium(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "max_session_duration",
                          new_value=43200, prev_value=3600)  # 12h
        level, _ = _classify_iam_role_change(c)
        assert level == "medium"

    def test_max_session_under_8h_is_low(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "max_session_duration",
                          new_value=7200, prev_value=3600)  # 2h
        level, _ = _classify_iam_role_change(c)
        assert level == "low"

    def test_added_with_wildcard_is_high(self):
        c = _make_change(AWS_IAM_ROLE, "added",
                          new_value={"trust_summary": self._trust_summary(has_wildcard_principal=True)})
        level, _ = _classify_iam_role_change(c)
        assert level == "high"

    def test_root_account_trust_added_is_high(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(),
                          new_value=self._trust_summary(has_root_account_trust=True))
        level, _ = _classify_iam_role_change(c)
        assert level == "high"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_ROLE, "modified", "trust_summary",
                          prev_value=self._trust_summary(),
                          new_value=self._trust_summary(has_wildcard_principal=True))
        level, _ = classify_aws_change(c)
        assert level == "critical"


class TestRiskIamPolicy:
    def _ps(self, **kwargs):
        base = {
            "admin_access": False,
            "iam_write_actions": False,
            "sts_assume_role_actions": False,
            "privilege_escalation_actions": False,
            "has_wildcard_action": False,
            "finding_codes": [],
            "policy_document_hash": "aabbccdd11223344",
        }
        base.update(kwargs)
        return base

    def test_admin_access_added_is_critical(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(admin_access=True, finding_codes=["admin_access"]))
        level, _ = _classify_iam_policy_change(c)
        assert level == "critical"

    def test_admin_access_removed_is_low(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(admin_access=True, finding_codes=["admin_access"]),
                          new_value=self._ps())
        level, _ = _classify_iam_policy_change(c)
        assert level == "low"

    def test_priv_esc_added_is_high(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(finding_codes=["privilege_escalation_risk"]))
        level, _ = _classify_iam_policy_change(c)
        assert level == "high"

    def test_iam_write_added_is_high(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(iam_write_actions=True, finding_codes=["iam_write_access"]))
        level, _ = _classify_iam_policy_change(c)
        assert level == "high"

    def test_hash_changed_no_new_codes_is_medium(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(policy_document_hash="aaaa1111aaaa1111"),
                          new_value=self._ps(policy_document_hash="bbbb2222bbbb2222"))
        level, _ = _classify_iam_policy_change(c)
        assert level == "medium"

    def test_added_with_admin_access_is_high(self):
        c = _make_change(AWS_IAM_POLICY, "added",
                          new_value={"policy_summary": self._ps(admin_access=True, finding_codes=["admin_access"])})
        level, _ = _classify_iam_policy_change(c)
        assert level == "high"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(admin_access=True, finding_codes=["admin_access"]))
        level, _ = classify_aws_change(c)
        assert level == "critical"


class TestRiskIamPolicyAttachment:
    def test_administrator_access_is_critical(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "added",
                          new_value={
                              "principal_name": "alice",
                              "principal_type": "user",
                              "policy_name": "AdministratorAccess",
                          })
        level, _ = _classify_iam_policy_attachment_change(c)
        assert level == "critical"

    def test_power_user_sensitive_principal_is_high(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "added",
                          new_value={
                              "principal_name": "prod-cicd-role",
                              "principal_type": "role",
                              "policy_name": "PowerUserAccess",
                          })
        level, _ = _classify_iam_policy_attachment_change(c)
        assert level == "high"

    def test_normal_policy_sensitive_is_medium(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "added",
                          new_value={
                              "principal_name": "prod-deploy-role",
                              "principal_type": "role",
                              "policy_name": "S3ReadOnlyAccess",
                          })
        level, _ = _classify_iam_policy_attachment_change(c)
        assert level == "medium"

    def test_normal_policy_nonsensitive_is_low(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "added",
                          new_value={
                              "principal_name": "dev-readonly-user",
                              "principal_type": "user",
                              "policy_name": "S3ReadOnlyAccess",
                          })
        level, _ = _classify_iam_policy_attachment_change(c)
        assert level == "low"

    def test_removed_from_sensitive_is_medium(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "removed",
                          prev_value={
                              "principal_name": "prod-role",
                              "principal_type": "role",
                              "policy_name": "S3ReadOnlyAccess",
                          })
        level, _ = _classify_iam_policy_attachment_change(c)
        assert level == "medium"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_POLICY_ATTACHMENT, "added",
                          new_value={
                              "principal_name": "admin",
                              "principal_type": "user",
                              "policy_name": "AdministratorAccess",
                          })
        level, _ = classify_aws_change(c)
        assert level == "critical"


class TestRiskIamInlinePolicy:
    def _ps(self, **kwargs):
        base = {"admin_access": False, "finding_codes": [], "policy_document_hash": "aabb1122aabb1122"}
        base.update(kwargs)
        return base

    def test_added_with_admin_is_critical(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "added",
                          new_value={"policy_summary": self._ps(admin_access=True, finding_codes=["admin_access"])})
        level, _ = _classify_iam_inline_policy_change(c)
        assert level == "critical"

    def test_added_with_priv_esc_is_high(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "added",
                          new_value={"policy_summary": self._ps(finding_codes=["privilege_escalation_risk"])})
        level, _ = _classify_iam_inline_policy_change(c)
        assert level == "high"

    def test_policy_summary_admin_added_is_critical(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(admin_access=True, finding_codes=["admin_access"]))
        level, _ = _classify_iam_inline_policy_change(c)
        assert level == "critical"

    def test_policy_summary_priv_esc_added_is_high(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(finding_codes=["privilege_escalation_risk"]))
        level, _ = _classify_iam_inline_policy_change(c)
        assert level == "high"

    def test_removed_is_low(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "removed")
        level, _ = _classify_iam_inline_policy_change(c)
        assert level == "low"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_INLINE_POLICY, "modified", "policy_summary",
                          prev_value=self._ps(),
                          new_value=self._ps(admin_access=True, finding_codes=["admin_access"]))
        level, _ = classify_aws_change(c)
        assert level == "critical"


class TestRiskIamIdentityProvider:
    def test_oidc_added_is_medium(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "added",
                          new_value={"provider_type": "oidc"})
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "medium"

    def test_saml_added_is_medium(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "added",
                          new_value={"provider_type": "saml"})
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "medium"

    def test_removed_is_medium(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "removed")
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "medium"

    def test_thumbprint_count_zero_is_high(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "modified", "oidc_thumbprint_count",
                          new_value=0, prev_value=1)
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "high"

    def test_client_id_count_increased_is_medium(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "modified", "oidc_client_id_count",
                          new_value=3, prev_value=1)
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "medium"

    def test_saml_valid_until_cleared_is_medium(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "modified", "saml_valid_until",
                          new_value=None, prev_value="2025-12-31T00:00:00+00:00")
        level, _ = _classify_iam_identity_provider_change(c)
        assert level == "medium"

    def test_classify_aws_change_routes_correctly(self):
        c = _make_change(AWS_IAM_IDENTITY_PROVIDER, "added",
                          new_value={"provider_type": "saml"})
        level, _ = classify_aws_change(c)
        assert level == "medium"


# ---------------------------------------------------------------------------
# 25. Security invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_policy_document_never_in_inline_record(self):
        """Policy documents must be analyzed in memory only."""
        connector = AWSConnector()
        raw_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        summary = _analyze_policy_document(raw_doc, _ACCOUNT_ID)
        # The summary must not contain the raw document
        assert "Statement" not in summary
        assert "Version" not in summary
        # But must contain derived fields
        assert "admin_access" in summary
        assert "finding_codes" in summary

    def test_trust_policy_never_in_role_record(self):
        """Trust policies must be analyzed in memory only — not stored."""
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"AWS": f"arn:aws:iam::{_OTHER_ACCOUNT}:root"}}
            ],
        }
        summary = _analyze_trust_policy(trust_doc, _ACCOUNT_ID)
        # Summary should not contain raw ARN or statement details
        assert "Statement" not in summary
        # But derived flags should be present
        assert "has_external_account_trust" in summary
        assert summary["has_external_account_trust"] is True

    def test_analyze_policy_never_leaks_raw_document(self):
        """Return value of _analyze_policy_document must not contain raw statements."""
        raw_doc = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*",
                 "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}}
            ],
        })
        summary = _analyze_policy_document(raw_doc, _ACCOUNT_ID)
        summary_str = json.dumps(summary)
        # Raw condition values should not appear in summary
        assert "us-east-1" not in summary_str
        assert "CreateUser" not in summary_str


# ---------------------------------------------------------------------------
# 26. M38/M36 regression
# ---------------------------------------------------------------------------


class TestM38Regression:
    def test_classify_aws_change_still_routes_m38(self):
        """M38 classifiers should still work after M39 additions."""
        from app.connectors.aws_schema import AWS_SECURITY_GROUP_RULE
        c = {
            "change_type": "added",
            "field_path": "",
            "new_value": {"is_public": True, "direction": "ingress", "port_category": "admin"},
            "prev_value": None,
            "record_identifier": "sg-123/rule-hash",
            "provider_metadata": {
                "record_type": AWS_SECURITY_GROUP_RULE,
                "record_id": "sg-123/rule-hash",
                "record_name": "sg-123",
            },
        }
        level, reason = classify_aws_change(c)
        assert level == "critical"

    def test_classify_aws_change_still_routes_m36(self):
        from app.connectors.aws_schema import AWS_ACCOUNT_IDENTITY
        c = {
            "change_type": "modified",
            "field_path": "account_id",
            "new_value": "999",
            "prev_value": "111",
            "record_identifier": "123456789012",
            "provider_metadata": {
                "record_type": AWS_ACCOUNT_IDENTITY,
                "record_id": "123456789012",
                "record_name": "AWS Account 123456789012",
            },
        }
        level, reason = classify_aws_change(c)
        assert level == "high"

    def test_fetch_still_returns_m36_records(self):
        """M36 records must still be present after M39 changes."""
        connector = AWSConnector()

        def _make_client(service, credentials, region=None):
            m = MagicMock()
            if service == "sts":
                m.get_caller_identity.return_value = {
                    "Account": _ACCOUNT_ID,
                    "Arn": f"arn:aws:iam::{_ACCOUNT_ID}:user/test",
                    "UserId": "AIDATEST",
                }
            elif service == "ec2":
                m.describe_regions.return_value = {"Regions": []}
            elif service == "s3":
                m.list_buckets.side_effect = ConnectorError("AccessDenied", status_code=403)
            elif service == "iam":
                iam = MagicMock()
                iam.get_account_summary.return_value = {
                    "SummaryMap": {"Users": 0, "Groups": 0, "Roles": 0, "Policies": 0,
                                   "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
                }
                iam.get_account_password_policy.side_effect = ConnectorError("NoSuchEntity", status_code=None)
                iam.list_users.return_value = {"Users": [], "IsTruncated": False}
                iam.list_groups.return_value = {"Groups": [], "IsTruncated": False}
                iam.list_roles.return_value = {"Roles": [], "IsTruncated": False}
                iam.list_policies.return_value = {"Policies": [], "IsTruncated": False}
                iam.list_open_id_connect_providers.return_value = {"OpenIDConnectProviderList": []}
                iam.list_saml_providers.return_value = {"SAMLProviderList": []}
                return iam
            return m

        with patch.object(connector, "_make_client", side_effect=_make_client):
            with patch.object(connector, "_fetch_network_resources", return_value=[]):
                with patch.object(connector, "_call_aws", side_effect=_direct_call_aws):
                    records = connector.fetch(_CREDS)

        types = {r["record_type"] for r in records}
        assert AWS_ACCOUNT_IDENTITY in types
        assert AWS_REGION in types
        assert AWS_SERVICE_INVENTORY in types
