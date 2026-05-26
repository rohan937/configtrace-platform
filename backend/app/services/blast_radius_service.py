"""Blast Radius service — M58.11.

Deterministic, on-demand blast radius analysis. Computes potential impact
surfaces for a change using provider-specific rules derived from:
  - provider (inferred from record_type prefix)
  - record_type
  - field_path
  - risk_level
  - risk_reason (for keyword signals — never raw values)
  - provider_metadata (safe fields only)

Design constraints (permanent):
  - No external API calls. No LLM. No AI.
  - Computed fresh per request; nothing is persisted.
  - Raw prev_value / new_value is NEVER accessed or forwarded.
  - Language rules: "potentially", "may affect", "may be" — never
    "confirmed affected", "caused by", "breach", "customers impacted",
    "publicly reachable" (unless proven from actual metadata).
  - available: false is always a safe fallback.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.schemas.blast_radius import (
    AffectedSurface,
    BlastRadiusItem,
    BlastRadiusResponse,
)

# ── Provider derivation ───────────────────────────────────────────────────────


def _derive_provider(record_type: str) -> str:
    rt = (record_type or "").lower()
    if rt.startswith("aws_"):       return "aws"
    if rt.startswith("github_"):    return "github"
    if rt.startswith("vercel_"):    return "vercel"
    if rt.startswith("stripe_"):    return "stripe"
    if rt.startswith("firebase_"):  return "firebase"
    if rt.startswith("supabase_"):  return "supabase"
    if rt.startswith("shopify_"):   return "shopify"
    if rt:                          return "cloudflare"
    return "unknown"


# ── Keyword helpers ───────────────────────────────────────────────────────────


def _kw(text: str, *keywords: str) -> bool:
    """Return True if any keyword appears in text (case-insensitive)."""
    t = (text or "").lower()
    return any(k.lower() in t for k in keywords)


# ── Shared confidence resolver ────────────────────────────────────────────────

_RISK_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _risk_or(risk_level: str, fallback: str) -> str:
    rl = (risk_level or "").lower()
    return rl if rl in _RISK_ORDER else fallback


# ── AWS ───────────────────────────────────────────────────────────────────────


def _analyze_aws(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if "security_group" in rt:
        domains.append("network_exposure")
        has_public  = _kw(rr, "public", "0.0.0.0", "::/0", "any ip", "anywhere", "open")
        has_admin   = _kw(rr, "ssh", "rdp", "winrm", "22", "3389", "5985", "5986", "admin")
        has_db      = _kw(rr, "mysql", "postgres", "mssql", "mongo", "redis",
                          "3306", "5432", "1433", "27017", "6379", "9200", "9300",
                          "database", "db port")
        has_web     = _kw(rr, "http", "https", "443", "80", "8080", "8443")

        net_evidence: list[str] = []
        if has_public:
            net_evidence.append("Public CIDR detected in risk reason")
        if has_admin:
            net_evidence.append("Admin/management port detected")
            domains.append("admin_access")
        if has_db:
            net_evidence.append("Database/cache port detected")
            domains.append("data_access")
        if has_web:
            net_evidence.append("Web port detected")
        if not net_evidence:
            net_evidence.append("Security group inbound rule changed")

        items.append(BlastRadiusItem(
            label="Network exposure",
            description=(
                "This security group change may affect inbound traffic rules for attached resources. "
                "Resources assigned to this group may inherit any new or removed access paths. "
                "Review whether the change opens or closes ports that affect your security posture."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium" if (has_public or has_admin or has_db) else "low",
            evidence=net_evidence,
            recommended_review=[
                "Confirm all resources currently attached to this security group.",
                "Verify that any opened ports are restricted to known IP ranges.",
                "Review VPC routing tables and subnet placement for attached resources.",
                "Confirm a VPN, bastion host, or AWS Systems Manager is available for admin access.",
            ],
        ))

        if has_admin:
            domains.append("admin_access")
            items.append(BlastRadiusItem(
                label="Admin access path",
                description=(
                    "Admin or management ports (SSH/RDP/WinRM) may be accessible if public CIDR rules "
                    "are present. Review whether access is intended to be restricted to known IPs or "
                    "a private network."
                ),
                severity="high" if has_public else "medium",
                confidence="medium" if has_public else "low",
                evidence=["Admin/management port in risk reason"]
                         + (["Public CIDR in risk reason"] if has_public else []),
                recommended_review=[
                    "Restrict admin ports to known IP ranges or a VPN CIDR.",
                    "Use AWS Systems Manager Session Manager as an alternative to direct SSH/RDP.",
                    "Confirm no production instances are reachable on admin ports from the public internet.",
                ],
            ))

        if has_db:
            items.append(BlastRadiusItem(
                label="Data access exposure",
                description=(
                    "Database or cache ports may be reachable if ingress rules were opened. "
                    "Review whether attached database resources are in private subnets and "
                    "whether direct DB access is intended from the rule source."
                ),
                severity="high" if has_public else "medium",
                confidence="low",
                evidence=["Database/cache port in risk reason"]
                         + (["Public CIDR detected"] if has_public else []),
                recommended_review=[
                    "Identify any RDS, ElastiCache, or DocumentDB resources sharing this security group.",
                    "Confirm database instances are in private subnets with no public IP.",
                    "Verify VPC endpoint or bastion access is used for authorized DB connections.",
                ],
            ))

        surfaces.extend([
            AffectedSurface(
                type="resource",
                provider="aws",
                label="Security group users",
                description=(
                    "EC2 instances, RDS databases, load balancers, and other resources "
                    "attached to this security group may inherit the modified inbound access rules."
                ),
                count=None,
                confidence="low",
                known=False,
            ),
            AffectedSurface(
                type="infra",
                provider="aws",
                label="VPC / network context",
                description=(
                    "Subnet placement, routing tables, internet gateways, and NAT gateway "
                    "configuration affect whether changed rules translate to actual public reachability."
                ),
                count=None,
                confidence="low",
                known=False,
            ),
        ])
        limitations.extend([
            "ConfigTrace may not know every resource attached to this security group unless it is included in monitored metadata.",
            "A public security group rule does not prove public reachability without route table, subnet, and attachment context.",
        ])
        conf = "medium" if (has_public or has_admin or has_db) else "low"

    elif "cloudtrail" in rt:
        domains.append("monitoring_visibility")
        items.append(BlastRadiusItem(
            label="Audit trail coverage",
            description=(
                "CloudTrail changes may reduce visibility into API calls and management events "
                "across your AWS account. Reduced logging could affect incident investigation "
                "and compliance audit coverage."
            ),
            severity="high",
            confidence="high",
            evidence=["CloudTrail configuration changed"],
            recommended_review=[
                "Confirm CloudTrail is still active and enabled in all required regions.",
                "Verify that log file validation is enabled.",
                "Check whether CloudWatch log delivery is still configured.",
                "Review whether compliance or audit requirements depend on this trail.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="workflow",
            provider="aws",
            label="Security monitoring and audit",
            description=(
                "Incident investigation, compliance auditing, and security alerting may depend on "
                "CloudTrail logs being continuously delivered."
            ),
            count=None,
            confidence="high",
            known=True,
        ))
        limitations.append(
            "Impact depends on whether this is the primary trail or a supplementary trail in this account."
        )
        conf = "high"

    elif "waf" in rt:
        domains.append("edge_protection")
        items.append(BlastRadiusItem(
            label="Web application firewall coverage",
            description=(
                "AWS WAF rule changes may alter filtering for application endpoints associated with "
                "this WebACL. Removed or weakened rules may reduce protection against injection, "
                "bot, or rate-limit patterns."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["AWS WAF rule or configuration changed"],
            recommended_review=[
                "Review the WAF dashboard for traffic anomalies after this change.",
                "Confirm removed rules have equivalent replacements.",
                "Verify that managed rule groups are still active.",
                "Check whether rate-based rules still protect high-traffic endpoints.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="infra",
            provider="aws",
            label="Web application endpoints",
            description="Applications and APIs protected by this WebACL may have altered filtering coverage.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Full impact depends on which resources (CloudFront, ALB, API Gateway) are associated with this WebACL."
        )
        conf = "medium"

    elif "cloudfront" in rt:
        domains.extend(["edge_protection", "deployment_path"])
        items.append(BlastRadiusItem(
            label="Edge delivery and TLS configuration",
            description=(
                "CloudFront changes may affect HTTPS enforcement, origin access, or content delivery "
                "behavior for end users. Weakened TLS settings may expose traffic in transit."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["CloudFront distribution configuration changed"],
            recommended_review=[
                "Confirm HTTPS redirect and minimum TLS version settings.",
                "Review origin access identity or origin access control settings.",
                "Verify WAF association is still in place if required.",
                "Check Lambda@Edge or CloudFront Functions associations.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="infra",
            provider="aws",
            label="Distribution viewers",
            description=(
                "End users accessing content through this CloudFront distribution may be affected "
                "by TLS, caching, or origin policy changes."
            ),
            count=None,
            confidence="low",
            known=False,
        ))
        limitations.append(
            "Impact depends on which origins, behaviors, and viewer policies are attached to this distribution."
        )
        conf = "medium"

    elif "route53" in rt:
        domains.append("dns_routing")
        is_email = _kw(fp or "", "mx", "spf", "dmarc", "dkim") or _kw(rr or "", "mail", "mx record")
        items.append(BlastRadiusItem(
            label="DNS routing",
            description=(
                "Route 53 record changes may affect service routing, health check behavior, "
                "or DNS-based failover. Propagation time varies by TTL."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Route 53 DNS record changed"],
            recommended_review=[
                "Confirm the expected record value from your infrastructure documentation.",
                "Review DNS health checks if this record is used for routing or failover.",
                "Check Route 53 traffic policies if weighted or latency-based routing is configured.",
            ],
        ))
        if is_email:
            items.append(BlastRadiusItem(
                label="Email authentication records",
                description=(
                    "Changes to MX, SPF, DKIM, or DMARC records may affect email delivery "
                    "and domain authentication for your domain."
                ),
                severity="medium",
                confidence="medium",
                evidence=["Email-related DNS record type inferred"],
                recommended_review=[
                    "Confirm SPF, DKIM, and DMARC records are still aligned.",
                    "Test email deliverability after DNS propagation.",
                    "Verify MX records point to the correct mail servers.",
                ],
            ))
        surfaces.append(AffectedSurface(
            type="infra",
            provider="aws",
            label="DNS-dependent services",
            description="Services and routing paths that depend on this DNS record may be affected during propagation.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "DNS propagation time varies by TTL and downstream resolver caching. Temporary inconsistencies may occur."
        )
        conf = "medium"

    elif "iam" in rt:
        domains.extend(["admin_access", "credential_access"])
        items.append(BlastRadiusItem(
            label="IAM access scope",
            description=(
                "IAM policy or role changes may alter what actions identities can perform across "
                "your AWS account. Overly permissive changes may allow unauthorized resource access "
                "or privilege escalation."
            ),
            severity=_risk_or(rl, "high"),
            confidence="medium",
            evidence=["AWS IAM policy or role changed"],
            recommended_review=[
                "Identify all principals (users, roles, services) that use this policy or role.",
                "Review whether the change grants new permissions or removes existing ones.",
                "Use AWS IAM Access Analyzer to audit cross-account or external access.",
                "Confirm this change corresponds to a known provisioning task.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="integration",
            provider="aws",
            label="IAM principals",
            description=(
                "Users, roles, or services that assume this role or attach this policy may have "
                "altered permissions after this change."
            ),
            count=None,
            confidence="low",
            known=False,
        ))
        limitations.append(
            "Full impact requires knowing all principals that assume or attach this IAM resource."
        )
        conf = "medium"

    else:
        # Generic AWS fallback
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="AWS configuration change",
            description=(
                "This AWS resource change may affect dependent services or infrastructure components. "
                "Review the change in the AWS console and identify any downstream dependencies."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"AWS resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the AWS console.",
                "Identify services or resources that depend on this configuration.",
            ],
        ))
        limitations.append(
            "No specific blast radius model is available for this AWS resource type yet."
        )
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Cloudflare ────────────────────────────────────────────────────────────────

_CF_DNS_TYPES = frozenset({
    "a", "aaaa", "cname", "ns", "srv", "ptr",
    "mx", "txt", "spf", "caa", "ds", "tlsa",
})

_CF_EMAIL_TYPES = frozenset({"mx", "txt", "spf", "tlsa", "caa", "ds"})


def _analyze_cloudflare(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if rt in _CF_DNS_TYPES or _kw(rt, "dns"):
        domains.append("dns_routing")
        is_routing = rt in ("a", "aaaa", "cname", "ns", "srv")
        is_email   = rt in _CF_EMAIL_TYPES

        if is_routing:
            items.append(BlastRadiusItem(
                label="DNS routing and proxy status",
                description=(
                    "A Cloudflare DNS routing record changed. This may affect how traffic is directed "
                    "to origin servers, whether the Cloudflare proxy is active, and how downstream "
                    "services resolve this hostname."
                ),
                severity=_risk_or(rl, "medium"),
                confidence="medium",
                evidence=[f"Cloudflare {rt.upper()} routing record changed"],
                recommended_review=[
                    "Confirm the expected record target from your infrastructure documentation.",
                    "Verify proxy status (orange cloud) is appropriate for the record.",
                    "Check DNS propagation using a resolver check tool.",
                    "Confirm services depending on this hostname are still routing correctly.",
                ],
            ))
        if is_email:
            domains.append("monitoring_visibility")
            items.append(BlastRadiusItem(
                label="Email delivery and domain authentication",
                description=(
                    "Changes to MX, TXT, SPF, DKIM, or DMARC records may affect outbound email "
                    "delivery and domain authentication. Incorrect records can cause email to be "
                    "rejected or marked as spam."
                ),
                severity="medium",
                confidence="high",
                evidence=[f"Cloudflare {rt.upper()} email/security record changed"],
                recommended_review=[
                    "Confirm SPF, DKIM, and DMARC records are still aligned.",
                    "Test email deliverability after DNS propagation.",
                    "Verify no legitimate email source was removed from SPF.",
                    "Check MX record priority and targets are correct.",
                ],
            ))
        if not (is_routing or is_email):
            items.append(BlastRadiusItem(
                label="DNS record change",
                description=(
                    "A Cloudflare DNS record was changed. Depending on the record type, this may "
                    "affect service availability, traffic routing, or security configuration."
                ),
                severity=_risk_or(rl, "medium"),
                confidence="low",
                evidence=[f"Cloudflare DNS record ({rt.upper()}) changed"],
                recommended_review=[
                    "Confirm the expected record value from your DNS management documentation.",
                    "Verify no unintended redirection or removal occurred.",
                ],
            ))

        surfaces.append(AffectedSurface(
            type="infra",
            provider="cloudflare",
            label="Domain-dependent services",
            description=(
                "Services, applications, and users that rely on this DNS record for routing "
                "may experience connectivity changes during propagation."
            ),
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "DNS propagation time varies. Immediate impact depends on TTL and downstream resolver caching."
        )
        conf = "medium"

    elif _kw(rt, "waf", "ruleset", "firewall"):
        domains.append("edge_protection")
        items.append(BlastRadiusItem(
            label="Edge web application firewall",
            description=(
                "Cloudflare WAF or ruleset changes may alter filtering behavior for traffic "
                "reaching your origin. Removed or weakened rules may reduce protection against "
                "injection, bot, or application-layer attack patterns."
            ),
            severity=_risk_or(rl, "high"),
            confidence="medium",
            evidence=["Cloudflare WAF / ruleset rule changed"],
            recommended_review=[
                "Review Cloudflare Firewall Events to confirm legitimate traffic is not affected.",
                "Verify that removed rules have replacement coverage.",
                "Check whether managed rulesets (OWASP, Bot Management) are still active.",
                "Monitor origin error rates for anomalies after the change.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="infra",
            provider="cloudflare",
            label="Origin applications",
            description=(
                "Traffic that previously matched WAF rules may now reach the origin unfiltered "
                "depending on the change."
            ),
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on which hostnames and applications are covered by this ruleset."
        )
        conf = "medium"

    elif _kw(rt, "ssl", "tls"):
        domains.append("edge_protection")
        items.append(BlastRadiusItem(
            label="TLS / SSL transport security",
            description=(
                "Cloudflare SSL/TLS settings control HTTPS enforcement and certificate behavior. "
                "Weakened settings may expose traffic to interception or downgrade attacks."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Cloudflare SSL/TLS configuration changed"],
            recommended_review=[
                "Confirm the minimum TLS version is still set appropriately (TLS 1.2 or higher recommended).",
                "Verify the SSL mode (Full/Full Strict) is still enforced.",
                "Check HSTS settings if strict transport security is required.",
                "Confirm origin certificate validity is unaffected.",
            ],
        ))
        limitations.append(
            "Impact depends on the specific setting changed and whether end users are on older TLS clients."
        )
        conf = "medium"

    else:
        # Generic Cloudflare
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Cloudflare configuration change",
            description=(
                "This Cloudflare configuration change may affect routing, security filtering, "
                "or content delivery for your domain."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Cloudflare resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Cloudflare dashboard.",
                "Confirm the expected configuration from your infrastructure documentation.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Cloudflare resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Firebase ──────────────────────────────────────────────────────────────────


def _analyze_firebase(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "rules", "firestore", "storage_rules", "realtime_database"):
        domains.extend(["data_access"])
        has_public_write = _kw(rr, "public write", "write: true", "allow write", "unauthenticated write",
                               "open write", "world writable")
        has_public_read  = _kw(rr, "public read", "allow read", "unauthenticated read", "open read")

        items.append(BlastRadiusItem(
            label="Client data access rules",
            description=(
                "Firebase security rules govern read/write access to Firestore, Realtime Database, "
                "or Storage from client-side applications. Overly permissive rules may expose data "
                "to unauthenticated or unauthorized users."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high" if (has_public_write or has_public_read) else "medium",
            evidence=(
                (["Public write access inferred from risk reason"] if has_public_write else [])
                + (["Public read access inferred from risk reason"] if has_public_read else [])
                + (["Firebase security rules changed"] if not (has_public_write or has_public_read) else [])
            ),
            recommended_review=[
                "Review the deployed rules in the Firebase console.",
                "Use the Firebase Rules Simulator to test access levels for common user roles.",
                "Confirm no collection or storage path containing personal data is publicly accessible.",
                "Verify the change was intentional and corresponds to a known deployment.",
            ],
        ))
        if has_public_write:
            items.append(BlastRadiusItem(
                label="Potential data integrity and abuse surface",
                description=(
                    "Public write access may allow arbitrary clients to write data to Firebase "
                    "collections or storage. This could enable data corruption, spam uploads, "
                    "or abuse of storage quotas."
                ),
                severity="high",
                confidence="medium",
                evidence=["Public write access inferred from risk reason"],
                recommended_review=[
                    "Restrict write access to authenticated users or specific user conditions.",
                    "Add field-level validation rules to prevent malformed writes.",
                    "Monitor Firebase usage for unexpected spikes in write operations.",
                ],
            ))
        surfaces.extend([
            AffectedSurface(
                type="resource",
                provider="firebase",
                label="Client-side app users",
                description=(
                    "Mobile and web clients that use the Firebase SDK access data subject to "
                    "these security rules."
                ),
                count=None,
                confidence="medium",
                known=False,
            ),
            AffectedSurface(
                type="resource",
                provider="firebase",
                label="Affected database paths / collections",
                description="Collections, documents, or storage paths covered by the changed rules.",
                count=None,
                confidence="low",
                known=False,
            ),
        ])
        limitations.extend([
            "ConfigTrace detects rule changes but cannot evaluate rule logic or determine which paths are exposed without the full rule context.",
            "Admin SDK and Cloud Functions access is not governed by security rules.",
        ])
        conf = "high" if (has_public_write or has_public_read) else "medium"

    elif _kw(rt, "app_check"):
        domains.append("auth_flow")
        items.append(BlastRadiusItem(
            label="App attestation enforcement",
            description=(
                "Firebase App Check verifies that requests originate from your legitimate app "
                "binary. Weakening or disabling App Check enforcement may allow unauthorized API "
                "usage from non-app clients or scripts."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["Firebase App Check configuration changed"],
            recommended_review=[
                "Confirm whether App Check enforcement was disabled or downgraded to unenforced.",
                "Review whether debug tokens are still limited to development environments.",
                "Check whether App Check metrics show an increase in unenforced requests.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="workflow",
            provider="firebase",
            label="Firebase API endpoints",
            description="Firebase APIs (Firestore, RTDB, Storage, Auth) that require App Check may be accessible without attestation.",
            count=None,
            confidence="high",
            known=True,
        ))
        limitations.append(
            "Impact depends on whether enforcement was fully disabled or only degraded."
        )
        conf = "high"

    elif _kw(rt, "auth", "authorized_domain"):
        domains.append("auth_flow")
        items.append(BlastRadiusItem(
            label="Authentication configuration",
            description=(
                "Firebase Auth settings control sign-in providers, authorized redirect domains, "
                "MFA settings, and session behavior. Changes may affect how users authenticate "
                "and where they can be redirected after sign-in."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Firebase Auth configuration changed"],
            recommended_review=[
                "Verify that the change was intentional and corresponds to a known deployment.",
                "Confirm sign-in providers are still correctly configured.",
                "Review authorized domains list for unexpected additions or removals.",
                "Test sign-in flows in staging before confirming production correctness.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="resource",
            provider="firebase",
            label="App users / sign-in flows",
            description="Users authenticating through Firebase Auth may be affected by provider or redirect domain changes.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on which sign-in providers are in use and whether redirect domains affect active user flows."
        )
        conf = "medium"

    elif _kw(rt, "remote_config"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Remote configuration and feature flags",
            description=(
                "Firebase Remote Config changes affect runtime behavior of production clients "
                "that fetch config values. Changes may affect feature flags, rollout percentages, "
                "or experiment parameters for active users."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Firebase Remote Config template changed"],
            recommended_review=[
                "Confirm the change corresponds to a known feature flag or rollout update.",
                "Verify rollout percentages are set correctly.",
                "Monitor app analytics after rollout for unexpected behavior changes.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="resource",
            provider="firebase",
            label="Production app clients",
            description="Active app users that fetch Remote Config values may receive the updated configuration.",
            count=None,
            confidence="high",
            known=True,
        ))
        limitations.append(
            "Impact depends on fetch cadence and whether client-side caching delays adoption."
        )
        conf = "medium"

    else:
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Firebase configuration change",
            description=(
                "This Firebase project configuration change may affect authentication, "
                "data access rules, or security settings for your Firebase-backed services."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Firebase resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Firebase console.",
                "Confirm the intended configuration.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Firebase resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Supabase ──────────────────────────────────────────────────────────────────


def _analyze_supabase(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "rls"):
        domains.append("data_access")
        rls_disabled = _kw(rr, "disabled", "off", "removed", "rls disabled")
        items.append(BlastRadiusItem(
            label="Row Level Security status",
            description=(
                "Supabase Row Level Security (RLS) controls which rows a database role can read "
                "or write from client-side queries. If RLS is disabled on a table that is accessible "
                "via the anon or authenticated key, all rows in that table may be readable or writable "
                "by any client without additional policy restrictions."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high" if rls_disabled else "medium",
            evidence=(
                ["RLS disabled inferred from risk reason"] if rls_disabled
                else ["RLS status changed"]
            ),
            recommended_review=[
                "Confirm whether the affected table is accessible via the anon or authenticated key.",
                "Check for existing RLS policies before re-enabling to avoid breaking app logic.",
                "Verify this table does not contain sensitive or personal user data.",
                "Review recent migration history for an intentional disable.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="resource",
                provider="supabase",
                label="Client-accessible table rows",
                description=(
                    "Rows in this table may be accessible to anon or authenticated key clients "
                    "depending on existing policies and key configuration."
                ),
                count=None,
                confidence="medium",
                known=False,
            ),
            AffectedSurface(
                type="integration",
                provider="supabase",
                label="Frontend / mobile app clients",
                description="Applications that query Supabase directly using the anon or authenticated key may have broader table access.",
                count=None,
                confidence="low",
                known=False,
            ),
        ])
        limitations.extend([
            "ConfigTrace detects RLS status changes but cannot confirm which roles or keys have access to this table without schema and policy context.",
            "Tables accessed only via the service role key are not affected by RLS changes — anon/authenticated key access requires extra care.",
        ])
        conf = "high"

    elif _kw(rt, "auth"):
        domains.append("auth_flow")
        items.append(BlastRadiusItem(
            label="Authentication configuration",
            description=(
                "Supabase Auth settings control user authentication flows, external OAuth providers, "
                "JWT configuration, and session expiry. Changes may affect how users sign in and "
                "how sessions are managed."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Supabase Auth settings changed"],
            recommended_review=[
                "Verify that configured OAuth providers are still active and correctly set up.",
                "Confirm JWT signing keys and expiry settings are unchanged if tokens are involved.",
                "Test sign-in flows after the change.",
                "Review allowed redirect URLs for unexpected additions.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="resource",
            provider="supabase",
            label="App users / sign-in flows",
            description="Users authenticating via Supabase Auth may be affected by provider or session configuration changes.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on which providers are in use and whether session changes affect active user tokens."
        )
        conf = "medium"

    elif _kw(rt, "storage", "policy"):
        domains.append("data_access")
        items.append(BlastRadiusItem(
            label="Storage or data access policy",
            description=(
                "Supabase storage or database policy changes affect who can read or write "
                "stored objects or table data. Overly permissive policies may expose private "
                "files or data to unintended users."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Supabase storage/policy configuration changed"],
            recommended_review=[
                "Review the current storage bucket policies and RLS policies for affected tables.",
                "Confirm no private files or sensitive table data are publicly accessible.",
                "Verify the change corresponds to a known deployment or migration.",
            ],
        ))
        limitations.append(
            "Impact depends on bucket visibility settings, path matching, and whether the service role is used."
        )
        conf = "medium"

    else:
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Supabase configuration change",
            description=(
                "This Supabase configuration change may affect database access, authentication, "
                "or storage settings for your application."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Supabase resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Supabase dashboard.",
                "Confirm the intended configuration.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Supabase resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── GitHub ────────────────────────────────────────────────────────────────────


def _analyze_github(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "branch_protection"):
        domains.append("deployment_path")
        review_removed = _kw(rr, "review", "required review", "pull request review")
        ci_removed     = _kw(rr, "status check", "ci", "required check")
        items.append(BlastRadiusItem(
            label="Production branch integrity",
            description=(
                "GitHub branch protection rule changes may affect the gates that prevent "
                "unreviewed or untested code from reaching protected branches. Weakened "
                "protection may allow direct commits or merges without required approvals."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=(
                (["Required review checks may have been removed"] if review_removed else [])
                + (["Required CI checks may have been removed"] if ci_removed else [])
                + (["Branch protection configuration changed"] if not (review_removed or ci_removed) else [])
            ),
            recommended_review=[
                "Identify the affected branch and whether it is a production or release branch.",
                "Confirm the change corresponds to a known team action.",
                "Audit recent commits to this branch for any that bypassed review.",
                "Restore required reviewers and status checks if the change was unintentional.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="workflow",
                provider="github",
                label="Code review gates",
                description="Pull requests targeting this branch may now be mergeable without required reviews.",
                count=None,
                confidence="high",
                known=True,
            ),
            AffectedSurface(
                type="workflow",
                provider="github",
                label="Deployment pipeline triggers",
                description="Merges to protected branches often trigger CI/CD pipelines. A weakened branch may allow unreviewed code to reach production.",
                count=None,
                confidence="medium",
                known=False,
            ),
        ])
        limitations.append(
            "Impact depends on which branch was affected and whether it is directly connected to a production deployment."
        )
        conf = "high"

    elif _kw(rt, "environment_protection", "environment"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Deployment environment gates",
            description=(
                "GitHub environment protection changes may affect required reviewers, deployment "
                "approval gates, and deployment secrets for production or staging environments."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["GitHub environment protection configuration changed"],
            recommended_review=[
                "Confirm required reviewers are still set for production environments.",
                "Verify deployment secrets have not been removed or altered.",
                "Check wait timer settings for time-sensitive environments.",
                "Confirm this change corresponds to a known DevOps task.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="workflow",
            provider="github",
            label="Deployment approval flows",
            description="Deployments to this environment may now proceed without required human approval.",
            count=None,
            confidence="high",
            known=True,
        ))
        limitations.append(
            "Impact depends on which environments are affected and what workflows deploy to them."
        )
        conf = "high"

    elif _kw(rt, "webhook"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Automation and CI/CD webhook",
            description=(
                "GitHub webhook changes may affect CI/CD pipelines, external integrations, "
                "or automation workflows that receive repository events."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["GitHub webhook configuration changed"],
            recommended_review=[
                "Identify which pipeline or integration depends on this webhook.",
                "Confirm the change was intentional and corresponds to a known task.",
                "Verify the endpoint URL is still reachable and expects the event payload.",
                "Check webhook delivery logs in GitHub for recent failures.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="workflow",
            provider="github",
            label="CI/CD and automation integrations",
            description="External systems that receive GitHub webhook events may have altered behavior.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on which external services receive this webhook and what actions they trigger."
        )
        conf = "medium"

    elif _kw(rt, "secret", "actions_secret"):
        domains.append("credential_access")
        items.append(BlastRadiusItem(
            label="CI/CD secrets and credentials",
            description=(
                "GitHub Actions secret changes may affect build pipelines, deployments, or "
                "integrations that depend on these values. Unexpected changes may indicate "
                "a rotation, removal, or unauthorized modification."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["GitHub Actions secret metadata changed"],
            recommended_review=[
                "Confirm the secret change was an intentional rotation or update.",
                "Verify dependent workflows still have access to required secrets.",
                "Check whether any scheduled workflows or manual workflows will be affected.",
                "Review organization-level secrets if repository secrets were removed.",
            ],
        ))
        limitations.extend([
            "ConfigTrace never accesses or stores secret values — only metadata changes are detected.",
            "Impact depends on which workflows reference this secret name.",
        ])
        conf = "medium"

    elif _kw(rt, "deploy_key"):
        domains.append("credential_access")
        items.append(BlastRadiusItem(
            label="Repository deploy key access",
            description=(
                "GitHub deploy key changes affect programmatic read (and potentially write) "
                "access to the repository. Write-enabled deploy keys allow pushing code directly."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["GitHub deploy key configuration changed"],
            recommended_review=[
                "Confirm the deploy key change was intentional.",
                "Verify the key's read-only vs. write access setting is appropriate.",
                "Check whether the key is associated with a known CI/CD system or automation.",
                "Remove the key if it is no longer needed.",
            ],
        ))
        limitations.append(
            "ConfigTrace detects deploy key metadata changes but cannot evaluate the key content itself."
        )
        conf = "high"

    else:
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="GitHub configuration change",
            description=(
                "This GitHub configuration change may affect code review requirements, "
                "deployment pipelines, or access controls for your repository."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"GitHub resource type changed: {rt}"],
            recommended_review=[
                "Review the change in GitHub settings.",
                "Confirm the expected configuration from your team policy.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this GitHub resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Stripe ────────────────────────────────────────────────────────────────────


def _analyze_stripe(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "webhook"):
        domains.append("payment_flow")
        webhook_removed = _kw(rr, "removed", "deleted", "disabled")
        items.append(BlastRadiusItem(
            label="Payment event delivery",
            description=(
                "Stripe webhooks deliver real-time payment events including payment confirmations, "
                "subscription renewals, invoice reconciliation, and refunds. Changes to webhook "
                "endpoints may cause downstream systems to miss critical billing lifecycle events."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=(
                ["Webhook endpoint removed or disabled"] if webhook_removed
                else ["Stripe webhook endpoint configuration changed"]
            ),
            recommended_review=[
                "Identify which downstream systems depend on this webhook endpoint.",
                "Confirm the endpoint URL is still reachable and returning 2xx responses.",
                "Review Stripe webhook delivery logs for recent failed deliveries.",
                "Verify payment confirmation, subscription, and refund events are still being processed.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="workflow",
                provider="stripe",
                label="Checkout fulfillment",
                description="Order fulfillment, license provisioning, or access grants that rely on payment.intent.succeeded events.",
                count=None,
                confidence="high",
                known=True,
            ),
            AffectedSurface(
                type="workflow",
                provider="stripe",
                label="Subscription lifecycle",
                description="Subscription renewals, cancellations, and trial expiry events that trigger billing state changes.",
                count=None,
                confidence="high",
                known=True,
            ),
            AffectedSurface(
                type="workflow",
                provider="stripe",
                label="Invoice reconciliation",
                description="Invoice payment and failure events used for billing automation or account state management.",
                count=None,
                confidence="medium",
                known=False,
            ),
        ])
        limitations.append(
            "Impact depends on which event types this endpoint is subscribed to and what actions the receiving system takes."
        )
        conf = "high"

    elif _kw(rt, "api_key", "apikey"):
        domains.append("payment_flow")
        items.append(BlastRadiusItem(
            label="Payment API key scope",
            description=(
                "Stripe API key changes affect the scope of payment and billing operations "
                "that integrations can perform. Unexpected key rotation or permission changes "
                "may affect API access for automation and third-party integrations."
            ),
            severity=_risk_or(rl, "high"),
            confidence="medium",
            evidence=["Stripe API key configuration changed"],
            recommended_review=[
                "Confirm this was an intentional key rotation.",
                "Verify dependent integrations and automations have updated credentials.",
                "Check whether restricted keys have appropriate permission scopes.",
                "Review Stripe Dashboard API logs for any failed requests after the change.",
            ],
        ))
        limitations.extend([
            "ConfigTrace never stores or reads Stripe API key values — only key metadata is tracked.",
            "Impact depends on which integrations use this key and what permissions it carries.",
        ])
        conf = "medium"

    elif _kw(rt, "billing_portal"):
        domains.append("customer_self_service")
        items.append(BlastRadiusItem(
            label="Customer billing portal",
            description=(
                "Stripe Billing Portal configuration changes affect the customer-facing "
                "subscription management experience, including which plans customers can switch to, "
                "whether they can cancel, and what payment methods they can update."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Stripe Billing Portal configuration changed"],
            recommended_review=[
                "Confirm the portal configuration changes were intentional.",
                "Verify customers can still access subscription management features they need.",
                "Test the portal flow in Stripe's test mode if possible.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="resource",
            provider="stripe",
            label="Customers using the billing portal",
            description="Customers who manage their own subscriptions via the Stripe-hosted portal may see different options.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on which portal features are enabled and which customers actively use self-service."
        )
        conf = "medium"

    elif _kw(rt, "tax"):
        domains.append("payment_flow")
        items.append(BlastRadiusItem(
            label="Tax and compliance settings",
            description=(
                "Stripe tax settings affect how sales tax or VAT is calculated and applied "
                "to checkout sessions and invoices. Changes may affect billing compliance "
                "or customer-visible pricing."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Stripe tax configuration changed"],
            recommended_review=[
                "Confirm the tax configuration change was intentional.",
                "Verify tax calculations are correct in Stripe's test mode.",
                "Check compliance requirements for affected customer regions.",
            ],
        ))
        limitations.append(
            "Impact depends on which products, prices, and customer geographies are affected."
        )
        conf = "medium"

    else:
        domains.append("payment_flow")
        items.append(BlastRadiusItem(
            label="Stripe configuration change",
            description=(
                "This Stripe configuration change may affect payment processing, billing, "
                "or webhook delivery."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Stripe resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Stripe Dashboard.",
                "Confirm payment and billing workflows are functioning correctly.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Stripe resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Vercel ────────────────────────────────────────────────────────────────────


def _analyze_vercel(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "deploy_hook"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Deployment trigger path",
            description=(
                "Vercel deploy hooks are secret URLs that trigger deployments when called — "
                "they function like API keys for your pipeline. Unexpected changes may indicate "
                "an unauthorized hook was added or a legitimate hook was removed, potentially "
                "breaking or exposing a deployment trigger."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["Vercel deploy hook configuration changed"],
            recommended_review=[
                "Confirm the hook change was intentional and corresponds to a known CI/CD or automation update.",
                "Verify the hook targets the expected branch.",
                "If a hook was removed, confirm that dependent automation still functions.",
                "Treat the new hook URL as a secret — rotate if it may have been exposed.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="workflow",
                provider="vercel",
                label="External deployment automation",
                description="External systems (CMS triggers, scheduled jobs, CI pipelines) that use this hook URL to initiate deployments.",
                count=None,
                confidence="medium",
                known=False,
            ),
            AffectedSurface(
                type="workflow",
                provider="vercel",
                label="Production deployment path",
                description="The deployment pipeline triggered by this hook may be connected to production or preview environments.",
                count=None,
                confidence="medium",
                known=False,
            ),
        ])
        limitations.append(
            "Impact depends on which external systems invoke this hook and whether the target branch reaches production."
        )
        conf = "high"

    elif _kw(rt, "deployment_protection", "protection"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Deployment access control",
            description=(
                "Vercel deployment protection controls who can access preview and production "
                "deployments. Weakened protection may expose in-progress or unreleased versions "
                "of your application to unintended users."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["Vercel deployment protection configuration changed"],
            recommended_review=[
                "Confirm the protection settings correspond to intended access policy.",
                "Verify that production deployments still require team authentication.",
                "Check whether preview deployments with unreleased features are now publicly accessible.",
                "Review which deployments are currently active and protected.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="infra",
            provider="vercel",
            label="Preview and production deployments",
            description="Active deployments may be accessible to users outside the expected audience if protection is weakened.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.append(
            "Impact depends on what is deployed in active preview or production builds."
        )
        conf = "high"

    elif _kw(rt, "env_var", "env"):
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Runtime configuration",
            description=(
                "Vercel environment variable changes may affect application behavior at build time "
                "or runtime. Changes may affect API endpoints, feature flags, or service integrations "
                "used by the deployed application."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Vercel environment variable metadata changed"],
            recommended_review=[
                "Confirm the variable change corresponds to a known deployment or configuration update.",
                "Verify dependent services or APIs still receive the correct configuration values.",
                "Check whether the change affects production, preview, or development environments.",
                "Review recent deployments for any unexpected behavior following this change.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="workflow",
            provider="vercel",
            label="Active deployments using this variable",
            description="Deployed application instances that consume this environment variable at runtime or build time.",
            count=None,
            confidence="medium",
            known=False,
        ))
        limitations.extend([
            "ConfigTrace never accesses or stores environment variable values — only metadata changes are detected.",
            "Impact depends on which deployment environments the variable is scoped to.",
        ])
        conf = "medium"

    elif _kw(rt, "domain"):
        domains.append("dns_routing")
        items.append(BlastRadiusItem(
            label="Production domain routing",
            description=(
                "Vercel domain configuration changes may affect how your production or preview "
                "URLs are routed. Changes could affect user traffic routing or SSL certificate "
                "assignment for the project."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Vercel domain configuration changed"],
            recommended_review=[
                "Confirm the domain change was intentional.",
                "Verify that production traffic is routing to the expected deployment.",
                "Check that SSL certificates are still valid and assigned.",
                "Confirm the old domain still serves traffic if needed during a migration.",
            ],
        ))
        limitations.append(
            "Impact depends on whether this domain serves production traffic or is used for preview/staging."
        )
        conf = "medium"

    else:
        domains.append("deployment_path")
        items.append(BlastRadiusItem(
            label="Vercel configuration change",
            description=(
                "This Vercel configuration change may affect deployment settings, environment "
                "variables, or access controls for your project."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Vercel resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Vercel dashboard.",
                "Confirm the intended configuration.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Vercel resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Shopify ───────────────────────────────────────────────────────────────────


def _analyze_shopify(
    rt: str, fp: str, rl: str, rr: str, pm: dict,
) -> dict:
    items: list[BlastRadiusItem] = []
    surfaces: list[AffectedSurface] = []
    domains: list[str] = []
    limitations: list[str] = []

    if _kw(rt, "app_permission", "app_scope"):
        domains.extend(["commerce_operations", "auth_flow"])
        scope_increased = _kw(rr, "increased", "added", "expanded", "new scope", "write")
        items.append(BlastRadiusItem(
            label="Installed app data access",
            description=(
                "Shopify app permission scope changes affect what store data an installed app can "
                "read or write. Increased scopes may grant access to customer data, orders, "
                "payments, or inventory depending on the scopes added."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high" if scope_increased else "medium",
            evidence=(
                ["Expanded app permissions inferred from risk reason"] if scope_increased
                else ["App permission scope changed"]
            ),
            recommended_review=[
                "Confirm the scope change was initiated by your team or a known app update.",
                "Review what data the new scopes allow the app to access.",
                "Verify the app is a trusted integration and not a compromised or rogue app.",
                "Audit recent app activity in the Shopify Partner Dashboard or app logs.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="resource",
                provider="shopify",
                label="Store data accessible to this app",
                description="Customer records, orders, payment data, or inventory the app can now access via new scopes.",
                count=None,
                confidence="medium",
                known=False,
            ),
            AffectedSurface(
                type="workflow",
                provider="shopify",
                label="Store operations",
                description="Write-scope expansions may allow the app to create, modify, or delete store data.",
                count=None,
                confidence="medium",
                known=False,
            ),
        ])
        limitations.append(
            "Full impact depends on what the app does with its new permissions — ConfigTrace cannot evaluate app behavior."
        )
        conf = "high"

    elif _kw(rt, "webhook"):
        domains.append("commerce_operations")
        items.append(BlastRadiusItem(
            label="Commerce event delivery",
            description=(
                "Shopify webhook changes may affect external systems that receive store events "
                "such as order creation, fulfillment updates, inventory changes, and refunds. "
                "Removed or modified webhooks may cause downstream systems to miss store events."
            ),
            severity=_risk_or(rl, "high"),
            confidence="high",
            evidence=["Shopify webhook configuration changed"],
            recommended_review=[
                "Identify which integration or service depends on this webhook topic.",
                "Confirm the endpoint URL is reachable and accepts the event payload.",
                "Review webhook delivery logs in the Shopify Partner Dashboard for failures.",
                "Verify order processing, inventory sync, and fulfillment flows are still working.",
            ],
        ))
        surfaces.extend([
            AffectedSurface(
                type="workflow",
                provider="shopify",
                label="Order fulfillment",
                description="External fulfillment services that receive order-related Shopify events.",
                count=None,
                confidence="high",
                known=True,
            ),
            AffectedSurface(
                type="workflow",
                provider="shopify",
                label="Inventory and third-party apps",
                description="Inventory management or ERP systems that sync state via Shopify webhooks.",
                count=None,
                confidence="medium",
                known=False,
            ),
        ])
        limitations.append(
            "Impact depends on which event topics this webhook subscribed to and what actions the receiving system takes."
        )
        conf = "high"

    elif _kw(rt, "store_policy", "policy"):
        domains.append("customer_self_service")
        items.append(BlastRadiusItem(
            label="Store policies and customer trust",
            description=(
                "Shopify store policy changes (refund, privacy, terms of service, shipping) "
                "affect legal compliance and customer-visible policy pages. Unexpected changes "
                "may affect customer trust or regulatory compliance."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Shopify store policy changed"],
            recommended_review=[
                "Confirm the policy change was intentional and reviewed by your team.",
                "Verify the updated policy complies with applicable regulations (GDPR, CCPA, etc.).",
                "Check whether any checkout flows reference the updated policy.",
            ],
        ))
        surfaces.append(AffectedSurface(
            type="resource",
            provider="shopify",
            label="Store customers",
            description="Customers who view policy pages or accept policies at checkout may encounter the updated text.",
            count=None,
            confidence="low",
            known=False,
        ))
        limitations.append(
            "Impact depends on whether the policy change affects active checkout flows or legal obligations."
        )
        conf = "medium"

    elif _kw(rt, "shop_metadata", "password", "store"):
        domains.append("commerce_operations")
        items.append(BlastRadiusItem(
            label="Storefront accessibility",
            description=(
                "Shopify shop metadata changes (password protection, store status, or domain) "
                "may affect storefront availability to customers or indicate a launch/maintenance "
                "state change."
            ),
            severity=_risk_or(rl, "medium"),
            confidence="medium",
            evidence=["Shopify shop metadata changed"],
            recommended_review=[
                "Confirm the change was intentional.",
                "Verify the storefront is accessible to customers if it is expected to be live.",
                "Check whether password protection was enabled or disabled.",
            ],
        ))
        limitations.append(
            "Impact depends on which metadata field changed and whether it affects customer-facing storefront access."
        )
        conf = "medium"

    else:
        domains.append("commerce_operations")
        items.append(BlastRadiusItem(
            label="Shopify configuration change",
            description=(
                "This Shopify configuration change may affect store operations, installed app "
                "access, or event delivery to external systems."
            ),
            severity=_risk_or(rl, "low"),
            confidence="low",
            evidence=[f"Shopify resource type changed: {rt}"],
            recommended_review=[
                "Review the change in the Shopify Admin.",
                "Confirm the intended configuration.",
            ],
        ))
        limitations.append("No specific blast radius model is available for this Shopify resource type.")
        conf = "low"

    return {
        "items": items, "surfaces": surfaces,
        "domains": list(dict.fromkeys(domains)),
        "limitations": limitations, "confidence": conf,
    }


# ── Title and summary builders ────────────────────────────────────────────────


_PROVIDER_LABELS: dict[str, str] = {
    "aws": "AWS",
    "cloudflare": "Cloudflare",
    "firebase": "Firebase",
    "supabase": "Supabase",
    "github": "GitHub",
    "stripe": "Stripe",
    "vercel": "Vercel",
    "shopify": "Shopify",
}

_DOMAIN_LABELS: dict[str, str] = {
    "network_exposure":    "Network exposure",
    "admin_access":        "Admin access",
    "data_access":         "Data access",
    "auth_flow":           "Authentication flow",
    "deployment_path":     "Deployment path",
    "payment_flow":        "Payment flow",
    "commerce_operations": "Commerce operations",
    "edge_protection":     "Edge protection",
    "monitoring_visibility": "Monitoring visibility",
    "credential_access":   "Credential access",
    "customer_self_service": "Customer self-service",
    "dns_routing":         "DNS routing",
}


def _build_title(provider: str, rt: str) -> str:
    prov_label = _PROVIDER_LABELS.get(provider, provider.title())
    for suffix, label in (
        ("security_group", "Security Group"),
        ("cloudtrail",     "CloudTrail"),
        ("cloudfront",     "CloudFront"),
        ("route53",        "Route 53"),
        ("iam",            "IAM"),
        ("waf",            "WAF"),
        ("branch_protection", "Branch Protection"),
        ("environment",    "Environment Protection"),
        ("webhook",        "Webhook"),
        ("deploy_hook",    "Deploy Hook"),
        ("env_var",        "Environment Variable"),
        ("rls",            "Row Level Security"),
        ("security_rules", "Security Rules"),
        ("app_check",      "App Check"),
        ("remote_config",  "Remote Config"),
        ("api_key",        "API Key"),
        ("billing_portal", "Billing Portal"),
        ("deploy_key",     "Deploy Key"),
        ("app_scope",      "App Permissions"),
        ("app_permission", "App Permissions"),
    ):
        if suffix in rt:
            return f"Potential impact of this {prov_label} {label} change"
    return f"Potential impact of this {prov_label} configuration change"


def _build_summary(
    provider: str, items: list[BlastRadiusItem], domains: list[str],
) -> str:
    if not items:
        return (
            "No specific blast radius model is available for this change. "
            "Review the change in context of your security posture."
        )
    domain_labels = [
        _DOMAIN_LABELS.get(d, d.replace("_", " ")) for d in domains[:3]
    ]
    domain_str = ", ".join(domain_labels) if domain_labels else "configuration"
    prov_label = _PROVIDER_LABELS.get(provider, provider.title())
    first_desc = items[0].description.split(". ")[0] + "."
    return (
        f"This {prov_label} change potentially affects {domain_str.lower()} surfaces. "
        f"{first_desc} "
        f"Review these surfaces before closing this finding."
    )


def _overall_confidence(
    item_confidences: list[str],
    provider_conf: str,
) -> str:
    order = {"high": 2, "medium": 1, "low": 0}
    scores = [order.get(c, 0) for c in item_confidences + [provider_conf]]
    m = max(scores)
    return "high" if m >= 2 else ("medium" if m >= 1 else "low")


# ── Main entry point ──────────────────────────────────────────────────────────


def compute_blast_radius(
    change_id: uuid.UUID,
    user_id: uuid.UUID,
    db: Session,
) -> BlastRadiusResponse:
    """Compute the blast radius for a change.

    Returns ``BlastRadiusResponse(available=False)`` when:
      - The primary change is not found / doesn't belong to user.
      - The change is low-risk and no meaningful surfaces can be inferred.

    Never raises; returns available=False on any unexpected condition.
    Raw prev_value / new_value is never accessed.
    """
    from app.models.change import Change as ChangeModel

    try:
        primary = (
            db.query(ChangeModel)
            .filter(ChangeModel.id == change_id, ChangeModel.user_id == user_id)
            .first()
        )
    except Exception:
        return BlastRadiusResponse(available=False)

    if primary is None:
        return BlastRadiusResponse(available=False)

    pm  = primary.provider_metadata or {}
    rt  = (pm.get("record_type") or "").lower()
    fp  = (primary.field_path or "").lower()
    rl  = (primary.risk_level or "low").lower()
    rr  = (primary.risk_reason or "").lower()

    provider = _derive_provider(rt)

    # Dispatch to provider-specific analyzer
    if provider == "aws":
        result = _analyze_aws(rt, fp, rl, rr, pm)
    elif provider == "cloudflare":
        result = _analyze_cloudflare(rt, fp, rl, rr, pm)
    elif provider == "firebase":
        result = _analyze_firebase(rt, fp, rl, rr, pm)
    elif provider == "supabase":
        result = _analyze_supabase(rt, fp, rl, rr, pm)
    elif provider == "github":
        result = _analyze_github(rt, fp, rl, rr, pm)
    elif provider == "stripe":
        result = _analyze_stripe(rt, fp, rl, rr, pm)
    elif provider == "vercel":
        result = _analyze_vercel(rt, fp, rl, rr, pm)
    elif provider == "shopify":
        result = _analyze_shopify(rt, fp, rl, rr, pm)
    else:
        # Unknown provider — no blast radius model
        return BlastRadiusResponse(
            available=False,
            title="",
            summary=(
                "No specific blast radius model is available for this change yet. "
                "Review the change in context of your security posture."
            ),
        )

    items: list[BlastRadiusItem] = result["items"]
    surfaces: list[AffectedSurface] = result["surfaces"]
    domains: list[str] = result["domains"]
    limitations: list[str] = result["limitations"]
    provider_conf: str = result["confidence"]

    # Low-risk changes with no meaningful items → not available
    if not items or (rl == "low" and provider_conf == "low"):
        return BlastRadiusResponse(available=False)

    confidence = _overall_confidence(
        [i.confidence for i in items], provider_conf
    )

    # Always append the canonical disclaimer
    limitations.append(
        "Blast radius is inferred from configuration metadata. "
        "Review provider context to understand actual impact scope."
    )
    # De-dup limitations
    seen_lim: set[str] = set()
    deduped_lim: list[str] = []
    for lim in limitations:
        if lim not in seen_lim:
            seen_lim.add(lim)
            deduped_lim.append(lim)

    title   = _build_title(provider, rt)
    summary = _build_summary(provider, items, domains)

    return BlastRadiusResponse(
        available=True,
        confidence=confidence,
        title=title,
        summary=summary,
        impact_domains=domains,
        items=items,
        affected_surfaces=surfaces,
        limitations=deduped_lim,
    )
