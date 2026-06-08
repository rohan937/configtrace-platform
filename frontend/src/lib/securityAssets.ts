/**
 * securityAssets.ts — group security findings by the asset they may affect (M61.4).
 *
 * The Affected Assets view turns the flat findings list (GET /security/findings)
 * into per-asset groups so users can see which repositories, webhooks, buckets,
 * security groups, DNS records, tables, rulesets, and projects currently carry
 * configuration exposure.
 *
 * Everything here is DERIVED from fields a finding already carries — no backend
 * changes, no invented data. We are deliberately conservative: when the exact
 * impacted asset is uncertain we fall back to neutral labels ("Provider
 * resource", "Configuration setting", "Unknown resource") and never overclaim
 * blast radius.
 */

import type { SecurityFinding, SecurityFindingSeverity } from "@/types";
import { SEVERITY_RANK } from "@/components/security/findingDisplay";

export interface AffectedAsset {
  /** Stable grouping key. */
  asset_key: string;
  /** Human asset-type label, e.g. "Repository", "Webhook", "Provider resource". */
  asset_type: string;
  /** Best-effort human identifier for the asset. */
  asset_label: string;
  provider: string;
  integration_id: string;
  resource_id: string | null;
  exposure_count: number;
  highest_severity: SecurityFindingSeverity;
  active_count: number;
  accepted_count: number;
  snoozed_count: number;
  resolved_count: number;
  /** Most recent last_seen_at across the asset's findings (ISO) or null. */
  last_seen_at: string | null;
  /** Earliest first_detected_at across the asset's findings (ISO) or null. */
  first_detected_at: string | null;
  findings: SecurityFinding[];
}

// ── Derivation helpers ────────────────────────────────────────────────────────

/** The record-identifier portion of a finding_key (`rule_id:record_id`). */
export function findingRecordId(f: SecurityFinding): string | null {
  const idx = f.finding_key.indexOf(":");
  if (idx < 0 || idx >= f.finding_key.length - 1) return null;
  const rest = f.finding_key.slice(idx + 1).trim();
  return rest.length > 0 ? rest : null;
}

// Asset-type keyword map, checked against the lowercased finding_key. Order
// matters — earlier, more specific matches win.
const TYPE_KEYWORDS: [needle: string, label: string][] = [
  ["webhook", "Webhook"],
  ["deploy_key", "Deploy key"],
  ["deploy-key", "Deploy key"],
  ["branch_protection", "Branch protection"],
  ["branch", "Branch"],
  ["repo", "Repository"],
  ["security_group", "Security group"],
  ["securitygroup", "Security group"],
  ["_sg_", "Security group"],
  ["bucket", "Bucket"],
  ["_s3", "Bucket"],
  ["access_key", "Access key"],
  ["access_analyzer", "Access analyzer"],
  ["iam", "IAM principal"],
  ["principal", "IAM principal"],
  ["vpc", "VPC"],
  ["flow_log", "VPC flow log"],
  ["dns", "DNS record"],
  ["waf", "WAF rule"],
  ["firewall", "Firewall rule"],
  ["ruleset", "Ruleset"],
  ["zone", "Cloudflare zone"],
  ["page_rule", "Page rule"],
  ["table", "Table"],
  ["schema", "Schema"],
  ["rls", "Row-level security"],
  ["auth", "Auth configuration"],
  ["project", "Project"],
  ["environment", "Environment"],
  ["env_", "Environment"],
  ["domain", "Domain"],
  ["certificate", "Certificate"],
  ["acm", "Certificate"],
  ["topic", "Topic"],
  ["policy", "Policy"],
  ["setting", "Configuration setting"],
  ["config", "Configuration setting"],
];

/** Best-effort, conservative asset-type label for a finding. */
export function deriveAssetType(f: SecurityFinding): string {
  const key = (f.finding_key || "").toLowerCase();
  for (const [needle, label] of TYPE_KEYWORDS) {
    if (key.includes(needle)) return label;
  }
  return "Provider resource";
}

// Evidence keys that are safe, human-readable identifiers (never secrets/hashes).
const LABEL_EVIDENCE_KEYS = [
  "name",
  "full_name",
  "repository",
  "repo",
  "bucket_name",
  "bucket",
  "security_group_id",
  "group_id",
  "vpc_id",
  "principal_name",
  "role_name",
  "user_name",
  "key_id_last4",
  "dns_name",
  "record_name",
  "host",
  "domain",
  "hostname",
  "rule_name",
  "ruleset",
  "zone",
  "zone_name",
  "table",
  "table_name",
  "schema",
  "project",
  "project_name",
  "topic",
  "webhook",
  "endpoint",
];

function asLabelString(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s || s.length > 100) return null;
  // Avoid hash-like or boolean-ish noise.
  if (/^(true|false|null|none)$/i.test(s)) return null;
  return s;
}

/** Best-effort, conservative human label for the asset a finding affects. */
export function deriveAssetLabel(f: SecurityFinding): string {
  const ev = (f.evidence ?? {}) as Record<string, unknown>;
  for (const k of LABEL_EVIDENCE_KEYS) {
    const s = asLabelString(ev[k]);
    if (s) return s;
  }
  // The record-identifier portion of the finding key is often human-readable
  // (e.g. "acme/widgets#webhook#1"); use it when it looks like an identifier.
  const rec = findingRecordId(f);
  if (rec && /[/#.\-:]/.test(rec) && rec.length <= 100) return rec;
  if (rec && rec.length <= 60) return rec;
  // Conservative fallbacks — never overclaim which asset is impacted.
  const t = deriveAssetType(f);
  if (t === "Configuration setting") return "Configuration setting";
  if (t === "Provider resource") return "Provider resource";
  return t;
}

/** Stable grouping key for a finding's asset (spec priority order). */
export function deriveAssetKey(f: SecurityFinding): string {
  if (f.resource_id) return `resource:${f.resource_id}`;
  const rec = findingRecordId(f);
  if (rec) return `rec:${f.provider}:${f.integration_id}:${rec}`;
  return `key:${f.provider}:${f.integration_id}:${f.finding_key}`;
}

// ── Grouping ──────────────────────────────────────────────────────────────────

function tsOrNull(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

function pickLabel(findings: SecurityFinding[]): string {
  // Use the most frequent non-fallback label; fall back to the first finding's.
  const counts = new Map<string, number>();
  for (const f of findings) {
    const l = deriveAssetLabel(f);
    counts.set(l, (counts.get(l) ?? 0) + 1);
  }
  let best: string | null = null;
  let bestN = -1;
  for (const [label, n] of counts) {
    const isFallback =
      label === "Provider resource" ||
      label === "Configuration setting" ||
      label === "Unknown resource";
    // Prefer specific labels; among ties, the more frequent one.
    const score = n + (isFallback ? -1000 : 0);
    if (score > bestN) {
      bestN = score;
      best = label;
    }
  }
  return best ?? "Provider resource";
}

/**
 * Group findings into affected assets. Pure and deterministic: assets are
 * returned sorted by highest severity, then exposure count, then label.
 */
export function groupFindingsByAsset(findings: SecurityFinding[]): AffectedAsset[] {
  const groups = new Map<string, SecurityFinding[]>();
  for (const f of findings) {
    const key = deriveAssetKey(f);
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }

  const assets: AffectedAsset[] = [];
  for (const [asset_key, group] of groups) {
    const rep = group[0];
    let highestRank = 99;
    let highest: SecurityFindingSeverity = "info";
    let active = 0;
    let accepted = 0;
    let snoozed = 0;
    let resolved = 0;
    let lastSeen: number | null = null;
    let firstDetected: number | null = null;

    for (const f of group) {
      const rank = SEVERITY_RANK[f.severity] ?? 99;
      if (rank < highestRank) {
        highestRank = rank;
        highest = f.severity;
      }
      if (f.status === "active") active += 1;
      else if (f.status === "accepted_risk") accepted += 1;
      else if (f.status === "snoozed") snoozed += 1;
      else if (f.status === "resolved") resolved += 1;

      const ls = tsOrNull(f.last_seen_at);
      if (ls !== null && (lastSeen === null || ls > lastSeen)) lastSeen = ls;
      const fd = tsOrNull(f.first_detected_at);
      if (fd !== null && (firstDetected === null || fd < firstDetected)) firstDetected = fd;
    }

    assets.push({
      asset_key,
      asset_type: deriveAssetType(rep),
      asset_label: pickLabel(group),
      provider: rep.provider,
      integration_id: rep.integration_id,
      resource_id: rep.resource_id,
      exposure_count: group.length,
      highest_severity: highest,
      active_count: active,
      accepted_count: accepted,
      snoozed_count: snoozed,
      resolved_count: resolved,
      last_seen_at: lastSeen !== null ? new Date(lastSeen).toISOString() : null,
      first_detected_at: firstDetected !== null ? new Date(firstDetected).toISOString() : null,
      findings: [...group].sort((a, b) => {
        const ra = SEVERITY_RANK[a.severity] ?? 99;
        const rb = SEVERITY_RANK[b.severity] ?? 99;
        if (ra !== rb) return ra - rb;
        return (tsOrNull(b.last_seen_at) ?? 0) - (tsOrNull(a.last_seen_at) ?? 0);
      }),
    });
  }

  assets.sort((a, b) => {
    const ra = SEVERITY_RANK[a.highest_severity] ?? 99;
    const rb = SEVERITY_RANK[b.highest_severity] ?? 99;
    if (ra !== rb) return ra - rb;
    if (b.exposure_count !== a.exposure_count) return b.exposure_count - a.exposure_count;
    return a.asset_label.localeCompare(b.asset_label);
  });

  return assets;
}

/** Distinct asset types present in a set of assets (for the filter dropdown). */
export function assetTypeOptions(assets: AffectedAsset[]): string[] {
  return [...new Set(assets.map((a) => a.asset_type))].sort();
}
