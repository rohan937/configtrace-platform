# Supabase Change-Classification Matrix (message-2 pass)

Scope: **classification correctness** for the 10 currently emitted and
tracked Supabase record types — severity, copy accuracy, restoration/
weakening direction, unknown-value safety (connector *and* classifier
together), added-record inspection, and Change/Security Finding severity
parity. Builds on the detection-QA pass (`2b342bd`,
`backend/tests/reports/supabase_detection_matrix.md`), which fixed the RLS
policy tracked-fields gap, added the missing `_build_provider_metadata()`
Supabase stanza, and removed the `_access_denied` synthetic-record pattern.

## Graphify summary

All four required queries ran successfully via
`/Users/rohan/.local/bin/graphify`. Per the task's explicit instruction,
success was **not** treated as evidence of freshness. The graph confirmed
`risk_rules/supabase.py` (M54), `SupabaseConnector`, and — critically —
`test_supabase_provider_depth_qa.py:375`'s "RLS disabled =
supabase_rls_disabled fires, NOT public_write" and a separate node
"mfa_required=None (not set) must NOT fire — evaluator checks 'is False'",
both confirming the RLS/public-write distinction and at least one existing
safe unknown-handling convention are indexed. `test_supabase_risk_audit.py`
surfaced as "Supabase risk accuracy audit — local-only regression tests."
The graph did **not** surface `supabase_detection_matrix.md`, `test_
supabase_detection_qa.py`, or any of the message-1 fixes (RLS tracked-
fields, provider_metadata stanza, `_access_denied` removal) by name,
confirming it is stale relative to `2b342bd`. No node hinted at the
Boolean-unknown-defaulting issue this pass fixes, nor at the two
`_classify_*` "added"-branch shape bugs found below — the graph is too
coarse for field/diff-level detail. All findings in this report come from
direct reads of `app/connectors/supabase.py`, `app/services/diff_service.py`,
`app/services/risk_rules/supabase.py`, and `app/services/security_rules/
supabase.py`, and from real `compute_diff()` execution.

## Root-cause bugs found and fixed this pass

### 1. Coordinated unknown-Boolean/count problem (connector + classifier, fixed together)

Per the deferred issue flagged in the message-1 report, neither side was
fixed in isolation:

**Connector** (`app/connectors/supabase.py`) — added `_bool_or_none()` and
`_count_or_none()` helpers and applied them to every Boolean/count field
not guaranteed present on every Management API response (removing the
`, False`/`, True` defaults from `.get(...)` and the outer `bool(...)`/`or
[]` coercions that silently turned "missing" into an explicit state):

| Field | Record type | Old default | New behavior |
|---|---|---|---|
| `email_enabled`, `phone_enabled`, `anonymous_enabled`, `mfa_totp_enabled` | auth_config | missing → `False` | missing → `None` |
| `leaked_password_protection_enabled`, `captcha_enabled`, `require_reauthentication_for_password_update`, `refresh_token_rotation_enabled` | auth_config | missing → `False` | missing → `None` |
| `additional_redirect_urls_count` | auth_config | missing → `0` | missing → `None`; explicit `[]` → `0` |
| OAuth `enabled` | oauth_provider | missing → `False` | missing → `None` |
| `s3_protocol_enabled` | storage_config | missing → `False` | missing → `None` |
| `verify_jwt` | edge_function | missing → `True` (already the safe direction, changed for consistency and to satisfy section F's explicit "required → unknown" test requirement) | missing → `None` |
| `env_var_key_count` | edge_function | missing → `0` | missing → `None`; explicit `[]` → `0` |
| `rls_enabled`, `rls_forced` | rls_status | missing → `False` (the **dangerous** direction — feeds the critical Finding) | missing → `None` |

Also fixed a related but distinct connector bug: `_fetch_network_restrictions()`
conflated "the `allowed_ranges` key is entirely absent from the response"
(malformed/unexpected shape) with "the key is present and explicitly `[]`"
(Supabase's own documented "no restrictions configured" signal) — both
produced an `is_unrestricted=True` record. Fixed to skip emitting a record
(unknown) when the key is missing, rather than asserting unrestricted.

**Classifier** (`app/services/risk_rules/supabase.py`) — added an explicit
`None`/unknown branch to every one of the above fields' classification
logic (19 call sites across `_classify_project_change`, `_classify_auth_
config_change`, `_classify_storage_config_change`, `_classify_edge_
function_change`, `_classify_rls_status_change`, `_classify_network_
restriction_change`, `_classify_oauth_provider_change`), each returning
cautious "...changed, but the new state could not be determined. Review
the current Supabase configuration." copy rather than falling into the
previous unconditional `else` branch that asserted an explicit restored/
weakened claim.

**Security Findings** were already unknown-safe before this pass (confirmed
via direct read and regression tests): `_eval_auth_config`, `_eval_rls`, and
`_eval_edge_function` all use explicit `is True`/`is False` checks (or
`"key" in record and record.get(key) is False`), so `None` never fires any
of the 10 rules — verified with 5 new regression tests exercising
`evaluate_record()` directly on records missing these fields entirely.

### 2. `_classify_rls_status_change`'s "added" branch checked the wrong data entirely

```python
if ct == "added":
    if not new_v:   # new_v is the FULL new record dict for an "added" Change
        return ("medium", "...without Row Level Security enabled...")
    return ("low", "...added with RLS enabled.")
```

A populated dict is **always truthy** in Python, so `not new_v` was always
`False` — every newly added table was silently classified as "added with
RLS enabled" regardless of its real `rls_enabled` value. Confirmed live via
`compute_diff()` before fixing: a table added with `rls_enabled: False`
produced `("low", "...was added with RLS enabled.")` — the exact opposite
of reality. **Fixed** to inspect `new_value.get("rls_enabled")` directly,
with an explicit unknown branch for when the field itself is absent.

### 3. `_classify_network_restriction_change`'s "added" branch checked the wrong data entirely (headline bug)

```python
if ct == "added":
    if new_v is True or (fp == "is_unrestricted" and new_v is True):
        return ("critical", "...network restrictions were removed...")
    if cidr in ("0.0.0.0/0", "::/0"):
        ...
    return ("low", "...Direct database access is now limited...")
```

Two independent problems made the **single most severe network-restriction
scenario** unreachable: (a) `new_v is True` compares a dict's identity
against the literal `True` object — always `False`; (b) `fp ==
"is_unrestricted"` — `field_path` is always empty for whole-record add/
remove events (compute_diff() never sets it), so this was also always
`False`. The result: when every explicit CIDR restriction is removed
(surfacing as the "unrestricted" sentinel record being newly "added" while
all prior CIDR records show as "removed"), the code fell all the way to
the generic "low" bucket — with **backwards copy** literally claiming
*"Direct database access is now limited to the listed addresses"* when
network access had actually just become **fully unrestricted**. Confirmed
live via `compute_diff()` before fixing. **Fixed** to inspect
`new_value.get("is_unrestricted")` directly — now correctly returns
`critical`.

## Confirmed correct, no fix needed

- `_classify_payment_link_change`-equivalent safe sequential-`if` patterns
  (e.g. `password_min_length`, `jwt_exp`, `oauth_provider_count`,
  `additional_redirect_urls_count`, `max_rows`, `file_size_limit`) all use
  `int(x)` wrapped in `try/except (TypeError, ValueError)` with explicit
  `is not None` guards — confirmed no live `int(x or 0)` unknown-as-zero
  bug exists anywhere in this file (reconfirmed this pass via a fresh grep;
  none found in the 10 live classifiers).
- `allowed_mime_types`'s classifier already treats `None` and `[]`
  identically on purpose (both mean "no MIME restriction, any file type
  uploadable" per Supabase's own semantics) — not a bug, an intentional
  design decision that predates this pass.
- `password_min_length`, `jwt_exp`'s numeric comparisons already had
  correct `is not None` guards before this pass — no change needed.

## Provider metadata completeness (reconfirmed via real `compute_diff()`)

| Record type | Identifying field(s) | Populated? |
|---|---|---|
| `supabase_rls_status` | `table_name`, `schema_name` | Yes (fixed in message 1, reconfirmed) |
| `supabase_edge_function` | `function_name`, `slug` | Yes (fixed in message 1, reconfirmed) |
| `supabase_network_restriction` | `cidr` | Yes (fixed in message 1, reconfirmed) |
| `supabase_custom_domain` | `custom_domain` | Yes (fixed in message 1, reconfirmed) |
| `supabase_oauth_provider` | `provider_name` | Yes (fixed in message 1, reconfirmed) |
| `supabase_project`, `supabase_auth_config`, `supabase_database_config`, `supabase_storage_config`, `supabase_api_config` | none beyond generic `record_name`/`record_id` | n/a — these are project-singleton records; no classifier reads an extra identifying field from provider_metadata for them |

All 5 metadata-dependent record types verified this pass via real
`compute_diff()` for **added**, **modified**, and **removed** Changes (not
just modified) — see `TestConnector*` / `TestClassifier*` test classes in
`test_supabase_change_classification_qa.py`.

## Security Finding parity (re-verified, no changes)

| Change | Change severity | Equivalent Finding | Finding severity | Relationship |
|---|---|---|---|---|
| `rls_enabled`→false | critical | `supabase_rls_disabled` | high | Change > Finding, justified (transition vs. static) |
| `has_public_select_policy`→true | high | `supabase_public_select_sensitive_table` | high | equal |
| `has_public_insert/update/delete_policy`→true | high | `supabase_public_write_policy` | high | equal |
| `anonymous_enabled`→true | critical | `supabase_anonymous_access_enabled` | medium | Change > Finding, justified |
| `mfa_totp_enabled`→false | high | (no direct MFA-disabled Finding exists — Findings cover leaked-password/refresh-rotation/captcha/reauth, not MFA directly) | n/a | Change-only, documented as intentional (MFA posture is covered via the auth-protection-missing Finding's combined language when leaked-password protection is also off, not a standalone MFA Finding) |
| `verify_jwt`→false | high | `supabase_edge_function_jwt_disabled` | high (medium if function name isn't sensitive-looking) | equal/Change ≥ Finding |
| `captcha_enabled`→false | medium | `supabase_captcha_disabled` | low | Change > Finding, satisfies "not lower" rule |
| `leaked_password_protection_enabled`→false | high | `supabase_auth_protection_missing` | medium | Change > Finding, justified |
| `refresh_token_rotation_enabled`→false | high | `supabase_refresh_token_rotation_disabled` | medium | Change > Finding, justified |
| `require_reauthentication_for_password_update`→false | medium | `supabase_password_update_reauth_disabled` | medium | equal |
| `is_unrestricted`→true | critical (**fixed this pass** for the "added" case) | no static Finding (network posture is Change-only by design) | n/a | Change-only, no gap |

No case found where a Change classification was rated *below* its
equivalent Finding, after this pass's fixes. Before fix #3, the "added
unrestricted network" case WAS effectively rated far below its own Change
convention (low vs. the intended critical) — now resolved.

## Change-only postures reconfirmed as intentional (no new Security Finding added)

- `supabase_project`, `supabase_database_config`, `supabase_api_config`,
  `supabase_custom_domain`, `supabase_network_restriction` (the CIDR-list
  Change severity already covers the unrestricted-network scenario at
  "critical" — a static Finding would be redundant with the resulting
  aggregate record's own posture, and prior context documents this as
  deliberate).
- `supabase_oauth_provider`, `supabase_storage_config`'s `s3_protocol_enabled`.
- MFA (`mfa_totp_enabled`) remains Change-only rather than gaining a
  dedicated static Finding — reviewed this pass and left as-is: MFA-
  disabled-as-a-standalone-Finding would need its own severity/copy design
  decision that's a message-1-detection-scope question (whether to add a
  new rule), not a message-2 classification-correctness fix, and adding a
  new Finding was explicitly out of scope ("Do not expand endpoint scope" /
  focus is classification correctness for existing rules).

## Classification matrix (54 representative cases)

| # | Category | Record type | Field(s) | Old → New | Detected? | Classifier branch | Severity (cur→exp) | Finding parity | Real-diff test? | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Project status | project | status | active→paused | Yes | `_classify_project_change` | high→high | n/a | test_supabase_risk_audit.py | PASS | — |
| 2 | Custom domain removed | project | has_custom_domain | true→false | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |
| 3 | Custom domain unknown | project | has_custom_domain | true→None | Yes | same | (was: falsely "added"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 4 | Email signup disabled | auth_config | email_enabled | true→false | Yes | `_classify_auth_config_change` | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |
| 5 | Email signup unknown | auth_config | email_enabled | true→None | Yes | same | (was: falsely "enabled"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 6 | Phone signup enabled | auth_config | phone_enabled | false→true | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |
| 7 | Phone signup unknown | auth_config | phone_enabled | true→None | Yes | same | (was: falsely "disabled"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 8 | Anonymous signup enabled | auth_config | anonymous_enabled | false→true | Yes | same | critical→critical | Finding `supabase_anonymous_access_enabled` (medium) | test_supabase_risk_audit.py | PASS | Change > Finding, justified |
| 9 | Anonymous signup disabled | auth_config | anonymous_enabled | true→false | Yes | same | low→low | n/a | test_supabase_risk_audit.py | PASS | improvement |
| 10 | Anonymous signup unknown | auth_config | anonymous_enabled | false→None | Yes | same | (was: falsely "disabled"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | not critical |
| 11 | MFA disabled | auth_config | mfa_totp_enabled | true→false | Yes | same | high→high | n/a (Change-only, documented) | test_supabase_risk_audit.py | PASS | — |
| 12 | MFA enabled | auth_config | mfa_totp_enabled | false→true | Yes | same | low→low | n/a | test_supabase_risk_audit.py | PASS | improvement |
| 13 | MFA unknown | auth_config | mfa_totp_enabled | true→None | Yes | same | (was: falsely "strengthens"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | matches graph hint "mfa_required=None must not fire" |
| 14 | Password min length decreased | auth_config | password_min_length | 12→6 | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | already safe (is not None guards) |
| 15 | Password min length unknown | auth_config | password_min_length | 12→None | Yes | same | low (generic, safe) | n/a | test_supabase_risk_audit.py | PASS | already safe |
| 16 | CAPTCHA disabled | auth_config | captcha_enabled | true→false | Yes | same | medium→medium | Finding `supabase_captcha_disabled` (low) | test_supabase_risk_audit.py | PASS | Change > Finding |
| 17 | CAPTCHA unknown | auth_config | captcha_enabled | true→None | Yes | same | (was: falsely "enabled"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 18 | Leaked-password protection disabled | auth_config | leaked_password_protection_enabled | true→false | Yes | same | high→high | Finding `supabase_auth_protection_missing` (medium) | test_supabase_risk_audit.py | PASS | Change > Finding |
| 19 | Leaked-password protection unknown | auth_config | leaked_password_protection_enabled | false→None | Yes | same | (was: falsely "will be warned"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 20 | Reauth-for-password-update disabled | auth_config | require_reauthentication_for_password_update | true→false | Yes | same | medium→medium | Finding `supabase_password_update_reauth_disabled` (medium) | test_supabase_risk_audit.py | PASS | equal |
| 21 | Reauth unknown | auth_config | require_reauthentication_for_password_update | false→None | Yes | same | (was: falsely "now required"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 22 | Refresh-token rotation disabled | auth_config | refresh_token_rotation_enabled | true→false | Yes | same | high→high | Finding `supabase_refresh_token_rotation_disabled` (medium) | test_supabase_risk_audit.py | PASS | Change > Finding |
| 23 | Refresh-token rotation unknown | auth_config | refresh_token_rotation_enabled | false→None | Yes | same | (was: falsely "enabled"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 24 | JWT expiry increased ≥2× | auth_config | jwt_exp | 3600→10800 | Yes | same | high→high | Finding `supabase_jwt_expiry_long` (medium, threshold 86400s) | test_supabase_risk_audit.py | PASS | already safe |
| 25 | Site URL changed | auth_config | site_url | https://a.com→https://b.com | Yes | same | high→high | n/a | test_supabase_risk_audit.py | PASS | — |
| 26 | Additional redirect URLs increased | auth_config | additional_redirect_urls_count | 1→3 | Yes | same | medium→medium | n/a (deferred Finding — no raw URLs stored) | test_supabase_risk_audit.py | PASS | — |
| 27 | Additional redirect URLs unknown | auth_config | additional_redirect_urls_count | 1→None | Yes | same | falls to generic "count changed" (try/except catches None), safe | n/a | already safe | PASS | no fix needed |
| 28 | OAuth provider count increased | auth_config | oauth_provider_count | 1→2 | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | already safe |
| 29 | RLS disabled | rls_status | rls_enabled | true→false | Yes | `_classify_rls_status_change` | critical→critical | equal-ish to `supabase_rls_disabled` (high), Change > Finding, justified | test_supabase_detection_qa.py | PASS | — |
| 30 | RLS enabled (restored) | rls_status | rls_enabled | false→true | Yes | same | low→low | n/a | test_supabase_risk_audit.py | PASS | improvement |
| 31 | RLS unknown | rls_status | rls_enabled | false→None | Yes | same | (was: falsely "security improvement"→now: medium, cautious) | Finding correctly skips (regression tested) | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 32 | RLS forced removed | rls_status | rls_forced | true→false | Yes | same | high→high | n/a | test_supabase_risk_audit.py | PASS | — |
| 33 | RLS forced unknown | rls_status | rls_forced | true→None | Yes | same | (was: falsely "enabled"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 34 | Public SELECT policy added | rls_status | has_public_select_policy | false→true | Yes (fixed msg 1) | same | high→high | equal to `supabase_public_select_sensitive_table` (high) | test_supabase_detection_qa.py | PASS | — |
| 35 | Public SELECT policy removed | rls_status | has_public_select_policy | true→false | Yes | same | low→low | n/a | test_supabase_detection_qa.py | PASS | improvement |
| 36 | Public SELECT policy unknown | rls_status | has_public_select_policy | true→None | Yes | same | (was: falsely "removed"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 37 | Public INSERT policy added | rls_status | has_public_insert_policy | false→true | Yes | same | high→high | equal to `supabase_public_write_policy` (high) | test_supabase_detection_qa.py | PASS | — |
| 38 | Public write policy unknown | rls_status | has_public_insert_policy | true→None | Yes | same | (was: falsely "removed"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 39 | exposed_to_anon added | rls_status | exposed_to_anon | false→true | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |
| 40 | exposed_to_anon unknown | rls_status | exposed_to_anon | true→None | Yes | same | (was: falsely "no longer has any policy"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 41 | Table added without RLS | rls_status | (whole record) | absent→present, rls_enabled=False | Yes | same | (was: falsely "low, added with RLS enabled"→now: medium) | n/a | test_supabase_change_classification_qa.py, test_milestone54.py, test_supabase_risk_audit.py (all fixed) | **FIXED** | headline bug #2 |
| 42 | Table added with RLS | rls_status | (whole record) | absent→present, rls_enabled=True | Yes | same | low→low (unchanged, now correctly evidenced) | n/a | test_supabase_change_classification_qa.py (new) | PASS (verified correct post-fix) | — |
| 43 | Table added, RLS unknown | rls_status | (whole record) | absent→present, no rls_enabled key | Yes | same | (was: falsely "low"→now: medium, cautious) | n/a | test_supabase_change_classification_qa.py, test_milestone54.py (new) | **FIXED** | — |
| 44 | Exposed schema changed | api_config | db_schema | public→internal | Yes | `_classify_api_config_change` | high→high | n/a | test_supabase_risk_audit.py | PASS | — |
| 45 | API max rows increased | api_config | max_rows | 100→1000 | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | already safe (is not None + try/except) |
| 46 | Storage MIME allow-list removed | storage_config | allowed_mime_types | [...]→None | Yes | `_classify_storage_config_change` | high→high | n/a | test_supabase_risk_audit.py | PASS | None/[] intentionally identical |
| 47 | S3 protocol enabled | storage_config | s3_protocol_enabled | false→true | Yes | same | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |
| 48 | S3 protocol unknown | storage_config | s3_protocol_enabled | true→None | Yes | same | (was: falsely "disabled"→now: low, cautious) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 49 | Edge Function JWT verification disabled | edge_function | verify_jwt | true→false | Yes | `_classify_edge_function_change` | high→high | equal to `supabase_edge_function_jwt_disabled` | test_supabase_detection_qa.py | PASS | — |
| 50 | Edge Function JWT verification unknown | edge_function | verify_jwt | true→None | Yes | same | (was: falsely "enabled"→now: medium, cautious) | Finding correctly skips (regression tested) | test_supabase_change_classification_qa.py (new) | **FIXED** | — |
| 51 | Env var key count unknown vs. zero | edge_function | env_var_key_count | (missing)→None vs explicit []→0 | Yes (fixed this pass) | same | medium (generic, unaffected by direction) | n/a | test_supabase_change_classification_qa.py (new) | **FIXED** | connector-level distinction |
| 52 | Network restriction added (unrestricted) | network_restriction | (whole record) | absent→present, is_unrestricted=True | Yes | `_classify_network_restriction_change` | (was: falsely "low"→now: critical) | n/a (Change-only) | test_supabase_change_classification_qa.py (new) | **FIXED** | headline bug #3 |
| 53 | Network restriction added (restricted CIDR) | network_restriction | (whole record) | absent→present, is_unrestricted=False | Yes | same | low→low (unchanged, correctly evidenced) | n/a | test_supabase_change_classification_qa.py (new) | PASS (verified correct post-fix) | — |
| 54 | OAuth provider disabled | oauth_provider | enabled | true→false | Yes | `_classify_oauth_provider_change` | medium→medium | n/a | test_supabase_risk_audit.py | PASS | — |

## Test results

```
pytest tests/test_supabase_provider_depth_qa.py tests/test_supabase_risk_audit.py \
  tests/test_milestone60_4_4_supabase_firebase_rules.py \
  tests/test_milestone71a_supabase_security_provider_foundation.py \
  tests/test_milestone71b_supabase_activity_ingestion.py \
  tests/test_milestone71c_supabase_activity_signals.py \
  tests/test_milestone71d_supabase_correlations.py \
  tests/test_milestone71e_supabase_demo_qa.py \
  tests/test_supabase_detection_qa.py tests/test_supabase_change_classification_qa.py -q
  -> 234 passed

pytest tests/test_milestone54.py -k "TestSupabaseRiskRules" -q
  -> 41 passed (1 pre-existing test found stale and fixed: test_new_table_with_rls_is_low
     used an unrealistic "added" Change shape — a bare bool as new_value instead of the
     real full-record dict — and coincidentally passed only because the old classifier
     bug happened to produce the same wrong-for-the-right-reason answer; also added
     test_new_table_rls_unknown_is_medium_and_cautious)

pytest tests/test_supabase_risk_audit.py -q (after fixing test_A4's shape, adding test_A4b)
  -> 40 passed (test_A4_new_table_without_rls_is_medium's shape fixed to a real dict;
     added test_A4b_new_table_with_rls_is_low)

pytest -k "supabase and rls"     -> 47 passed (2.0s, foreground, no timeout)
pytest -k "supabase and storage" -> 12 passed (1.7s, foreground, no timeout)
pytest -k "supabase and function" -> 22 passed (62.2s, foreground, completed before the
  120s guard — reported as-is per instructions, no broadening of the filter)
```

`-k "supabase"` and `-k "supabase and auth"` were **not** re-attempted —
both hung repeatedly in the message-1 pass and the task explicitly says not
to rerun them. All exact files plus the two additionally-discovered stale
tests (found via `-k "supabase and rls"`, which is why the narrow filters
were valuable this pass despite the broad ones being unusable) are treated
as authoritative.

No zero-selection filters were encountered. Frontend was not touched this
pass — no new/changed Security Finding rules — `npx tsc --noEmit` was not
run (not required).

## Files changed this pass

- `backend/app/connectors/supabase.py` — added `_bool_or_none()` /
  `_count_or_none()` helpers; applied to 13 fields across auth_config,
  oauth_provider, storage_config, edge_function, and rls_status; fixed
  `_fetch_network_restrictions()`'s missing-key-vs-empty-list conflation.
- `backend/app/services/risk_rules/supabase.py` — added 19 explicit
  unknown branches; fixed the RLS "added" branch's wrong-data-shape bug;
  fixed the network-restriction "added" branch's wrong-data-shape bug
  (the headline severity-inversion fix).
- `backend/tests/test_supabase_change_classification_qa.py` — new, 50
  regression tests.
- `backend/tests/test_milestone54.py` — fixed 1 stale "added" Change-shape
  test, added 1 new test for the unknown case.
- `backend/tests/test_supabase_risk_audit.py` — fixed 1 stale "added"
  Change-shape test, added 1 companion test.
- `backend/tests/reports/supabase_change_classification_matrix.md` — this
  report (new).

## Safe to push?

Not evaluated (push explicitly out of scope). All exact and narrow Supabase
test filters pass (275 tests across the exact-file + milestone54-class
runs, plus 47+12+22 via narrow `-k` filters). No new/changed Security
Finding rules were added, so no registry/frontend/provider-depth
re-verification was required beyond what messages 1 and 2 already confirm.
Live Supabase Management API validation remains advisable to confirm the
real API's actual behavior for the fields now preserved as `None` (in
particular, whether `rls_enabled` and the M57.8 auth fields are ever
genuinely absent on a real project, versus always present in practice) —
this pass's fixes are defensively correct either way, but their real-world
trigger frequency can only be confirmed against a live project.
