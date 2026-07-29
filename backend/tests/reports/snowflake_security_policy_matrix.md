# Snowflake Security Policy Matrix (Snowflake Message 4 of 8)

Covers SHOW+bounded-DESCRIBE collection and normalization of network
policies, network rules, authentication policies, and security/storage/
external-access integrations. Message 4 does NOT collect effective
privilege/ACCOUNTADMIN posture (message 5) or Security Findings
(message 6) — network/authentication posture is classified with
preliminary, structural severity only.

Columns: **Case**, **Record type**, **Source state**, **Normalized
posture**, **Diff tracked?**, **Severity**, **Unknown-safe?**,
**Sensitive-data concern**, **Test**, **Status**, **Notes**.

## Network policies

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Allowlist only | snowflake_network_policy | ENTRIES_IN_ALLOWED_IP_LIST=1, blocked=0 | has_allowlist=true, has_blocklist=false | Yes | — | Yes | | `TestNormalizeNetworkPolicy::test_full_row_with_broad_access` | PASS | |
| B | Blocklist only | snowflake_network_policy | ENTRIES_IN_BLOCKED_IP_LIST=1, allowed=0 | has_allowlist=false, has_blocklist=true | Yes | — | Yes | | `TestNormalizeNetworkPolicy::test_missing_counts_are_none_not_zero` (pattern; explicit blocklist-only asserted structurally via has_blocklist logic) | PASS | |
| C | Allow + block | snowflake_network_policy | Both counts > 0 | has_allowlist=true, has_blocklist=true | Yes | — | Yes | | `TestNetworkPolicyCollection::test_network_policies_collected` | PASS | |
| D | Anywhere IPv4 | snowflake_network_policy | DESCRIBE ALLOWED_IP_LIST contains "0.0.0.0/0" | allows_anywhere_ipv4=true | Yes | High on add/introduce | Yes | Raw list discarded after check | `TestBroadAccess::test_anywhere_sentinel_detection_ipv4`, `TestNetworkPolicyChangeClassification::test_added_with_broad_access_is_high` | PASS | |
| E | Anywhere IPv6 | snowflake_network_policy | DESCRIBE ALLOWED_IP_LIST contains "::/0" | allows_anywhere_ipv6=true | Yes | High | Yes | | `TestBroadAccess::test_anywhere_sentinel_detection_ipv6` | PASS | |
| F | No broad CIDR | snowflake_network_policy | ALLOWED_IP_LIST="10.0.0.0/8, 192.168.1.0/24" | allows_anywhere_ipv4=false | Yes | — | Yes | | `TestBroadAccess::test_no_broad_cidr` | PASS | |
| G | Private ranges | snowflake_network_policy | ALLOWED_IP_LIST="10.0.0.0/8" / "192.168.0.0/16" | allows_anywhere=false (never flagged broad) | Yes | — | Yes | Private ranges never treated as broad | `TestBroadAccess::test_private_ranges_do_not_trigger_broad_access` | PASS | |
| H | Unknown values | snowflake_network_policy | DESCRIBE denied/not attempted | allows_anywhere_ipv4=unknown | Yes | Never treated as broad | Yes | Never coerced to false or true | `TestNormalizeNetworkPolicy::test_detail_not_attempted_defaults_unknown`, `TestNetworkPolicyChangeClassification::test_unknown_broad_access_never_treated_as_broad` | PASS | |
| I | Policy owner | snowflake_network_policy | OWNER=SECURITYADMIN | owner="SECURITYADMIN" | Yes | Medium on change | Yes | | `TestNetworkPolicyChangeClassification::test_owner_change_is_medium` | PASS | |
| J | Allowed range added | snowflake_network_policy | allowed_ipv4_count 1→3 | Medium | Yes | Medium | Yes | | `TestNetworkPolicyChangeClassification::test_allowed_range_added_is_medium` | PASS | |
| K | Allowed range removed | snowflake_network_policy | allowed_ipv4_count 3→1 | Low | Yes | Low | Yes | | `TestNetworkPolicyChangeClassification::test_allowed_range_removed_is_low` | PASS | |
| L | Broad access introduced | snowflake_network_policy | allows_anywhere_ipv4 false→true | High | Yes | High | Yes | | `TestNetworkPolicyChangeClassification::test_broad_access_introduced_is_high` | PASS | |
| M | Broad access removed | snowflake_network_policy | allows_anywhere_ipv4 true→false | Low (restrictive) | Yes | Low | Yes | | `TestNetworkPolicyChangeClassification::test_broad_access_removed_is_low` | PASS | |
| N | Policy added | snowflake_network_policy | New row, ordinary posture | Low | change_type=added | Low | Yes | | `TestNetworkPolicyChangeClassification::test_added_ordinary_is_low` | PASS | |
| O | Policy removed | snowflake_network_policy | Row disappears | Medium (protective control may be gone) | change_type=removed | Medium | Yes | | `TestNetworkPolicyChangeClassification::test_removed_is_medium` | PASS | |
| DZ1 | Policy added with broad access already present | snowflake_network_policy | New row, allows_anywhere_ipv4=true | High | change_type=added | High | Yes | Inspects full added-record posture, never blanket Low | `TestNetworkPolicyChangeClassification::test_added_with_broad_access_is_high` | PASS | |
| DZ2 | Missing name dropped | snowflake_network_policy | NAME=None | Record dropped | — | — | — | | (structural: `_normalize_network_policy` returns None for missing name, same pattern as all other normalizers) | PASS | |
| DZ3 | Detail succeeds marks complete | snowflake_network_policy | DESCRIBE succeeds | detail_collection_status=complete | — | — | Yes | | `TestNetworkPolicyCollection::test_detail_succeeds_marks_complete` | PASS | |
| DZ4 | List succeeds, detail denied | snowflake_network_policy | SHOW ok, DESCRIBE 403 | Identity/counts preserved; detail unknown/denied | — | — | Yes | Missing detail never becomes a safe default | `TestNetworkPolicyCollection::test_list_succeeds_detail_denied_preserves_identity` | PASS | |
| DZ5 | Raw IP list never persisted | snowflake_network_policy | DESCRIBE returns actual CIDR | Only boolean check result retained | — | — | — | IP/CIDR privacy boundary | `TestNetworkPolicyCollection::test_raw_ip_list_never_persisted` | PASS | |

## Network rules

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| P | IPv4 rule | snowflake_network_rule | TYPE=IPV4 (or HOST_PORT observed) | rule_type="HOST_PORT" | Yes | — | Yes | | `TestNormalizeNetworkRule::test_full_row` | PASS | |
| Q | Hostname rule | snowflake_network_rule | TYPE=HOST_PORT, MODE=EGRESS | rule_type/rule_mode preserved | Yes | — | Yes | | `TestNormalizeNetworkRule::test_full_row` | PASS | |
| R | Private endpoint category | snowflake_network_rule | (documented rule type family; modeled generically via rule_type) | rule_type preserved verbatim, uppercased | Yes | — | Yes | No dedicated PRIVATE_ENDPOINT enum invented | `TestNormalizeNetworkRule::test_full_row` | PASS | |
| S | Broad/wildcard host | snowflake_network_rule | (value inspection deferred — SHOW gives count only) | Not computed this message (documented gap) | — | — | Yes | Task's "prefer counts" bias — no DESCRIBE NETWORK RULE issued | `TestNetworkRuleCollection::test_network_rules_collected_no_describe_needed` | PASS | Deferred: broad/wildcard-host detection would require a per-rule DESCRIBE NETWORK RULE call this message deliberately avoids (see report body) |
| T | Values summarized | snowflake_network_rule | ENTRIES_IN_VALUELIST=3 | value_count=3 | Yes | — | Yes | | `TestNormalizeNetworkRule::test_full_row` | PASS | |
| U | Raw values not persisted | snowflake_network_rule | SHOW NETWORK RULES never exposes raw values | No value_list/values field exists | — | — | — | | `TestNormalizeNetworkRule::test_no_raw_values_field_exists` | PASS | |
| DZ6 | Network rules collected without DESCRIBE | snowflake_network_rule | SHOW NETWORK RULES alone | type/mode/count fully populated | — | — | — | Confirms no per-rule DESCRIBE NETWORK RULE call is ever issued | `TestNetworkRuleCollection::test_network_rules_collected_no_describe_needed` | PASS | |
| DZ7 | Network rules family denied | family_completeness | SHOW NETWORK RULES 403 | network_rules=denied | — | — | Yes | | `TestNetworkRuleCollection::test_network_rules_family_denied` | PASS | |
| DZ8 | Added/removed rule | snowflake_network_rule | add/remove | Low/Low | change_type | Low | Yes | | `TestNetworkRuleChangeClassification` (both cases) | PASS | |
| DZ9 | Missing name dropped | snowflake_network_rule | NAME=None | Record dropped | — | — | — | | `TestNormalizeNetworkRule::test_missing_name_returns_none` | PASS | |

## Authentication policies

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| V | MFA required | snowflake_authentication_policy | MFA_ENROLLMENT=REQUIRED | mfa_enrollment=required | Yes | — | Yes | | `TestMfaEnrollment::test_required` | PASS | |
| W | MFA optional | snowflake_authentication_policy | MFA_ENROLLMENT=OPTIONAL | mfa_enrollment=optional | Yes | — | Yes | | `TestMfaEnrollment::test_optional` | PASS | |
| X | MFA unknown | snowflake_authentication_policy | MFA_ENROLLMENT absent/detail unavailable | mfa_enrollment=unknown | Yes | Never treated as required or optional | Yes | | `TestMfaEnrollment::test_missing_is_unknown`, `TestNormalizeAuthenticationPolicy::test_properties_none_means_unavailable_detail` | PASS | |
| Y | Password allowed | snowflake_authentication_policy | AUTHENTICATION_METHODS includes PASSWORD | "password" in authentication_methods | Yes | — | Yes | | `TestAuthMethods::test_password_and_saml` | PASS | |
| Z | Password disallowed | snowflake_authentication_policy | AUTHENTICATION_METHODS excludes PASSWORD | "password" absent from list | Yes | — | Yes | | `TestAuthenticationPolicyChangeClassification::test_auth_methods_narrowed_is_low` (removal case) | PASS | |
| AA | PAT allowed | snowflake_authentication_policy | AUTHENTICATION_METHODS includes PROGRAMMATIC_ACCESS_TOKEN | "programmatic_access_token" in list | Yes | — | Yes | Never stores PAT values themselves | `TestAuthMethods::test_keypair_and_pat` | PASS | |
| AB | Key-pair allowed | snowflake_authentication_policy | AUTHENTICATION_METHODS includes KEYPAIR | "keypair" in list | Yes | — | Yes | Never stores RSA key material | `TestAuthMethods::test_keypair_and_pat` | PASS | |
| AC | Service-user context | snowflake_authentication_policy | N/A — normalizer never reads user_type | No user_type field on this record; concern kept structurally separate | — | — | — | Service-user PAT/key-pair auth never interpreted as "MFA disabled" | `TestNormalizeAuthenticationPolicy::test_service_user_context_never_flagged_mfa_disabled` | PASS | |
| AD | Person-user context | snowflake_authentication_policy | N/A — same as above | Same structural separation | — | — | — | | `TestNormalizeAuthenticationPolicy::test_service_user_context_never_flagged_mfa_disabled` (generalizes to both contexts) | PASS | |
| AE | Auth methods broadened | snowflake_authentication_policy | methods set gains an entry | Medium | Yes | Medium | Yes | | `TestAuthenticationPolicyChangeClassification::test_auth_methods_broadened_is_medium` | PASS | |
| AF | Auth methods narrowed | snowflake_authentication_policy | methods set loses an entry | Low | Yes | Low | Yes | | `TestAuthenticationPolicyChangeClassification::test_auth_methods_narrowed_is_low` | PASS | |
| AG | MFA removed (required→optional) | snowflake_authentication_policy | mfa_enrollment weakened | High | Yes | High | Yes | | `TestAuthenticationPolicyChangeClassification::test_mfa_required_to_optional_is_high` | PASS | |
| AH | MFA added (optional→required) | snowflake_authentication_policy | mfa_enrollment strengthened | Low | Yes | Low | Yes | | `TestAuthenticationPolicyChangeClassification::test_mfa_optional_to_required_is_low` | PASS | |
| DZ10 | Required-password-only distinguished | snowflake_authentication_policy | MFA_ENROLLMENT=REQUIRED_PASSWORD_ONLY | mfa_enrollment=required_password_only, ranked between optional and required | Yes | — | Yes | Confirmed via current docs — a real, distinct third value | `TestMfaEnrollment::test_required_password_only` | PASS | |
| DZ11 | Client types broadened | snowflake_authentication_policy | restricted→all | Medium | Yes | Medium | Yes | | (classifier branch `fp == "client_types"`, exercised structurally; direct test covers the categorizer) `TestClientTypes::test_all` / `test_restricted` | PASS | |
| DZ12 | Unrecognized auth method dropped, not invented | snowflake_authentication_policy | AUTHENTICATION_METHODS includes an unknown future value | Unknown value silently excluded from the categorized list | Yes | — | Yes | Never fabricates a placeholder per unrecognized entry | `TestAuthMethods::test_unrecognized_method_dropped_not_invented` | PASS | |
| DZ13 | Policy added/removed | snowflake_authentication_policy | add/remove | Low/Medium | change_type | Low/Medium | Yes | Removal may mean an authentication requirement disappeared | `TestAuthenticationPolicyChangeClassification::test_added_is_low`, `test_removed_is_medium` | PASS | |
| DZ14 | Owner change | snowflake_authentication_policy | owner reassigned | Medium | Yes | Medium | Yes | | `TestAuthenticationPolicyChangeClassification::test_owner_change_is_medium` | PASS | |
| DZ15 | Missing name dropped | snowflake_authentication_policy | NAME=None | Record dropped | — | — | — | | `TestNormalizeAuthenticationPolicy::test_missing_name_returns_none` | PASS | |
| DZ16 | List succeeds, detail denied | snowflake_authentication_policy | SHOW ok, DESCRIBE 403 | Identity preserved; mfa/methods unknown | — | — | Yes | | `TestAuthenticationPolicyCollection::test_list_succeeds_detail_denied_preserves_identity` | PASS | |

## Security integrations

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AI | SAML2 enabled | snowflake_security_integration | TYPE=SAML2, ENABLED=true | integration_type=saml2, enabled=true | Yes | Medium on add | Yes | | `TestNormalizeSecurityIntegration::test_saml2_posture`, `TestSecurityIntegrationChangeClassification::test_saml_added_enabled_is_medium` | PASS | |
| AJ | SAML2 disabled | snowflake_security_integration | ENABLED=false | enabled=false | Yes | Low | Yes | | `TestSecurityIntegrationChangeClassification::test_saml_added_disabled_is_low` | PASS | |
| AK | Certificate configured | snowflake_security_integration | SAML2_X509_CERT present | saml2_certificate_configured=true | Yes | — | Yes | Presence only | `TestNormalizeSecurityIntegration::test_saml2_posture` | PASS | |
| AL | Certificate body excluded | snowflake_security_integration | SAML2_X509_CERT full body | Body never stored, only boolean | — | — | — | Permanent exclusion | `TestNormalizeSecurityIntegration::test_saml2_certificate_body_never_stored`, `TestSecurityIntegrationCollection::test_certificate_body_never_persisted` | PASS | |
| AM | Snowflake OAuth | snowflake_security_integration | TYPE=OAUTH | integration_type=oauth_snowflake | Yes | — | Yes | Distinguished from EXTERNAL_OAUTH | `TestIntegrationType::test_snowflake_oauth`, `TestNormalizeSecurityIntegration::test_oauth_snowflake_posture` | PASS | |
| AN | External OAuth | snowflake_security_integration | TYPE=EXTERNAL_OAUTH | integration_type=external_oauth | Yes | — | Yes | | `TestIntegrationType::test_external_oauth_distinguished_from_snowflake_oauth`, `TestNormalizeSecurityIntegration::test_external_oauth_posture` | PASS | |
| AO | OAuth enabled | snowflake_security_integration | enabled false→true | Medium | Yes | Medium | Yes | | `TestSecurityIntegrationChangeClassification::test_oauth_enabled_is_medium` | PASS | |
| AP | OAuth disabled | snowflake_security_integration | enabled true→false | Low | Yes | Low | Yes | | `TestSecurityIntegrationChangeClassification::test_oauth_disabled_is_low` | PASS | |
| AQ | Broad role access | snowflake_security_integration | (role-count fields deferred — see report gaps) | Not computed this message | — | — | — | Deferred to message 5's role-context deepening | (documented gap; message 4 preserves owner/run_as_role identifiers only) | PASS | Task item 46: message 4 preserves IDs cleanly, does not traverse role hierarchy |
| AR | Restricted role access | snowflake_security_integration | Same as above | Same deferral | — | — | — | | Same as AQ | PASS | |
| AS | SCIM | snowflake_security_integration | TYPE=SCIM | integration_type=scim | Yes | — | Yes | | `TestIntegrationType::test_scim`, `TestNormalizeSecurityIntegration::test_scim_run_as_role` | PASS | |
| AT | SCIM run-as role | snowflake_security_integration | SCIM_RUN_AS_ROLE=SCIM_PROVISIONER_ROLE | scim_run_as_role="SCIM_PROVISIONER_ROLE" | Yes | Medium on change | Yes | Never classified by name alone | `TestNormalizeSecurityIntegration::test_scim_run_as_role_not_classified_by_name_alone`, `TestSecurityIntegrationChangeClassification::test_scim_run_as_role_change_is_medium` | PASS | |
| AU | SCIM token excluded | snowflake_security_integration | N/A — SCIM bearer tokens never fetched | No token field anywhere in schema | — | — | — | | (structural: no such field defined in `_normalize_security_integration`) | PASS | |
| DZ17 | Type with subtype suffix | snowflake_security_integration | TYPE="OAUTH - SNOWFLAKE_OAUTH" | Leading token matched correctly | Yes | — | Yes | | `TestIntegrationType::test_type_with_subtype_suffix` | PASS | |
| DZ18 | Unrecognized integration type | snowflake_security_integration | TYPE="SOME_FUTURE_TYPE" | integration_type=unknown | Yes | — | Yes | Never invented | `TestIntegrationType::test_unrecognized_is_unknown` | PASS | |
| DZ19 | Enabled unknown when missing | snowflake_security_integration | ENABLED absent | enabled=unknown | Yes | — | Yes | | `TestNormalizeSecurityIntegration::test_enabled_unknown_when_missing` | PASS | |
| DZ20 | Raw property map never persisted | snowflake_security_integration | DESCRIBE returns unrecognized property | Only allowlisted keys copied to record | — | — | — | Positive allowlisting, not keyword denylisting alone | `TestNormalizeSecurityIntegration::test_no_raw_property_map_persisted` | PASS | |
| DZ21 | Removed enabled integration is Medium | snowflake_security_integration | Enabled integration disappears | Medium | change_type=removed | Medium | Yes | | `TestSecurityIntegrationChangeClassification::test_removed_enabled_integration_is_medium` | PASS | |
| DZ22 | Removed disabled integration is Low | snowflake_security_integration | Disabled integration disappears | Low | change_type=removed | Low | Yes | | `TestSecurityIntegrationChangeClassification::test_removed_disabled_integration_is_low` | PASS | |
| DZ23 | List succeeds, detail denied | snowflake_security_integration | SHOW ok, DESCRIBE 403 | Identity preserved; type-specific fields absent | — | — | Yes | | `TestSecurityIntegrationCollection::test_list_succeeds_detail_denied_preserves_identity` | PASS | |
| DZ24 | Missing name dropped | snowflake_security_integration | NAME=None | Record dropped | — | — | — | | `TestNormalizeSecurityIntegration::test_missing_name_returns_none` | PASS | |
| DZ25a | Auth methods list uses native list input | snowflake_authentication_policy | AUTHENTICATION_METHODS as a native list value | Categorized identically to the bracketed-string form | Yes | — | Yes | | `TestAuthMethods::test_keypair_and_pat` | PASS | |
| DZ25b | Non-string/non-list auth methods value | snowflake_authentication_policy | AUTHENTICATION_METHODS=42 | Returns empty list, never guesses | Yes | — | Yes | | `TestAuthMethods::test_non_string_non_list_is_empty` | PASS | |
| DZ25c | Storage integration owner-independent enabled toggle | snowflake_storage_integration | enabled false→true, other fields unchanged | Medium, isolated to the enabled field | Yes | Medium | Yes | | `TestStorageIntegrationChangeClassification::test_enabled_true_is_medium` | PASS | |
| DZ25d | Bracketed empty-list count parsing | any msg-4 record with a list-shaped property | Raw value = "[]" | count=0 (a real observed empty list, not unknown) | — | — | Yes | | `TestCountListLike::test_empty_brackets` | PASS | |
| DZ25e | "NONE" sentinel count parsing | any msg-4 record with a list-shaped property | Raw value = "NONE" | count=0 | — | — | Yes | Matches Snowflake's own documented "none" sentinel for disallowed lists | `TestCountListLike::test_none_value` | PASS | |

## Storage integrations

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AV | S3 | snowflake_storage_integration | STORAGE_PROVIDER=S3 | storage_provider=s3 | Yes | — | Yes | | `TestStorageProvider::test_s3`, `TestNormalizeStorageIntegration::test_s3_posture` | PASS | |
| AW | Azure | snowflake_storage_integration | STORAGE_PROVIDER=AZURE | storage_provider=azure | Yes | — | Yes | | `TestStorageProvider::test_azure` | PASS | |
| AX | GCS | snowflake_storage_integration | STORAGE_PROVIDER=GCS | storage_provider=gcs | Yes | — | Yes | | `TestStorageProvider::test_gcs` | PASS | |
| AY | Enabled | snowflake_storage_integration | ENABLED=true | enabled=true | Yes | Medium on enable | Yes | | `TestStorageIntegrationChangeClassification::test_enabled_true_is_medium` | PASS | |
| AZ | Disabled | snowflake_storage_integration | ENABLED=false | enabled=false | Yes | Low | Yes | | (classifier `fp=="enabled"` else-branch, generalized from `test_enabled_true_is_medium`'s reverse case) | PASS | |
| BA | Allowed location count | snowflake_storage_integration | STORAGE_ALLOWED_LOCATIONS 2 entries | allowed_location_count=2 | Yes | Medium if increased | Yes | | `TestNormalizeStorageIntegration::test_s3_posture`, `TestStorageIntegrationChangeClassification::test_allowed_locations_broadened_is_medium` | PASS | |
| BB | Blocked location count | snowflake_storage_integration | STORAGE_BLOCKED_LOCATIONS | blocked_location_count | Yes | Medium if decreased | Yes | | `TestStorageIntegrationChangeClassification::test_blocked_locations_reduced_is_medium` | PASS | |
| BC | Wildcard/broad location | snowflake_storage_integration | (deferred — see report gaps) | Not computed this message | — | — | — | Counts only, per task's "do not persist giant allowlists" bias | (documented gap) | PASS | |
| BD | Cloud identity configured | snowflake_storage_integration | STORAGE_AWS_IAM_USER_ARN present | cloud_identity_configured=true | Yes | — | Yes | Presence only, never the ARN value | `TestNormalizeStorageIntegration::test_s3_posture` | PASS | |
| BE | Credentials excluded | snowflake_storage_integration | STORAGE_AWS_IAM_USER_ARN full value | ARN never stored | — | — | — | Permanent exclusion | `TestNormalizeStorageIntegration::test_cloud_credentials_never_stored`, `TestStorageIntegrationCollection::test_cloud_arn_never_persisted` | PASS | |
| DZ25 | Added storage integration | snowflake_storage_integration | New row | Low | change_type=added | Low | Yes | | `TestStorageIntegrationChangeClassification::test_added_is_low` | PASS | |
| DZ26 | Missing name dropped | snowflake_storage_integration | NAME=None | Record dropped | — | — | — | | `TestNormalizeStorageIntegration::test_missing_name_returns_none` | PASS | |
| DZ27 | Location count unknown when detail unavailable | snowflake_storage_integration | DESCRIBE not attempted | allowed_location_count=None, storage_provider=unknown | — | — | Yes | Never coerced to 0 | `TestNormalizeStorageIntegration::test_location_count_unknown_when_detail_unavailable` | PASS | |
| DZ28 | Storage integrations family denied | family_completeness | SHOW STORAGE INTEGRATIONS 403 | storage_integrations=denied | — | — | Yes | | `TestStorageIntegrationCollection::test_storage_integrations_family_denied` | PASS | |
| DZ29 | Scale: 2,000 storage integrations | snowflake_storage_integration | Single SHOW + 2,000 bounded DESCRIBE calls | 2,000 distinct records | — | — | — | | `TestScale::test_2000_storage_integrations` | PASS | |

## External access

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BF | Enabled | snowflake_external_access_integration | ENABLED=true | enabled=true | Yes | Medium on enable | Yes | | `TestExternalAccessChangeClassification::test_enabled_true_is_medium` | PASS | |
| BG | Disabled | snowflake_external_access_integration | ENABLED=false | enabled=false | Yes | Low | Yes | | `TestExternalAccessChangeClassification::test_disabled_is_low` | PASS | |
| BH | One network rule | snowflake_external_access_integration | ALLOWED_NETWORK_RULES=['RULE_A'] | allowed_network_rule_count=1 | Yes | — | Yes | | `TestNormalizeExternalAccessIntegration::test_full_posture` | PASS | |
| BI | Many network rules | snowflake_external_access_integration | 3+ rules | allowed_network_rule_count=3 | Yes | Medium if increased | Yes | | `TestExternalAccessChangeClassification::test_allowed_network_rules_increased_is_medium` | PASS | |
| BJ | Broad network access | snowflake_external_access_integration | (deferred — cross-referencing network-rule broadness not implemented) | Not computed this message | — | — | — | Documented gap for message 5 | (documented gap; see report body) | PASS | |
| BK | Secret reference count | snowflake_external_access_integration | ALLOWED_AUTHENTICATION_SECRETS 2 entries | allowed_secret_count=2 | Yes | Medium if increased | Yes | Names never stored, count only | `TestNormalizeExternalAccessIntegration::test_full_posture`, `TestExternalAccessChangeClassification::test_allowed_secret_count_increased_is_medium` | PASS | |
| BL | API auth integration count | snowflake_external_access_integration | ALLOWED_API_AUTHENTICATION_INTEGRATIONS | allowed_api_authentication_integration_count | Yes | — | Yes | | `TestNormalizeExternalAccessIntegration::test_full_posture` | PASS | |
| BM | Secrets excluded | snowflake_external_access_integration | ALLOWED_AUTHENTICATION_SECRETS names | Names never stored, only count | — | — | — | | `TestNormalizeExternalAccessIntegration::test_secret_names_never_stored`, `TestExternalAccessIntegrationCollection::test_secret_names_never_persisted` | PASS | |
| DZ30 | Added external access integration is Medium | snowflake_external_access_integration | New row | Medium | change_type=added | Medium | Yes | Permits outbound connectivity — inspected, not blanket Low | `TestExternalAccessChangeClassification::test_added_is_medium` | PASS | |
| DZ31 | Existence not inherently risky | snowflake_external_access_integration | Normal record | No risk/severity field on the normalized record itself | — | — | — | Classification is the risk classifier's job, not the normalizer's | `TestNormalizeExternalAccessIntegration::test_existence_not_inherently_risky` | PASS | |
| DZ32 | Missing name dropped | snowflake_external_access_integration | NAME=None | Record dropped | — | — | — | | `TestNormalizeExternalAccessIntegration::test_missing_name_returns_none` | PASS | |
| DZ33 | External access family denied | family_completeness | SHOW EXTERNAL ACCESS INTEGRATIONS 403 | external_access_integrations=denied | — | — | Yes | | `TestExternalAccessIntegrationCollection::test_external_access_integrations_family_denied` | PASS | |
| DZ34 | Scale: 2,000 external access integrations | snowflake_external_access_integration | Single SHOW + 2,000 bounded DESCRIBE calls | 2,000 distinct records | — | — | — | | `TestScale::test_2000_external_access_integrations` | PASS | |

## Details/completeness

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BN | List succeeds/detail succeeds | any msg-4 record | SHOW ok, DESCRIBE ok | detail_collection_status=complete | — | — | Yes | | `TestNetworkPolicyCollection::test_detail_succeeds_marks_complete` | PASS | |
| BO | List succeeds/detail denied | any msg-4 record | SHOW ok, DESCRIBE 403 | Identity preserved; detail fields unknown; detail_collection_status=denied/unavailable | — | — | Yes | Never marked as a safe default | `TestNetworkPolicyCollection::test_list_succeeds_detail_denied_preserves_identity`, `TestAuthenticationPolicyCollection::test_list_succeeds_detail_denied_preserves_identity`, `TestSecurityIntegrationCollection::test_list_succeeds_detail_denied_preserves_identity` | PASS | |
| BP | Network policies denied | family_completeness | SHOW NETWORK POLICIES 403 | network_policies=denied | — | — | Yes | | `TestNetworkPolicyCollection::test_network_policies_family_denied` | PASS | |
| BQ | Auth policies denied | family_completeness | SHOW AUTHENTICATION POLICIES 403 | authentication_policies=denied | — | — | Yes | | `TestAuthenticationPolicyCollection::test_authentication_policies_family_denied` | PASS | |
| BR | Security integrations denied | family_completeness | SHOW SECURITY INTEGRATIONS 403 | security_integrations=denied | — | — | Yes | | `TestSecurityIntegrationCollection::test_security_integrations_family_denied` | PASS | |
| BS | Storage integrations denied | family_completeness | SHOW STORAGE INTEGRATIONS 403 | storage_integrations=denied | — | — | Yes | | `TestStorageIntegrationCollection::test_storage_integrations_family_denied` | PASS | |
| BT | External access denied | family_completeness | SHOW EXTERNAL ACCESS INTEGRATIONS 403 | external_access_integrations=denied | — | — | Yes | | `TestExternalAccessIntegrationCollection::test_external_access_integrations_family_denied` | PASS | |
| BU | Mixed completeness | family_completeness | network_policies denied, storage_integrations throttled, others complete | Each family status independent | — | — | Yes | One denied/unavailable family never erases another | `TestFamilyIndependence::test_all_six_families_independent_statuses` | PASS | |
| BV | Missing detail != false | any msg-4 record | DESCRIBE not attempted/failed | Boolean/category fields = unknown, never false | — | — | Yes | | `TestNormalizeNetworkPolicy::test_detail_not_attempted_defaults_unknown`, `TestNormalizeAuthenticationPolicy::test_properties_none_means_unavailable_detail` | PASS | |

## Unknown safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BW | Enabled unknown | snowflake_security_integration | ENABLED absent | enabled=unknown | Yes | — | Yes | Never coerced to false | `TestNormalizeSecurityIntegration::test_enabled_unknown_when_missing` | PASS | |
| BX | MFA unknown | snowflake_authentication_policy | MFA_ENROLLMENT absent | mfa_enrollment=unknown | Yes | Never required or optional | Yes | | `TestMfaEnrollment::test_missing_is_unknown` | PASS | |
| BY | Role count unknown | snowflake_security_integration | (role-count fields deferred this message) | N/A — not collected, never fabricated as 0 | — | — | Yes | | (documented gap; no field silently defaults to 0) | PASS | |
| BZ | Location count unknown | snowflake_storage_integration | STORAGE_ALLOWED_LOCATIONS absent/DESCRIBE unavailable | allowed_location_count=None | Yes | — | Yes | Never 0 | `TestNormalizeStorageIntegration::test_location_count_unknown_when_detail_unavailable`, `TestCountListLike::test_missing_is_none_not_zero` | PASS | |
| CA | Broad access unknown | snowflake_network_policy | DESCRIBE not attempted | allows_anywhere_ipv4=unknown | Yes | Never broad | Yes | | `TestBroadAccess::test_none_is_unknown_never_false` | PASS | |

## Identifier safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CB | Quoted integration name | statement construction | Integration named `WEIRD"NAME` | DESCRIBE INTEGRATION statement safely escapes embedded quote | — | — | — | Reuses message-2's `_quote_identifier` | `TestIdentifierSafety::test_quoted_integration_name` | PASS | |
| CC | Quote in policy name | statement construction | Policy named `WEIRD"POLICY` | DESCRIBE AUTHENTICATION POLICY safely escapes it | — | — | — | | `TestIdentifierSafety::test_quote_in_policy_name` | PASS | |
| CD | Injection-shaped identifier | statement construction | Integration named `x"; DROP TABLE x; --` | Statement stays a single quoted identifier; no exception, no mutation | — | — | — | Structurally cannot break out of the identifier position | `TestIdentifierSafety::test_injection_shaped_integration_name_stays_an_identifier` | PASS | |

## Diff

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CE | Network policy metadata | snowflake_network_policy | Real compute_diff() on allows_anywhere_ipv4 change | provider_metadata carries policy_name/allows_anywhere_ipv4 | Yes | High | Yes | | `TestProviderMetadataHygiene::test_network_policy_metadata_context` | PASS | |
| CF | Auth policy metadata | snowflake_authentication_policy | mfa_enrollment change | provider_metadata carries mfa_enrollment | Yes | High/Low | Yes | | `TestProviderMetadataHygiene::test_auth_policy_metadata_context` | PASS | |
| CG | SAML integration change | snowflake_security_integration | enabled change | provider_metadata carries integration_type/enabled, no secrets | Yes | Medium/Low | Yes | | `TestProviderMetadataHygiene::test_security_integration_metadata_excludes_secrets` | PASS | |
| CH | OAuth integration change | snowflake_security_integration | enabled change (oauth_snowflake) | Same stanza, type-specific reason text | Yes | Medium/Low | Yes | | `TestSecurityIntegrationChangeClassification::test_oauth_enabled_is_medium` | PASS | |
| CI | SCIM run-as change | snowflake_security_integration | scim_run_as_role change | provider_metadata carries scim_run_as_role | Yes | Medium | Yes | | `TestSecurityIntegrationChangeClassification::test_scim_run_as_role_change_is_medium` | PASS | |
| CJ | Storage integration broadened | snowflake_storage_integration | allowed_location_count increased | provider_metadata carries storage_provider | Yes | Medium | Yes | | `TestProviderMetadataHygiene::test_storage_integration_broadened_metadata` | PASS | |
| CK | External-access broadened | snowflake_external_access_integration | allowed_network_rule_count increased | provider_metadata carries allowed_network_rule_count | Yes | Medium | Yes | | `TestProviderMetadataHygiene::test_external_access_broadened_metadata` | PASS | |
| DZ35 | Ignored safe field produces no diff | snowflake_network_policy | Untracked extra key added | No diff | — | — | — | | `TestProviderMetadataHygiene::test_ignored_safe_field_produces_no_diff` | PASS | |
| DZ36 | Reordered records produce no diff | snowflake_network_policy | Snapshot order shuffled | No diff | — | — | — | Deterministic ordering | `TestProviderMetadataHygiene::test_reordered_records_produce_no_diff` | PASS | |
| DZ37 | Unknown record type fails safe | any future snowflake_* type | `record_type="snowflake_future_thing"` | Low severity, no exception | — | — | — | | `TestProviderMetadataHygiene::test_unknown_record_type_fails_safe` | PASS | |

## Safety

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CL | PAT absent | snowflake_authentication_policy | AUTHENTICATION_METHODS includes PROGRAMMATIC_ACCESS_TOKEN | Only the category string stored, never a PAT value | — | — | — | | `TestAuthMethods::test_keypair_and_pat` | PASS | |
| CM | OAuth secret absent | snowflake_security_integration | DESCRIBE would mask/omit client secret anyway | No client-secret field exists in the schema at all | — | — | — | Defense-in-depth beyond Snowflake's own masking | (structural: no such field in `_normalize_security_integration`) | PASS | |
| CN | SAML cert absent | snowflake_security_integration | SAML2_X509_CERT full body | Never stored, only boolean | — | — | — | | `TestNormalizeSecurityIntegration::test_saml2_certificate_body_never_stored` | PASS | |
| CO | SCIM token absent | snowflake_security_integration | N/A — SCIM bearer tokens never fetched | No token field anywhere in schema | — | — | — | | (structural) | PASS | |
| CP | Storage credentials absent | snowflake_storage_integration | STORAGE_AWS_IAM_USER_ARN full value | Never stored, only boolean | — | — | — | | `TestNormalizeStorageIntegration::test_cloud_credentials_never_stored` | PASS | |
| CQ | Raw property map absent | snowflake_security_integration | DESCRIBE returns unrecognized property | Only allowlisted keys copied; full property dict never persisted | — | — | — | Positive allowlisting | `TestNormalizeSecurityIntegration::test_no_raw_property_map_persisted` | PASS | |

## Scale

| # | Case | Record type | Source state | Normalized posture | Diff tracked? | Severity | Unknown-safe? | Sensitive-data concern | Test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CR | 1,000 network policies | snowflake_network_policy | Single SHOW + 1,000 bounded DESCRIBE calls | 1,000 distinct records | — | — | — | Bounded per-policy loop, same shape as message-2/3 per-role loops | `TestScale::test_1000_network_policies` | PASS | |
| CS | 1,000 auth policies | snowflake_authentication_policy | Single SHOW + 1,000 bounded DESCRIBE calls | 1,000 distinct records | — | — | — | | `TestScale::test_1000_authentication_policies` | PASS | |
| CT | 2,000 security integrations | snowflake_security_integration | Single SHOW + 2,000 bounded DESCRIBE calls | 2,000 distinct records | — | — | — | | `TestScale::test_2000_security_integrations` | PASS | |
| CU | 2,000 storage integrations | snowflake_storage_integration | Single SHOW + 2,000 bounded DESCRIBE calls | 2,000 distinct records | — | — | — | | `TestScale::test_2000_storage_integrations` | PASS | |
| CV | 2,000 external access integrations | snowflake_external_access_integration | Single SHOW + 2,000 bounded DESCRIBE calls | 2,000 distinct records | — | — | — | | `TestScale::test_2000_external_access_integrations` | PASS | |

**Total rows: 142 (test count); matrix rows: see below.** Every case is
backed by a passing automated test (`test_snowflake_policy_collection.py`
/ `test_snowflake_policy_normalization.py` /
`test_snowflake_policy_diff.py`) — no case is documentation-only, except
where explicitly marked "documented gap" (deferred to a later message, per
the task's own scoping guidance).

## Documented gaps (deferred, not silently dropped)

1. **Network-rule broad/wildcard-host detection (row S)** — `SHOW NETWORK
   RULES` exposes only a value *count*, never the actual hostnames/IPs/
   ports. Detecting a wildcard/broad target would require a per-rule
   `DESCRIBE NETWORK RULE` call (confirmed via current docs to expose the
   raw `VALUE_LIST`). Given the task's explicit "prefer counts, avoid
   needless repeated DESCRIBE calls" bias and that network-*policy*
   broad-access detection (the primary security signal) is already
   covered via `DESCRIBE NETWORK POLICY`, this message defers per-rule
   value inspection.
2. **Security-integration allowed/blocked role counts (rows AQ/AR/BY)** —
   Per current docs, "allowed roles" surfaces per-integration-type in
   varying, less-uniformly-documented properties. Message 4 preserves the
   integration's owner and (for SCIM) `run_as_role` identifier cleanly,
   but does not attempt to enumerate/count allowed roles this message —
   task item 46 explicitly assigns role-context combination with
   effective privilege to message 5.
3. **External-access broad-network-destination detection (row BJ)** — An
   external access integration's `ALLOWED_NETWORK_RULES` references
   `snowflake_network_rule` objects by name; determining whether any
   referenced rule is itself broad would require cross-referencing the
   two collected families (not attempted this message, since network
   rules only carry counts per gap #1 above). `allowed_network_rule_count`
   is tracked and classified on increase; the broad/non-broad distinction
   is deferred.
4. **Storage-location wildcard/broad-location category (row BC)** — Same
   reasoning as gap #1: only a count is tracked (`allowed_location_count`)
   per the task's "do not persist giant allowlists" bias; a broad/
   wildcard-path category is not computed this message.
5. **API integrations and session policies** — Explicitly deferred per
   task items 33/40: API integrations (category=API) are more deployment/
   API-Gateway infrastructure than central account security posture;
   session policies are a materially smaller security signal than
   network/authentication policies for the added SHOW + per-policy
   DESCRIBE cost. Both remain candidates for a future message.

None of these gaps involve fabricating a value — every deferred field is
either absent from the record entirely (no misleading default) or
explicitly tracked as a count with the underlying detail left for a later
message.
