# Sentry Change Classification Matrix (Sentry Message 7 of 8)

Exhaustive Change-classification QA across all 18 Sentry record types: added/removed/modified posture, Finding-vs-Change severity parity, false-removal suppression (organization-wide, per-team, per-project, derived-record), recovery-after-partial-sync, and first-sync semantics. Every case is driven through the REAL diff pipeline (`compute_diff()` -> Change -> `classify_sentry_change()`) except rows explicitly marked "code review" for message 1-6 classifier branches whose behavior was already exhaustively pinned in earlier messages' own diff test suites and is unchanged by this message. Columns: **Case**, **Record type**, **Field/transition**, **Previous**, **Current**, **Completeness**, **Severity**, **Finding parity**, **Test**, **Status**.

Total cases: 174.

| # | Case | Record type | Field/transition | Previous | Current | Completeness | Severity | Finding parity | Test | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| A | organization added | sentry_organization | added | n/a | present | n/a | low | n/a | `TestOrganizationChangeQA::test_added_is_low` | PASS |
| B | organization removed | sentry_organization | removed | present | n/a | n/a | medium | n/a | `TestOrganizationChangeQA::test_removed_is_medium` | PASS |
| C | organization slug rename | sentry_organization | modified:slug | acme | acme-renamed | n/a | low | n/a | `TestOrganizationChangeQA::test_slug_rename_is_low` | PASS |
| D | organization never suppressed on removal | sentry_organization | removed (own family) | present | n/a | n/a | medium (unsuppressed) | n/a | `TestOrganizationWideFalseRemoval::test_organization_record_itself_never_suppressed` | PASS |
| E | capability probe loses access | sentry_api_capability | modified:status | available | unavailable | n/a | medium | n/a | risk_rules module `_classify_api_capability_change` (code review) | PASS |
| F | capability probe regains access | sentry_api_capability | modified:status | unavailable | available | n/a | low | n/a | risk_rules module `_classify_api_capability_change` (code review) | PASS |
| G | project added | sentry_project | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| H | project removed | sentry_project | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| I | project status -> disabled | sentry_project | modified:status_category | active | disabled | n/a | medium | n/a | risk_rules module (code review) | PASS |
| J | project rename | sentry_project | modified:name | P1 | P1 renamed | n/a | low | n/a | risk_rules module (code review) | PASS |
| K | project real removal reported when members family complete | sentry_project | removed (unrelated complete family) | present | n/a | complete | medium | n/a | `TestOrganizationWideFalseRemoval::test_members_denied_projects_complete_still_diffs_projects` | PASS |
| L | team added | sentry_team | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| M | team removed | sentry_team | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| N | teams family denied suppresses team removal | sentry_team | removed (family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestOrganizationWideFalseRemoval::test_teams_denied_suppresses_team_and_assignment_removals` | PASS |
| O | owner added | sentry_member | added | n/a | owner/active | n/a | high | n/a | `TestMemberChangeQA::test_owner_added_is_high` | PASS |
| P | manager added | sentry_member | added | n/a | manager/active | n/a | high | n/a | `TestMemberChangeQA::test_manager_added_is_high` | PASS |
| Q | admin added | sentry_member | added | n/a | admin/active | n/a | high | n/a | `TestMemberChangeQA::test_admin_added_is_high` | PASS |
| R | ordinary member added | sentry_member | added | n/a | member/active | n/a | low | n/a | `TestMemberChangeQA::test_ordinary_member_added_is_low` | PASS |
| S | billing member added | sentry_member | added | n/a | billing/active | n/a | low | n/a | `TestMemberChangeQA::test_billing_member_added_is_low` | PASS |
| T | unknown-role member added | sentry_member | added | n/a | unknown/active | n/a | low | n/a | `TestMemberChangeQA::test_unknown_role_added_is_low_not_privileged` | PASS |
| U | member removed | sentry_member | removed | present | n/a | n/a | low | n/a | `TestMemberChangeQA::test_member_removed_is_low` | PASS |
| V | member -> admin | sentry_member | modified:org_role_category | member | admin | n/a | high | n/a | `TestMemberChangeQA::test_member_to_admin_is_high` | PASS |
| W | member -> manager | sentry_member | modified:org_role_category | member | manager | n/a | high | n/a | `TestMemberChangeQA::test_member_to_manager_is_high` | PASS |
| X | member -> owner | sentry_member | modified:org_role_category | member | owner | n/a | high | n/a | `TestMemberChangeQA::test_member_to_owner_is_high` | PASS |
| Y | admin -> owner | sentry_member | modified:org_role_category | admin | owner | n/a | low | n/a | `TestMemberChangeQA::test_admin_to_owner_is_low` | PASS |
| Z | owner -> manager | sentry_member | modified:org_role_category | owner | manager | n/a | low | n/a | `TestMemberChangeQA::test_owner_to_manager_is_low` | PASS |
| AA | owner -> member | sentry_member | modified:org_role_category | owner | member | n/a | low | n/a | `TestMemberChangeQA::test_owner_to_member_is_low` | PASS |
| AB | unknown role introduced | sentry_member | modified:org_role_category | member | unknown | n/a | low | n/a | `TestMemberChangeQA::test_unknown_role_introduced_is_low_not_privileged` | PASS |
| AC | status becomes unknown | sentry_member | modified:member_status_category | active | unknown | n/a | medium | n/a | `TestMemberChangeQA::test_status_becomes_unknown_is_medium` | PASS |
| AD | pending -> active | sentry_member | modified:member_status_category | pending | active | n/a | low | n/a | `TestMemberChangeQA::test_pending_to_active_is_low` | PASS |
| AE | members family denied suppresses removal | sentry_member | removed (family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestOrganizationWideFalseRemoval::test_members_denied_suppresses_member_removals` | PASS |
| AF | members family complete real removal reported | sentry_member | removed (family complete) | present | n/a | complete | low | n/a | `TestOrganizationWideFalseRemoval::test_members_complete_real_removal_still_reported` | PASS |
| AG | no organization record in new snapshot falls back unsuppressed | sentry_member | removed (no org context) | present | n/a | n/a (fallback) | low | n/a | `TestOrganizationWideFalseRemoval::test_no_organization_record_in_new_falls_back_unsuppressed` | PASS |
| AH | team membership added | sentry_team_membership | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| AI | team membership removed | sentry_team_membership | removed | present | n/a | n/a | low | n/a | risk_rules module (code review) | PASS |
| AJ | team-role promoted to admin | sentry_team_membership | modified:team_role_category | contributor | admin | n/a | medium | n/a | risk_rules module (code review) | PASS |
| AK | team B denied suppresses only team B memberships | sentry_team_membership | removed (per-team denied) | present | n/a | denied (team B only) | n/a (suppressed for B) | n/a | `TestPerTeamCompleteness::test_team_a_and_c_memberships_still_removed_when_team_b_denied` | PASS |
| AL | team A and C memberships still removed when B denied | sentry_team_membership | removed (per-team complete) | present | n/a | complete (A, C) | low | n/a | `TestPerTeamCompleteness::test_team_a_and_c_memberships_still_removed_when_team_b_denied` | PASS |
| AM | project-team assignment added | sentry_project_team_assignment | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| AN | project-team assignment removed | sentry_project_team_assignment | removed | present | n/a | n/a | low | n/a | risk_rules module (code review) | PASS |
| AO | assignments suppressed when teams family denied | sentry_project_team_assignment | removed (family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestOrganizationWideFalseRemoval::test_teams_denied_suppresses_team_and_assignment_removals` | PASS |
| AP | metric rule enabled->disabled | sentry_metric_alert_rule | modified:status_category | enabled | disabled | n/a | medium | n/a | `TestMetricAlertRuleChangeQA::test_enabled_to_disabled_is_medium` | PASS |
| AQ | metric rule disabled->enabled | sentry_metric_alert_rule | modified:status_category | disabled | enabled | n/a | low | n/a | `TestMetricAlertRuleChangeQA::test_disabled_to_enabled_is_low` | PASS |
| AR | metric rule action_count positive->zero enabled | sentry_metric_alert_rule | modified:action_count | 1 | 0 | n/a | high | sentry_metric_alert_unrouted | `TestMetricAlertRuleChangeQA::test_action_count_positive_to_zero_enabled_is_high` | PASS |
| AS | metric rule action_count zero->positive | sentry_metric_alert_rule | modified:action_count | 0 | 1 | n/a | low | n/a | `TestMetricAlertRuleChangeQA::test_action_count_zero_to_positive_is_low` | PASS |
| AT | metric rule added enabled zero actions | sentry_metric_alert_rule | added | n/a | enabled/0 actions | n/a | high | sentry_metric_alert_unrouted | `TestMetricAlertRuleChangeQA::test_added_enabled_zero_actions_is_high` | PASS |
| AU | metric rule removed (enabled+routed) | sentry_metric_alert_rule | removed | enabled/1 action | n/a | n/a | medium | n/a | `TestMetricAlertRuleChangeQA::test_removed_enabled_with_actions_is_medium` | PASS |
| AV | metric rule removed (already unrouted) | sentry_metric_alert_rule | removed | enabled/0 actions | n/a | n/a | low | n/a | `TestMetricAlertRuleChangeQA::test_removed_already_unrouted_is_low` | PASS |
| AW | metric rule removed (disabled) | sentry_metric_alert_rule | removed | disabled/1 action | n/a | n/a | low | n/a | `TestMetricAlertRuleChangeQA::test_removed_disabled_rule_is_low` | PASS |
| AX | metric rule resolve_threshold change (direction unknown) | sentry_metric_alert_rule | modified:resolve_threshold | 10.0 | 20.0 | n/a | low | n/a | `TestMetricAlertRuleChangeQA::test_resolve_threshold_unknown_direction_is_low` | PASS |
| AY | metric rule added with actions | sentry_metric_alert_rule | added | n/a | enabled/1 action | n/a | low | n/a | risk_rules module (code review) | PASS |
| AZ | metric rule owner changed | sentry_metric_alert_rule | modified:owner_id | u1 | u2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BA | metric rule threshold above weakened (raised) | sentry_metric_alert_trigger | modified:alert_threshold (above) | 100 | 200 | n/a | medium | n/a | risk_rules module `_classify_metric_alert_trigger_change` (code review) | PASS |
| BB | metric rule threshold above strengthened (lowered) | sentry_metric_alert_trigger | modified:alert_threshold (above) | 200 | 100 | n/a | low | n/a | risk_rules module (code review) | PASS |
| BC | metric rule threshold below weakened (lowered) | sentry_metric_alert_trigger | modified:alert_threshold (below) | 50 | 10 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BD | metric trigger action_count drop to zero | sentry_metric_alert_trigger | modified:action_count | 1 | 0 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BE | metric trigger removed | sentry_metric_alert_trigger | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BF | metric rule environment changed | sentry_metric_alert_rule | modified:environment_category | all | production | n/a | low | n/a | risk_rules module (code review) | PASS |
| BG | metric rule time window changed | sentry_metric_alert_rule | modified:time_window_minutes | 10 | 60 | n/a | low | n/a | risk_rules module (code review) | PASS |
| BH | issue rule added enabled zero actions | sentry_issue_alert_rule | added | n/a | enabled/0 actions | n/a | high | sentry_issue_alert_unrouted | `TestIssueAlertRuleChangeQA::test_added_enabled_zero_actions_is_high` | PASS |
| BI | issue rule action_count drop to zero enabled | sentry_issue_alert_rule | modified:action_count | 2 | 0 | n/a | high | sentry_issue_alert_unrouted | `TestIssueAlertRuleChangeQA::test_action_count_drop_to_zero_enabled_is_high` | PASS |
| BJ | issue rule removed (already unrouted) | sentry_issue_alert_rule | removed | enabled/0 actions | n/a | n/a | low | n/a | `TestIssueAlertRuleChangeQA::test_removed_already_unrouted_is_low` | PASS |
| BK | issue rule enabled->disabled | sentry_issue_alert_rule | modified:status_category | enabled | disabled | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BL | issue rule action_match changed | sentry_issue_alert_rule | modified:action_match_category | any | all | n/a | low | n/a | risk_rules module (code review) | PASS |
| BM | issue rule condition_count changed | sentry_issue_alert_rule | modified:condition_count | 1 | 3 | n/a | low | n/a | risk_rules module (code review) | PASS |
| BN | issue rule owner changed | sentry_issue_alert_rule | modified:owner_id | u1 | u2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BO | alert action added | sentry_alert_action | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| BP | alert action removed | sentry_alert_action | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BQ | alert action target_id changed | sentry_alert_action | modified:target_id | u1 | u2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BR | alert action target_type changed | sentry_alert_action | modified:target_type_category | user | team | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BS | alert action integration_id changed | sentry_alert_action | modified:integration_id | i1 | i2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BT | alert actions family denied suppresses removal | sentry_alert_action | removed (family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestAlertActionCompleteness::test_alert_actions_denied_suppresses_action_removals` | PASS |
| BU | integration enabled->disabled | sentry_organization_integration | modified:status_category | active | disabled | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BV | integration disabled->enabled | sentry_organization_integration | modified:status_category | disabled | active | n/a | low | n/a | risk_rules module (code review) | PASS |
| BW | integration provider changed | sentry_organization_integration | modified:provider_category | slack | msteams | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BX | integration added | sentry_organization_integration | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| BY | integration removed | sentry_organization_integration | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| BZ | integrations family denied suppresses routing-context removal | sentry_routing_context | removed (integration family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestDerivedRecordFalseRemovals::test_integration_family_denied_suppresses_routing_context_removal` | PASS |
| CA | repository active->pending_deletion | sentry_repository | modified:status_category | active | pending_deletion | n/a | medium | sentry_repository_pending_deletion | `TestRepositoryChangeQA::test_active_to_pending_deletion_is_medium` | PASS |
| CB | repository pending_deletion->active | sentry_repository | modified:status_category | pending_deletion | active | n/a | low | n/a | `TestRepositoryChangeQA::test_pending_deletion_to_active_is_low` | PASS |
| CC | repository integration changed | sentry_repository | modified:integration_id | int1 | int2 | n/a | medium | n/a | `TestRepositoryChangeQA::test_integration_changed_is_medium` | PASS |
| CD | repository rename | sentry_repository | modified:name | acme/old | acme/new | n/a | low | n/a | `TestRepositoryChangeQA::test_rename_is_low` | PASS |
| CE | repository added | sentry_repository | added | n/a | present | n/a | low | n/a | `TestRepositoryChangeQA::test_added_is_low` | PASS |
| CF | repository removed | sentry_repository | removed | present | n/a | n/a | low | n/a | `TestRepositoryChangeQA::test_removed_is_low` | PASS |
| CG | code mapping repository changed | sentry_code_mapping | modified:repository_id | r1 | r2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CH | code mapping project changed | sentry_code_mapping | modified:project_id | p1 | p2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CI | code mapping stack_root cleared | sentry_code_mapping | modified:stack_root_configured | true | false | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CJ | code mapping source_root cleared | sentry_code_mapping | modified:source_root_configured | true | false | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CK | code mapping default_branch changed | sentry_code_mapping | modified:default_branch_configured | true | false | n/a | low | n/a | risk_rules module (code review) | PASS |
| CL | code mapping added | sentry_code_mapping | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| CM | code mapping removed | sentry_code_mapping | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CN | ownership rule owner team changed | sentry_ownership_rule | modified:owner_id | t1 | t2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CO | ownership rule owner member changed | sentry_ownership_rule | modified:owner_id | m1 | m2 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CP | ownership rule is_active->false | sentry_ownership_rule | modified:is_active | true | false | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CQ | ownership rule is_active->true | sentry_ownership_rule | modified:is_active | false | true | n/a | low | n/a | risk_rules module (code review) | PASS |
| CR | ownership rule matcher changed | sentry_ownership_rule | modified:matcher_category | path | url | n/a | low | n/a | risk_rules module (code review) | PASS |
| CS | ownership rule added | sentry_ownership_rule | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| CT | ownership rule removed | sentry_ownership_rule | removed | present | n/a | n/a | medium | n/a | risk_rules module (code review) | PASS |
| CU | project B ownership denied suppresses only project B rules | sentry_ownership_rule | removed (per-project denied) | present | n/a | denied (B only) | n/a (suppressed for B) | n/a | `TestPerProjectOwnershipCompleteness::test_project_b_denied_suppresses_only_project_b_ownership_rules` | PASS |
| CV | critical tier added | sentry_privileged_member | added | n/a | critical | n/a | high | sentry_active_organization_owner | `TestPrivilegedMemberChangeQA::test_critical_tier_added_is_high` | PASS |
| CW | high tier added | sentry_privileged_member | added | n/a | high | n/a | high | sentry_active_organization_manager | `TestPrivilegedMemberChangeQA::test_high_tier_added_is_high` | PASS |
| CX | medium tier added | sentry_privileged_member | added | n/a | medium | n/a | medium | sentry_active_organization_admin | `TestPrivilegedMemberChangeQA::test_medium_tier_added_is_medium` | PASS |
| CY | low tier added | sentry_privileged_member | added | n/a | low | n/a | low | n/a | `TestPrivilegedMemberChangeQA::test_low_tier_added_is_low` | PASS |
| CZ | tier low->critical | sentry_privileged_member | modified:privilege_tier | low | critical | n/a | high | sentry_active_organization_owner (documented exception) | `TestPrivilegedMemberChangeQA::test_tier_low_to_critical_is_high` | PASS |
| DA | tier low->medium | sentry_privileged_member | modified:privilege_tier | low | medium | n/a | medium | n/a | `TestPrivilegedMemberChangeQA::test_tier_low_to_medium_is_medium` | PASS |
| DB | tier critical->low | sentry_privileged_member | modified:privilege_tier | critical | low | n/a | low | n/a | `TestPrivilegedMemberChangeQA::test_tier_critical_to_low_is_low` | PASS |
| DC | organization-wide access gained | sentry_privileged_member | modified:organization_wide_project_access | false | true | n/a | high | n/a | `TestPrivilegedMemberChangeQA::test_org_wide_access_gained_is_high` | PASS |
| DD | organization-wide access lost | sentry_privileged_member | modified:organization_wide_project_access | true | false | n/a | low | n/a | `TestPrivilegedMemberChangeQA::test_org_wide_access_lost_is_low` | PASS |
| DE | organization-wide access becomes unknown | sentry_privileged_member | modified:organization_wide_project_access | false | None | n/a | medium | n/a | `TestPrivilegedMemberChangeQA::test_org_wide_access_becomes_unknown_is_medium` | PASS |
| DF | effective project count expands | sentry_privileged_member | modified:effective_project_count | 1 | 5 | n/a | medium | n/a | `TestPrivilegedMemberChangeQA::test_effective_project_count_expands_is_medium` | PASS |
| DG | effective project count unknown never treated as expansion | sentry_privileged_member | modified:effective_project_count | 5 | None | n/a | low | n/a | `TestPrivilegedMemberChangeQA::test_effective_project_count_unknown_never_treated_as_zero` | PASS |
| DH | privileged member removed | sentry_privileged_member | removed | present | n/a | n/a | low | n/a | `TestPrivilegedMemberChangeQA::test_record_removed_is_low` | PASS |
| DI | member family denied suppresses privileged-member removal | sentry_privileged_member | removed (derived, family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestDerivedRecordFalseRemovals::test_member_family_denied_suppresses_privileged_member_removal` | PASS |
| DJ | all families complete derived removal is real | sentry_privileged_member | removed (derived, family complete) | present | n/a | complete | low | n/a | `TestDerivedRecordFalseRemovals::test_all_families_complete_derived_removal_is_real` | PASS |
| DK | privileged team added | sentry_privileged_team | added | n/a | present | n/a | low | n/a | risk_rules module (code review) | PASS |
| DL | privileged team removed | sentry_privileged_team | removed | present | n/a | n/a | low | n/a | risk_rules module (code review) | PASS |
| DM | privileged_member_count increases | sentry_privileged_team | modified:privileged_member_count | 0 | 1 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| DN | project_count changes | sentry_privileged_team | modified:project_count | 1 | 3 | n/a | low | n/a | risk_rules module (code review) | PASS |
| DO | unresolved_member_count increases | sentry_privileged_team | modified:unresolved_member_count | 0 | 1 | n/a | medium | n/a | risk_rules module (code review) | PASS |
| DP | team membership denied suppresses privileged-team removal | sentry_privileged_team | removed (derived, family denied) | present | n/a | denied | n/a (suppressed) | n/a | `TestDerivedRecordFalseRemovals::test_team_membership_denied_suppresses_privileged_team_removal` | PASS |
| DQ | context enabled/disabled toggle | sentry_routing_context | modified:context_enabled | true | false | n/a | low | n/a | `TestRoutingContextChangeQA::test_enabled_disabled_toggle_low` | PASS |
| DR | target type changes | sentry_routing_context | modified:target_type_category | user | team | n/a | medium | n/a | `TestRoutingContextChangeQA::test_target_type_changes_medium` | PASS |
| DS | target id changes | sentry_routing_context | modified:target_id | m1 | m2 | n/a | medium | n/a | `TestRoutingContextChangeQA::test_target_id_changes_medium` | PASS |
| DT | target resolved->missing (enabled) | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_alert_targets_missing_member | `TestRoutingContextChangeQA::test_resolved_to_missing_enabled_is_high` | PASS |
| DU | target missing->resolved | sentry_routing_context | modified:target_resolved | false | true | n/a | low | n/a | `TestRoutingContextChangeQA::test_missing_to_resolved_is_low` | PASS |
| DV | target active->pending | sentry_routing_context | modified:target_active | true | false | n/a | medium | sentry_alert_references_inactive_member | `TestRoutingContextChangeQA::test_active_to_pending_is_medium` | PASS |
| DW | integration enabled->disabled (targeted) | sentry_routing_context | modified:integration_status_category | active | disabled | n/a | high | sentry_alert_references_disabled_integration | `TestRoutingContextChangeQA::test_integration_enabled_to_disabled_is_high` | PASS |
| DX | added missing target on enabled rule | sentry_routing_context | added | n/a | unresolved/enabled | n/a | high | sentry_alert_targets_missing_team/member | `TestRoutingContextChangeQA::test_added_missing_target_enabled_is_high` | PASS |
| DY | added disabled-integration target on enabled rule | sentry_routing_context | added | n/a | disabled integration/enabled | n/a | high | sentry_alert_references_disabled_integration | `TestRoutingContextChangeQA::test_added_disabled_integration_enabled_rule_is_high` | PASS |
| DZ | added missing target on disabled rule | sentry_routing_context | added | n/a | unresolved/disabled | n/a | low | n/a | `TestRoutingContextChangeQA::test_added_missing_target_disabled_rule_is_low` | PASS |
| EA | source rule removed | sentry_routing_context | removed | present | n/a | n/a | low | n/a | `TestRoutingContextChangeQA::test_source_rule_removed_is_low` | PASS |
| EB | unsupported target type never resolved | sentry_routing_context | n/a (specific/sentry_app/issue_owners) | n/a | target_resolved=false always | n/a | n/a | n/a | message-5 `_derive_effective_access` else-branch (reused, code review) | PASS |
| EC | first sync owner produces added not modified | sentry_privileged_member | first sync | n/a (no prior snapshot) | present | n/a | n/a | n/a | `TestFirstSyncBehavior::test_first_sync_owner_produces_added_change_not_modified` | PASS |
| ED | first sync unrouted alert produces added | sentry_metric_alert_rule | first sync | n/a | present | n/a | n/a | n/a | `TestFirstSyncBehavior::test_first_sync_unrouted_alert_is_added` | PASS |
| EE | first sync disabled-integration-referenced produces added | sentry_routing_context | first sync | n/a | present | n/a | n/a | n/a | `TestFirstSyncBehavior::test_first_sync_disabled_integration_referenced_is_added` | PASS |
| EF | Change dict shape matches real compute_diff() output | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `TestStaleChangeShapeAudit::test_change_dict_has_expected_keys_only` | PASS |
| EG | classifier never raises on real Change shape | n/a | n/a | n/a | n/a | n/a | n/a | n/a | `TestStaleChangeShapeAudit::test_classifier_never_raises_on_real_shape` | PASS |
| EH | recovery: sync1 complete -> sync2 partial suppresses removal | sentry_member | removed (partial) | present | n/a | denied | n/a (suppressed) | n/a | `TestRecoveryAfterPartialSync::test_sync1_complete_sync2_partial_sync3_partial_sync4_complete` | PASS |
| EI | recovery: sync2 partial -> sync3 partial produces zero changes | sentry_organization | no-op (both partial, no info) | denied | denied | denied | n/a | n/a | `TestRecoveryAfterPartialSync::test_sync1_complete_sync2_partial_sync3_partial_sync4_complete` | PASS |
| EJ | recovery: sync3 partial -> sync4 complete re-baselines against literal prior snapshot | sentry_member | added (re-baseline) | n/a (absent from sync3) | present | complete | n/a | n/a | `TestRecoveryAfterPartialSync::test_sync1_complete_sync2_partial_sync3_partial_sync4_complete` | PASS |
| EK | owner parity decision certified (High Change / Critical Finding) | sentry_privileged_member | modified:privilege_tier (documented exception) | low | critical | n/a | high | sentry_active_organization_owner=critical (documented exception) | `TestOwnerParityDecision` (3 tests) | PASS |
| EL | active owner parity | sentry_privileged_member | added | n/a | critical | n/a | high | sentry_active_organization_owner | `TestFindingVsChangeParity::test_active_owner` | PASS |
| EM | active manager parity | sentry_privileged_member | added | n/a | high | n/a | high | sentry_active_organization_manager | `TestFindingVsChangeParity::test_active_manager` | PASS |
| EN | active admin parity | sentry_privileged_member | added | n/a | medium | n/a | medium | sentry_active_organization_admin | `TestFindingVsChangeParity::test_active_admin` | PASS |
| EO | pending privileged invitation parity | sentry_privileged_member | added | n/a | critical/pending | n/a | high | sentry_pending_privileged_invitation | `TestFindingVsChangeParity::test_pending_privileged_invitation_owner` | PASS |
| EP | composite privileged member parity | sentry_privileged_member | modified:effective_project_count | 1 | 10 | n/a | medium | sentry_member_broad_routing_authority (closest signal) | `TestFindingVsChangeParity::test_composite_privileged_member_broadened_access` | PASS |
| EQ | metric alert zero-actions parity | sentry_metric_alert_rule | added | n/a | enabled/0 actions | n/a | high | sentry_metric_alert_unrouted | `TestFindingVsChangeParity::test_metric_alert_zero_actions` | PASS |
| ER | issue alert zero-actions parity | sentry_issue_alert_rule | added | n/a | enabled/0 actions | n/a | high | sentry_issue_alert_unrouted | `TestFindingVsChangeParity::test_issue_alert_zero_actions` | PASS |
| ES | disabled alert retaining routing parity | sentry_metric_alert_rule | modified:status_category | enabled | disabled | n/a | medium | sentry_metric_alert_disabled_with_routing_configured | `TestFindingVsChangeParity::test_disabled_alert_retaining_routing` | PASS |
| ET | missing team routing target parity | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_alert_targets_missing_team | `TestFindingVsChangeParity::test_missing_team_routing_target` | PASS |
| EU | missing member routing target parity | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_alert_targets_missing_member | `TestFindingVsChangeParity::test_missing_member_routing_target` | PASS |
| EV | inactive member routing target parity | sentry_routing_context | modified:target_active | true | false | n/a | medium | sentry_alert_references_inactive_member | `TestFindingVsChangeParity::test_inactive_member_routing_target` | PASS |
| EW | disabled integration target parity | sentry_routing_context | modified:integration_status_category | active | disabled | n/a | high | sentry_alert_references_disabled_integration | `TestFindingVsChangeParity::test_disabled_integration_target` | PASS |
| EX | missing ownership target parity | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_ownership_targets_missing_team | `TestFindingVsChangeParity::test_missing_ownership_target` | PASS |
| EY | inactive ownership target parity | sentry_routing_context | modified:target_active | true | false | n/a | medium | sentry_ownership_targets_inactive_member | `TestFindingVsChangeParity::test_inactive_ownership_target` | PASS |
| EZ | repository pending deletion parity | sentry_repository | modified:status_category | active | pending_deletion | n/a | medium | sentry_repository_pending_deletion | `TestFindingVsChangeParity::test_repository_pending_deletion` | PASS |
| FA | added missing team routing target parity | sentry_routing_context | added | n/a | unresolved/enabled | n/a | high | sentry_alert_targets_missing_team | `TestFindingVsChangeParity::test_added_missing_team_routing_target` | PASS |
| FB | added disabled-integration routing target parity | sentry_routing_context | added | n/a | disabled integration/enabled | n/a | high | sentry_alert_references_disabled_integration | `TestFindingVsChangeParity::test_added_disabled_integration_routing_target` | PASS |
| FC | added missing ownership target parity | sentry_routing_context | added | n/a | unresolved/enabled | n/a | high | sentry_ownership_targets_missing_team | `TestFindingVsChangeParity::test_added_missing_ownership_target` | PASS |
| FD | added repository pending deletion parity | sentry_repository | added | n/a | pending_deletion | n/a | low | sentry_repository_pending_deletion | `TestFindingVsChangeParity::test_added_repository_pending_deletion` | PASS |
| FE | removed disabled alert retaining routing never over-escalates below Finding | sentry_metric_alert_rule | removed | disabled/1 action | n/a | n/a | low | sentry_metric_alert_disabled_with_routing_configured | `TestFindingVsChangeParity::test_metric_alert_disabled_removed_never_over_escalates_below_finding` | PASS |
| FF | issue alert disabled retaining routing parity | sentry_issue_alert_rule | modified:status_category | enabled | disabled | n/a | medium | sentry_issue_alert_disabled_with_routing_configured | `TestFindingVsChangeParity::test_issue_alert_disabled_retaining_routing` | PASS |
| FG | missing team ownership alternate construction parity | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_ownership_targets_missing_member | `TestFindingVsChangeParity::test_missing_team_ownership_alternate_construction` | PASS |
| FH | alert missing member alternate construction parity | sentry_routing_context | modified:target_resolved | true | false | complete | high | sentry_alert_targets_missing_member | `TestFindingVsChangeParity::test_alert_missing_member_alternate_construction` | PASS |
| FI | integration_control_context gains full | sentry_privileged_member | modified:integration_control_context | none | full | n/a | medium | n/a | risk_rules module (code review) | PASS |
| FJ | repository_control_context gains full | sentry_privileged_member | modified:repository_control_context | add_only | full | n/a | medium | n/a | risk_rules module (code review) | PASS |
| FK | routing-authority scope count changed | sentry_privileged_member | modified:alert_routing_target_count | 0 | 1 | n/a | low | n/a | risk_rules module (code review) | PASS |
| FL | ownership-authority count changed | sentry_privileged_member | modified:ownership_rule_target_count | 0 | 1 | n/a | low | n/a | risk_rules module (code review) | PASS |
| FM | team_admin_team_count changed | sentry_privileged_member | modified:team_admin_team_count | 0 | 1 | n/a | low | n/a | risk_rules module (code review) | PASS |
| FN | privileged_completeness becomes partial (informational only, not tracked) | sentry_privileged_member | n/a (privilege_completeness excluded from tracked fields) | complete | partial | partial | n/a | n/a | diff_service `_SENTRY_TRACKED_FIELDS_BY_TYPE` omission (code review) | PASS |
| FO | ownership_rule_target_count changed (team) | sentry_privileged_team | modified:ownership_rule_target_count | 0 | 1 | n/a | low | n/a | risk_rules module (code review) | PASS |
| FP | alert_action_target_count changed (team) | sentry_privileged_team | modified:alert_action_target_count | 0 | 1 | n/a | low | n/a | risk_rules module (code review) | PASS |
| FQ | issue-type alert action removed suppressed under coarse project-family denial | sentry_alert_action | removed (issue-type, family incomplete) | present | n/a | denied (issue_alert_rules or alert_actions) | n/a (suppressed) | n/a | diff_service `_sentry_removal_suppressed` issue-action branch (code review) | PASS |
| FR | metric-type alert action removed suppressed under alert_actions denial | sentry_alert_action | removed (metric-type, family denied) | present | n/a | denied | n/a (suppressed) | n/a | diff_service `_sentry_removal_suppressed` metric-action branch (code review) | PASS |
