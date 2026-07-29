# Microsoft Entra ID / Microsoft Graph Permission Matrix (Entra Message 8 of 8)

Authoritative application-permission requirements for every Microsoft Graph
surface ConfigTrace's Entra connector reads, verified directly against
current official Microsoft Learn documentation on 2026-07-29 (not memory,
not blog posts). No client secrets or tenant-specific values appear in
this report.

**Least-privilege discipline**: every row lists the permission Microsoft
Learn itself marks "least privileged" for that operation. ConfigTrace never
requests `Directory.ReadWrite.All` or any `*.ReadWrite.*` permission, and
never asks for the Global Administrator role — this connector is
read-only end to end.

## Authentication model (verified)

**Source**: ["Get access without a user - Microsoft Graph"](https://learn.microsoft.com/en-us/graph/auth-v2-service) — Microsoft Learn, `microsoftgraph/microsoft-graph-docs`, last verified content dated 2025-08-29.

Verified claims:
- OAuth 2.0 client-credentials grant: `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with `grant_type=client_credentials`, `client_id`, `client_secret`, `scope=https://graph.microsoft.com/.default`.
- The `.default` scope tells the token endpoint to include every application permission the tenant admin has already consented to — there is no per-request scope narrowing for app-only tokens.
- Application permissions "always require administrator consent" (never silent/self-consent).
- **No discrepancy** with the existing connector implementation (`backend/app/connectors/entra.py`) — this is exactly what `_acquire_token()` already does.

## Permission matrix

| # | ConfigTrace surface | Graph endpoint | Least-privileged application permission | Higher alternatives | Admin consent | Core/Optional | Denial impact | ConfigTrace family | Source (Microsoft Learn) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Tenant identity | `GET /organization` | `Organization.Read.All` | `Directory.Read.All`, `Organization.ReadWrite.All`, `Directory.ReadWrite.All` | Yes | **Core** — required to establish tenant identity at all | Integration creation fails outright (Invalid) | `entra_organization` | [Get organization](https://learn.microsoft.com/en-us/graph/api/organization-get) |
| 2 | Users | `GET /users` | `User.Read.All` | `Directory.Read.All` | Yes | **Core** | `users` family denied — Partial | `entra_user` | [List users](https://learn.microsoft.com/en-us/graph/api/user-list) |
| 3 | Groups | `GET /groups` | `Group.Read.All` (or `GroupMember.Read.All`) | `Directory.Read.All` | Yes | **Core** | `groups` family denied — Partial | `entra_group` | [List groups](https://learn.microsoft.com/en-us/graph/api/group-list) |
| 4 | Group memberships | `GET /groups/{id}/members` | `GroupMember.Read.All` | `Directory.Read.All`, `Group.Read.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All` | Yes | **Core** | `memberships` family denied — Partial; inaccessible member objects return limited `@odata.type`+`id` only per Microsoft's documented degraded-read behavior, never a fabricated full profile | `entra_group_membership` | [List group members](https://learn.microsoft.com/en-us/graph/api/group-list-members) |
| 5 | Applications | `GET /applications` | `Application.Read.All` | `Application.ReadWrite.OwnedBy`, `Application.ReadWrite.All`, `Directory.Read.All` | Yes | **Core** | `applications` family denied — Partial | `entra_application` | [List applications](https://learn.microsoft.com/en-us/graph/api/application-list) |
| 6 | Service principals (enterprise apps) | `GET /servicePrincipals` | `Application.Read.All` | `Application.ReadWrite.OwnedBy`, `Application.ReadWrite.All`, `Directory.Read.All` | Yes | **Core** | `service_principals` family denied — Partial | `entra_service_principal` | [List servicePrincipals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list) |
| 7 | App-role assignments | `GET /servicePrincipals/{id}/appRoleAssignedTo` | `Application.Read.All` | `Application.ReadWrite.All`, `Application.ReadWrite.OwnedBy`, `Directory.Read.All`, `Directory.ReadWrite.All` | Yes | **Core** | `app_role_assignments` family denied — Partial (loses enterprise-app user/group assignments AND SP-to-SP Graph permission grants) | `entra_application_user_assignment`, `entra_application_group_assignment`, `entra_service_principal_app_role_assignment` | [List appRoleAssignedTo](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto) |
| 8 | OAuth delegated permission grants (consent) | `GET /oauth2PermissionGrants` | `Directory.Read.All` | `DelegatedPermissionGrant.ReadWrite.All`, `Directory.ReadWrite.All` | Yes | **Optional** — no narrower read-only permission exists for this endpoint; requires the broader `Directory.Read.All` rather than an app/OAuth-scoped permission | `oauth2_permission_grants` family denied — Partial; consent-risk Security Findings and Changes are simply not evaluated for this tenant, everything else unaffected | `entra_oauth2_permission_grant` | [List oAuth2PermissionGrants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list) |
| 9 | Conditional Access policies | `GET /identity/conditionalAccess/policies` | `Policy.Read.All` | None documented (no higher application-permission alternative listed by Microsoft) | Yes | **Optional** — also requires a Microsoft Entra ID P1/P2 conditional-access-capable license in the tenant | `conditional_access_policies` family denied/unavailable — Partial | `entra_conditional_access_policy` | [List Conditional Access policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies) |
| 10 | Authentication strength policies | `GET /policies/authenticationStrengthPolicies` | `Policy.Read.AuthenticationMethod` | `Policy.Read.All`, `Policy.ReadWrite.AuthenticationMethod`, `Policy.ReadWrite.ConditionalAccess` | Yes | **Optional** | `authentication_strengths` family denied — Partial | `entra_authentication_strength` | [List authenticationStrengthPolicies](https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies) |
| 11 | Authentication methods policy | `GET /policies/authenticationMethodsPolicy` | `Policy.Read.AuthenticationMethod` | `Policy.ReadWrite.AuthenticationMethod`, `Policy.Read.All` | Yes | **Optional** | `authentication_methods` family denied — Partial | `entra_authentication_method` | [Get authenticationMethodsPolicy](https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get) |
| 12 | Directory role definitions | `GET /roleManagement/directory/roleDefinitions` | `RoleManagement.Read.Directory` | `Directory.Read.All`, `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All` | Yes | **Optional** — required for privileged-identity/role-name resolution but the connector degrades gracefully without it | `directory_role_definitions` family denied — Partial | `entra_directory_role` | [List roleDefinitions](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roledefinitions) |
| 13 | Directory role assignments | `GET /roleManagement/directory/roleAssignments` | `RoleManagement.Read.Directory` | `RoleManagement.Read.All`, `Directory.Read.All`, `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All` | Yes | **Optional** — powers ALL privileged-identity/group/service-principal derivation and every privilege-related Security Finding; strongly recommended but not required to connect | `directory_role_assignments` family denied — Partial (privileged identity/group/SP posture and 20+ related Findings are simply not evaluated) | `entra_directory_role_assignment`, `entra_privileged_identity`, `entra_privileged_group`, `entra_privileged_service_principal` | [List unifiedRoleAssignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments) |

## Minimal permission set for a "Full coverage" connection

To reach `Full` coverage (every monitored family readable), grant all 13
distinct application permissions above:

`Organization.Read.All`, `User.Read.All`, `Group.Read.All` (or
`GroupMember.Read.All`), `Application.Read.All`, `Directory.Read.All`,
`Policy.Read.All`, `Policy.Read.AuthenticationMethod`,
`RoleManagement.Read.Directory`.

(`Directory.Read.All` alone covers rows 4/6/7/8's requirements when
present; it is listed as an alternative rather than duplicated as a
separate line item.)

A tenant that grants only the 5 **Core** rows (Organization, Users,
Groups, Group memberships, Applications, Service principals, App-role
assignments) still gets a useful `Partial` connection — identity
lifecycle, application/enterprise-app inventory, and their respective
Security Findings all work; only consent-risk, Conditional Access,
authentication-policy, and privileged-identity coverage are absent until
the optional permissions are added later (no reconnect needed — Graph
permission changes take effect on the next scheduled sync once admin
consent is granted).

## Explicitly NOT requested

- `Directory.ReadWrite.All` — never requested; this connector is read-only.
- `RoleManagement.ReadWrite.Directory` — never requested.
- Any Global Administrator, Privileged Role Administrator, or other
  standing directory-role assignment for the app registration's service
  principal — application permissions alone are sufficient; ConfigTrace
  never asks a customer to assign their app registration a directory role.

## Verification status

All 13 rows were verified by fetching the live Microsoft Learn page for
each operation on 2026-07-29 (not derived from message 1-7 assumptions,
not from memory, not from blogs/Stack Overflow). No discrepancy was found
between the already-implemented connector code and current official
documentation — the message 1-7 permission assumptions were correct.
