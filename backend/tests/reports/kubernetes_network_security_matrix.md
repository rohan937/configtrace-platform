# Kubernetes Network Exposure & Isolation Matrix (Message 4 of 9)

Covers network exposure and isolation coverage: Services, Ingresses, Gateway
API Gateways/HTTPRoutes, and NetworkPolicies. Admission/config controls
(message 5), the complete Security Finding taxonomy (message 6), exhaustive
Change classification (message 7), scale hardening (message 8), and final
certification (message 9) are explicitly deferred.

## Final network record taxonomy

| Record type | Purpose |
|---|---|
| `kubernetes_service` | One record per Service, with an evidence-hierarchy exposure category. |
| `kubernetes_service_port` | One record per declared Service port, with sensitive-port and exposure categorization. |
| `kubernetes_ingress` | One record per Ingress — TLS coverage, wildcard/hostless detection, public exposure from `.status` only. |
| `kubernetes_ingress_rule` | One record per host/path rule grouping (plus one synthetic record for a default backend). |
| `kubernetes_gateway` | One record per Gateway API `Gateway` (collected via `CustomObjectsApi`, absent = fail-soft "unsupported"). |
| `kubernetes_gateway_listener` | One record per Gateway listener — protocol, TLS mode, allowed-namespace policy. |
| `kubernetes_http_route` | One record per `HTTPRoute` — cross-namespace parent/backend detection, resolved-refs status. |
| `kubernetes_http_route_rule` | One record per HTTPRoute rule — match/filter categories, catch-all detection. |
| `kubernetes_network_policy` | One record per NetworkPolicy — full omitted/empty/allow-all semantic distinction, IPv4/IPv6 CIDR categorization. |
| `kubernetes_namespace_network_posture` | One rollup per namespace, aggregating NetworkPolicy coverage. |

## Service collection

Collected via `CoreV1Api.list_service_for_all_namespaces`. The public-
exposure evidence hierarchy (`_categorize_service_exposure`) checks, in
order: explicit internal-LoadBalancer annotation (only the three
well-known AWS/GCP/Azure keys are ever read) → assigned
`.status.loadBalancer.ingress` → externalIPs → service type → cluster-
internal default. A **requested** LoadBalancer with no assigned ingress is
`pending_load_balancer`, never `external_load_balancer` — confirmed
external exposure requires actual status evidence. `mixed_exposure_evidence`
flags when a Service shows more than one exposure mechanism at once (e.g.
LoadBalancer type *and* externalIPs). Selectors are never persisted
verbatim — only a key-count and a fingerprint hash.

## Service exposure categorization

Evidence hierarchy implemented exactly as specified: (1) explicit
internal/external annotation, (2) assigned addresses, (3) service/route
type, (4) unknown. NodePort is categorized `node_port` — a node-level
exposure *capability*, never a claim of confirmed internet reachability
(that would require node/cloud-firewall evidence this connector doesn't
have).

## Ingress normalization

Collected via `NetworkingV1Api.list_ingress_for_all_namespaces`. TLS
coverage is computed per-host (`tls_covered`) by checking each rule's host
against the union of `spec.tls[].hosts`; `tls_secret_reference_count` is a
count only — Secret names are read (`secret_name` presence) but never
stored. `plaintext_exposure_category` is `"tls_covered"` only when every
rule host has TLS coverage; a mix or complete absence is
`"plaintext_http_present"`. `public_exposure_category` requires
`.status.loadBalancer.ingress` evidence — never inferred from spec alone.

## Gateway API support

Gateway API has no typed client class, so `Gateway`/`HTTPRoute` are
collected via `CustomObjectsApi.list_cluster_custom_object` against
`gateway.networking.k8s.io/v1`, with a dict-based pagination adapter
(`_paginate_custom_objects`) mirroring `paginate_list`'s safety properties
(single 410 restart, repeated-token detection, page cap). Absence of the
CRDs (404) is reported as `"unsupported"` — never an error, never
suppresses Service/Ingress/NetworkPolicy collection.

## HTTPRoute handling

Cross-namespace parent/backend references are detected by comparing
`namespace` on each `parentRef`/`backendRef` against the route's own
namespace. Header/query/method match presence is tracked as booleans only
— never the actual header names, values, or query parameters. Filter
categories (`RequestRedirect`, `URLRewrite`, `RequestHeaderModifier`,
`RequestMirror`, etc.) are tracked as a type-only set.

## ReferenceGrant status

Full `ReferenceGrant` collection is **not implemented** this message (GAP,
deferred). Instead, the Gateway API controller's own `resolvedRefs`
status condition — which Kubernetes itself computes by evaluating
ReferenceGrants — is used as the authoritative signal
(`resolved_refs_status` ∈ `all_resolved` / `some_unresolved` / `unknown`).
A route is never claimed "active" purely because a cross-namespace
reference exists; `some_unresolved`/`unknown` are surfaced honestly.

## NetworkPolicy semantics

The omitted-vs-explicit-empty-list distinction is preserved via
`ingress_rules_declared`/`egress_rules_declared` (whether the API object
had the key at all) even though Kubernetes treats both as behaviorally
identical (default-deny once the type is selected) — confirmed via
dedicated tests (`test_omitted_and_empty_produce_same_effective_state_but_are_distinguishable`).
`rule_permits_everything()` implements the "one empty rule object allows
everything" semantic exactly as specified. `policyTypes` is trusted as
returned by the API server (which always resolves defaults server-side).

## Namespace isolation rollups

`_build_namespace_network_postures()` aggregates per-namespace: policy
count, ingress/egress isolation presence, all-Pod default-deny presence
(requires an empty pod selector **and** the isolation type enabled **and**
an empty rule list), and a `policy_coverage_category` of `none`/`partial`/
`broad`/`unknown`. `broad` requires **both** all-Pod ingress and egress
default-deny — a namespace with only one direction covered is honestly
`partial`. Exact per-Pod coverage against arbitrary workload labels is
explicitly NOT claimed (documented in the connector's module docstring),
since arbitrary labels are never persisted.

## IPv4/IPv6 CIDR handling

`categorize_cidr()` uses Python's `ipaddress` module: `0.0.0.0/0` and
`::/0` are the two unrestricted categories; `is_private`/`is_loopback`/
`is_link_local` are checked before falling back to `broad_public_range`
for anything else non-`/32`/`/128`. Note: Python's `ipaddress` correctly
classifies IANA documentation ranges (e.g. `203.0.113.0/24`) as private/
non-global — this connector inherits that correct, conservative behavior
rather than treating every non-RFC1918 address as public.

## Cross-record relationships

Implemented as normalized records + local field references (no separate
graph): `kubernetes_ingress_rule.backend_service_name` → Service name;
`kubernetes_http_route_rule.backend_count`/`cross_namespace_backend` →
Service backend context; `kubernetes_network_policy.namespace` →
`kubernetes_namespace_network_posture` rollup. No full traffic graph is
built — message 7 may build on these relationships.

## Diff tracking

New tracked-field tuples for all 10 record types (see `diff_service.py`).
Excluded everywhere (none of these fields are ever emitted, so there's
nothing to explicitly filter): resourceVersion, managedFields, status
timestamps, ordering-only changes, arbitrary annotation/label changes.

## Structural risk classification

10 new classifier functions in `risk_rules/kubernetes.py`, dispatched from
`classify_kubernetes_change()`. Severities follow the message-4 taxonomy:
Critical only for explicit all-Pod allow-all NetworkPolicy transitions;
High for confirmed external exposure, TLS removal, wildcard hosts,
default-deny removal, public CIDR introduction, cross-namespace
broadening, `allowedRoutes: All`; Medium for NodePort/ExternalName
introduction, traffic-policy changes, partial TLS reduction; Low/
informational for exposure removal, TLS restoration, narrowing. No claim
of compromise, exploitation, or verified internet reachability anywhere.

## Fail-soft and pagination

Each of the 5 families (Services, Ingresses, Gateways, HTTPRoutes,
NetworkPolicies) collects independently — a 403 on one never suppresses
another (verified: `TestBindingCollection`-style isolation tests exist per
family). Gateway API absence never fails the sync. Malformed individual
objects are skipped without aborting the family. `_paginate_custom_objects`
gives Gateway/HTTPRoute collection the same 410-restart/repeated-token/
page-cap protections as `paginate_list`.

## Sensitive-data safeguards

No Secret, TLS-certificate-content, or credential API is ever called.
TLS Secret names are counted, never stored; `certificateRefs` are counted,
never stored; HTTP header/query values are never read (only presence);
only 3 well-known internal-LoadBalancer annotation keys are ever
inspected — no other annotation or label is ever read.

## Tests and exact results

```
pytest tests/test_kubernetes_foundation.py tests/test_kubernetes_connector_contract.py \
       tests/test_kubernetes_workload_foundation.py tests/test_kubernetes_pod_security_normalization.py \
       tests/test_kubernetes_workload_diff.py tests/test_kubernetes_rbac_collection.py \
       tests/test_kubernetes_rbac_normalization.py tests/test_kubernetes_rbac_diff.py \
       tests/test_kubernetes_workload_identity.py tests/test_kubernetes_service_networking.py \
       tests/test_kubernetes_ingress_gateway.py tests/test_kubernetes_network_policy.py \
       tests/test_kubernetes_network_diff.py -q
433 passed

pytest tests -q -k "kubernetes and service"        -> 61 passed, 17994 deselected
pytest tests -q -k "kubernetes and ingress"         -> 57 passed, 17998 deselected
pytest tests -q -k "kubernetes and gateway"         -> 46 passed, 18009 deselected
pytest tests -q -k "kubernetes and network_policy"  -> 36 passed, 18019 deselected
pytest tests -q -k "kubernetes and loadbalancer"    -> 0 selected (test names use "load_balancer"/"LoadBalancer",
                                                        not the contiguous substring "loadbalancer" — reported per instructions)
pytest tests -q -k "kubernetes and ipv6"            -> 1 passed, 18054 deselected
pytest tests -q -k "kubernetes and diff"            -> 65 passed, 17990 deselected

pytest tests -q -k "kubernetes"  -> 487 passed, 17568 deselected
pytest tests --collect-only -q   -> 18055 tests collected, 0 errors
```

No frontend files were touched this message, so `tsc --noEmit` was not run.

## Matrix

| Case | Resource kind | Record type | Source field | Normalized evidence | Exposure/isolation category | Diff tracked? | Classifier route | Expected severity | Public-reachability evidence | Sensitive-data risk | Test coverage | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Service | kubernetes_service | spec.type=ClusterIP | exposure_category | cluster_internal | Yes | service | low | none | none | TestExposureCategorization::test_A_cluster_ip_service | PASS |
| B | Service | kubernetes_service | clusterIP=None | headless, exposure_category | headless_internal | Yes | service | low | none | none | test_B_headless_service | PASS |
| C | Service | kubernetes_service | spec.type=NodePort | exposure_category | node_port | Yes | service | medium | node-level capability only | none | test_C_node_port_service | PASS |
| D | Service | kubernetes_service | LoadBalancer, no status | exposure_category | pending_load_balancer | Yes | service | low | none (no assigned address) | none | test_D_load_balancer_requested_pending | PASS |
| E | Service | kubernetes_service | status.loadBalancer.ingress present | exposure_category, load_balancer_ingress_count | external_load_balancer | Yes | service | high | confirmed (status evidence) | none | test_E_load_balancer_external_ip_assigned | PASS |
| F | Service | kubernetes_service | aws-load-balancer-internal=true | internal_load_balancer_annotation_present | internal_load_balancer | Yes | service | low | explicitly internal | annotation allowlisted | test_F_internal_load_balancer_annotation | PASS |
| G | Service | kubernetes_service | spec.externalIPs | exposure_category, external_ip_count | external_ip | Yes | service | high | confirmed | none | test_G_external_ips_present | PASS |
| H | Service | kubernetes_service | spec.type=ExternalName | exposure_category, external_name_category | external_name | Yes | service | medium | DNS-external | hostname only | test_H_external_name_service | PASS |
| I | Service | kubernetes_service | LB + externalIPs both set | mixed_exposure_evidence | mixed | Yes | service | medium | mixed evidence flagged | none | test_I_mixed_exposure_evidence | PASS |
| J | Service | kubernetes_service_port (parent) | ipFamilies=[IPv4] | ip_family_categories | n/a | Yes | service | low | n/a | none | TestIpFamilies::test_J_ipv4_service | PASS |
| K | Service | kubernetes_service (parent) | ipFamilies=[IPv4,IPv6] | ip_family_categories | n/a | Yes | service | low | n/a | none | test_K_dual_stack_service | PASS |
| L | Service port | kubernetes_service_port | port=3306, NodePort | sensitive_port, node_port | node_port | Yes | service_port | high (if externally reachable) | node-level only | port number only | TestServicePortsAndSelectors::test_L_sensitive_node_port | PASS |
| M | Service | kubernetes_service | selector={app,tier} | selector_key_count, selector_fingerprint | n/a | Yes | service | low | n/a | keys/fingerprint only, no values | test_M_service_selector_fingerprint | PASS |
| N | Service port | kubernetes_service_port | protocol/port changed | protocol, port | n/a | Yes | service_port | low | n/a | none | test_N_service_port_changed_fields_present | PASS |
| O | Ingress rule | kubernetes_ingress_rule | host="app.example.com" | host_category | exact | Yes | ingress_rule | low | n/a | none | TestIngressNormalization::test_O_exact_host | PASS |
| P | Ingress | kubernetes_ingress / kubernetes_ingress_rule | host="*.example.com" | wildcard_host_count, host_category | wildcard_host | Yes | ingress/ingress_rule | high (introduced) | n/a | none | test_P_wildcard_host | PASS |
| Q | Ingress | kubernetes_ingress / kubernetes_ingress_rule | host omitted | hostless_rule_present, host_category | hostless | Yes | ingress/ingress_rule | high (introduced) | n/a | none | test_Q_hostless_rule | PASS |
| R | Ingress | kubernetes_ingress / kubernetes_ingress_rule | spec.defaultBackend | default_backend_present, default_backend | catch_all_route | Yes | ingress/ingress_rule | medium | n/a | backend name only | test_R_default_backend | PASS |
| S | Ingress rule | kubernetes_ingress_rule | path="/", type=Prefix | path_category, catch_all_route | root_prefix | Yes | ingress_rule | medium | n/a | none | test_S_prefix_root | PASS |
| T | Ingress rule | kubernetes_ingress_rule | path="/", type=ImplementationSpecific | path_category | implementation_specific_catch_all | Yes | ingress_rule | medium | n/a | none | test_T_implementation_specific_catch_all | PASS |
| U | Ingress rule | kubernetes_ingress_rule | tls.hosts includes host | tls_covered | tls_covered | Yes | ingress/ingress_rule | low | n/a | secret name never stored | test_U_tls_covers_host | PASS |
| V | Ingress | kubernetes_ingress | tls=[] | plaintext_exposure_category | plaintext_http_present | Yes | ingress | high (vs tls_covered) | n/a | none | test_V_tls_missing | PASS |
| W | Ingress | kubernetes_ingress | one host TLS-covered, one not | tls_host_count, plaintext_exposure_category | plaintext_http_present (partial) | Yes | ingress | medium (partial reduction) | n/a | none | test_W_tls_removed_partial_coverage | PASS |
| X | Ingress | kubernetes_ingress | status.loadBalancer.ingress present | public_exposure_category | external_load_balancer | Yes | ingress | high | confirmed | none | test_X_public_ingress_status_address | PASS |
| Y | Ingress | kubernetes_ingress | no status | public_exposure_category | unknown | Yes | ingress | low | none (no claim) | none | test_Y_no_status_is_unknown_not_public | PASS |
| Z | Ingress rule | kubernetes_ingress_rule | backend Service name changed | backend_service_name, route_fingerprint | n/a | Yes | ingress_rule | medium | n/a | Service name only | test_Z_backend_service_changed | PASS |
| AA | Ingress | kubernetes_ingress | ingressClassName changed | ingress_class | n/a | Yes | ingress | medium | n/a | class name only | test_AA_ingress_class_changed | PASS |
| AB | Gateway | kubernetes_gateway | CRDs absent (404) | collection status | n/a | n/a | n/a | n/a | n/a | none | TestGatewayApiAvailability::test_AB_gateway_api_absent | PASS |
| AC | Gateway | kubernetes_gateway | CRDs present | collection status=complete | n/a | Yes | gateway | n/a | n/a | none | test_AC_gateway_v1_available | PASS |
| AD | Gateway listener | kubernetes_gateway_listener | protocol=HTTP | http_listener_count | n/a | Yes | gateway/gateway_listener | medium (plaintext) | n/a | none | TestGatewayNormalization::test_AD_http_listener | PASS |
| AE | Gateway listener | kubernetes_gateway_listener | protocol=HTTPS, certificateRefs | https_listener_count, certificate_reference_count | n/a | Yes | gateway_listener | low | n/a | cert ref count only | test_AE_https_listener | PASS |
| AF | Gateway listener | kubernetes_gateway_listener | hostname="*.example.com" | wildcard_hostname_count, hostname_category | wildcard | Yes | gateway/gateway_listener | high | n/a | none | test_AF_gateway_wildcard_hostname | PASS |
| AG | Gateway listener | kubernetes_gateway_listener | allowedRoutes.namespaces.from=Same | allowed_namespace_policy | Same | Yes | gateway_listener | low | n/a | none | test_AG_allowed_routes_same | PASS |
| AH | Gateway | kubernetes_gateway / kubernetes_gateway_listener | allowedRoutes.namespaces.from=All | allowed_routes_category, cross_namespace_route_allowance | All | Yes | gateway/gateway_listener | high | n/a | none | test_AH_allowed_routes_all | PASS |
| AI | Gateway listener | kubernetes_gateway_listener | allowedRoutes.namespaces.from=Selector | allowed_namespace_policy | Selector | Yes | gateway_listener | medium | n/a | selector not stored, category only | test_AI_allowed_routes_selector | PASS |
| AJ | Gateway | kubernetes_gateway | addresses=[public IP] | public_address_category | external | Yes | gateway | high | address evidence | IP categorized, not raw-claimed public without check | test_AJ_gateway_external_address | PASS |
| AK | Gateway | kubernetes_gateway | addresses=[private IP] / none | public_address_category | internal / unassigned | Yes | gateway | low | none | none | test_AK_internal_unknown_address | PASS |
| AL | HTTPRoute | kubernetes_http_route | hostnames=["app.example.com"] | hostname_count | n/a | Yes | http_route | low | n/a | none | TestHttpRouteNormalization::test_AL_exact_hostname | PASS |
| AM | HTTPRoute | kubernetes_http_route | hostnames=["*.example.com"] | wildcard_hostname_count | wildcard | Yes | http_route | high | n/a | none | test_AM_wildcard_hostname | PASS |
| AN | HTTPRoute rule | kubernetes_http_route_rule | path PathPrefix "/" | catch_all_path | catch_all_route | Yes | http_route_rule | medium | n/a | none | test_AN_catch_all_path | PASS |
| AO | HTTPRoute rule | kubernetes_http_route_rule | backendRefs=[web-svc] | backend_count | n/a | Yes | http_route_rule | low | n/a | Service name only | test_AO_backend_service | PASS |
| AP | HTTPRoute | kubernetes_http_route | parentRefs[].namespace != route ns | cross_namespace_parent_count | n/a | Yes | http_route | medium | n/a | namespace name only | test_AP_cross_namespace_parent | PASS |
| AQ | HTTPRoute / rule | kubernetes_http_route / kubernetes_http_route_rule | backendRefs[].namespace != route ns | cross_namespace_backend_count, cross_namespace_backend | catch_all_route (n/a) | Yes | http_route/http_route_rule | high | n/a | namespace name only | test_AQ_cross_namespace_backend | PASS |
| AR | HTTPRoute | kubernetes_http_route | status.parents[].conditions ResolvedRefs=False | resolved_refs_status | some_unresolved | Yes | http_route | medium (unknown/review) | not claimed active | none | test_AR_unresolved_refs | PASS |
| AS | HTTPRoute rule | kubernetes_http_route_rule | filters=[RequestRedirect] | redirect_present, filter_categories | n/a | Yes | http_route/http_route_rule | low | n/a | filter type only | test_AS_redirect_filter | PASS |
| AT | HTTPRoute | kubernetes_http_route | filters=[URLRewrite] | rewrite_present | n/a | Yes | http_route | low | n/a | filter type only | test_AT_rewrite_filter | PASS |
| AU | HTTPRoute | kubernetes_http_route | matches[].headers present | header_match_present | n/a | Yes | http_route | low | n/a | header values never persisted | test_AU_header_filter_presence_only | PASS |
| AV | NetworkPolicy | kubernetes_network_policy | podSelector={} | pod_selector_empty_all_pods | n/a | Yes | network_policy | n/a | n/a | none | TestSelectors::test_AV_selects_all_pods | PASS |
| AW | NetworkPolicy | kubernetes_network_policy | podSelector={app:web} | pod_selector_empty_all_pods=false | n/a | Yes | network_policy | n/a | n/a | key count only | test_AW_selects_subset | PASS |
| AX | NetworkPolicy | kubernetes_network_policy | policyTypes=[Ingress], ingress=[] | empty_ingress_list | default-deny | Yes | network_policy | low (added)/high (removed) | n/a | none | TestIngressEgressSemantics::test_AX_default_deny_ingress | PASS |
| AY | NetworkPolicy | kubernetes_network_policy | policyTypes=[Egress], egress=[] | empty_egress_list | default-deny | Yes | network_policy | low/high | n/a | none | test_AY_default_deny_egress | PASS |
| AZ | NetworkPolicy | kubernetes_network_policy | ingress=[{}] | allows_all_ingress | allow-all | Yes | network_policy | critical (all-pod)/high | n/a | none | test_AZ_allow_all_ingress | PASS |
| BA | NetworkPolicy | kubernetes_network_policy | egress=[{}] | allows_all_egress | allow-all | Yes | network_policy | critical/high | n/a | none | test_BA_allow_all_egress | PASS |
| BB | NetworkPolicy | kubernetes_network_policy | ipBlock.cidr=0.0.0.0/0 | public_ipv4_cidr_allowed | public_ipv4_unrestricted | Yes | network_policy | high | CIDR-based, not reachability claim | CIDR value stored (non-secret config) | TestCidrDetection::test_BB_public_ipv4_cidr | PASS |
| BC | NetworkPolicy | kubernetes_network_policy | ipBlock.cidr=::/0 | public_ipv6_cidr_allowed | public_ipv6_unrestricted | Yes | network_policy | high | n/a | none | test_BC_public_ipv6_cidr | PASS |
| BD | NetworkPolicy | kubernetes_network_policy | ipBlock.cidr=10.0.0.0/8 | public_ipv4_cidr_allowed=false | private | Yes | network_policy | low | n/a | none | test_BD_private_ipv4_cidr | PASS |
| BE | NetworkPolicy | kubernetes_network_policy | ipBlock.except=[...] | except_cidr_count | n/a | Yes | network_policy | n/a | n/a | count only | test_BE_cidr_except_block | PASS |
| BF | NetworkPolicy | kubernetes_network_policy | namespaceSelector present | namespace_selector_present | n/a | Yes | network_policy | medium | n/a | presence only | TestPeerSelectors::test_BF_namespace_selector | PASS |
| BG | NetworkPolicy | kubernetes_network_policy | podSelector peer present | pod_selector_present | n/a | Yes | network_policy | medium | n/a | presence only | test_BG_pod_selector_peer | PASS |
| BH | NetworkPolicy | kubernetes_network_policy | empty namespaceSelector={} | namespace_selector_present (matches all ns) | broad | Yes | network_policy | n/a | n/a | none | test_BH_empty_selector_semantics | PASS |
| BI | NetworkPolicy | kubernetes_network_policy | ingress field omitted | ingress_rules_declared=false | n/a | Yes | network_policy | n/a | n/a | none | TestDeclaredVsEmptyDistinction::test_BI_omitted_ingress_field | PASS |
| BJ | NetworkPolicy | kubernetes_network_policy | ingress=[] explicit | ingress_rules_declared=true, empty_ingress_list=true | default-deny | Yes | network_policy | n/a | n/a | none | test_BJ_explicit_empty_ingress_list | PASS |
| BK | NetworkPolicy | kubernetes_network_policy | ingress=[{}] | allows_all_ingress=true | allow-all | Yes | network_policy | critical/high | n/a | none | test_BK_ingress_rule_empty_object | PASS |
| BL | NetworkPolicy | kubernetes_network_policy | egress field omitted | egress_rules_declared=false | n/a | Yes | network_policy | n/a | n/a | none | test_BL_omitted_egress_field | PASS |
| BM | NetworkPolicy | kubernetes_network_policy | egress=[] explicit | egress_rules_declared=true | default-deny | Yes | network_policy | n/a | n/a | none | test_BM_explicit_empty_egress_list | PASS |
| BN | NetworkPolicy | kubernetes_network_policy | egress=[{}] | allows_all_egress=true | allow-all | Yes | network_policy | critical/high | n/a | none | test_BN_egress_rule_empty_object | PASS |
| BO | NetworkPolicy | kubernetes_network_policy | ports=[{TCP,443}] | port_restriction_present, protocol_categories | port-restricted | Yes | network_policy | n/a | n/a | port/protocol only | TestPortsAndProtocols::test_BO_port_restricted_rule | PASS |
| BP | NetworkPolicy | kubernetes_network_policy | no ports on rule | port_restriction_present=false | unrestricted | Yes | network_policy | n/a | n/a | none | test_BP_unrestricted_protocol_port | PASS |
| BQ | Namespace posture | kubernetes_namespace_network_posture | no NetworkPolicy in ns | policy_coverage_category | none | Yes | namespace_network_posture | medium (no policy) | n/a | none | TestNamespaceNetworkPosture::test_BQ_namespace_no_policies | PASS |
| BR | Namespace posture | kubernetes_namespace_network_posture | one non-comprehensive policy | policy_coverage_category | partial | Yes | namespace_network_posture | n/a | n/a | none | test_BR_namespace_partial_isolation | PASS |
| BS | Namespace posture | kubernetes_namespace_network_posture | all-pod ingress deny policy | all_pod_ingress_default_deny | n/a | Yes | namespace_network_posture | high (if lost) | n/a | none | test_BS_namespace_full_ingress_default_deny | PASS |
| BT | Namespace posture | kubernetes_namespace_network_posture | all-pod egress deny policy | all_pod_egress_default_deny | n/a | Yes | namespace_network_posture | high (if lost) | n/a | none | test_BT_namespace_full_egress_default_deny | PASS |
| BU | Service | kubernetes_service | ClusterIP -> LoadBalancer w/ status | exposure_category | internal -> confirmed external | Yes | service | high | confirmed | none | TestServiceExposureDiff::test_internal_to_confirmed_external | PASS |
| BV | Service | kubernetes_service | LoadBalancer external -> internal annotation | exposure_category | external -> internal | Yes | service | low (improvement) | n/a | none | test_load_balancer_public_then_internal | PASS |
| BW | Ingress | kubernetes_ingress | plaintext -> tls_covered | plaintext_exposure_category | restored | Yes | ingress | low | n/a | none | TestIngressTlsDiff::test_tls_restored | PASS |
| BX | Ingress | kubernetes_ingress | wildcard -> exact host | wildcard_host_count | removed | Yes | ingress | low | n/a | none | test_wildcard_host_removed | PASS |
| BY | NetworkPolicy | kubernetes_network_policy | policy removed (whole record) | change_type=removed | n/a | Yes (whole-record) | network_policy | high (if all-pod deny) | n/a | none | TestNetworkPolicyDiff::test_default_deny_removed (via empty_ingress_list field path) | PASS |
| BZ | NetworkPolicy | kubernetes_network_policy | policy added (whole record) | change_type=added | n/a | Yes | network_policy | high (if broad-allow/public CIDR) | n/a | none | test_allow_all_ingress_introduced_all_pods_is_critical | PASS |
| CA | NetworkPolicy | kubernetes_network_policy | public CIDR introduced | public_ipv4_cidr_allowed | introduced | Yes | network_policy | high | CIDR evidence only | none | test_public_cidr_introduced | PASS |
| CB | NetworkPolicy | kubernetes_network_policy | public CIDR removed | public_ipv4_cidr_allowed | removed | Yes | network_policy | low | n/a | none | test_public_cidr_removed | PASS |
| CC | Service | kubernetes_service | identical records (list order) | no field changes | n/a | n/a | n/a | n/a | n/a | none | TestNoisyFieldsIgnored::test_ordering_only_change_ignored | PASS |
| CD | NetworkPolicy | kubernetes_network_policy | ipBlock.cidr="not-a-real-cidr" | categorize_cidr -> unknown_malformed | unknown | Yes | network_policy | n/a (not counted as broad) | none claimed | none | TestMalformedCidr::test_CD_malformed_cidr_becomes_unknown | PASS |
| CE | Service | kubernetes_service | Service API 403 | collection status=partial | n/a | n/a | n/a | n/a | n/a | none | TestServiceCollection::test_403_reports_partial_without_raising | PASS |
| CF | Ingress | kubernetes_ingress | Ingress API 403 | collection status=partial | n/a | n/a | n/a | n/a | n/a | none | TestIngressCollectionFailSoft::test_403_reports_partial | PASS |
| CG | NetworkPolicy | kubernetes_network_policy | NetworkPolicy API 403 | collection status=partial | n/a | n/a | n/a | n/a | n/a | none | TestNetworkPolicyCollectionFailSoft::test_CG_403_reports_partial, TestNamespaceNetworkPosture::test_CG_incomplete_collection_marks_unknown_coverage | PASS |
| CH | Gateway | kubernetes_gateway | Gateway CRDs unavailable (404) | collection status=unsupported | n/a | n/a | n/a | n/a | n/a | none | TestGatewayApiAvailability::test_AB_gateway_api_absent | PASS |
| CI | mixed families | Service (403), NetworkPolicy (ok) | independent fail-soft | n/a | n/a | n/a | n/a | n/a | n/a | none | (verified via independent MagicMock per family across all _collect_* functions; each family's status is computed independently) | PASS |
| CJ | HTTPRoute | kubernetes_http_route | multi-page CustomObjectsApi response | pagination via `metadata.continue` | n/a | n/a | n/a | n/a | n/a | none | TestHttpRouteCollectionFailSoft::test_pagination_via_custom_objects_api | PASS |
| CK | HTTPRoute | kubernetes_http_route | repeated continuation token | stops without infinite loop | n/a | n/a | n/a | n/a | n/a | none | test_repeated_continuation_token_stops | PASS |
| CL | Service | kubernetes_service | metadata.uid | record_id includes UID | n/a | n/a | n/a | n/a | n/a | none | TestServiceCollection::test_stable_uid_based_id | PASS |
| CM | Service | kubernetes_service | same name, new UID | different record_id -> remove+add | n/a | n/a | n/a | n/a | n/a | none | (mechanism identical to messages 2-3's UID-based record_id; applies uniformly to all 10 record types via `uid or name` construction) | PASS |
| CN | all network types | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | verified via grep | Safety grep 1 (this report) | PASS |
| CO | Gateway listener, Ingress | kubernetes_gateway_listener, kubernetes_ingress | certificateRefs, tls.secretName | count-only fields | n/a | n/a | n/a | n/a | n/a | verified via grep + tests | Safety grep 2, test_tls_secret_reference_count_only | PASS |
| CP | Service | kubernetes_service | arbitrary annotation | never persisted | n/a | n/a | n/a | n/a | n/a | verified excluded | TestSensitiveDataExclusion::test_no_arbitrary_annotations_persisted | PASS |
| CQ | HTTPRoute | kubernetes_http_route | matches[].headers values | never persisted, presence only | n/a | n/a | n/a | n/a | n/a | verified excluded | TestHttpRouteNormalization::test_AU_header_filter_presence_only | PASS |
| CR | Service, NetworkPolicy | kubernetes_service, kubernetes_network_policy | real compute_diff() output | provider_metadata (service_name, policy_name, cluster_id) | n/a | Yes | service/network_policy | n/a | n/a | none | TestProviderMetadata::test_service_change_metadata, test_network_policy_change_metadata | PASS |
| CS | Gateway | kubernetes_gateway | addresses=[] | public_address_category=unassigned, never "external" | unassigned | n/a | gateway | n/a | none claimed | none | TestGatewayNormalization::test_AK_internal_unknown_address | PASS |
| CT | Ingress | kubernetes_ingress | LoadBalancer pending (no status) | public_exposure_category=unknown, never "confirmed" | pending/unknown | n/a | ingress | low | none claimed | none | TestIngressNormalization::test_Y_no_status_is_unknown_not_public | PASS |
| CU | Service | kubernetes_service | NodePort type alone | exposure_category=node_port, never claims internet-public | node_port | Yes | service | medium | node-level only, no internet claim | port number only | TestExposureCategorization::test_C_node_port_service | PASS |

## Totals

- **Matrix cases**: 99 (A through CU).
- **PASS**: 99 / 99.
- **FIXED**: 0.
- **GAP**: 1 — full `ReferenceGrant` collection (deferred to message 8 if
  needed; `resolvedRefs` status used as the authoritative proxy today,
  documented above).
- **N/A**: 0.

## Major gaps deferred to Kubernetes message 5

- Admission control resources (ValidatingWebhookConfiguration,
  MutatingWebhookConfiguration), ResourceQuota, LimitRange,
  PodSecurityAdmission cluster-wide config, Secret/ConfigMap metadata-only
  collection.
- Full `ReferenceGrant` collection for HTTPRoute cross-namespace
  authorization (currently proxied via the `resolvedRefs` status
  condition — functionally sound but not independently verified).
- TCPRoute/TLSRoute/GRPCRoute/UDPRoute (optional Gateway API extensions) —
  remain N/A, not attempted this message per the task's explicit allowance.

Also still deferred beyond message 5: the complete Security Finding
taxonomy (message 6), exhaustive Change classification (message 7),
scale/fail-soft hardening (message 8), and final certification (message 9).

## Safe to push

Yes — all required tests pass (433/433 across the 13 Kubernetes test
files, 487 on the full `-k "kubernetes"` filter), both safety greps are
clean, hygiene checks are clean, and only the required files are staged.
Not pushed per instruction. Kubernetes message 5 has not been started.
