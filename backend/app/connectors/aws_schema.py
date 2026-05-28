"""AWS connector record type constants — M36 / M37 / M38 / M39 / M40 / M41 / M42 / M43 / M44 / M45 / M46 / M47 / M48 / M49."""
from __future__ import annotations

# ── M36 record types ──────────────────────────────────────────────────────────
AWS_ACCOUNT_IDENTITY = "aws_account_identity"
AWS_REGION = "aws_region"
AWS_SERVICE_INVENTORY = "aws_service_inventory"

# ── M37 record types ──────────────────────────────────────────────────────────
AWS_S3_BUCKET = "aws_s3_bucket"

# ── M38 record types — Security Groups + VPC Network Exposure ─────────────────
AWS_SECURITY_GROUP = "aws_security_group"
AWS_SECURITY_GROUP_RULE = "aws_security_group_rule"
AWS_VPC = "aws_vpc"
AWS_SUBNET = "aws_subnet"
AWS_ROUTE_TABLE = "aws_route_table"
AWS_INTERNET_GATEWAY = "aws_internet_gateway"
AWS_NETWORK_ACL = "aws_network_acl"

# ── M39 record types — IAM Identity, Permissions, Policy and Trust Risk ───────
# One per AWS account — aggregate account-level IAM posture.
AWS_IAM_ACCOUNT_SUMMARY = "aws_iam_account_summary"
# One per IAM user — identity, MFA, access key counts, group/policy membership.
AWS_IAM_USER = "aws_iam_user"
# One per IAM access key — metadata only; secret key is NEVER stored.
AWS_IAM_ACCESS_KEY = "aws_iam_access_key"
# One per IAM group — members, attached and inline policies.
AWS_IAM_GROUP = "aws_iam_group"
# One per IAM role — trust summary, attached and inline policies.
AWS_IAM_ROLE = "aws_iam_role"
# One per customer-managed IAM policy — default-version policy summary.
AWS_IAM_POLICY = "aws_iam_policy"
# One per principal-to-managed-policy attachment (user, group, or role).
AWS_IAM_POLICY_ATTACHMENT = "aws_iam_policy_attachment"
# One per inline policy per principal (user, group, or role).
AWS_IAM_INLINE_POLICY = "aws_iam_inline_policy"
# One per OIDC or SAML identity provider registered in the account.
AWS_IAM_IDENTITY_PROVIDER = "aws_iam_identity_provider"

# ── M40 record types — Route53 DNS + CloudFront CDN Routing Config ────────────
# One per Route53 hosted zone — zone-level posture (public/private, NS, VPC links).
AWS_ROUTE53_HOSTED_ZONE = "aws_route53_hosted_zone"
# One per Route53 resource record set — individual DNS record (A, CNAME, MX, TXT, …).
AWS_ROUTE53_RECORD = "aws_route53_record"
# One per CloudFront distribution — CDN config, origins, protocol, aliases, WAF.
AWS_CLOUDFRONT_DISTRIBUTION = "aws_cloudfront_distribution"

# ── M41 record types — Secrets Manager + SSM Parameter Metadata ──────────────
# One per Secrets Manager secret — metadata only; secret value is NEVER stored.
AWS_SECRETSMANAGER_SECRET = "aws_secretsmanager_secret"
# One per SSM Parameter — metadata only; parameter value is NEVER stored.
AWS_SSM_PARAMETER = "aws_ssm_parameter"

# ── M42 record types — RDS Database Exposure / Backup / Encryption Config ────
# One per RDS DB instance — metadata only; no DB data, passwords, or connections.
AWS_RDS_DB_INSTANCE = "aws_rds_db_instance"
# One per RDS/Aurora DB cluster — metadata only.
AWS_RDS_DB_CLUSTER = "aws_rds_db_cluster"
# One per RDS DB subnet group — VPC/subnet topology metadata.
AWS_RDS_DB_SUBNET_GROUP = "aws_rds_db_subnet_group"
# One per RDS DB snapshot — metadata only; no log downloads or data access.
AWS_RDS_DB_SNAPSHOT = "aws_rds_db_snapshot"
# One per RDS DB cluster snapshot — metadata only.
AWS_RDS_DB_CLUSTER_SNAPSHOT = "aws_rds_db_cluster_snapshot"

# ── M45 record types — CloudTrail + GuardDuty + Security Hub Posture ─────────
# One per CloudTrail trail — posture/config metadata only; events/log objects NEVER accessed.
AWS_CLOUDTRAIL_TRAIL = "aws_cloudtrail_trail"
# One per CloudTrail event data store — posture metadata only; events NEVER read.
AWS_CLOUDTRAIL_EVENT_DATA_STORE = "aws_cloudtrail_event_data_store"
# One per GuardDuty detector (one per region) — posture metadata only; findings NEVER accessed.
AWS_GUARDDUTY_DETECTOR = "aws_guardduty_detector"
# One per GuardDuty publishing destination — metadata only; finding payloads NEVER stored.
AWS_GUARDDUTY_PUBLISHING_DESTINATION = "aws_guardduty_publishing_destination"
# One per Security Hub account-region posture — findings NEVER accessed.
AWS_SECURITYHUB_ACCOUNT = "aws_securityhub_account"
# One per Security Hub standard subscription — metadata only.
AWS_SECURITYHUB_STANDARD_SUBSCRIPTION = "aws_securityhub_standard_subscription"
# One per Security Hub finding aggregator — metadata only.
AWS_SECURITYHUB_FINDING_AGGREGATOR = "aws_securityhub_finding_aggregator"

# ── M46 record types — ECS/EKS/ECR Container Platform Config ─────────────────
# One per ECS cluster per region — posture metadata; task logs NEVER read.
AWS_ECS_CLUSTER = "aws_ecs_cluster"
# One per ECS service per cluster — posture metadata; env var values NEVER stored.
AWS_ECS_SERVICE = "aws_ecs_service"
# One per ECS task definition revision — container metadata; secrets/env values NEVER stored.
AWS_ECS_TASK_DEFINITION = "aws_ecs_task_definition"
# One per EKS cluster per region — posture metadata; Kubernetes API NEVER called.
AWS_EKS_CLUSTER = "aws_eks_cluster"
# One per EKS node group — scaling/security posture metadata.
AWS_EKS_NODE_GROUP = "aws_eks_node_group"
# One per EKS Fargate profile — selector/role metadata.
AWS_EKS_FARGATE_PROFILE = "aws_eks_fargate_profile"
# One per EKS add-on — version/status metadata.
AWS_EKS_ADDON = "aws_eks_addon"
# One per ECR repository per region — policy/scan/encryption metadata; images NEVER pulled.
AWS_ECR_REPOSITORY = "aws_ecr_repository"
# One per ECR registry scanning configuration per region.
AWS_ECR_REGISTRY_SCANNING_CONFIG = "aws_ecr_registry_scanning_config"

# ── M47 record types — EventBridge + SQS/SNS Messaging Config ────────────────
# One per EventBridge event bus per region — policy/posture; event payloads NEVER read.
AWS_EVENTBRIDGE_EVENT_BUS = "aws_eventbridge_event_bus"
# One per EventBridge rule per bus per region — schedule/pattern/target metadata; events NEVER read.
AWS_EVENTBRIDGE_RULE = "aws_eventbridge_rule"
# One per EventBridge target per rule per bus per region — routing metadata; event payloads NEVER read.
AWS_EVENTBRIDGE_TARGET = "aws_eventbridge_target"
# One per EventBridge archive per region — retention/state metadata; archived events NEVER read.
AWS_EVENTBRIDGE_ARCHIVE = "aws_eventbridge_archive"
# One per SQS queue per region — config/policy metadata; messages NEVER read.
AWS_SQS_QUEUE = "aws_sqs_queue"
# One per SNS topic per region — config/policy/subscription posture; notifications NEVER read.
AWS_SNS_TOPIC = "aws_sns_topic"
# One per SNS subscription per topic per region — protocol/filter metadata; endpoints hashed only.
AWS_SNS_SUBSCRIPTION = "aws_sns_subscription"

# ── M48 record types — KMS + Backup + Organizations/SCPs ────────────────────
# One per KMS key per region — config/policy posture; cryptographic ops NEVER called.
AWS_KMS_KEY = "aws_kms_key"
# One per KMS alias per region — alias name/target mapping; key material NEVER accessed.
AWS_KMS_ALIAS = "aws_kms_alias"
# One per AWS Backup vault per region — lock/encryption posture; backup contents NEVER read.
AWS_BACKUP_VAULT = "aws_backup_vault"
# One per AWS Backup plan per region — rule/schedule/lifecycle posture; backup jobs NEVER started.
AWS_BACKUP_PLAN = "aws_backup_plan"
# One per AWS Backup selection per plan — resource coverage posture; protected data NEVER accessed.
AWS_BACKUP_SELECTION = "aws_backup_selection"
# One per AWS Backup recovery point per vault — metadata only; backup contents NEVER read or restored.
AWS_BACKUP_RECOVERY_POINT = "aws_backup_recovery_point"
# One per AWS Organization — feature/policy type posture; org not mutated.
AWS_ORGANIZATIONS_ORGANIZATION = "aws_organizations_organization"
# One per AWS Organizations member account — status/membership posture; account not mutated.
AWS_ORGANIZATIONS_ACCOUNT = "aws_organizations_account"
# One per Organizational Unit — structure/SCP attachment posture; OU not mutated.
AWS_ORGANIZATIONS_OU = "aws_organizations_ou"
# One per Service Control Policy — deny/allow structure posture; SCP not mutated.
AWS_ORGANIZATIONS_SCP = "aws_organizations_scp"
# One per SCP-to-target attachment — attachment posture; attachments not mutated.
AWS_ORGANIZATIONS_SCP_ATTACHMENT = "aws_organizations_scp_attachment"

# ── M49 record types — CloudWatch Alarms + Observability Config ──────────────
# One per CloudWatch metric alarm per region — config/threshold posture; metric datapoints NEVER read.
AWS_CLOUDWATCH_METRIC_ALARM = "aws_cloudwatch_metric_alarm"
# One per CloudWatch composite alarm per region — rule/action posture; evaluation state NEVER read.
AWS_CLOUDWATCH_COMPOSITE_ALARM = "aws_cloudwatch_composite_alarm"
# One per CloudWatch dashboard per region — widget count + body hash; dashboard body NEVER stored.
AWS_CLOUDWATCH_DASHBOARD = "aws_cloudwatch_dashboard"
# One per CloudWatch Logs log group per region — retention/encryption posture; log events NEVER read.
AWS_CLOUDWATCH_LOG_GROUP = "aws_cloudwatch_log_group"
# One per CloudWatch Logs metric filter per log group — pattern hash/counts; raw patterns NEVER stored.
AWS_CLOUDWATCH_METRIC_FILTER = "aws_cloudwatch_metric_filter"
# One per CloudWatch Logs subscription filter per log group — destination type/posture; log events NEVER read.
AWS_CLOUDWATCH_SUBSCRIPTION_FILTER = "aws_cloudwatch_subscription_filter"
# One per CloudWatch metric stream per region — filter/destination posture; metric datapoints NEVER read.
AWS_CLOUDWATCH_METRIC_STREAM = "aws_cloudwatch_metric_stream"
# One per CloudWatch anomaly detector per namespace/metric — config posture; anomaly results NEVER read.
AWS_CLOUDWATCH_ANOMALY_DETECTOR = "aws_cloudwatch_anomaly_detector"

# ── M59.9 — AWS Part 2 expansion: governance / identity / supply-chain ───────
# One per AWS Config configuration recorder per region.  Metadata only —
# we never store recorded configuration history items.
AWS_CONFIG_RECORDER = "aws_config_recorder"

# One per AWS Config delivery channel per region.  Metadata only.
AWS_CONFIG_DELIVERY_CHANNEL = "aws_config_delivery_channel"

# One per IAM Access Analyzer.  Metadata only.
AWS_ACCESS_ANALYZER = "aws_access_analyzer"

# One per IAM Access Analyzer finding.  Stores the resource ARN HASH plus
# severity/status/finding-type.  Raw policy statements are NEVER persisted.
AWS_ACCESS_ANALYZER_FINDING = "aws_access_analyzer_finding"

# One per Security Hub finding.  Stores severity/standard/status/finding-type
# only — Investigator field bodies are NEVER persisted, and resource ARNs
# are HASHED to avoid leaking customer infrastructure paths.
AWS_SECURITYHUB_FINDING = "aws_securityhub_finding"

# One per ACM certificate.  Metadata only — private-key material is NEVER
# accessible from the ACM API and is therefore impossible to leak here.
AWS_ACM_CERTIFICATE = "aws_acm_certificate"


# ── M59.8 — AWS Part 1 expansion: EC2 exposure + VPC Flow Logs ────────────────
# One per EC2 instance — metadata only; no instance memory, EBS, or userdata.
# SECURITY: tags + metadata-options + network-interface summary only.  We
# never store user-data, EBS contents, or IAM-instance-profile credentials.
AWS_EC2_INSTANCE = "aws_ec2_instance"

# One per VPC Flow Log configuration — metadata only.  We never store
# captured flow-log records (which contain IP traffic data).
AWS_VPC_FLOW_LOG = "aws_vpc_flow_log"


# ── M44 record types — Load Balancers + WAF Config ───────────────────────────
# One per ELBv2 load balancer (Application, Network, Gateway) — metadata only.
AWS_ELBV2_LOAD_BALANCER = "aws_elbv2_load_balancer"
# One per ELBv2 target group — metadata only; no target contents.
AWS_ELBV2_TARGET_GROUP = "aws_elbv2_target_group"
# One per ELBv2 listener — metadata only; no request/response traffic.
AWS_ELBV2_LISTENER = "aws_elbv2_listener"
# One per ELBv2 listener rule — metadata only; no rule-matched traffic.
AWS_ELBV2_LISTENER_RULE = "aws_elbv2_listener_rule"
# One per Classic (v1) ELB — metadata only; no access log objects.
AWS_ELB_CLASSIC_LOAD_BALANCER = "aws_elb_classic_load_balancer"
# One per WAFv2 Web ACL — metadata only; sampled requests NEVER accessed.
AWS_WAFV2_WEB_ACL = "aws_wafv2_web_acl"
# One per WAFv2 Web ACL association — maps Web ACL to a protected resource.
AWS_WAFV2_WEB_ACL_ASSOCIATION = "aws_wafv2_web_acl_association"

# ── M43 record types — Lambda + API Gateway Runtime/API Config ───────────────
# One per Lambda function — metadata only; function code is NEVER accessed.
AWS_LAMBDA_FUNCTION = "aws_lambda_function"
# One per Lambda alias — routing/traffic split metadata.
AWS_LAMBDA_ALIAS = "aws_lambda_alias"
# One per Lambda event source mapping — trigger/stream metadata.
AWS_LAMBDA_EVENT_SOURCE_MAPPING = "aws_lambda_event_source_mapping"
# One per Lambda function URL — public endpoint auth/CORS metadata.
AWS_LAMBDA_FUNCTION_URL = "aws_lambda_function_url"
# One per API Gateway REST API — metadata; no request/response bodies or logs.
AWS_APIGATEWAY_REST_API = "aws_apigateway_rest_api"
# One per API Gateway REST API stage — deployment/logging/throttling metadata.
AWS_APIGATEWAY_REST_STAGE = "aws_apigateway_rest_stage"
# One per API Gateway V2 (HTTP/WebSocket) API — metadata only.
AWS_APIGATEWAYV2_API = "aws_apigatewayv2_api"
# One per API Gateway V2 stage — deployment/logging/routing metadata.
AWS_APIGATEWAYV2_STAGE = "aws_apigatewayv2_stage"

AWS_RECORD_TYPES: frozenset[str] = frozenset({
    AWS_ACCOUNT_IDENTITY,
    AWS_REGION,
    AWS_SERVICE_INVENTORY,
    # M37
    AWS_S3_BUCKET,
    # M38
    AWS_SECURITY_GROUP,
    AWS_SECURITY_GROUP_RULE,
    AWS_VPC,
    AWS_SUBNET,
    AWS_ROUTE_TABLE,
    AWS_INTERNET_GATEWAY,
    AWS_NETWORK_ACL,
    # M39
    AWS_IAM_ACCOUNT_SUMMARY,
    AWS_IAM_USER,
    AWS_IAM_ACCESS_KEY,
    AWS_IAM_GROUP,
    AWS_IAM_ROLE,
    AWS_IAM_POLICY,
    AWS_IAM_POLICY_ATTACHMENT,
    AWS_IAM_INLINE_POLICY,
    AWS_IAM_IDENTITY_PROVIDER,
    # M40
    AWS_ROUTE53_HOSTED_ZONE,
    AWS_ROUTE53_RECORD,
    AWS_CLOUDFRONT_DISTRIBUTION,
    # M41
    AWS_SECRETSMANAGER_SECRET,
    AWS_SSM_PARAMETER,
    # M42
    AWS_RDS_DB_INSTANCE,
    AWS_RDS_DB_CLUSTER,
    AWS_RDS_DB_SUBNET_GROUP,
    AWS_RDS_DB_SNAPSHOT,
    AWS_RDS_DB_CLUSTER_SNAPSHOT,
    # M43
    AWS_LAMBDA_FUNCTION,
    AWS_LAMBDA_ALIAS,
    AWS_LAMBDA_EVENT_SOURCE_MAPPING,
    AWS_LAMBDA_FUNCTION_URL,
    AWS_APIGATEWAY_REST_API,
    AWS_APIGATEWAY_REST_STAGE,
    AWS_APIGATEWAYV2_API,
    AWS_APIGATEWAYV2_STAGE,
    # M44
    AWS_ELBV2_LOAD_BALANCER,
    AWS_ELBV2_TARGET_GROUP,
    AWS_ELBV2_LISTENER,
    AWS_ELBV2_LISTENER_RULE,
    AWS_ELB_CLASSIC_LOAD_BALANCER,
    AWS_WAFV2_WEB_ACL,
    AWS_WAFV2_WEB_ACL_ASSOCIATION,
    # M45
    AWS_CLOUDTRAIL_TRAIL,
    AWS_CLOUDTRAIL_EVENT_DATA_STORE,
    AWS_GUARDDUTY_DETECTOR,
    AWS_GUARDDUTY_PUBLISHING_DESTINATION,
    AWS_SECURITYHUB_ACCOUNT,
    AWS_SECURITYHUB_STANDARD_SUBSCRIPTION,
    AWS_SECURITYHUB_FINDING_AGGREGATOR,
    # M46
    AWS_ECS_CLUSTER,
    AWS_ECS_SERVICE,
    AWS_ECS_TASK_DEFINITION,
    AWS_EKS_CLUSTER,
    AWS_EKS_NODE_GROUP,
    AWS_EKS_FARGATE_PROFILE,
    AWS_EKS_ADDON,
    AWS_ECR_REPOSITORY,
    AWS_ECR_REGISTRY_SCANNING_CONFIG,
    # M47
    AWS_EVENTBRIDGE_EVENT_BUS,
    AWS_EVENTBRIDGE_RULE,
    AWS_EVENTBRIDGE_TARGET,
    AWS_EVENTBRIDGE_ARCHIVE,
    AWS_SQS_QUEUE,
    AWS_SNS_TOPIC,
    AWS_SNS_SUBSCRIPTION,
    # M48
    AWS_KMS_KEY,
    AWS_KMS_ALIAS,
    AWS_BACKUP_VAULT,
    AWS_BACKUP_PLAN,
    AWS_BACKUP_SELECTION,
    AWS_BACKUP_RECOVERY_POINT,
    AWS_ORGANIZATIONS_ORGANIZATION,
    AWS_ORGANIZATIONS_ACCOUNT,
    AWS_ORGANIZATIONS_OU,
    AWS_ORGANIZATIONS_SCP,
    AWS_ORGANIZATIONS_SCP_ATTACHMENT,
    # M49
    AWS_CLOUDWATCH_METRIC_ALARM,
    AWS_CLOUDWATCH_COMPOSITE_ALARM,
    AWS_CLOUDWATCH_DASHBOARD,
    AWS_CLOUDWATCH_LOG_GROUP,
    AWS_CLOUDWATCH_METRIC_FILTER,
    AWS_CLOUDWATCH_SUBSCRIPTION_FILTER,
    AWS_CLOUDWATCH_METRIC_STREAM,
    AWS_CLOUDWATCH_ANOMALY_DETECTOR,
    # M59.8 — Part 1 expansion
    AWS_EC2_INSTANCE,
    AWS_VPC_FLOW_LOG,
    # M59.9 — Part 2 expansion
    AWS_CONFIG_RECORDER,
    AWS_CONFIG_DELIVERY_CHANNEL,
    AWS_ACCESS_ANALYZER,
    AWS_ACCESS_ANALYZER_FINDING,
    AWS_SECURITYHUB_FINDING,
    AWS_ACM_CERTIFICATE,
})
