# AgentCore Runtime in VPC mode, wired to the EKS lab:
#   Runtime ENI (this SG) --8080--> session Pods (cluster SG rule + platform network policy ipBlock)
#   Runtime execution role  --> operator policy (Code Interpreter, Bedrock, recordings), EKS access entry,
#                               session registry table, KMS key that seals Pod tokens in the registry.
data "aws_eks_cluster" "main" { name = var.cluster_name }
data "aws_vpc" "main" { id = var.vpc_id }
data "aws_subnet" "runtime_existing" {
  for_each = local.create_network ? toset([]) : toset(var.subnet_ids)
  id       = each.value
}

resource "aws_security_group" "runtime" {
  name        = "${var.project_name}-runtime"
  description = "AgentCore Runtime ENIs: HTTPS out, Pod port 8080 inside the VPC"
  vpc_id      = var.vpc_id
  lifecycle {
    precondition {
      condition     = alltrue([for s in data.aws_subnet.runtime_existing : s.vpc_id == var.vpc_id])
      error_message = "All runtime subnets must belong to vpc_id."
    }
  }
}
resource "aws_vpc_security_group_egress_rule" "runtime_https" {
  security_group_id = aws_security_group.runtime.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Bedrock, S3, STS, ECR, EKS API"
}
resource "aws_vpc_security_group_egress_rule" "runtime_pods" {
  security_group_id = aws_security_group.runtime.id
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = data.aws_vpc.main.cidr_block
  description       = "device and workload agents in session Pods"
}
resource "aws_vpc_security_group_egress_rule" "runtime_dns" {
  security_group_id = aws_security_group.runtime.id
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = data.aws_vpc.main.cidr_block
  description       = "VPC resolver"
}
# The EKS private endpoint ENIs carry the cluster security group too: admit the Runtime on the API port.
resource "aws_vpc_security_group_ingress_rule" "eks_api_from_runtime" {
  security_group_id            = data.aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.runtime.id
  description                  = "${var.project_name} AgentCore Runtime to the Kubernetes API"
}
# Pods carry the cluster security group; admit the Runtime on the agent port only.
resource "aws_vpc_security_group_ingress_rule" "pods_from_runtime" {
  security_group_id            = data.aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.runtime.id
  description                  = "${var.project_name} AgentCore Runtime to session Pods"
}

# Session registry: runtimeSessionId -> sandbox session, Pod, token. Tokens are sealed with this key by the
# application (encryption context = runtime session id), and the table itself is encrypted with it at rest.
resource "aws_kms_key" "registry" {
  description             = "${var.project_name} session registry"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_kms_alias" "registry" {
  name          = "alias/${var.project_name}-session-registry"
  target_key_id = aws_kms_key.registry.key_id
}
resource "aws_dynamodb_table" "sessions" {
  name         = "${var.project_name}-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "runtime_session_id"
  attribute {
    name = "runtime_session_id"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.registry.arn
  }
  point_in_time_recovery { enabled = false }
}

resource "aws_iam_role" "runtime" {
  name = "${var.project_name}-runtime"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AssumeRolePolicy", Effect = "Allow", Action = "sts:AssumeRole",
      Principal = { Service = "bedrock-agentcore.amazonaws.com" },
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account },
        ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:bedrock-agentcore:${var.region}:${local.account}:*" }
      }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "runtime_operator" {
  role       = aws_iam_role.runtime.name
  policy_arn = var.operator_policy_arn
}
# The documented Runtime execution-role permissions plus the registry. ENIs for VPC mode are created through
# the service-linked role AWSServiceRoleForBedrockAgentCoreNetwork, not this role.
resource "aws_iam_role_policy" "runtime" {
  name = "runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      { Sid = "ECRImageAccess", Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
      Resource = "arn:${local.partition}:ecr:${var.region}:${local.account}:repository/${var.project_name}-runtime" },
      { Sid = "ECRTokenAccess", Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["logs:DescribeLogStreams", "logs:CreateLogGroup"],
      Resource = "arn:${local.partition}:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*" },
      { Effect = "Allow", Action = ["logs:PutResourcePolicy"],
      Resource = "arn:${local.partition}:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/${local.runtime_name}-*" },
      { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = "arn:${local.partition}:logs:${var.region}:${local.account}:log-group:*" },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = "arn:${local.partition}:logs:${var.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*" },
      { Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"], Resource = "*" },
      { Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*", Condition = { StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" } } },
      { Sid    = "GetAgentAccessToken", Effect = "Allow",
        Action = ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
        Resource = [
          "arn:${local.partition}:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default",
          "arn:${local.partition}:bedrock-agentcore:${var.region}:${local.account}:workload-identity-directory/default/workload-identity/${local.runtime_name}-*"
      ] },
      { Sid    = "SessionRegistry", Effect = "Allow",
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"],
      Resource = aws_dynamodb_table.sessions.arn },
      { Sid = "RegistryKey", Effect = "Allow", Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
      Resource = aws_kms_key.registry.arn }
    ]
  })
}
# The Runtime runs sessions with the same namespace RBAC as a human operator.
resource "aws_eks_access_entry" "runtime" {
  cluster_name      = var.cluster_name
  principal_arn     = aws_iam_role.runtime.arn
  kubernetes_groups = ["cwe-operators"]
  type              = "STANDARD"
}

resource "aws_bedrockagentcore_agent_runtime" "main" {
  agent_runtime_name = "${local.runtime_name}_runtime"
  description        = "${var.project_name}: coding agent on Code Interpreter with EKS build/run Pods"
  role_arn           = aws_iam_role.runtime.arn
  agent_runtime_artifact {
    container_configuration { container_uri = var.runtime_image }
  }
  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      security_groups = [aws_security_group.runtime.id]
      subnets         = local.runtime_subnet_ids
    }
  }
  protocol_configuration { server_protocol = "HTTP" }
  lifecycle_configuration {
    idle_runtime_session_timeout = var.idle_runtime_session_timeout
    max_lifetime                 = var.max_lifetime
  }
  environment_variables = merge({
    AWS_REGION                       = var.region
    CWE_PROJECT_NAME                 = var.project_name
    CWE_CODE_INTERPRETER_ID          = var.code_interpreter_id
    CWE_STORAGE_URI                  = "s3://${var.recordings_bucket}/${var.recordings_prefix}"
    CWE_SESSION_TIMEOUT_SECONDS      = tostring(max(var.idle_runtime_session_timeout, 1800))
    CWE_ANDROID_BACKEND              = "eks"
    CWE_EKS_CLUSTER_NAME             = var.cluster_name
    CWE_EKS_NAMESPACE                = var.eks_namespace
    CWE_EKS_ACCESS                   = "pod"
    CWE_EKS_KUBECONFIG               = "/home/app/.kube/cwe.yaml"
    CWE_WORKLOAD_IMAGE               = var.workload_image
    CWE_SESSION_TABLE                = aws_dynamodb_table.sessions.name
    CWE_REGISTRY_KMS_KEY_ID          = aws_kms_key.registry.arn
    CWE_SESSION_REGISTRY_TTL_SECONDS = tostring(var.session_registry_ttl_seconds)
  }, var.runtime_environment)
  depends_on = [aws_iam_role_policy.runtime, aws_iam_role_policy_attachment.runtime_operator, aws_eks_access_entry.runtime,
  aws_route_table_association.runtime, aws_vpc_endpoint.interface, aws_vpc_endpoint.gateway]
}
