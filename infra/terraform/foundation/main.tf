# Storage has a separate state, so compute teardown never deletes recordings.
data "aws_s3_bucket" "recordings" {
  bucket = coalesce(var.recordings_bucket_name, "${var.project_name}-recordings-${local.account}-${var.region}")
}

resource "aws_iam_role" "code_interpreter" {
  name = "${var.project_name}-code-interpreter-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRole",
      Principal = { Service = "bedrock-agentcore.amazonaws.com" },
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account },
        ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:bedrock-agentcore:${var.region}:${local.account}:*" }
      }
    }]
  })
}
resource "aws_iam_role_policy" "code_interpreter" {
  name = "recordings"
  role = aws_iam_role.code_interpreter.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      {
        Effect    = "Allow", Action = ["s3:ListBucket"], Resource = data.aws_s3_bucket.recordings.arn,
        Condition = { StringLike = { "s3:prefix" = ["${var.recordings_prefix}/*"] } }
      },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${data.aws_s3_bucket.recordings.arn}/${var.recordings_prefix}/*" }
    ]
  })
}
resource "aws_bedrockagentcore_code_interpreter" "main" {
  name               = "${replace(var.project_name, "-", "_")}_public"
  execution_role_arn = aws_iam_role.code_interpreter.arn
  network_configuration { network_mode = "PUBLIC" }
  depends_on = [aws_iam_role_policy.code_interpreter]
}
resource "aws_ecr_repository" "images" {
  for_each             = toset(["device-agent", "android-builder", "android-emulator"])
  name                 = "${var.project_name}-${each.key}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true
  image_scanning_configuration { scan_on_push = true }
}
resource "aws_iam_policy" "operator" {
  name = "${var.project_name}-operator"
  policy = jsonencode({
    Version = "2012-10-17", Statement = concat([
      {
        Sid = "Sandbox", Effect = "Allow",
        Action = [
          "bedrock-agentcore:StartCodeInterpreterSession", "bedrock-agentcore:StopCodeInterpreterSession",
          "bedrock-agentcore:InvokeCodeInterpreter", "bedrock-agentcore:GetCodeInterpreterSession",
          "bedrock-agentcore:ListCodeInterpreterSessions", "bedrock-agentcore:GetCodeInterpreter"
        ], Resource = aws_bedrockagentcore_code_interpreter.main.code_interpreter_arn
      },
      {
        Sid    = "Models", Effect = "Allow",
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        Resource = flatten([for m in var.bedrock_model_ids : [
          "arn:${local.partition}:bedrock:*::foundation-model/${m}",
          "arn:${local.partition}:bedrock:*:${local.account}:inference-profile/${m}",
        ]])
      },
      {
        Effect    = "Allow", Action = ["s3:ListBucket"], Resource = data.aws_s3_bucket.recordings.arn,
        Condition = { StringLike = { "s3:prefix" = ["${var.recordings_prefix}/*"] } }
      },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "${data.aws_s3_bucket.recordings.arn}/${var.recordings_prefix}/*" },
      { Effect = "Allow", Action = ["eks:DescribeCluster"], Resource = aws_eks_cluster.main.arn }
      ], var.enable_optional_evaluation_permissions ? [
      {
        Sid = "OptionalMemoryAndEvaluation", Effect = "Allow",
        Action = ["bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents", "bedrock-agentcore:RetrieveMemoryRecords",
        "bedrock-agentcore:Evaluate", "bedrock-agentcore:GetEvaluator", "bedrock-agentcore:ListEvaluators"],
        Resource = "*"
      },
      {
        Sid      = "OptionalTraceQuery", Effect = "Allow", Action = ["logs:StartQuery", "logs:GetQueryResults"],
        Resource = "${aws_cloudwatch_log_group.cluster.arn}:*"
      }
    ] : [])
  })
}

# The live demo uses this role, rather than deployment administrator credentials.
# Trust is limited to the explicitly configured deployment principal.
resource "aws_iam_role" "operator" {
  name                 = "${var.project_name}-session-operator"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRole",
      Principal = { AWS = var.cluster_admin_role_arn }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "operator" {
  role       = aws_iam_role.operator.name
  policy_arn = aws_iam_policy.operator.arn
}
resource "aws_eks_access_entry" "session_operator" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.operator.arn
  kubernetes_groups = ["cwe-operators"]
  type              = "STANDARD"
}
