output "cluster_name" { value = aws_eks_cluster.main.name }
output "cluster_arn" { value = aws_eks_cluster.main.arn }
output "cluster_endpoint" { value = aws_eks_cluster.main.endpoint }
output "cluster_certificate" { value = aws_eks_cluster.main.certificate_authority[0].data }
output "region" { value = var.region }
output "project_name" { value = var.project_name }
output "code_interpreter_id" { value = aws_bedrockagentcore_code_interpreter.main.code_interpreter_id }
output "recordings_bucket" { value = data.aws_s3_bucket.recordings.id }
output "operator_policy_arn" { value = aws_iam_policy.operator.arn }
output "operator_role_arn" { value = aws_iam_role.operator.arn }
output "repositories" { value = { for name, repo in aws_ecr_repository.images : name => repo.repository_url } }
output "android_node_group" { value = aws_eks_node_group.android.node_group_name }
output "build_node_group" { value = aws_eks_node_group.build.node_group_name }
output "cluster_security_group_id" { value = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id }
output "vpc_id" { value = var.vpc_id }
output "subnet_ids" { value = var.subnet_ids }
output "recordings_prefix" { value = var.recordings_prefix }
