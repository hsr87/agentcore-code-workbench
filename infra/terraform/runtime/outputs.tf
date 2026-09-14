output "agent_runtime_arn" { value = aws_bedrockagentcore_agent_runtime.main.agent_runtime_arn }
output "agent_runtime_id" { value = aws_bedrockagentcore_agent_runtime.main.agent_runtime_id }
output "runtime_role_arn" { value = aws_iam_role.runtime.arn }
output "runtime_security_group_id" { value = aws_security_group.runtime.id }
output "session_table" { value = aws_dynamodb_table.sessions.name }
output "registry_kms_key_arn" { value = aws_kms_key.registry.arn }
# Copy into the platform root's orchestrator_cidrs so the network policy admits the Runtime.
output "runtime_subnet_cidrs" {
  value = local.create_network ? [for s in aws_subnet.runtime : s.cidr_block] : [for s in data.aws_subnet.runtime_existing : s.cidr_block]
}
output "runtime_subnet_ids" { value = local.runtime_subnet_ids }
