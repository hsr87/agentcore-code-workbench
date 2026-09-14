variable "region" {
  type    = string
  default = "us-east-1"
}
variable "project_name" {
  description = "Same value as the foundation root."
  type        = string
  default     = "cwe-eks"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.project_name))
    error_message = "Use 2..21 lowercase letters, digits or hyphens, starting with a letter."
  }
}
variable "runtime_image" {
  description = "ECR image of runtime/Dockerfile (linux/arm64) with an immutable tag, e.g. <acct>.dkr.ecr.<region>.amazonaws.com/cwe-eks-runtime:v1."
  type        = string
  validation {
    condition     = can(regex("\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._/-]+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", var.runtime_image)) && !can(regex(":latest$", var.runtime_image))
    error_message = "runtime_image must be an ECR image reference with an explicit, non-latest tag."
  }
}
variable "cluster_name" {
  description = "foundation output cluster_name."
  type        = string
}
variable "vpc_id" {
  description = "VPC of the EKS cluster. The Runtime's ENIs are placed here so it can reach Pod IPs directly."
  type        = string
}
variable "subnet_ids" {
  description = "Existing private subnets (with NAT) for the Runtime ENIs: the Runtime needs Bedrock, S3, STS, ECR and the EKS API. At least two AZs. Ignored when private_subnets creates them."
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.subnet_ids) == 0 || length(var.subnet_ids) >= 2
    error_message = "Use subnets in at least two AZs."
  }
}
variable "code_interpreter_id" {
  description = "foundation output code_interpreter_id."
  type        = string
}
variable "recordings_bucket" {
  description = "foundation output recordings_bucket."
  type        = string
}
variable "recordings_prefix" {
  type    = string
  default = "cwe"
}
variable "operator_policy_arn" {
  description = "foundation output operator_policy_arn: Code Interpreter, Bedrock, recordings prefix and eks:DescribeCluster."
  type        = string
}
variable "workload_image" {
  description = "Default toolchain image for WorkloadProfile (device_agent/Dockerfile.workload), immutable tag."
  type        = string
  default     = ""
}
variable "eks_namespace" {
  type    = string
  default = "cwe"
}
variable "idle_runtime_session_timeout" {
  description = "Seconds a runtime session may sit idle before its microVM is released. Keep it at or below CWE_SESSION_TIMEOUT_SECONDS so the sandbox outlives the microVM."
  type        = number
  default     = 1800
}
variable "max_lifetime" {
  description = "Maximum microVM lifetime in seconds (service maximum 28800). WorkloadProfile.job_timeout_seconds should exceed it; the registry carries the Pod across."
  type        = number
  default     = 28800
}
variable "runtime_environment" {
  description = "Extra environment variables for the Runtime container (CWE_AGENT_MODEL, CWE_JUDGE_MODEL, ...). Never put secrets here."
  type        = map(string)
  default     = {}
}
variable "session_registry_ttl_seconds" {
  type    = number
  default = 86400
}
