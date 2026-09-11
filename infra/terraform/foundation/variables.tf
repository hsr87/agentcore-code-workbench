variable "region" {
  type    = string
  default = "us-east-1"
}
variable "project_name" {
  type    = string
  default = "cwe-eks"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.project_name))
    error_message = "Use 2..21 lowercase letters, digits or hyphens, starting with a letter."
  }
}
variable "vpc_id" { type = string }
variable "subnet_ids" {
  description = "At least two AZs. Private subnets need NAT; public subnets need map_public_ip_on_launch for node egress."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "EKS requires subnets in at least two AZs."
  }
}
variable "cluster_version" {
  description = "Choose a Kubernetes version currently supported by EKS in your region."
  type        = string
}
variable "cluster_admin_role_arn" {
  description = "IAM role ARN (not an STS session ARN) used to install the platform Terraform stack."
  type        = string
}
variable "operator_role_arns" {
  description = "IAM roles allowed to manage sessions only in the lab namespace."
  type        = set(string)
  default     = []
}
variable "endpoint_public_access" {
  type    = bool
  default = false
}
variable "endpoint_public_access_cidrs" {
  type    = list(string)
  default = []
  validation {
    condition     = alltrue([for c in var.endpoint_public_access_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"])
    error_message = "Use fixed IPv4 office/VPN CIDRs; 0.0.0.0/0 is not allowed."
  }
}
variable "android_instance_type" {
  type    = string
  default = "m8i.2xlarge"
  validation {
    condition     = can(regex("^(c8i|m8i|r8i)\\.", var.android_instance_type))
    error_message = "Use a nested-virtualization-capable c8i, m8i or r8i instance."
  }
}
variable "android_desired_size" {
  type    = number
  default = 1
}
variable "android_max_size" {
  type    = number
  default = 4
}
variable "recordings_bucket_name" {
  description = "Override when importing the retained CloudFormation bucket."
  type        = string
  default     = null
}
variable "recordings_prefix" {
  description = "Key prefix inside the recordings bucket. Sandbox and operator access is confined to it."
  type        = string
  default     = "cwe"
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", var.recordings_prefix))
    error_message = "recordings_prefix must be a single path segment."
  }
}
variable "bedrock_model_ids" {
  description = "Models the operator role may invoke. Narrower than a wildcard over every Bedrock model."
  type        = list(string)
  default     = ["anthropic.claude-opus-5*", "us.anthropic.claude-opus-5*"]
}
variable "enable_optional_evaluation_permissions" {
  description = "Opt in to Memory/Evaluations and CloudWatch query permissions; disabled for the Android demo."
  type        = bool
  default     = false
}
