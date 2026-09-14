# Optional private network for the Runtime when the EKS VPC only has public subnets (a default VPC, a lab).
# Runtime ENIs never receive a public IP, so they need private subnets whose default route is a NAT gateway.
# Leave `private_subnets` empty and pass existing private subnets through `subnet_ids` in a real VPC.
variable "private_subnets" {
  description = "New private subnets to create for the Runtime, keyed by a stable name. CIDRs must be free in the VPC."
  type        = map(object({ cidr = string, availability_zone = string }))
  default     = {}
  validation {
    condition     = length(var.private_subnets) == 0 || length(var.private_subnets) >= 2
    error_message = "Create at least two private subnets (two AZs) or none."
  }
}
variable "nat_public_subnet_id" {
  description = "Existing public subnet that hosts the single NAT gateway for private_subnets."
  type        = string
  default     = null
}
variable "private_access" {
  description = "How the Runtime reaches AWS from its private subnets: nat (one NAT gateway, needs an Elastic IP) or endpoints (PrivateLink for Bedrock, AgentCore, STS, KMS, Logs, X-Ray plus S3 and DynamoDB gateway endpoints; no internet path at all)."
  type        = string
  default     = "nat"
  validation {
    condition     = contains(["nat", "endpoints"], var.private_access)
    error_message = "private_access must be nat or endpoints."
  }
}
variable "nat_eip_allocation_id" {
  description = "Reuse an existing, unassociated Elastic IP for the NAT gateway instead of allocating one (accounts at the EIP quota)."
  type        = string
  default     = null
}

locals {
  create_network     = length(var.private_subnets) > 0
  use_nat            = local.create_network && var.private_access == "nat"
  use_endpoints      = local.create_network && var.private_access == "endpoints"
  runtime_subnet_ids = local.create_network ? [for s in aws_subnet.runtime : s.id] : var.subnet_ids
  # Everything the Runtime talks to: models, Code Interpreter, EKS control plane (DescribeCluster) and token signing,
  # registry key, telemetry, and ECR (the
  # image is pulled through the VPC ENI in VPC mode; layers come from S3 via the gateway endpoint).
  interface_endpoints = ["bedrock-runtime", "bedrock-agentcore", "sts", "kms", "logs", "xray", "ecr.api", "ecr.dkr", "eks"]
}

resource "aws_subnet" "runtime" {
  for_each                = var.private_subnets
  vpc_id                  = var.vpc_id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.availability_zone
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.project_name}-runtime-${each.key}" }
}
data "aws_subnet" "nat_public" {
  count = local.use_nat ? 1 : 0
  id    = var.nat_public_subnet_id
}
resource "aws_eip" "nat" {
  count  = local.use_nat && var.nat_eip_allocation_id == null ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.project_name}-runtime-nat" }
}
resource "aws_nat_gateway" "runtime" {
  count         = local.use_nat ? 1 : 0
  allocation_id = var.nat_eip_allocation_id != null ? var.nat_eip_allocation_id : aws_eip.nat[0].id
  subnet_id     = var.nat_public_subnet_id
  tags          = { Name = "${var.project_name}-runtime" }
  lifecycle {
    precondition {
      condition     = data.aws_subnet.nat_public[0].vpc_id == var.vpc_id
      error_message = "nat_public_subnet_id must belong to vpc_id."
    }
  }
}
resource "aws_route_table" "runtime" {
  count  = local.create_network ? 1 : 0
  vpc_id = var.vpc_id
  dynamic "route" {
    for_each = local.use_nat ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.runtime[0].id
    }
  }
  tags = { Name = "${var.project_name}-runtime-private" }
}
resource "aws_route_table_association" "runtime" {
  for_each       = var.private_subnets
  subnet_id      = aws_subnet.runtime[each.key].id
  route_table_id = aws_route_table.runtime[0].id
}

# PrivateLink alternative to NAT: the Runtime subnets have no route to the internet at all.
resource "aws_security_group" "endpoints" {
  count       = local.use_endpoints ? 1 : 0
  name        = "${var.project_name}-runtime-endpoints"
  description = "PrivateLink endpoints used by the AgentCore Runtime"
  vpc_id      = var.vpc_id
}
resource "aws_vpc_security_group_ingress_rule" "endpoints_from_runtime" {
  count                        = local.use_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.runtime.id
}
resource "aws_vpc_endpoint" "interface" {
  for_each            = local.use_endpoints ? toset(local.interface_endpoints) : toset([])
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.runtime_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = { Name = "${var.project_name}-runtime-${each.value}" }
}
resource "aws_vpc_endpoint" "gateway" {
  for_each          = local.use_endpoints ? toset(["s3", "dynamodb"]) : toset([])
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.runtime[0].id]
  tags              = { Name = "${var.project_name}-runtime-${each.value}" }
}
