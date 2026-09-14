resource "aws_iam_role" "cluster" {
  name = "${local.name}-cluster"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "eks.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${local.name}/cluster"
  retention_in_days = 30
}
# Per-device authentication tokens live in Kubernetes Secrets, so encrypt etcd with a key this
# account controls: revoking the key revokes the Secrets, and every use is visible in CloudTrail.
resource "aws_kms_key" "secrets" {
  description             = "${local.name} EKS secret envelope encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-eks-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}
resource "aws_eks_cluster" "main" {
  name                      = local.name
  role_arn                  = aws_iam_role.cluster.arn
  version                   = var.cluster_version
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  encryption_config {
    provider { key_arn = aws_kms_key.secrets.arn }
    resources = ["secrets"]
  }
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access
    public_access_cidrs     = var.endpoint_public_access ? var.endpoint_public_access_cidrs : null
  }
  lifecycle {
    precondition {
      condition     = !var.endpoint_public_access || length(var.endpoint_public_access_cidrs) > 0
      error_message = "Public endpoint access requires fixed allowed CIDRs."
    }
    precondition {
      condition     = alltrue([for s in data.aws_subnet.nodes : s.vpc_id == var.vpc_id])
      error_message = "All node subnets must belong to vpc_id."
    }
  }
  depends_on = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.cluster]
}
data "aws_subnet" "nodes" {
  for_each = toset(var.subnet_ids)
  id       = each.value
}
resource "aws_eks_access_entry" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = var.cluster_admin_role_arn
  type          = "STANDARD"
}
resource "aws_eks_access_policy_association" "admin" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_eks_access_entry.admin.principal_arn
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}
resource "aws_eks_access_entry" "operator" {
  for_each          = setsubtract(var.operator_role_arns, toset([var.cluster_admin_role_arn, aws_iam_role.operator.arn]))
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = each.value
  kubernetes_groups = ["cwe-operators"]
  type              = "STANDARD"
}
resource "aws_iam_role" "node" {
  name = "${local.name}-node"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy_attachment" "node" {
  for_each   = toset(["AmazonEKSWorkerNodePolicy", "AmazonEC2ContainerRegistryPullOnly"])
  role       = aws_iam_role.node.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.value}"
}
# VPC CNI uses its own pod role. Emulator/build Pods have neither a service
# account token nor access to the node's instance credentials.
resource "aws_iam_openid_connect_provider" "cluster" {
  url            = aws_eks_cluster.main.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
}
locals {
  oidc_host = replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")
}
resource "aws_iam_role" "cni" {
  name = "${local.name}-cni"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity",
      Principal = { Federated = aws_iam_openid_connect_provider.cluster.arn },
      Condition = { StringEquals = {
        "${local.oidc_host}:sub" = "system:serviceaccount:kube-system:aws-node",
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
      } }
    }]
  })
}
resource "aws_iam_role_policy_attachment" "cni" {
  role       = aws_iam_role.cni.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}
resource "aws_eks_addon" "cni" {
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = "vpc-cni"
  service_account_role_arn    = aws_iam_role.cni.arn
  configuration_values        = jsonencode({ enableNetworkPolicy = "true", env = { NETWORK_POLICY_ENFORCING_MODE = "strict" } })
  resolve_conflicts_on_create = "OVERWRITE"
  depends_on                  = [aws_iam_role_policy_attachment.cni]
}
resource "aws_launch_template" "system" {
  name_prefix = "${local.name}-system-"
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 40
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
}
resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = ["m6i.large"]
  labels          = { "cwe/workload" = "system" }
  launch_template {
    id      = aws_launch_template.system.id
    version = aws_launch_template.system.latest_version
  }
  scaling_config {
    min_size     = 1
    desired_size = 1
    max_size     = 2
  }
  depends_on = [aws_iam_role_policy_attachment.node, aws_eks_addon.cni]
}
resource "aws_launch_template" "android" {
  name_prefix = "${local.name}-android-"
  cpu_options { nested_virtualization = "enabled" }
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 100
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  # EKS merges this MIME user data with its AL2023 nodeadm bootstrap.
  user_data = base64encode(<<-EOT
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="CWEBOUNDARY"

    --CWEBOUNDARY
    Content-Type: text/x-shellscript; charset="us-ascii"

    #!/bin/bash
    set -euo pipefail
    echo kvm_intel > /etc/modules-load.d/cwe-kvm.conf
    modprobe kvm_intel
    test -c /dev/kvm
    chmod 666 /dev/kvm
    --CWEBOUNDARY--
  EOT
  )
}
resource "aws_eks_node_group" "android" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "android"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.android_instance_type]
  labels          = { "cwe/workload" = "android" }
  taint {
    key    = "cwe/android"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
  launch_template {
    id      = aws_launch_template.android.id
    version = aws_launch_template.android.latest_version
  }
  scaling_config {
    min_size     = 0
    desired_size = var.android_desired_size
    max_size     = var.android_max_size
  }
  lifecycle {
    precondition {
      condition     = var.android_desired_size >= 0 && var.android_desired_size <= var.android_max_size
      error_message = "android_desired_size must be between zero and android_max_size."
    }
  }
  depends_on = [aws_iam_role_policy_attachment.node, aws_eks_addon.cni]
}
# Build/run workloads (WorkloadProfile) need memory and disk, not KVM, so they get their own node group on any
# instance family. Nothing else schedules here: the taint keeps system Pods and emulators off these nodes.
resource "aws_launch_template" "build" {
  name_prefix = "${local.name}-build-"
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.build_volume_size
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
}
resource "aws_eks_node_group" "build" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "build"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.build_instance_type]
  labels          = { "cwe/workload" = "build" }
  taint {
    key    = "cwe/build"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
  launch_template {
    id      = aws_launch_template.build.id
    version = aws_launch_template.build.latest_version
  }
  scaling_config {
    min_size     = 0
    desired_size = var.build_desired_size
    max_size     = var.build_max_size
  }
  lifecycle {
    precondition {
      condition     = var.build_desired_size >= 0 && var.build_desired_size <= var.build_max_size
      error_message = "build_desired_size must be between zero and build_max_size."
    }
  }
  depends_on = [aws_iam_role_policy_attachment.node, aws_eks_addon.cni]
}
resource "aws_eks_addon" "core" {
  for_each                    = toset(["coredns", "kube-proxy"])
  cluster_name                = aws_eks_cluster.main.name
  addon_name                  = each.key
  resolve_conflicts_on_create = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.system]
}
