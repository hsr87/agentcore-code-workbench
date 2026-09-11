terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
  }
}
variable "kube_context" { type = string }
variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}
variable "namespace" {
  type    = string
  default = "cwe"
}
variable "kvm_plugin_image" {
  description = "Reviewed generic-device-plugin image. This DaemonSet is privileged, so a mutable tag is refused."
  type        = string
  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.kvm_plugin_image)) || can(regex(":[A-Za-z0-9_][A-Za-z0-9_.-]*$", var.kvm_plugin_image))
    error_message = "kvm_plugin_image must carry an explicit tag or digest."
  }
  validation {
    condition     = !can(regex(":latest$", var.kvm_plugin_image))
    error_message = "kvm_plugin_image must not use the mutable :latest tag; pin a digest for a privileged workload."
  }
}
provider "kubernetes" {
  config_path    = pathexpand(var.kubeconfig_path)
  config_context = var.kube_context
}
resource "kubernetes_namespace_v1" "lab" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "cwe"
      # The emulator image can start as root, but cannot request privileged mode, host paths or host networking.
      # Pin the version so an upgrade cannot silently change what is enforced, and surface the stricter profile.
      "pod-security.kubernetes.io/enforce"         = "baseline"
      "pod-security.kubernetes.io/enforce-version" = "v1.31"
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/warn"            = "restricted"
    }
  }
}
resource "kubernetes_service_account_v1" "device" {
  metadata {
    name      = "cwe-device"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  automount_service_account_token = false
}
resource "kubernetes_role_v1" "operator" {
  metadata {
    name      = "cwe-operator"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  rule {
    api_groups = ["batch"]
    resources  = ["jobs"]
    verbs      = ["create", "get", "list", "watch", "delete"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["get", "list", "watch"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods/log"]
    verbs      = ["get"]
  }
  rule {
    api_groups = [""]
    resources  = ["pods/portforward"]
    verbs      = ["create", "get"]
  }
  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["create"]
  }
}
resource "kubernetes_role_binding_v1" "operator" {
  metadata {
    name      = "cwe-operator"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.operator.metadata[0].name
  }
  subject {
    kind      = "Group"
    name      = "cwe-operators"
    api_group = "rbac.authorization.k8s.io"
  }
}
resource "kubernetes_resource_quota_v1" "lab" {
  metadata {
    name      = "cwe-limits"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  spec {
    hard = { pods = "16", "count/jobs.batch" = "16", "count/secrets" = "32", "requests.cpu" = "80", "requests.memory" = "160Gi" }
  }
}
# Only the node-level device plugin is privileged. It advertises one KVM slot
# per node; session containers receive /dev/kvm via the device plugin API.
resource "kubernetes_daemon_set_v1" "kvm" {
  metadata {
    name      = "cwe-kvm"
    namespace = "kube-system"
  }
  spec {
    selector { match_labels = { app = "cwe-kvm" } }
    template {
      metadata { labels = { app = "cwe-kvm" } }
      spec {
        node_selector                   = { "cwe/workload" = "android" }
        automount_service_account_token = false
        toleration {
          key      = "cwe/android"
          operator = "Equal"
          value    = "true"
          effect   = "NoSchedule"
        }
        container {
          name  = "kvm"
          image = var.kvm_plugin_image
          args  = ["--device", jsonencode({ name = "kvm", groups = [{ count = 1, paths = [{ path = "/dev/kvm" }] }] })]
          security_context { privileged = true }
          resources {
            requests = { cpu = "50m", memory = "32Mi" }
            limits   = { cpu = "100m", memory = "64Mi" }
          }
          volume_mount {
            name       = "devices"
            mount_path = "/dev"
          }
          volume_mount {
            name       = "plugins"
            mount_path = "/var/lib/kubelet/device-plugins"
          }
        }
        volume {
          name = "devices"
          host_path { path = "/dev" }
        }
        volume {
          name = "plugins"
          host_path { path = "/var/lib/kubelet/device-plugins" }
        }
      }
    }
  }
}
# Anything in this namespace is denied by default; the policy below re-opens exactly
# what a device Pod needs. Without this, a Pod that does not match that selector
# (a debug Job, a future sidecar) would have unrestricted access to the VPC.
resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "cwe-default-deny"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}
# Port-forward goes through the Kubernetes API. Direct pod access is only for
# explicitly labelled in-cluster orchestrator Pods, including other namespaces.
resource "kubernetes_network_policy_v1" "device" {
  metadata {
    name      = "cwe-device"
    namespace = kubernetes_namespace_v1.lab.metadata[0].name
  }
  spec {
    pod_selector { match_labels = { "app.kubernetes.io/name" = "cwe-android" } }
    policy_types = ["Ingress", "Egress"]
    ingress {
      from {
        namespace_selector { match_labels = { "app.kubernetes.io/part-of" = "cwe" } }
        pod_selector { match_labels = { "cwe/role" = "orchestrator" } }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
    egress {
      to {
        namespace_selector { match_labels = { "kubernetes.io/metadata.name" = "kube-system" } }
        pod_selector { match_labels = { "k8s-app" = "kube-dns" } }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
    egress {
      to {
        ip_block {
          cidr = "0.0.0.0/0"
          # Private, carrier-grade NAT and link-local ranges: no VPC neighbour and no instance metadata.
          except = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"]
        }
      }
      ports {
        protocol = "TCP"
        port     = "443"
      }
    }
  }
}
# Strict CNI enforcement also needs a policy for CoreDNS. Other Pods may query
# it; upstream DNS and Kubernetes API access remain available to CoreDNS.
resource "kubernetes_network_policy_v1" "dns" {
  metadata {
    name      = "cwe-coredns"
    namespace = "kube-system"
  }
  spec {
    pod_selector { match_labels = { "k8s-app" = "kube-dns" } }
    policy_types = ["Ingress", "Egress"]
    ingress {
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
    egress {}
  }
}
output "namespace" { value = kubernetes_namespace_v1.lab.metadata[0].name }
