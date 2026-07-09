"""
Expected attribute/dimension schema for Splunk Observability Cloud signals.
Defines what attributes are required, recommended, and optional for each signal type,
and which attributes are needed for Related Content correlation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "warning", "info"]


@dataclass
class AttributeRule:
    name: str
    severity: Severity          # Impact if missing
    purpose: str                # Why it matters
    related_content: bool = False  # Needed for Related Content linking
    alternatives: list[str] = field(default_factory=list)  # Acceptable substitutes


# ── APM (spans/traces) ────────────────────────────────────────────────────────

APM_RULES: list[AttributeRule] = [
    AttributeRule("service.name", "critical", "Service identity — required for all APM views", related_content=True),
    AttributeRule("deployment.environment", "critical", "Environment scoping — required for Service Centric view and Related Content", related_content=True),
    AttributeRule("host.name", "warning", "Links APM to Infrastructure Monitoring and Logs (Related Content)", related_content=True),
    AttributeRule("host.id", "info", "EC2 instance ID — present on EC2 spans; used for EC2 APM→IM host match but not for Logs-IM correlation"),
    AttributeRule("k8s.pod.name", "warning", "Kubernetes pod correlation — required for K8s navigator linking", related_content=True),
    AttributeRule("k8s.node.name", "warning", "Kubernetes node correlation", related_content=True),
    AttributeRule("k8s.namespace.name", "warning", "Kubernetes namespace scoping"),
    AttributeRule("container.id", "warning", "Container-level correlation for runtime metrics"),
    AttributeRule("telemetry.sdk.name", "info", "Identifies instrumentation library"),
    AttributeRule("telemetry.sdk.version", "info", "Instrumentation version — useful for upgrade tracking"),
    AttributeRule("telemetry.sdk.language", "info", "Runtime language identification"),
    AttributeRule("span.kind", "info", "SERVER/CLIENT/PRODUCER/CONSUMER classification"),
    AttributeRule("http.status_code", "info", "HTTP error detection", alternatives=["http.response.status_code"]),
    AttributeRule("http.method", "info", "HTTP method dimension", alternatives=["http.request.method"]),
    AttributeRule("http.url", "info", "Full URL — useful for endpoint grouping", alternatives=["url.full"]),
    AttributeRule("db.system", "info", "Database type — required for DB dashboard"),
    AttributeRule("db.name", "info", "Database name dimension"),
    AttributeRule("net.peer.name", "info", "Downstream host identification", alternatives=["server.address"]),
]

# Attributes required for APM ↔ IM Related Content
# host.name is the primary linking field; host.id is not used for Logs-Infra correlation
APM_TO_IM_LINK_ATTRS = {"host.name", "k8s.pod.name"}

# Attributes required for APM ↔ Logs Related Content
APM_TO_LOGS_LINK_ATTRS = {"deployment.environment", "service.name"}


# ── Metrics (IM) ──────────────────────────────────────────────────────────────

METRICS_RULES: list[AttributeRule] = [
    AttributeRule("host.name", "critical", "Host identity — required for Host Navigator and IM dashboards", related_content=True, alternatives=["host", "aws_private_dns_name", "instance_name", "azure_computer_name"]),
    AttributeRule("host", "critical", "Host identity (legacy convention)", related_content=True, alternatives=["host.name", "aws_private_dns_name", "instance_name", "azure_computer_name"]),
    AttributeRule("sf_environment", "warning", "Environment scoping — required for Related Content to APM", related_content=True),
    AttributeRule("deployment.environment", "warning", "OTel environment convention — maps to sf_environment", related_content=True),
    AttributeRule("k8s.pod.name", "warning", "Pod-level granularity for K8s Navigator", related_content=True, alternatives=["kubernetes_pod_name"]),
    AttributeRule("k8s.node.name", "warning", "Node-level rollup for K8s Navigator", related_content=True, alternatives=["kubernetes_node"]),
    AttributeRule("k8s.cluster.name", "warning", "Cluster scoping for K8s Navigator", related_content=True, alternatives=["kubernetes_cluster"]),
    AttributeRule("k8s.namespace.name", "warning", "Namespace dimension for K8s Navigator", alternatives=["kubernetes_namespace"]),
    AttributeRule("kubernetes_workload_name", "warning", "Workload-level grouping for K8s Navigator (Deployment/StatefulSet/DaemonSet)", related_content=True, alternatives=["k8s.workload.name"]),
    AttributeRule("container.name", "info", "Container-level breakdown", alternatives=["k8s.container.name", "container.id"]),
    # sf_service is the Splunk-internal dimension used to link IM metrics back to an APM service.
    # The platform treats sf_service and service.name as equivalent when querying, but sf_service
    # is the field the Related Content engine actually looks for on K8s/host metrics.
    AttributeRule("sf_service", "warning", "Links IM metrics to APM service — primary field for IM↔APM Related Content. OTel convention service.name is mapped to sf_service at ingest.", related_content=True, alternatives=["service.name"]),
    AttributeRule("cloud.provider", "info", "Cloud provider identification (aws/gcp/azure)"),
    AttributeRule("cloud.region", "info", "Cloud region dimension"),
    AttributeRule("cloud.account.id", "info", "Cloud account scoping"),
    AttributeRule("cloud.infrastructure_service", "info", "Cloud service type (e.g. EC2, EBS, RDS) — enables cloud-service-specific Related Content tiles"),
]

# Dimensions required for IM ↔ APM Related Content
# sf_service (or its OTel equivalent service.name) must be present on K8s/host metrics
# for the IM → APM Related Content link to function.
IM_TO_APM_LINK_DIMS = {"host.name", "host", "k8s.pod.name", "kubernetes_pod_name", "sf_service"}


# ── Logs ─────────────────────────────────────────────────────────────────────

LOGS_RULES: list[AttributeRule] = [
    AttributeRule("service.name", "critical", "Service identity — required for Log Observer service filter and Related Content", related_content=True),
    AttributeRule("deployment.environment", "critical", "Environment scoping — required for Related Content", related_content=True, alternatives=["sf_environment"]),
    AttributeRule("trace_id", "warning", "APM ↔ Logs correlation — enables trace-to-log linking", related_content=True, alternatives=["traceId", "trace.id"]),
    AttributeRule("span_id", "warning", "Span-level log correlation", related_content=True, alternatives=["spanId", "span.id"]),
    AttributeRule("host.name", "warning", "Host-level log aggregation and IM correlation", related_content=True, alternatives=["host", "hostname"]),
    AttributeRule("severity_text", "warning", "Log level (INFO/WARN/ERROR) — required for severity filtering", alternatives=["level", "log.level", "severity"]),
    AttributeRule("severity_number", "info", "Numeric severity for sorting/filtering"),
    AttributeRule("body", "critical", "Log message content"),
    AttributeRule("timestamp", "critical", "Log timestamp — required for timeline ordering", alternatives=["time", "@timestamp"]),
    AttributeRule("k8s.pod.name", "info", "Pod-level log filtering", alternatives=["kubernetes_pod_name"]),
    AttributeRule("k8s.namespace.name", "info", "Namespace-level log filtering", alternatives=["kubernetes_namespace"]),
    AttributeRule("k8s.cluster.name", "info", "Cluster-level log filtering — enables K8s navigator Related Content from logs", alternatives=["kubernetes_cluster"]),
    AttributeRule("kubernetes_workload_name", "info", "Workload-level log grouping (Deployment/StatefulSet/DaemonSet)", alternatives=["k8s.workload.name"]),
    AttributeRule("container.name", "info", "Container log source identification", alternatives=["k8s.container.name"]),
    AttributeRule("cloud.infrastructure_service", "info", "Cloud service type — enables cloud-service-specific Related Content from logs"),
]

# Log Observer Connect (LOC) specific — Splunk Platform logs linked to O11y
LOC_RULES: list[AttributeRule] = [
    AttributeRule("service.name", "critical", "Required for LOC service correlation"),
    AttributeRule("deployment.environment", "critical", "Required for LOC environment scoping", alternatives=["sf_environment"]),
    AttributeRule("trace_id", "warning", "Required for APM ↔ LOC trace linking", alternatives=["traceId"]),
    AttributeRule("span_id", "warning", "Required for APM ↔ LOC span linking", alternatives=["spanId"]),
    AttributeRule("host", "warning", "Required for LOC ↔ IM host correlation", alternatives=["host.name", "hostname"]),
]

# ── Related Content link map ──────────────────────────────────────────────────

RELATED_CONTENT_LINKS = [
    {
        "from": "APM",
        "to": "Infrastructure Monitoring",
        "required_attrs": ["host.name", "deployment.environment"],
        "description": "Service Centric view → Host / Container / K8s tiles",
    },
    {
        "from": "APM",
        "to": "Logs (Unified Identity)",
        "required_attrs": ["service.name", "deployment.environment", "trace_id"],
        "description": "Trace view → Related Logs panel",
    },
    {
        "from": "APM",
        "to": "Logs (Log Observer Connect)",
        "required_attrs": ["service.name", "deployment.environment", "trace_id"],
        "description": "Trace view → Splunk Platform logs via LOC",
    },
    {
        "from": "Infrastructure Monitoring",
        "to": "APM",
        "required_attrs": ["sf_service (or service.name)", "sf_environment OR deployment.environment"],
        "description": "Host Navigator → APM service context. sf_service is the primary field; service.name is mapped to sf_service at ingest.",
    },
    {
        "from": "Infrastructure Monitoring",
        "to": "Logs",
        "required_attrs": ["host.name OR host", "deployment.environment"],
        "description": "Host Navigator → Related Logs",
    },
    {
        "from": "APM",
        "to": "Infrastructure Monitoring (Kubernetes)",
        "required_attrs": ["service.name", "deployment.environment", "k8s.cluster.name"],
        "description": "Service Centric view → Kubernetes cluster map / K8s Navigator",
    },
    {
        "from": "APM / Infrastructure Monitoring",
        "to": "Logs (K8s)",
        "required_attrs": ["k8s.cluster.name", "k8s.pod.name OR k8s.node.name OR container.id"],
        "description": "K8s Navigator → Related Logs for pod/node/container",
    },
]

# ── Service Centric View requirements ─────────────────────────────────────────

SERVICE_CENTRIC_REQUIREMENTS = {
    "runtime_metrics": {
        "description": "Runtime metrics (JVM, .NET, Node.js etc.) in Service Centric view",
        "required_dims": ["service.name", "deployment.environment", "host.name OR container.id"],
        "note": "Must use OTel runtime instrumentation libraries or equivalent metric names",
        "expected_metrics": {
            "jvm": ["jvm.memory.heap.used", "jvm.gc.pause", "process.runtime.jvm.memory.usage"],
            "dotnet": ["process.runtime.dotnet.gc.collections.count", "process.runtime.dotnet.heap.size"],
            "nodejs": ["process.runtime.nodejs.memory.heap.used"],
        },
    },
    "infrastructure_metrics": {
        "description": "Infrastructure metrics in Service Centric view",
        "required_dims": ["host.name OR k8s.pod.name", "deployment.environment"],
        "note": "Host/container metrics must share host.name dimension with APM spans",
    },
    "code_profiling": {
        "description": "AlwaysOn Profiling data in Service Centric view",
        "required_attrs": ["service.name", "deployment.environment"],
        "note": "Requires Splunk OTel Java/Python agent with profiling enabled",
    },
}
