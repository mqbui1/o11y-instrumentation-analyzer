# Instrumentation Analyzer — How It Works

This document explains exactly what the Splunk Observability Instrumentation Analyzer does, what API calls it makes, and what data it accesses. It is intended to help customers evaluate the tool's safety before running it in their environment.

---

## Overview

The analyzer reads existing telemetry data already in your Splunk Observability Cloud org to check whether the right attributes and dimensions are present across APM traces, infrastructure metrics, and logs. It identifies gaps that break Related Content linking, Service Centric view, and other platform features.

**The tool:**
- ✅ Reads a small sample of existing telemetry (traces, metrics, logs)
- ✅ Checks for the presence of required metadata attributes
- ✅ Runs entirely on your local machine
- ✅ Outputs a report locally (markdown, JSON, or HTML)
- ❌ Does not write, modify, or delete any data
- ❌ Does not install agents or make configuration changes
- ❌ Does not send data to any third party
- ❌ Does not access span payloads, log message bodies, or actual metric values

---

## Token Requirements

A **read-only API token** is sufficient. The tool only calls read endpoints. It does **not** require an ingest token, admin permissions, or write access.

Minimum token scope: `API` (read-only).

---

## API Calls Made

### APM (Traces)

The tool samples recent traces to check span attribute coverage.

| Call | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST /v2/apm/graphql` — `StartAnalyticsSearch` | Search for up to 50 trace IDs within the lookback window. Same query the Splunk Observability UI uses when browsing traces. |
| 2 | `POST /v2/apm/graphql` — `GetAnalyticsSearch` | Poll for search results. |
| 3 | `POST /v2/apm/graphql` — `TraceFullDetailsLessValidation` | Fetch span tag/attribute keys for up to 20 traces. Reads attribute names only — no span payloads or business data. |

**Default sample size:** 50 trace IDs searched, up to 20 traces fetched in full.
**Lookback window:** 3 hours (configurable via `--lookback-hours`).

---

### Metrics (Infrastructure Monitoring)

The tool queries the MTS catalog to check dimension coverage.

| Call | Endpoint | Purpose |
|------|----------|---------|
| 1 | `GET /v2/metrictimeseries` | Sample up to 200 active MTS. Reads dimension names and values only — no actual metric data points are fetched. |
| 2 | `GET /v2/metrictimeseries` (repeated) | Check for the presence of runtime metric names (JVM, .NET, Node.js) — one query per metric name. Checks existence only, no data points read. |

**Default sample size:** 200 MTS.

---

### Logs

The tool samples recent log records to check field coverage.

| Call | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST /v1/log/search` | Fetch up to 100 recent log records. Reads field keys and values to check attribute presence. |

**Default sample size:** 100 log records.

---

## What the Tool Looks At

The tool checks **whether metadata attributes are present** — not the actual content or values of those attributes.

| It checks | It does NOT look at |
|-----------|---------------------|
| "Does this span have a `host.name` attribute?" | The actual hostname value |
| "Is `deployment.environment` set on this MTS?" | The environment name beyond filtering |
| "Does this log record have a `trace_id` field?" | The trace ID value or log message body |

The only exception: `service.name` and `deployment.environment` values are used to **filter** the sample when `--service` or `--environment` flags are passed — this scopes analysis to the specific service or environment you specify.

---

## Where Data Goes

The tool runs entirely on the machine where it is executed. It makes HTTPS API calls to:

- `https://api.<realm>.signalfx.com` — metrics and logs
- `https://app.<realm>.signalfx.com` — APM GraphQL

All results are written locally as a report (markdown/JSON/HTML) to stdout or a file you specify. No data is sent to any third-party service.

---

## Checks Performed

### APM Checks

Sampled spans are checked for the following attributes. Presence is measured as a percentage across all sampled spans.

| Attribute | Severity | Why It Matters |
|-----------|----------|----------------|
| `service.name` | Critical | Service identity — required for all APM views |
| `deployment.environment` | Critical | Environment scoping — required for Service Centric view and Related Content |
| `host.name` / `host.id` | Warning | Links APM to Infrastructure Monitoring (Related Content) |
| `k8s.pod.name` | Warning | Kubernetes pod correlation — required for K8s Navigator linking |
| `k8s.node.name` | Warning | Kubernetes node correlation |
| `k8s.namespace.name` | Warning | Kubernetes namespace scoping |
| `container.id` | Warning | Container-level correlation for runtime metrics |
| `telemetry.sdk.name/version/language` | Info | Identifies instrumentation library and runtime |
| `span.kind` | Info | SERVER/CLIENT/PRODUCER/CONSUMER classification |
| `http.status_code`, `http.method`, `http.url` | Info | HTTP protocol context |
| `db.system`, `db.name` | Info | Database type — required for DB dashboard |
| `net.peer.name` | Info | Downstream host identification |

**Related Content gap checks (APM):**
- **APM → Infrastructure Monitoring**: requires `host.name` OR `host.id` OR `k8s.pod.name` on spans
- **APM → Logs**: requires `service.name` AND `deployment.environment` on spans

---

### Metrics (IM) Checks

Sampled MTS are checked for the following dimensions:

| Dimension | Severity | Why It Matters |
|-----------|----------|----------------|
| `host.name` / `host` | Critical | Host identity — required for Host Navigator and IM dashboards |
| `sf_environment` / `deployment.environment` | Warning | Environment scoping — required for Related Content to APM |
| `k8s.pod.name` | Warning | Pod-level granularity for K8s Navigator |
| `k8s.node.name` | Warning | Node-level rollup for K8s Navigator |
| `k8s.cluster.name` | Warning | Cluster scoping for K8s Navigator |
| `k8s.namespace.name` | Warning | Namespace dimension |
| `kubernetes_workload_name` | Warning | Workload-level grouping (Deployment/StatefulSet/DaemonSet) |
| `sf_service` / `service.name` | Warning | Links IM metrics to APM service — primary field for IM↔APM Related Content |
| `cloud.provider` | Info | Cloud provider identification (aws/gcp/azure) |
| `cloud.region` | Info | Cloud region dimension |
| `cloud.account.id` | Info | Cloud account scoping |
| `cloud.infrastructure_service` | Info | Cloud service type (EC2, RDS, etc.) — enables cloud-specific Related Content tiles |
| `container.name` | Info | Container-level breakdown |

**Additional checks:**
- **Runtime metrics presence**: checks whether JVM, .NET, or Node.js runtime metric names exist in the catalog for the given service
- **Service Centric view**: checks whether `host.name`/`host`/`k8s.pod.name` are present (required for the infrastructure tab)

**Related Content gap checks (Metrics):**
- **IM → APM**: requires `host`/`host.name`, `sf_environment`/`deployment.environment`, AND `sf_service`/`service.name`
- **IM → Logs**: requires `host.name`/`host`

---

### Logs Checks

Sampled log records are checked for the following fields. The tool auto-detects whether logs are **Unified Identity** (native Splunk Observability logs) or **Log Observer Connect** (Splunk Platform logs) and applies the appropriate rules.

| Field | Severity | Why It Matters |
|-------|----------|----------------|
| `body` | Critical | Log message content |
| `timestamp` | Critical | Required for timeline ordering |
| `service.name` | Critical | Required for Log Observer service filter and Related Content |
| `deployment.environment` | Critical | Environment scoping — required for Related Content |
| `severity_text` | Warning | Log level (INFO/WARN/ERROR) — required for severity filtering |
| `trace_id` / `span_id` | Warning | APM↔Logs correlation — enables trace-to-log linking |
| `host.name` | Warning | Host-level log aggregation and IM correlation |
| `k8s.pod.name` | Info | Pod-level log filtering |
| `k8s.namespace.name` | Info | Namespace-level log filtering |
| `k8s.cluster.name` | Info | Cluster-level filtering — enables K8s Navigator Related Content from logs |
| `kubernetes_workload_name` | Info | Workload-level log grouping |
| `container.name` | Info | Container log source identification |
| `cloud.infrastructure_service` | Info | Cloud service type context |

**Log Observer Connect (LOC) additional checks:**
- `source`/`sourcetype` fields present (Splunk Platform field extraction)
- `service.name` injection — often missing in LOC since Splunk Platform does not inject it automatically

**Related Content gap checks (Logs):**
- **Logs → APM**: requires `service.name` AND `deployment.environment`
- **Logs → APM (trace-level)**: additionally requires `trace_id`
- **Logs → IM**: requires `host.name`/`host`

---

### Cross-Signal Correlation Checks

After analyzing each signal independently, the tool checks whether Related Content links can actually form between signals by verifying shared dimensions are present on both sides:

| Link | Conditions Required |
|------|---------------------|
| **APM → Infrastructure Monitoring** | APM spans have `host.name`/`host.id`/`k8s.pod.name` AND IM metrics have `host`/`host.name` AND env AND `sf_service`/`service.name` |
| **APM → Logs** | Both have `service.name`, logs have `deployment.environment`; `trace_id` required for trace-level linking |
| **Infrastructure Monitoring → Logs** | Both have `host.name`/`host` |

Each link is rated **ok**, **partial**, or **broken** with a specific fix recommendation.

---

## Scoring

Each signal (APM, Metrics, Logs) produces a score from **0–100** based on how completely the required attributes are present across the sampled data:

- **Critical** attributes missing: highest deduction (weight 3)
- **Warning** attributes missing: medium deduction (weight 2)
- **Info** attributes missing: low deduction (weight 1)

A **combined score** is the average across all three signals. The tool exits with code `0` if all Related Content links are functional, `1` if any are broken or partial.

---

## Default Limits (Configurable)

| Parameter | Default | Flag |
|-----------|---------|------|
| Lookback window | 3 hours | `--lookback-hours` |
| APM traces sampled | 50 trace IDs, 20 fetched in full | `--apm-sample-size` |
| Metrics MTS sampled | 200 | `--metrics-sample-size` |
| Log records sampled | 100 | `--logs-sample-size` |

All limits can be reduced further if the customer wants to minimize API call volume.
