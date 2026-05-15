# o11y-instrumentation-analyzer

Analyzes APM spans, infrastructure metrics, and logs for missing attributes and
dimensions that break Related Content, Service Centric view, and runtime metrics
in Splunk Observability Cloud.

Works with both **Unified Identity** (native O11y logs) and **Log Observer Connect**
(Splunk Platform logs linked via LOC).

## What it checks

**APM (traces/spans)**
- `service.name`, `deployment.environment` — required for all APM views
- `host.name` / `host.id` / `k8s.pod.name` — APM → Infrastructure Monitoring linking
- Kubernetes resource attributes
- SDK telemetry attributes, HTTP/DB span attributes

**Infrastructure Metrics**
- `host.name` / `host` — Host Navigator and IM dashboards
- `sf_environment` / `deployment.environment` — environment scoping
- Kubernetes dimensions (pod, node, cluster, namespace)
- Service-level runtime metrics (JVM, .NET, Node.js)

**Logs**
- `service.name`, `deployment.environment` — Log Observer service filter + Related Content
- `trace_id`, `span_id` — APM ↔ Logs trace-level correlation
- `host.name` — Infrastructure Monitoring ↔ Logs correlation
- Auto-detects Unified Identity vs Log Observer Connect logs
- LOC-specific check: `service.name` injection from Splunk Platform

**Cross-signal Related Content links**
- APM → Infrastructure Monitoring (Service Centric view infrastructure tab)
- APM → Logs (trace view Related Logs panel)
- Infrastructure Monitoring → Logs (Host Navigator Related Logs)

## Requirements

- Python 3.10+
- No third-party packages required (stdlib only)
- A Splunk Observability API access token with read access to APM, metrics, and logs

## Usage

```bash
# Basic analysis — entire org, last 3 hours
python3 analyze.py --realm us1 --token <your_token>

# Scope to a specific service and environment
python3 analyze.py --realm us1 --token $TOKEN --service frontend --environment production

# Output as HTML report
python3 analyze.py --realm us1 --token $TOKEN --format html --output report.html

# Output all three formats to a directory
python3 analyze.py --realm us1 --token $TOKEN --format all --output ./reports/

# Use env var for token
export SPLUNK_ACCESS_TOKEN=<your_token>
python3 analyze.py --realm us0 --format json | jq .correlation
```

## Output formats

| Format | Description |
|--------|-------------|
| `md`   | Markdown (default) — pipe to a file or view in terminal |
| `json` | Full structured JSON — machine-readable, integrates with other tools |
| `html` | Self-contained HTML report with interactive UI — open in any browser |
| `all`  | Writes all three formats to the output directory |

## Options

```
--realm REALM              Splunk Observability realm (us0, us1, eu0, jp0, etc.)
--token TOKEN              API access token (or SPLUNK_ACCESS_TOKEN env var)
--service SERVICE          Scope to a specific service name
--environment ENV          Scope to a specific environment
--lookback-hours N         Lookback window in hours (default: 3)
--apm-sample-size N        Traces to sample for APM (default: 50)
--metrics-sample-size N    MTS to sample for metrics (default: 200)
--logs-sample-size N       Log records to sample (default: 100)
--skip-apm                 Skip APM trace analysis
--skip-metrics             Skip infrastructure metrics analysis
--skip-logs                Skip log analysis
--format {md,json,html,all} Output format (default: md)
--output PATH              Output file or directory (default: stdout)
--verbose                  Enable verbose logging
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All Related Content links are functional |
| `1`  | One or more links are broken or partially broken |

## Score interpretation

Each signal receives a 0–100 data health score based on attribute/dimension
coverage weighted by severity:

| Range | Interpretation |
|-------|---------------|
| 90–100 | Excellent — all key attributes present |
| 70–89  | Good — minor gaps, Related Content mostly functional |
| 50–69  | Fair — some critical attributes missing, expect partial RC failures |
| 0–49   | Poor — significant gaps, Related Content will be broken |

## Architecture

```
analyze.py              CLI entry point
core/
  schema.py             Attribute rule definitions (APM, Metrics, Logs, LOC)
  apm_analyzer.py       Trace sampling via GraphQL Trace Analytics API
  metrics_analyzer.py   MTS catalog sampling via /v2/metrictimeseries
  logs_analyzer.py      Log sampling via /v1/log/search, Unified + LOC detection
  correlation_checker.py  Cross-signal Related Content link validation
report/
  renderer.py           Markdown / JSON / HTML output renderers
  templates/
    report.html         Interactive HTML report template
```
