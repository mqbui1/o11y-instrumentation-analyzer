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

**Logs (Log Observer Connect)**
- Queries Splunk Platform (Cloud or Enterprise) directly via the REST API
- `service.name`, `deployment.environment` — Log Observer service filter + Related Content
- `trace_id`, `span_id` — APM ↔ Logs trace-level correlation
- `host` / `host.name` — Infrastructure Monitoring ↔ Logs correlation
- Requires `--splunk-url` and `--splunk-token` (Splunk Platform credentials)

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

# Include log analysis via Log Observer Connect — single index
python3 analyze.py --realm us0 --token $TOKEN \
  --splunk-url https://prd-p-<stack>.splunkcloud.com:8089 \
  --splunk-token $SPLUNK_PLATFORM_TOKEN \
  --splunk-index otel_logs \
  --format html --output report.html

# LOC with per-environment index mapping (different index per environment)
python3 analyze.py --realm us0 --token $TOKEN \
  --splunk-url https://prd-p-<stack>.splunkcloud.com:8089 \
  --splunk-token $SPLUNK_PLATFORM_TOKEN \
  --splunk-index-map "prod=tiaa_prod_logs,staging=tiaa_staging_logs,dev=tiaa_dev_logs" \
  --environments prod,staging,dev \
  --format html --output report.html
```

### Per-environment breakdown

Run the analysis across multiple environments and get a consolidated HTML report with
a summary table and per-environment drill-down (RC link status, APM/Metrics/Logs scores).

```bash
# Target specific environments (recommended — faster, avoids analyzing stale/test envs)
python3 analyze.py --realm us0 --token $TOKEN \
  --environments prod,staging,dev \
  --format html --output report.html

# Auto-discover all environments in the org (capped at 20 by default)
python3 analyze.py --realm us0 --token $TOKEN \
  --breakdown-by-env \
  --format html --output report.html

# Auto-discover up to 50 environments
python3 analyze.py --realm us0 --token $TOKEN \
  --breakdown-by-env --max-environments 50 \
  --format html --output report.html

# Skip logs if Log Observer is not configured (speeds up each env)
python3 analyze.py --realm us0 --token $TOKEN \
  --environments prod,staging,dev \
  --skip-logs \
  --format html --output report.html
```

> **Performance:** Each environment takes ~30–60 seconds depending on API latency.
> For 10 environments expect ~5–10 minutes; for 40 environments expect ~20–30 minutes.
> Use `--environments` to target only the environments you care about.

## Output formats

| Format | Description |
|--------|-------------|
| `md`   | Markdown (default) — pipe to a file or view in terminal |
| `json` | Full structured JSON — machine-readable, integrates with other tools |
| `html` | Self-contained HTML report with interactive UI — open in any browser |
| `all`  | Writes all three formats to the output directory |

## Options

```
Connection:
  --realm REALM              Splunk Observability realm (us0, us1, eu0, jp0, etc.)
  --token TOKEN              API access token (or SPLUNK_ACCESS_TOKEN env var)

Scope:
  --service SERVICE          Scope to a specific service name
  --environment ENV          Scope to a specific environment
  --lookback-hours N         Lookback window in hours (default: 3)

Sampling:
  --apm-sample-size N        Traces to sample for APM (default: 50)
  --metrics-sample-size N    MTS to sample for metrics metadata (default: 200)
  --logs-sample-size N       Log records to sample (default: 100)

Signals:
  --skip-apm                 Skip APM trace analysis
  --skip-metrics             Skip infrastructure metrics analysis
  --skip-logs                Skip log analysis

Log Observer Connect (Splunk Platform):
  --splunk-url URL           Splunk Platform management endpoint
                             e.g. https://prd-p-<stack>.splunkcloud.com:8089
                             (or set SPLUNK_PLATFORM_URL env var)
  --splunk-token TOKEN       Splunk Platform Bearer token with search permissions.
                             Create in Splunk Platform: Settings → Tokens.
                             (or set SPLUNK_PLATFORM_TOKEN env var)
  --splunk-index INDEX       Splunk index to search (default: * = all accessible).
                             Fallback when --splunk-index-map has no entry for an environment.
  --splunk-index-map MAP     Map deployment.environment to Splunk indexes.
                             Format: env1=index1,env2=index2
                             e.g. prod=tiaa_prod_logs,dev=tiaa_dev_logs
                             Environments not in the map fall back to --splunk-index.
  --no-verify-ssl            Disable SSL verification (Splunk Enterprise self-signed certs)

Output:
  --format {md,json,html,all} Output format (default: md)
  --output PATH              Output file or directory (default: stdout)

Environment breakdown:
  --environments ENV[,ENV…]  Comma-separated list of environments to analyze.
                             Produces a per-environment breakdown report.
                             Implies --breakdown-by-env.
  --breakdown-by-env         Auto-discover environments and analyze each one.
  --max-environments N       Cap on auto-discovered environments (default: 20)

Misc:
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
  apm_analyzer.py       Trace sampling via GraphQL Trace Analytics API (parallel fetch)
  metrics_analyzer.py   Per-dimension existence checks via /v2/metrictimeseries (parallel)
  logs_analyzer.py      Log sampling via /v1/log/search, Unified + LOC detection
  correlation_checker.py  Cross-signal Related Content link validation
  env_discovery.py      Environment discovery via /v2/dimension, junk filtering
report/
  renderer.py           Markdown / JSON / HTML output renderers
  templates/
    report.html         Interactive HTML report template (breakdown + single-env modes)
```
