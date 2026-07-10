# o11y-instrumentation-analyzer

Analyzes APM spans, infrastructure metrics, and logs for missing attributes and
dimensions that break Related Content, Service Centric view, and runtime metrics
in Splunk Observability Cloud.

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

**Logs** — see [Log Analysis Modes](#log-analysis-modes) below
- `service.name`, `deployment.environment` — Log Observer service filter + Related Content
- `trace_id`, `span_id` — APM ↔ Logs trace-level correlation
- `host` / `host.name` — Infrastructure Monitoring ↔ Logs correlation

**Cross-signal Related Content links**
- APM → Infrastructure Monitoring (Service Centric view infrastructure tab)
- APM → Logs (trace view Related Logs panel)
- Infrastructure Monitoring → Logs (Host Navigator Related Logs)

## Requirements

- Python 3.10+
- No third-party packages required (stdlib only)
- A Splunk Observability Cloud API access token with read access to APM and metrics

## Log Analysis Modes

Splunk Observability Cloud does not store logs natively. Logs live in Splunk Platform
(Cloud or Enterprise) and are surfaced in O11y through **Log Observer Connect (LOC)**.
The analyzer queries Splunk Platform directly via its REST API.

There are two authentication models depending on how your org is configured:

---

### Mode 1 — Log Observer Connect (dedicated service account)

Used when LOC is configured with a dedicated Splunk Platform service account.
The service account was created in Splunk Platform specifically for the LOC connection
and registered under **Splunk Observability Cloud → Admin → Log Observer Connect**.

**Credentials needed:**

| What | Where to get it |
|------|----------------|
| Splunk Platform management URL | `https://prd-p-<stack>.splunkcloud.com:8089` — from the Splunk Cloud admin console |
| Splunk Platform service account token | Splunk Platform → Settings → Tokens → New Token (assign to the LOC service account, needs `search` capability on the target index) |
| Index name(s) | The Splunk index(es) where logs land, e.g. `main`, `otel_logs` |

```bash
python3 analyze.py \
  --realm us0 --token $O11Y_TOKEN \
  --splunk-url https://prd-p-<stack>.splunkcloud.com:8089 \
  --splunk-token $SPLUNK_SERVICE_ACCOUNT_TOKEN \
  --splunk-index otel_logs \
  --environments prod,staging,dev \
  --format html --output report.html
```

---

### Mode 2 — Log Observer Connect with Unified Identity

Used when Splunk Cloud Platform and Splunk Observability Cloud share a **Unified Identity**
(federated authentication). Users and service principals authenticate through a common
identity layer, so a single Splunk Cloud Platform token grants access to both products.

The token is a Splunk Cloud Platform API token issued to a principal that has **both**
Splunk Observability Cloud access and Splunk Platform search permissions on the relevant
indexes. It is obtained via the Splunk Cloud Platform identity system (not the traditional
Settings → Tokens path).

**Credentials needed:**

| What | Where to get it |
|------|----------------|
| Splunk Platform management URL | Same as Mode 1 — `https://prd-p-<stack>.splunkcloud.com:8089` |
| Splunk Cloud unified identity token | Splunk Cloud Platform → user/service principal API token with search permissions. The principal must have the `search` capability scoped to the relevant indexes. |
| Index name(s) | Same as Mode 1 |

```bash
python3 analyze.py \
  --realm us0 --token $O11Y_TOKEN \
  --splunk-url https://prd-p-<stack>.splunkcloud.com:8089 \
  --splunk-token $SPLUNK_UNIFIED_IDENTITY_TOKEN \
  --splunk-index otel_logs \
  --environments prod,staging,dev \
  --format html --output report.html
```

> **Note:** Both modes use identical CLI flags and the same Splunk Platform REST API
> (`/services/search/jobs/export`). The only difference is the token source and the
> account it represents.

---

### Per-environment index mapping

If different environments land in different Splunk indexes, use `--splunk-index-map`:

```bash
python3 analyze.py \
  --realm us0 --token $O11Y_TOKEN \
  --splunk-url https://prd-p-<stack>.splunkcloud.com:8089 \
  --splunk-token $SPLUNK_TOKEN \
  --splunk-index-map "prod=tiaa_prod_logs,staging=tiaa_staging_logs,dev=tiaa_dev_logs" \
  --environments prod,staging,dev \
  --format html --output report.html
```

Environments not in the map fall back to `--splunk-index` (default: `*`).

---

### Verify Splunk connectivity before running

```bash
curl -s -k -X POST \
  "https://prd-p-<stack>.splunkcloud.com:8089/services/search/jobs/export" \
  -H "Authorization: Bearer <your-token>" \
  -d "search=search index=<index> earliest=-1h | head 3 | spath input=_raw | fieldsummary" \
  -d "output_mode=json" -d "count=50" | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line.strip())
        if 'result' in obj:
            r = obj['result']
            print(f\"{r.get('field',''):40s}  count={r.get('count',''):5s}\")
    except: pass
"
```

This lists every field present on recent events — confirm `service.name`,
`deployment.environment`, `trace_id`, and `host` appear before running the full analysis.

---

## Usage

```bash
# APM + Metrics only (no logs)
python3 analyze.py --realm us1 --token $O11Y_TOKEN --skip-logs

# Scope to a specific service and environment
python3 analyze.py --realm us1 --token $O11Y_TOKEN \
  --service frontend --environment production

# Output as HTML report
python3 analyze.py --realm us1 --token $O11Y_TOKEN \
  --format html --output report.html

# All three formats to a directory
python3 analyze.py --realm us1 --token $O11Y_TOKEN \
  --format all --output ./reports/
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
