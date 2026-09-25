"""
Logs analyzer — queries Splunk Platform (Cloud or Enterprise) via the REST API
to assess log field coverage for Log Observer Connect (LOC).

LOC architecture:
  Splunk Platform (Cloud/Enterprise) stores logs.
  Splunk Observability Cloud queries them via LOC using a service account token.
  There is no log storage in O11y itself — the /v1/log/search endpoint does not exist.

Required inputs:
  splunk_url   — Splunk Platform management endpoint, e.g.
                 https://prd-p-<stack>.splunkcloud.com:8089
  splunk_token — Splunk Platform Bearer token (Settings → Tokens in Splunk Platform)
  splunk_index — index to search (default: *)
"""
from __future__ import annotations

import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from .schema import LOC_RULES

logger = logging.getLogger(__name__)

# Fields that indicate an event came from Splunk Platform (always present)
_SPLUNK_NATIVE_FIELDS = {"_time", "_raw", "index", "source", "sourcetype", "host", "splunk_server"}


def _splunk_export(
    splunk_url: str,
    splunk_token: str,
    spl: str,
    limit: int = 100,
    verify_ssl: bool = True,
) -> list[dict]:
    """Run a blocking SPL export search against the Splunk Platform REST API.

    Uses /services/search/jobs/export which streams results synchronously —
    no async job management needed.

    Returns a list of event result dicts (Splunk field → value).
    """
    url = f"{splunk_url.rstrip('/')}/services/search/jobs/export"
    body = urllib.parse.urlencode({
        "search": spl,
        "output_mode": "json",
        "count": limit,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    # Splunk Cloud uses Bearer tokens; some Splunk Enterprise setups use "Splunk <token>"
    auth_header = (
        splunk_token if splunk_token.startswith("Bearer ") or splunk_token.startswith("Splunk ")
        else f"Bearer {splunk_token}"
    )
    req.add_header("Authorization", auth_header)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=60) as resp:
            records = []
            for line in resp.read().decode("utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        records.append(obj["result"])
                except json.JSONDecodeError:
                    pass
            return records
    except urllib.error.HTTPError as e:
        body_text = (e.read() or b"")[:400].decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body_text}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Request failed: {e}")


# Splunk's /services/search/jobs/export only serializes fields that are
# referenced somewhere in the SPL pipeline (search-time filters, table,
# stats, fields, etc.) — a plain `head N` with no field references silently
# omits fields like service.name/trace_id/span_id from the returned JSON,
# even when they are fully populated indexed fields on every event. Confirmed
# live 2026-09-25: an identical query with `| table service.name, trace_id,
# span_id` on the exact same events returned 100% coverage, while the bare
# `head`-only query returned 0% for every one of these — a false "missing
# field" reading purely from lazy export-time field materialization, not
# real data absence. Force materialization by explicitly referencing every
# field _extract_fields() looks for. `fields` keeps internal fields
# (_time, _raw, host, source, sourcetype, index) automatically.
_MATERIALIZE_FIELDS = [
    "service.name", "deployment.environment", "sf_environment",
    "trace_id", "traceId", "span_id", "spanId",
    "host", "host.name", "hostname",
    "severity_text", "level", "log.level", "severity",
    "timestamp", "time", "@timestamp",
]


def _build_spl(
    index: str,
    lookback_hours: int,
    service: str | None,
    environment: str | None,
    limit: int,
) -> str:
    """Build an SPL query to fetch recent log events scoped to service/environment."""
    filters = [f"index={index}", f"earliest=-{lookback_hours}h", "latest=now"]

    # OTel field names with dots — single-quote the field name in SPL
    if service:
        filters.append(f"'service.name'=\"{service}\"")
    if environment:
        # Try both OTel and legacy field names
        filters.append(
            f"('deployment.environment'=\"{environment}\" OR sf_environment=\"{environment}\")"
        )

    # No quoting here — unlike eval/comparison contexts, the `fields` command
    # takes bare field names and quoting them makes Splunk look for a field
    # literally named "'service.name'" (with quote characters), matching
    # nothing. Confirmed live: quoted version broke deployment.environment
    # too (previously 100% via the filter clause), unquoted fixes it.
    field_list = ", ".join(_MATERIALIZE_FIELDS)

    # | spath extracts JSON fields from _raw — handles OTel logs stored as JSON blobs
    # without pre-configured field extractions in Splunk
    # | fields — forces materialization, see _MATERIALIZE_FIELDS comment above
    return (
        "search " + " ".join(filters)
        + f" | head {limit} | spath input=_raw | fields {field_list}"
    )


def _extract_fields(record: dict) -> dict[str, str]:
    """Flatten a Splunk event result to a normalised field dict."""
    fields: dict[str, str] = {k: str(v) for k, v in record.items() if v is not None and v != ""}

    # Normalise common aliases to canonical names used in LOC_RULES
    for canonical, aliases in [
        ("trace_id",       ["traceId", "trace.id", "traceid", "otel.trace_id"]),
        ("span_id",        ["spanId", "span.id", "spanid"]),
        ("severity_text",  ["level", "log.level", "severity", "loglevel", "log_level"]),
        ("host.name",      ["hostname"]),          # "host" is kept as-is by Splunk
        ("service.name",   ["service_name"]),
        ("deployment.environment", ["sf_environment", "environment"]),
        ("timestamp",      ["_time", "time", "@timestamp", "ts"]),
    ]:
        if canonical not in fields:
            for alias in aliases:
                if alias in fields:
                    fields[canonical] = fields[alias]
                    break

    # Body presence — map _raw or message to "body"
    for body_key in ("message", "msg", "_raw"):
        if record.get(body_key):
            fields.setdefault("body", str(record[body_key])[:1])
            break

    return fields


def analyze_logs(
    realm: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    lookback_hours: int = 3,
    sample_size: int = 100,
    splunk_url: str | None = None,
    splunk_token: str | None = None,
    splunk_index: str = "*",
    verify_ssl: bool = True,
) -> dict[str, Any]:
    """
    Query Splunk Platform via the REST API and assess field coverage for LOC.

    Requires splunk_url and splunk_token.  Pass --splunk-url and --splunk-token
    on the CLI.  If not provided, returns a no-config result.
    """
    if not splunk_url or not splunk_token:
        return {
            "error": "not_configured",
            "mode": "loc",
            "logs_sampled": 0,
            "findings": [{
                "rule": "no_config",
                "severity": "warning",
                "message": (
                    "Splunk Platform connection not configured. "
                    "Provide --splunk-url (e.g. https://prd-p-<stack>.splunkcloud.com:8089) "
                    "and --splunk-token (Splunk Platform Bearer token) to enable log assessment."
                ),
            }],
            "score": 0,
        }

    logger.info(
        "Logs: querying Splunk Platform %s (index=%s, service=%s, env=%s)",
        splunk_url, splunk_index, service, environment,
    )

    spl = _build_spl(splunk_index, lookback_hours, service, environment, sample_size)
    logger.debug("Logs: SPL = %s", spl)

    try:
        records = _splunk_export(splunk_url, splunk_token, spl, limit=sample_size,
                                 verify_ssl=verify_ssl)
    except RuntimeError as e:
        err = str(e)
        if "HTTP 401" in err or "HTTP 403" in err:
            hint = (
                f"Splunk Platform auth failed ({err[:8]}). "
                "Verify the token is valid and has search permissions."
            )
        elif "HTTP 404" in err:
            hint = (
                "Splunk Platform REST API not found (404). "
                "Check that --splunk-url points to the management endpoint "
                "(e.g. https://prd-p-<stack>.splunkcloud.com:8089)."
            )
        else:
            hint = f"Splunk Platform search failed: {err}"
        logger.error(hint)
        return {
            "error": hint,
            "mode": "loc",
            "logs_sampled": 0,
            "findings": [{"rule": "api_error", "severity": "warning", "message": hint}],
            "score": 0,
        }

    if not records:
        return {
            "error": None,
            "mode": "loc",
            "logs_sampled": 0,
            "findings": [{
                "rule": "no_data",
                "severity": "warning",
                "message": (
                    f"No log records returned from index={splunk_index} in the last "
                    f"{lookback_hours}h. Verify the index name, time range, and that "
                    "logs are actively ingesting."
                ),
            }],
            "score": 0,
        }

    total = len(records)
    logger.info("Logs: retrieved %d records from Splunk Platform", total)

    field_presence: dict[str, int] = defaultdict(int)
    services_seen: set[str] = set()
    trace_id_coverage = 0

    for record in records:
        fields = _extract_fields(record)
        for rule in LOC_RULES:
            candidates = [rule.name] + rule.alternatives
            if any(fields.get(c) for c in candidates):
                field_presence[rule.name] += 1
        if svc := fields.get("service.name"):
            services_seen.add(svc)
        if fields.get("trace_id"):
            trace_id_coverage += 1

    # Build findings
    findings: list[dict] = []
    for rule in LOC_RULES:
        present = field_presence[rule.name]
        pct = round(present / total * 100, 1)
        missing_pct = 100 - pct

        if missing_pct == 0:
            continue

        if missing_pct == 100:
            sev, status = rule.severity, "missing"
        elif missing_pct >= 50:
            sev, status = rule.severity, "partial"
        else:
            sev, status = "info", "partial"

        findings.append({
            "field": rule.name,
            "alternatives_checked": rule.alternatives,
            "status": status,
            "severity": sev,
            "present_pct": pct,
            "missing_pct": missing_pct,
            "logs_checked": total,
            "related_content": rule.related_content,
            "purpose": rule.purpose,
        })

    trace_pct = round(trace_id_coverage / total * 100, 1)
    rc_gaps = _check_rc_gaps(field_presence, total)
    score = _compute_score(findings)

    return {
        "error": None,
        "mode": "loc",
        "mode_description": "Log Observer Connect (Splunk Platform logs)",
        "logs_sampled": total,
        "services_seen": sorted(services_seen),
        "trace_id_coverage_pct": trace_pct,
        "findings": sorted(findings, key=lambda f: (
            {"critical": 0, "warning": 1, "info": 2}[f["severity"]], -f["missing_pct"]
        )),
        "related_content_gaps": rc_gaps,
        "loc_findings": [],
        "score": score,
    }


def _check_rc_gaps(field_presence: dict[str, int], total: int) -> list[dict]:
    gaps = []
    if total == 0:
        return gaps

    def _has(name: str, threshold: float = 0.5) -> bool:
        return field_presence.get(name, 0) / total >= threshold

    if not _has("service.name"):
        gaps.append({
            "link": "Logs → APM",
            "severity": "critical",
            "missing": ["service.name"],
            "impact": (
                "Logs cannot be correlated to APM services in Log Observer Connect. "
                "Add a field extraction or transform in Splunk Platform to populate service.name."
            ),
        })

    if not (_has("deployment.environment") or _has("sf_environment")):
        gaps.append({
            "link": "Logs → APM / IM",
            "severity": "critical",
            "missing": ["deployment.environment"],
            "impact": (
                "Logs cannot be scoped to an environment. "
                "Related Content links from APM traces to logs will fail."
            ),
        })

    if not _has("trace_id"):
        gaps.append({
            "link": "Logs → APM (trace linking)",
            "severity": "warning",
            "missing": ["trace_id"],
            "impact": (
                "Log records cannot be linked to specific APM traces. "
                "The trace view 'Related Logs' panel will be empty."
            ),
        })

    if not (_has("host.name") or _has("host")):
        gaps.append({
            "link": "Logs → Infrastructure Monitoring",
            "severity": "warning",
            "missing": ["host / host.name"],
            "impact": (
                "Logs cannot be correlated to host-level metrics. "
                "Host Navigator 'Related Logs' will be empty."
            ),
        })

    return gaps


def _compute_score(findings: list[dict]) -> int:
    weights = {"critical": 3, "warning": 2, "info": 1}
    max_weight = sum(weights[r.severity] for r in LOC_RULES)
    if max_weight == 0:
        return 100
    deductions = sum(weights.get(f["severity"], 1) * (f["missing_pct"] / 100) for f in findings)
    return max(0, round(100 - (deductions / max_weight * 100)))
