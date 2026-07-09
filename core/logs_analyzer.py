"""
Logs analyzer — checks log fields for both Unified Identity (native O11y logs)
and Log Observer Connect (Splunk Platform logs linked to O11y).
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from .schema import LOGS_RULES, LOC_RULES

logger = logging.getLogger(__name__)

# Log Observer Connect detection heuristics
_LOC_INDICATOR_FIELDS = {"index", "source", "sourcetype", "_raw", "punct", "linecount"}


def _api_post(api_base: str, token: str, path: str, body: dict) -> dict:
    url = f"{api_base}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Request failed: {e}")


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Request failed: {e}")


def _search_logs(
    api_base: str,
    token: str,
    start_ms: int,
    end_ms: int,
    service: str | None = None,
    environment: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Query Log Observer for recent log records."""
    filters: list[dict] = []
    if service:
        filters.append({"field": "service.name", "values": [service], "type": "field.value"})
    if environment:
        filters.append({
            "OR": [
                {"field": "deployment.environment", "values": [environment], "type": "field.value"},
                {"field": "sf_environment", "values": [environment], "type": "field.value"},
            ]
        })

    body = {
        "searchQuery": {"filters": filters, "keywords": []},
        "startTime": start_ms,
        "endTime": end_ms,
        "limit": limit,
        "sources": [{"type": "logs"}],
    }
    try:
        data = _api_post(api_base, token, "/v1/log/search", body)
        return data.get("results") or data.get("logs") or []
    except RuntimeError as e:
        logger.warning("Log search failed (may not have Log Observer): %s", e)
        return []


def _detect_log_mode(log_records: list[dict]) -> str:
    """
    Detect whether logs are Unified Identity (native O11y) or Log Observer Connect (Splunk Platform).
    Returns: 'unified', 'loc', or 'mixed'
    """
    unified_count = 0
    loc_count = 0
    for record in log_records:
        fields = set((record.get("fields") or record).keys())
        if fields & _LOC_INDICATOR_FIELDS:
            loc_count += 1
        else:
            unified_count += 1

    if loc_count > 0 and unified_count > 0:
        return "mixed"
    if loc_count > 0:
        return "loc"
    return "unified"


def _extract_log_fields(record: dict) -> dict[str, str]:
    """Flatten a log record to a field dict."""
    if "fields" in record and isinstance(record["fields"], dict):
        fields = dict(record["fields"])
    else:
        fields = {k: v for k, v in record.items() if k not in ("body", "message", "_raw")}

    # Normalize common aliases
    for canonical, aliases in [
        ("trace_id", ["traceId", "trace.id", "traceid"]),
        ("span_id", ["spanId", "span.id", "spanid"]),
        ("severity_text", ["level", "log.level", "severity", "loglevel"]),
        ("host.name", ["host", "hostname"]),
        ("timestamp", ["time", "@timestamp", "ts"]),
    ]:
        if canonical not in fields:
            for alias in aliases:
                if alias in fields:
                    fields[canonical] = fields[alias]
                    break

    # Body/message presence
    for body_key in ("body", "message", "_raw", "msg"):
        if record.get(body_key):
            fields["body"] = str(record[body_key])[:1]
            break

    return fields


def analyze_logs(
    realm: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    lookback_hours: int = 3,
    sample_size: int = 100,
) -> dict[str, Any]:
    """
    Sample recent logs and check for missing fields.
    Handles both Unified Identity and Log Observer Connect.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - lookback_hours * 3600 * 1000

    logger.info("Logs: sampling log records (lookback=%dh, service=%s, env=%s)", lookback_hours, service, environment)

    log_records = _search_logs(api_base, token, start_ms, now_ms, service, environment, limit=sample_size)

    if not log_records:
        return {
            "error": None,
            "mode": "unknown",
            "logs_sampled": 0,
            "findings": [{"rule": "no_data", "severity": "warning",
                          "message": "No log records found. Log Observer may not be configured, "
                                     "or no logs were ingested in the lookback window."}],
            "score": 0,
        }

    log_mode = _detect_log_mode(log_records)
    logger.info("Logs: sampled %d records, detected mode=%s", len(log_records), log_mode)

    # Choose rules based on detected mode
    rules = LOC_RULES if log_mode == "loc" else LOGS_RULES

    total = len(log_records)
    field_presence: dict[str, int] = defaultdict(int)
    services_seen: set[str] = set()
    trace_id_coverage = 0

    for record in log_records:
        fields = _extract_log_fields(record)
        for rule in rules:
            candidates = [rule.name] + rule.alternatives
            if any(fields.get(c) for c in candidates):
                field_presence[rule.name] += 1
        if svc := fields.get("service.name"):
            services_seen.add(svc)
        if fields.get("trace_id"):
            trace_id_coverage += 1

    # Build findings
    findings: list[dict] = []
    for rule in rules:
        present = field_presence[rule.name]
        pct = round(present / total * 100, 1)
        missing_pct = 100 - pct

        if missing_pct == 0:
            continue

        if missing_pct == 100:
            sev = rule.severity
            status = "missing"
        elif missing_pct >= 50:
            sev = rule.severity
            status = "partial"
        else:
            sev = "info"
            status = "partial"

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

    # Trace correlation coverage
    trace_pct = round(trace_id_coverage / total * 100, 1)
    rc_gaps = _check_rc_gaps_logs(field_presence, total, log_mode)

    # LOC-specific checks
    loc_findings = []
    if log_mode in ("loc", "mixed"):
        loc_findings = _check_loc_specific(log_records)

    score = _compute_score(findings, total)

    return {
        "error": None,
        "mode": log_mode,
        "mode_description": {
            "unified": "Unified Identity (native Splunk Observability logs)",
            "loc": "Log Observer Connect (Splunk Platform logs)",
            "mixed": "Mixed — both native and Splunk Platform logs detected",
            "unknown": "Could not determine log mode",
        }.get(log_mode, log_mode),
        "logs_sampled": total,
        "services_seen": sorted(services_seen),
        "trace_id_coverage_pct": trace_pct,
        "findings": sorted(findings, key=lambda f: ({"critical": 0, "warning": 1, "info": 2}[f["severity"]], -f["missing_pct"])),
        "related_content_gaps": rc_gaps,
        "loc_findings": loc_findings,
        "score": score,
    }


def _check_rc_gaps_logs(field_presence: dict[str, int], total: int, mode: str) -> list[dict]:
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
            "impact": "Logs cannot be correlated to APM services. "
                      "Log Observer service filter will not work.",
        })

    if not _has("deployment.environment"):
        gaps.append({
            "link": "Logs → APM / IM",
            "severity": "critical",
            "missing": ["deployment.environment"],
            "impact": "Logs cannot be scoped to environment. "
                      "Related Content links from APM to logs will fail.",
        })

    if not _has("trace_id"):
        gaps.append({
            "link": "Logs → APM (trace linking)",
            "severity": "warning",
            "missing": ["trace_id"],
            "impact": "Individual log records cannot be linked to specific traces. "
                      "Trace view 'Related Logs' panel will be empty.",
        })

    if not (_has("host.name") or _has("host")):
        gaps.append({
            "link": "Logs → Infrastructure Monitoring",
            "severity": "warning",
            "missing": ["host.name / host"],
            "impact": "Logs cannot be correlated to host-level metrics. "
                      "Host Navigator 'Related Logs' will be empty.",
        })

    return gaps


def _check_loc_specific(log_records: list[dict]) -> list[dict]:
    """Log Observer Connect specific checks."""
    findings = []
    has_source = any(
        (r.get("fields") or r).get("source") or (r.get("fields") or r).get("sourcetype")
        for r in log_records
    )
    has_index = any((r.get("fields") or r).get("index") for r in log_records)

    if not has_source:
        findings.append({
            "check": "LOC source/sourcetype",
            "severity": "info",
            "message": "source/sourcetype fields not detected in LOC logs — "
                       "confirm Splunk Platform field extraction is configured.",
        })

    # Check for service.name in LOC logs (often missing since Splunk doesn't inject it)
    has_service = any(
        (r.get("fields") or r).get("service.name")
        for r in log_records
    )
    if not has_service:
        findings.append({
            "check": "LOC service.name injection",
            "severity": "critical",
            "message": "service.name not found in Log Observer Connect logs. "
                       "Configure a field alias or transform in Splunk Platform to inject "
                       "service.name before forwarding to Observability Cloud.",
        })

    return findings


def _compute_score(findings: list[dict], total: int) -> int:
    if total == 0:
        return 0
    weights = {"critical": 3, "warning": 2, "info": 1}
    max_weight = sum(weights[r.severity] for r in LOGS_RULES)
    deductions = 0
    for f in findings:
        w = weights.get(f["severity"], 1)
        deductions += w * (f["missing_pct"] / 100)
    return max(0, round(100 - (deductions / max_weight * 100)))
