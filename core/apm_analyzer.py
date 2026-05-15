"""
APM signal analyzer — samples traces and spans to identify missing attributes.
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

from .schema import APM_RULES, APM_TO_IM_LINK_ATTRS, APM_TO_LOGS_LINK_ATTRS, AttributeRule

logger = logging.getLogger(__name__)

_GRAPHQL_TRACE_SEARCH = """
mutation searchTraces($query: String!, $limit: Int!, $startMs: Long!, $endMs: Long!) {
  getAnalyticsSearch(
    query: $query
    startTimeMs: $startMs
    endTimeMs: $endMs
    limit: $limit
    type: TRACE
  ) {
    sections {
      sectionType
      legacyTraceExamples {
        traceId
        spans {
          spanId
          parentSpanId
          serviceName
          operationName
          startTimeMs
          durationMs
          tags { key value }
          attributes { key value }
          resourceAttributes { key value }
        }
      }
    }
  }
}
"""


def _graphql_post(app_base: str, token: str, query: str, variables: dict) -> dict:
    url = f"{app_base}/api/v2/graphql"
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _search_traces(
    app_base: str,
    token: str,
    start_ms: int,
    end_ms: int,
    service: str | None = None,
    environment: str | None = None,
    limit: int = 20,
) -> list[dict]:
    filters = []
    if service:
        filters.append(f'service:"{service}"')
    if environment:
        filters.append(f'environment:"{environment}"')
    query = " AND ".join(filters) if filters else "*"

    payload = _graphql_post(app_base, token, _GRAPHQL_TRACE_SEARCH, {
        "query": query, "limit": limit,
        "startMs": start_ms, "endMs": end_ms,
    })
    traces = []
    for section in (payload.get("data") or {}).get("getAnalyticsSearch", {}).get("sections") or []:
        if section.get("sectionType") == "traceExamples":
            traces.extend(section.get("legacyTraceExamples") or [])
    return traces


def _collect_span_attrs(span: dict) -> dict[str, str]:
    """Flatten all attribute sources from a span into a single dict."""
    attrs: dict[str, str] = {}
    for source in ("tags", "attributes", "resourceAttributes"):
        for kv in span.get(source) or []:
            k, v = str(kv.get("key") or ""), str(kv.get("value") or "")
            if k:
                attrs[k] = v
    # serviceName is a top-level field
    if span.get("serviceName"):
        attrs.setdefault("service.name", str(span["serviceName"]))
    return attrs


def analyze_apm(
    realm: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    lookback_hours: int = 3,
    sample_size: int = 50,
) -> dict[str, Any]:
    """
    Sample recent traces and check spans for missing/present attributes.
    Returns a structured findings dict.
    """
    app_base = f"https://app.{realm}.signalfx.com"
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - lookback_hours * 3600 * 1000

    logger.info("APM: sampling traces (lookback=%dh, service=%s, env=%s)", lookback_hours, service, environment)

    try:
        traces = _search_traces(app_base, token, start_ms, now_ms, service, environment, limit=sample_size)
    except RuntimeError as e:
        return {"error": str(e), "traces_sampled": 0, "findings": [], "score": 0}

    if not traces:
        return {
            "error": None,
            "traces_sampled": 0,
            "findings": [{"rule": "no_data", "severity": "critical",
                          "message": "No traces found in the lookback window. APM data may not be ingesting."}],
            "score": 0,
        }

    # Collect all spans across sampled traces
    all_spans: list[dict[str, str]] = []
    services_seen: set[str] = set()
    environments_seen: set[str] = set()

    for trace in traces:
        for span in trace.get("spans") or []:
            attrs = _collect_span_attrs(span)
            all_spans.append(attrs)
            if svc := attrs.get("service.name"):
                services_seen.add(svc)
            if env := attrs.get("deployment.environment"):
                environments_seen.add(env)

    total_spans = len(all_spans)
    logger.info("APM: sampled %d traces, %d spans across %d service(s)", len(traces), total_spans, len(services_seen))

    # Check each rule across all sampled spans
    findings: list[dict] = []
    attr_presence: dict[str, int] = defaultdict(int)  # attr -> count of spans that have it

    for span_attrs in all_spans:
        for rule in APM_RULES:
            candidates = [rule.name] + rule.alternatives
            if any(span_attrs.get(c) for c in candidates):
                attr_presence[rule.name] += 1

    for rule in APM_RULES:
        present = attr_presence[rule.name]
        pct = round(present / total_spans * 100, 1) if total_spans else 0
        missing_pct = 100 - pct

        if missing_pct == 0:
            continue

        # Determine finding severity — missing 100% is worse than partial
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
            "attribute": rule.name,
            "alternatives_checked": rule.alternatives,
            "status": status,
            "severity": sev,
            "present_pct": pct,
            "missing_pct": missing_pct,
            "spans_checked": total_spans,
            "related_content": rule.related_content,
            "purpose": rule.purpose,
        })

    # Related Content gap analysis
    rc_gaps = _check_rc_gaps_apm(attr_presence, total_spans)

    # Compute score: 0-100, weighted by severity
    score = _compute_score(findings, total_spans)

    return {
        "error": None,
        "traces_sampled": len(traces),
        "spans_sampled": total_spans,
        "services_seen": sorted(services_seen),
        "environments_seen": sorted(environments_seen),
        "findings": sorted(findings, key=lambda f: ({"critical": 0, "warning": 1, "info": 2}[f["severity"]], -f["missing_pct"])),
        "related_content_gaps": rc_gaps,
        "score": score,
    }


def _check_rc_gaps_apm(attr_presence: dict[str, int], total: int) -> list[dict]:
    gaps = []
    if total == 0:
        return gaps

    def _has(name: str, threshold: float = 0.5) -> bool:
        return attr_presence.get(name, 0) / total >= threshold

    # APM → IM link
    host_ok = _has("host.name") or _has("host.id") or _has("k8s.pod.name")
    if not host_ok:
        gaps.append({
            "link": "APM → Infrastructure Monitoring",
            "severity": "critical",
            "missing": ["host.name / host.id / k8s.pod.name"],
            "impact": "Service Centric view will not show host/container/K8s infrastructure tiles. "
                      "Related Content panel will not link to IM.",
        })

    # APM → Logs link
    env_ok = _has("deployment.environment")
    svc_ok = _has("service.name")
    if not env_ok or not svc_ok:
        missing = []
        if not svc_ok:
            missing.append("service.name")
        if not env_ok:
            missing.append("deployment.environment")
        gaps.append({
            "link": "APM → Logs",
            "severity": "critical",
            "missing": missing,
            "impact": "Related Content will not link traces to Log Observer or Log Observer Connect.",
        })

    return gaps


def _compute_score(findings: list[dict], total_spans: int) -> int:
    if total_spans == 0:
        return 0
    weights = {"critical": 3, "warning": 2, "info": 1}
    max_weight = sum(weights[r.severity] for r in APM_RULES)
    deductions = 0
    for f in findings:
        w = weights.get(f["severity"], 1)
        deductions += w * (f["missing_pct"] / 100)
    score = max(0, round(100 - (deductions / max_weight * 100)))
    return score
