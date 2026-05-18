"""
Metrics (IM) analyzer — samples MTS catalog to identify missing dimensions.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from typing import Any

from .schema import METRICS_RULES, IM_TO_APM_LINK_DIMS, SERVICE_CENTRIC_REQUIREMENTS

logger = logging.getLogger(__name__)


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _sample_mts(
    api_base: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Sample active MTS from the catalog, optionally scoped to service/env."""
    filters = []
    if service:
        filters.append(f'sf_service:"{service}"')
    if environment:
        filters.append(f'sf_environment:"{environment}" OR deployment.environment:"{environment}" OR k8s.cluster.name:"{environment}"')

    query = " AND ".join(filters)
    try:
        data = _api_get(api_base, token, "/v2/metrictimeseries", {
            "query": query, "limit": limit,
        })
        return data.get("results") or []
    except RuntimeError as e:
        logger.warning("MTS catalog query failed: %s", e)
        return []


def _sample_metrics_usage(api_base: str, token: str, lookback: str = "P1D") -> list[dict]:
    """Sample metrics usage breakdown for custom/high-volume metrics."""
    try:
        data = _api_get(api_base, token, "/v2/metrics-usage/metrics", {
            "query": "sf_isBilled:true", "limit": 100,
        })
        return data.get("results") or []
    except RuntimeError as e:
        logger.warning("Metrics usage query failed: %s", e)
        return []


def _check_runtime_metrics(api_base: str, token: str, service: str | None, environment: str | None) -> dict:
    """Check whether expected runtime metrics exist for the service."""
    results: dict[str, Any] = {}
    for runtime, metric_names in SERVICE_CENTRIC_REQUIREMENTS["runtime_metrics"]["expected_metrics"].items():
        found = []
        missing = []
        for metric in metric_names:
            filters = [f"sf_metric:{metric}"]
            if service:
                filters.append(f'sf_service:"{service}"')
            try:
                data = _api_get(api_base, token, "/v2/metrictimeseries", {
                    "query": " AND ".join(filters), "limit": 1,
                })
                if data.get("results"):
                    found.append(metric)
                else:
                    missing.append(metric)
            except RuntimeError:
                missing.append(metric)
        results[runtime] = {"found": found, "missing": missing}
    return results


def analyze_metrics(
    realm: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    lookback_hours: int = 3,
    sample_size: int = 200,
) -> dict[str, Any]:
    """
    Sample MTS catalog and check for missing dimensions.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    logger.info("Metrics: sampling MTS catalog (service=%s, env=%s)", service, environment)

    mts_list = _sample_mts(api_base, token, service, environment, limit=sample_size)

    if not mts_list:
        return {
            "error": None,
            "mts_sampled": 0,
            "findings": [{"rule": "no_data", "severity": "warning",
                          "message": "No active MTS found matching the filter. "
                                     "Check that metrics are actively ingesting."}],
            "score": 0,
        }

    total = len(mts_list)
    logger.info("Metrics: sampled %d MTS", total)

    # Count presence of each dimension across sampled MTS
    dim_presence: dict[str, int] = defaultdict(int)
    metric_names_seen: set[str] = set()
    namespaces_seen: set[str] = set()

    for mts in mts_list:
        dims = mts.get("dimensions") or {}
        for rule in METRICS_RULES:
            candidates = [rule.name] + rule.alternatives
            if any(dims.get(c) for c in candidates):
                dim_presence[rule.name] += 1
        if mn := (mts.get("metric") or mts.get("name")):
            metric_names_seen.add(str(mn))
        if ns := dims.get("namespace"):
            namespaces_seen.add(str(ns))

    # Build findings
    findings: list[dict] = []
    for rule in METRICS_RULES:
        present = dim_presence[rule.name]
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
            "dimension": rule.name,
            "alternatives_checked": rule.alternatives,
            "status": status,
            "severity": sev,
            "present_pct": pct,
            "missing_pct": missing_pct,
            "mts_checked": total,
            "related_content": rule.related_content,
            "purpose": rule.purpose,
        })

    # Related Content gap check
    rc_gaps = _check_rc_gaps_metrics(dim_presence, total)

    # Runtime metrics presence
    runtime_check = _check_runtime_metrics(api_base, token, service, environment)

    # Service Centric view assessment
    sc_gaps = _check_service_centric_gaps(dim_presence, total, runtime_check)

    score = _compute_score(findings, total)

    return {
        "error": None,
        "mts_sampled": total,
        "metric_names_sample": sorted(metric_names_seen)[:20],
        "namespaces_seen": sorted(namespaces_seen),
        "findings": sorted(findings, key=lambda f: ({"critical": 0, "warning": 1, "info": 2}[f["severity"]], -f["missing_pct"])),
        "related_content_gaps": rc_gaps,
        "service_centric_gaps": sc_gaps,
        "runtime_metrics": runtime_check,
        "score": score,
    }


def _check_rc_gaps_metrics(dim_presence: dict[str, int], total: int) -> list[dict]:
    gaps = []
    if total == 0:
        return gaps

    def _has(name: str, threshold: float = 0.5) -> bool:
        return dim_presence.get(name, 0) / total >= threshold

    host_ok = _has("host.name") or _has("host") or _has("aws_private_dns_name") or _has("instance_name") or _has("azure_computer_name")
    if not host_ok:
        gaps.append({
            "link": "Infrastructure Monitoring → APM / Logs",
            "severity": "critical",
            "missing": ["host.name / host"],
            "impact": "Host Navigator cannot correlate to APM services or logs. "
                      "Related Content links will be broken.",
        })

    env_ok = _has("sf_environment") or _has("deployment.environment") or _has("k8s.cluster.name") or _has("kubernetes_cluster")
    if not env_ok:
        gaps.append({
            "link": "Infrastructure Monitoring → APM",
            "severity": "critical",
            "missing": ["sf_environment / deployment.environment"],
            "impact": "Metrics cannot be scoped to an environment. "
                      "Service Centric view infrastructure tab will be empty.",
        })

    # sf_service (or service.name) must be present on K8s/host metrics for IM→APM
    # Related Content to work. This is the primary linking field — without it the
    # Host Navigator cannot resolve which APM service a host/pod belongs to.
    svc_ok = _has("sf_service") or _has("service.name")
    if not svc_ok:
        gaps.append({
            "link": "Infrastructure Monitoring → APM",
            "severity": "warning",
            "missing": ["sf_service / service.name"],
            "impact": "Host Navigator and K8s Navigator cannot link to APM service context. "
                      "The IM→APM Related Content tile will not appear. "
                      "Note: service.name is mapped to sf_service at ingest — either is acceptable.",
        })

    return gaps


def _check_service_centric_gaps(
    dim_presence: dict[str, int],
    total: int,
    runtime_check: dict,
) -> list[dict]:
    gaps = []
    if total == 0:
        return gaps

    def _has(name: str, threshold: float = 0.3) -> bool:
        return dim_presence.get(name, 0) / total >= threshold

    # Infrastructure metrics in Service Centric
    if not (_has("host.name") or _has("host") or _has("k8s.pod.name") or _has("kubernetes_pod_name")):
        gaps.append({
            "check": "Infrastructure metrics in Service Centric view",
            "severity": "critical",
            "issue": "host.name/host dimension missing — infrastructure tab will be empty",
            "fix": "Add host.name dimension to all host-level metrics",
        })

    # Runtime metrics
    all_missing = True
    for runtime, result in runtime_check.items():
        if result["found"]:
            all_missing = False
    if all_missing:
        gaps.append({
            "check": "Runtime metrics in Service Centric view",
            "severity": "warning",
            "issue": "No runtime metrics found (JVM, .NET, Node.js). "
                     "Runtime tab in Service Centric view will be empty.",
            "fix": "Enable OTel runtime instrumentation or send equivalent metric names "
                   "with service.name and deployment.environment dimensions.",
        })

    return gaps


def _compute_score(findings: list[dict], total: int) -> int:
    if total == 0:
        return 0
    weights = {"critical": 3, "warning": 2, "info": 1}
    max_weight = sum(weights[r.severity] for r in METRICS_RULES)
    deductions = 0
    for f in findings:
        w = weights.get(f["severity"], 1)
        deductions += w * (f["missing_pct"] / 100)
    return max(0, round(100 - (deductions / max_weight * 100)))
