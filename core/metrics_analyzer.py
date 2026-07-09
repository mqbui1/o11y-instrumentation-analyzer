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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .schema import METRICS_RULES, IM_TO_APM_LINK_DIMS, SERVICE_CENTRIC_REQUIREMENTS

logger = logging.getLogger(__name__)


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Request failed: {e}")


def _sample_mts(
    api_base: str,
    token: str,
    service: str | None = None,
    environment: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Sample active MTS from the catalog, optionally scoped to service/env.

    Runs two queries and merges results to avoid sampling bias: unfiltered APIs
    tend to return the most-numerous metric type first (e.g. process metrics),
    which can crowd out k8s metrics entirely in the sample.
    """
    # Build base query — try deployment.environment first (OTel convention),
    # fall back to sf_environment if no results. Using OR causes slow full-scans.
    def _make_filters(env_field: str) -> list[str]:
        f = []
        if service:
            f.append(f'sf_service:"{service}"')
        if environment:
            f.append(f'{env_field}:"{environment}"')
        return f

    def _query_mts(filters: list[str], lim: int) -> list[dict]:
        q = " AND ".join(filters)
        data = _api_get(api_base, token, "/v2/metrictimeseries", {"query": q, "limit": lim})
        return data.get("results") or []

    # General sample — majority of the budget
    general_limit = limit * 3 // 4
    results: list[dict] = []
    try:
        results = _query_mts(_make_filters("deployment.environment"), general_limit)
        # If no results with OTel convention, retry with sf_environment
        if not results and environment:
            results = _query_mts(_make_filters("sf_environment"), general_limit)
    except RuntimeError as e:
        logger.warning("MTS catalog query failed: %s", e)

    # K8s-targeted sample — ensures k8s dimensions aren't crowded out
    k8s_limit = limit - len(results)
    if k8s_limit > 0:
        k8s_filters = _make_filters("deployment.environment") + ["k8s.cluster.name:*"]
        try:
            k8s_results = _query_mts(k8s_filters, k8s_limit)
            seen_ids = {m["id"] for m in results if m.get("id")}
            results += [m for m in k8s_results if m.get("id") not in seen_ids]
        except RuntimeError as e:
            logger.debug("K8s MTS query failed (may not have k8s metrics): %s", e)

    return results


def _dim_exists(
    api_base: str,
    token: str,
    dim: str,
    service: str | None,
    environment: str | None,
) -> bool:
    """Return True if any active MTS carries this dimension."""
    base: list[str] = [f"{dim}:*"]
    if service:
        base.append(f'sf_service:"{service}"')

    env_fields = []
    if environment:
        env_fields = ["deployment.environment", "sf_environment"]

    if env_fields:
        for env_field in env_fields:
            q = " AND ".join(base + [f'{env_field}:"{environment}"'])
            try:
                data = _api_get(api_base, token, "/v2/metrictimeseries", {"query": q, "limit": 1})
                if data.get("results"):
                    return True
            except RuntimeError:
                pass
    else:
        q = " AND ".join(base)
        try:
            data = _api_get(api_base, token, "/v2/metrictimeseries", {"query": q, "limit": 1})
            if data.get("results"):
                return True
        except RuntimeError:
            pass
    return False


def _any_dim_exists(
    api_base: str,
    token: str,
    dims: list[str],
    service: str | None,
    environment: str | None,
) -> bool:
    """Return True if any candidate dimension exists on at least one active MTS."""
    return any(_dim_exists(api_base, token, d, service, environment) for d in dims)


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
    """Check whether expected runtime metrics exist for the service (parallel per metric)."""
    results: dict[str, Any] = {}

    def _probe(metric: str) -> bool:
        filters = [f"sf_metric:{metric}"]
        if service:
            filters.append(f'sf_service:"{service}"')
        try:
            data = _api_get(api_base, token, "/v2/metrictimeseries", {
                "query": " AND ".join(filters), "limit": 1,
            })
            return bool(data.get("results"))
        except RuntimeError:
            return False

    all_metrics = [
        (runtime, metric)
        for runtime, names in SERVICE_CENTRIC_REQUIREMENTS["runtime_metrics"]["expected_metrics"].items()
        for metric in names
    ]

    with ThreadPoolExecutor(max_workers=8) as ex:
        probe_results = list(ex.map(lambda t: (t[0], t[1], _probe(t[1])), all_metrics))

    for runtime, metric, found in probe_results:
        bucket = results.setdefault(runtime, {"found": [], "missing": []})
        (bucket["found"] if found else bucket["missing"]).append(metric)

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
    Check for missing dimensions across all active MTS using per-dimension
    existence queries, avoiding sampling bias. A small sample is still fetched
    for metric name / namespace metadata only.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    logger.info("Metrics: checking dimensions across all active MTS (service=%s, env=%s)", service, environment)

    # Small sample for metadata (metric names, namespaces) only
    meta_sample = _sample_mts(api_base, token, service, environment, limit=50)
    metric_names_seen: set[str] = set()
    namespaces_seen: set[str] = set()
    for mts in meta_sample:
        dims = mts.get("dimensions") or {}
        if mn := (mts.get("metric") or mts.get("name")):
            metric_names_seen.add(str(mn))
        if ns := dims.get("namespace"):
            namespaces_seen.add(str(ns))

    # Verify org/env actually has metrics before running per-dimension checks
    if not meta_sample:
        # Try a completely unfiltered check to distinguish no-env-data vs no-metrics
        env_probe_filters: list[str] = []
        if service:
            env_probe_filters.append(f'sf_service:"{service}"')
        probe_q = " AND ".join(env_probe_filters) if env_probe_filters else ""
        try:
            probe = _api_get(api_base, token, "/v2/metrictimeseries",
                             {"query": probe_q or "*", "limit": 1})
        except RuntimeError:
            probe = {}
        if not probe.get("results"):
            return {
                "error": None,
                "mts_sampled": 0,
                "findings": [{"rule": "no_data", "severity": "warning",
                              "message": "No active MTS found matching the filter. "
                                         "Check that metrics are actively ingesting."}],
                "score": 0,
            }

    # Per-dimension existence check across ALL active MTS — run all rules in parallel
    logger.info("Metrics: running per-dimension existence checks for %d rules", len(METRICS_RULES))
    dim_present: dict[str, bool] = {}

    def _check_rule(rule: Any) -> tuple:
        candidates = [rule.name] + rule.alternatives
        found = _any_dim_exists(api_base, token, candidates, service, environment)
        logger.debug("Metrics: %s → %s", rule.name, "found" if found else "missing")
        return rule.name, found

    with ThreadPoolExecutor(max_workers=8) as ex:
        for name, found in ex.map(_check_rule, METRICS_RULES):
            dim_present[name] = found

    # Build findings — binary present/missing (no sampling bias)
    findings: list[dict] = []
    for rule in METRICS_RULES:
        if dim_present[rule.name]:
            continue
        findings.append({
            "dimension": rule.name,
            "alternatives_checked": rule.alternatives,
            "status": "missing",
            "severity": rule.severity,
            "present_pct": 0,
            "missing_pct": 100,
            "mts_checked": "all",
            "related_content": rule.related_content,
            "purpose": rule.purpose,
        })

    # dim_presence with total=1 for RC/service-centric gap checks (binary: 1=present, 0=missing)
    dim_presence: dict[str, int] = {k: (1 if v else 0) for k, v in dim_present.items()}

    rc_gaps = _check_rc_gaps_metrics(dim_presence, 1)
    runtime_check = _check_runtime_metrics(api_base, token, service, environment)
    sc_gaps = _check_service_centric_gaps(dim_presence, 1, runtime_check)
    score = _compute_score(findings, 1)

    return {
        "error": None,
        "mts_sampled": len(meta_sample),
        "metric_names_sample": sorted(metric_names_seen)[:20],
        "namespaces_seen": sorted(namespaces_seen),
        "findings": sorted(findings, key=lambda f: {"critical": 0, "warning": 1, "info": 2}[f["severity"]]),
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
