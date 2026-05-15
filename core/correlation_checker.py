"""
Cross-signal correlation checker — validates that Related Content links
can actually form between APM, IM, and Logs by checking for shared dimension values.
"""
from __future__ import annotations

import logging
from typing import Any

from .schema import RELATED_CONTENT_LINKS

logger = logging.getLogger(__name__)


def check_cross_signal_correlation(
    apm_result: dict[str, Any],
    metrics_result: dict[str, Any],
    logs_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Given analysis results from all three signal types, determine whether
    Related Content links can actually form between them.
    """
    findings: list[dict] = []
    link_status: list[dict] = []

    # ── APM ↔ IM ─────────────────────────────────────────────────────────────
    apm_has_host = _result_has_attr(apm_result, "apm", {"host.name", "host.id", "k8s.pod.name"})
    im_has_host = _result_has_attr(metrics_result, "metrics", {"host.name", "host", "k8s.pod.name"})
    apm_has_env = _result_has_attr(apm_result, "apm", {"deployment.environment"})
    im_has_env = _result_has_attr(metrics_result, "metrics", {"sf_environment", "deployment.environment"})

    apm_im_ok = apm_has_host and im_has_host and apm_has_env and im_has_env
    link_status.append({
        "link": "APM → Infrastructure Monitoring",
        "status": "ok" if apm_im_ok else "broken",
        "severity": "critical" if not apm_im_ok else None,
        "conditions": [
            {"check": "APM spans have host.name/host.id/k8s.pod.name", "pass": apm_has_host},
            {"check": "IM metrics have host.name/host dimension", "pass": im_has_host},
            {"check": "APM spans have deployment.environment", "pass": apm_has_env},
            {"check": "IM metrics have sf_environment/deployment.environment", "pass": im_has_env},
        ],
        "impact": "Service Centric view infrastructure tab will be empty." if not apm_im_ok else None,
        "fix": _apm_im_fix(apm_has_host, im_has_host, apm_has_env, im_has_env) if not apm_im_ok else None,
    })

    # ── APM ↔ Logs ───────────────────────────────────────────────────────────
    apm_has_svc = _result_has_attr(apm_result, "apm", {"service.name"})
    logs_has_svc = _result_has_attr(logs_result, "logs", {"service.name"})
    logs_has_trace = _result_has_attr(logs_result, "logs", {"trace_id"})
    logs_has_env = _result_has_attr(logs_result, "logs", {"deployment.environment"})

    apm_logs_ok = apm_has_svc and logs_has_svc and logs_has_env
    apm_logs_trace_ok = apm_logs_ok and logs_has_trace

    log_mode = logs_result.get("mode", "unknown")
    link_status.append({
        "link": f"APM → Logs ({_log_mode_label(log_mode)})",
        "status": "ok" if apm_logs_ok else ("partial" if apm_has_svc else "broken"),
        "severity": "critical" if not apm_logs_ok else ("warning" if not apm_logs_trace_ok else None),
        "conditions": [
            {"check": "APM spans have service.name", "pass": apm_has_svc},
            {"check": "Logs have service.name", "pass": logs_has_svc},
            {"check": "Logs have deployment.environment", "pass": logs_has_env},
            {"check": "Logs have trace_id (for trace-level linking)", "pass": logs_has_trace},
        ],
        "impact": _apm_logs_impact(apm_logs_ok, apm_logs_trace_ok),
        "fix": _apm_logs_fix(logs_has_svc, logs_has_env, logs_has_trace, log_mode) if not apm_logs_trace_ok else None,
    })

    # ── IM ↔ Logs ────────────────────────────────────────────────────────────
    im_has_host2 = _result_has_attr(metrics_result, "metrics", {"host.name", "host"})
    logs_has_host = _result_has_attr(logs_result, "logs", {"host.name", "host"})

    im_logs_ok = im_has_host2 and logs_has_host
    link_status.append({
        "link": "Infrastructure Monitoring → Logs",
        "status": "ok" if im_logs_ok else "broken",
        "severity": "warning" if not im_logs_ok else None,
        "conditions": [
            {"check": "IM metrics have host.name/host dimension", "pass": im_has_host2},
            {"check": "Logs have host.name/host field", "pass": logs_has_host},
        ],
        "impact": "Host Navigator 'Related Logs' panel will be empty." if not im_logs_ok else None,
        "fix": _im_logs_fix(im_has_host2, logs_has_host) if not im_logs_ok else None,
    })

    # ── Overall assessment ───────────────────────────────────────────────────
    broken = [l for l in link_status if l["status"] == "broken"]
    partial = [l for l in link_status if l["status"] == "partial"]
    ok = [l for l in link_status if l["status"] == "ok"]

    if broken:
        overall = "broken"
    elif partial:
        overall = "partial"
    else:
        overall = "ok"

    # Compute overall data health score
    scores = []
    for result in [apm_result, metrics_result, logs_result]:
        if isinstance(result.get("score"), int):
            scores.append(result["score"])
    combined_score = round(sum(scores) / len(scores)) if scores else 0

    return {
        "overall_status": overall,
        "combined_score": combined_score,
        "links": link_status,
        "broken_count": len(broken),
        "partial_count": len(partial),
        "ok_count": len(ok),
        "summary": _build_summary(link_status, combined_score),
        "top_recommendations": _build_recommendations(link_status, apm_result, metrics_result, logs_result),
    }


def _result_has_attr(result: dict, signal: str, attr_names: set[str], threshold_pct: float = 30.0) -> bool:
    """Check if any of the given attribute names are sufficiently present in a result."""
    if result.get("error") or result.get("mts_sampled", result.get("spans_sampled", result.get("logs_sampled", 1))) == 0:
        return False

    findings = result.get("findings") or []
    # If it's not in findings (missing list), it means it's present
    missing_attrs = {f.get("attribute") or f.get("dimension") or f.get("field") for f in findings}

    for attr in attr_names:
        if attr not in missing_attrs:
            return True
        # Check if it's only partially missing (still present in some)
        for f in findings:
            fname = f.get("attribute") or f.get("dimension") or f.get("field")
            if fname == attr and f.get("present_pct", 0) >= threshold_pct:
                return True
    return False


def _log_mode_label(mode: str) -> str:
    return {
        "unified": "Unified Identity",
        "loc": "Log Observer Connect",
        "mixed": "Unified + LOC",
        "unknown": "Unknown mode",
    }.get(mode, mode)


def _apm_im_fix(apm_has_host: bool, im_has_host: bool, apm_has_env: bool, im_has_env: bool) -> str:
    fixes = []
    if not apm_has_host:
        fixes.append("Add host.name resource attribute to APM instrumentation (set via OTEL_RESOURCE_ATTRIBUTES or SDK resource detector).")
    if not im_has_host:
        fixes.append("Ensure host-level metrics include 'host' or 'host.name' dimension.")
    if not apm_has_env:
        fixes.append("Set deployment.environment in APM spans (OTEL_RESOURCE_ATTRIBUTES=deployment.environment=<env>).")
    if not im_has_env:
        fixes.append("Add sf_environment or deployment.environment dimension to infrastructure metrics.")
    return " ".join(fixes)


def _apm_logs_impact(apm_logs_ok: bool, trace_ok: bool) -> str | None:
    if not apm_logs_ok:
        return "APM 'Related Logs' panel will be empty. Log Observer service filter won't show this service."
    if not trace_ok:
        return "Logs are correlated at service level but not trace level. Individual trace → log linking won't work."
    return None


def _apm_logs_fix(logs_has_svc: bool, logs_has_env: bool, logs_has_trace: bool, mode: str) -> str:
    fixes = []
    if not logs_has_svc:
        if mode == "loc":
            fixes.append("In Splunk Platform, add a field alias or transform to inject service.name into LOC logs.")
        else:
            fixes.append("Include service.name field in all log records.")
    if not logs_has_env:
        fixes.append("Include deployment.environment field in log records.")
    if not logs_has_trace:
        fixes.append("Inject trace_id/span_id into log records using OTel log bridge API or manual instrumentation.")
    return " ".join(fixes)


def _im_logs_fix(im_has_host: bool, logs_has_host: bool) -> str:
    fixes = []
    if not im_has_host:
        fixes.append("Add host or host.name dimension to infrastructure metrics.")
    if not logs_has_host:
        fixes.append("Include host.name or host field in log records.")
    return " ".join(fixes)


def _build_summary(link_status: list[dict], score: int) -> str:
    broken = [l["link"] for l in link_status if l["status"] == "broken"]
    partial = [l["link"] for l in link_status if l["status"] == "partial"]

    parts = [f"Data health score: {score}/100."]
    if broken:
        parts.append(f"Related Content links broken: {', '.join(broken)}.")
    if partial:
        parts.append(f"Partial correlation: {', '.join(partial)}.")
    if not broken and not partial:
        parts.append("All Related Content links are functional.")
    return " ".join(parts)


def _build_recommendations(
    link_status: list[dict],
    apm: dict, metrics: dict, logs: dict,
) -> list[dict]:
    recs = []
    priority = 1

    for link in link_status:
        if link["status"] in ("broken", "partial") and link.get("fix"):
            recs.append({
                "priority": priority,
                "link": link["link"],
                "severity": link.get("severity", "warning"),
                "recommendation": link["fix"],
            })
            priority += 1

    # Add signal-specific top recommendations
    for result, signal in [(apm, "APM"), (metrics, "Metrics"), (logs, "Logs")]:
        for f in (result.get("findings") or [])[:2]:
            if f.get("severity") == "critical" and f.get("status") == "missing":
                attr = f.get("attribute") or f.get("dimension") or f.get("field", "")
                recs.append({
                    "priority": priority,
                    "link": signal,
                    "severity": "critical",
                    "recommendation": f"[{signal}] Add missing attribute '{attr}': {f.get('purpose', '')}",
                })
                priority += 1

    return recs[:10]  # Top 10 recommendations
