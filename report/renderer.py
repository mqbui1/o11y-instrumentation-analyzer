"""
Output renderers for instrumentation analysis results.
Supports Markdown, JSON, and HTML output formats.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


# ── Markdown ─────────────────────────────────────────────────────────────────

def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    meta = report.get("meta", {})
    correlation = report.get("correlation", {})
    apm = report.get("apm", {})
    metrics = report.get("metrics", {})
    logs = report.get("logs", {})

    lines += [
        "# Splunk Observability Instrumentation Analysis",
        "",
        f"**Generated:** {meta.get('generated_at', 'unknown')}",
        f"**Realm:** {meta.get('realm', 'unknown')}",
    ]
    if meta.get("service"):
        lines.append(f"**Service filter:** `{meta['service']}`")
    if meta.get("environment"):
        lines.append(f"**Environment filter:** `{meta['environment']}`")
    lines.append("")

    # ── Overall status ────────────────────────────────────────────────────────
    score = correlation.get("combined_score", 0)
    overall = correlation.get("overall_status", "unknown")
    score_bar = _score_bar(score)
    lines += [
        "## Overall Data Health",
        "",
        f"**Score:** {score}/100 {score_bar}",
        f"**Related Content Status:** {_status_badge(overall)}",
        "",
        f"> {correlation.get('summary', '')}",
        "",
    ]

    # ── Related Content links ─────────────────────────────────────────────────
    lines += ["## Related Content Link Status", ""]
    for link in correlation.get("links", []):
        icon = "✓" if link["status"] == "ok" else ("⚠" if link["status"] == "partial" else "✗")
        lines.append(f"### {icon} {link['link']} — `{link['status'].upper()}`")
        lines.append("")
        for cond in link.get("conditions", []):
            mark = "- [x]" if cond["pass"] else "- [ ]"
            lines.append(f"{mark} {cond['check']}")
        if link.get("impact"):
            lines.append(f"\n**Impact:** {link['impact']}")
        if link.get("fix"):
            lines.append(f"\n**Fix:** {link['fix']}")
        lines.append("")

    # ── Top recommendations ───────────────────────────────────────────────────
    recs = correlation.get("top_recommendations", [])
    if recs:
        lines += ["## Top Recommendations", ""]
        for rec in recs:
            sev_label = f"[{rec.get('severity', 'info').upper()}]"
            lines.append(f"{rec['priority']}. **{sev_label} {rec['link']}** — {rec['recommendation']}")
        lines.append("")

    # ── Per-signal sections ───────────────────────────────────────────────────
    lines += _markdown_signal_section("APM", apm, "attribute", "spans_sampled")
    lines += _markdown_signal_section("Infrastructure Metrics", metrics, "dimension", "mts_sampled")
    lines += _markdown_signal_section("Logs", logs, "field", "logs_sampled")

    return "\n".join(lines)


def _markdown_signal_section(title: str, result: dict, key_name: str, count_key: str) -> list[str]:
    lines: list[str] = [f"## {title}", ""]

    if result.get("error"):
        lines += [f"**Error:** {result['error']}", ""]
        return lines

    sampled = result.get(count_key, result.get("traces_sampled", 0))
    score = result.get("score", 0)
    lines.append(f"**Score:** {score}/100  |  **Sampled:** {sampled:,}")

    if title == "APM":
        if result.get("services_seen"):
            lines.append(f"**Services:** {', '.join(result['services_seen'])}")
        if result.get("environments_seen"):
            lines.append(f"**Environments:** {', '.join(result['environments_seen'])}")
    elif title == "Logs":
        lines.append(f"**Mode:** {result.get('mode_description', result.get('mode', 'unknown'))}")
        if result.get("services_seen"):
            lines.append(f"**Services:** {', '.join(result['services_seen'])}")
        lines.append(f"**Trace ID coverage:** {result.get('trace_id_coverage_pct', 0)}%")
    lines.append("")

    findings = result.get("findings", [])
    if not findings:
        lines += ["All checked attributes/dimensions are present.", ""]
        return lines

    # Group by severity
    for sev in ("critical", "warning", "info"):
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue
        lines.append(f"### {sev.capitalize()} findings")
        lines.append("")
        lines.append(f"| {key_name.capitalize()} | Status | Present | Missing | Purpose |")
        lines.append("|---|---|---|---|---|")
        for f in sev_findings:
            attr = f.get(key_name, f.get("attribute", f.get("dimension", f.get("field", ""))))
            status = f.get("status", "")
            present_pct = f"{f.get('present_pct', 0)}%"
            missing_pct = f"{f.get('missing_pct', 0)}%"
            purpose = f.get("purpose", "")[:80]
            lines.append(f"| `{attr}` | {status} | {present_pct} | {missing_pct} | {purpose} |")
        lines.append("")

    # RC gaps
    rc_gaps = result.get("related_content_gaps", [])
    if rc_gaps:
        lines += ["### Related Content gaps", ""]
        for gap in rc_gaps:
            lines.append(f"- **{gap['link']}** [{gap['severity'].upper()}]: {gap['impact']}")
        lines.append("")

    return lines


def _score_bar(score: int) -> str:
    filled = round(score / 10)
    return "█" * filled + "░" * (10 - filled)


def _status_badge(status: str) -> str:
    return {"ok": "OK", "partial": "PARTIAL", "broken": "BROKEN", "unknown": "UNKNOWN"}.get(status, status.upper())


# ── JSON ──────────────────────────────────────────────────────────────────────

def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)


# ── HTML ──────────────────────────────────────────────────────────────────────

def render_html(report: dict[str, Any]) -> str:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "report.html")
    with open(template_path, encoding="utf-8") as f:
        template = f.read()

    report_json = json.dumps(report, indent=2, default=str)
    return template.replace("__REPORT_JSON__", report_json)


# ── Report builder ────────────────────────────────────────────────────────────

def build_report(
    realm: str,
    apm_result: dict[str, Any],
    metrics_result: dict[str, Any],
    logs_result: dict[str, Any],
    correlation_result: dict[str, Any],
    service: str | None = None,
    environment: str | None = None,
) -> dict[str, Any]:
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "realm": realm,
            "service": service,
            "environment": environment,
            "tool": "o11y-instrumentation-analyzer",
        },
        "correlation": correlation_result,
        "apm": apm_result,
        "metrics": metrics_result,
        "logs": logs_result,
    }
