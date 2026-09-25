#!/usr/bin/env python3
"""
Splunk Observability Instrumentation Analyzer

Analyzes APM spans, infrastructure metrics, and logs for missing attributes/
dimensions that break Related Content, Service Centric view, and runtime
metrics. Works with both Unified Identity and Log Observer Connect.

Usage:
  python3 analyze.py --realm us1 --token <token> [options]

Examples:
  # Analyze all signals for entire org
  python3 analyze.py --realm us1 --token $TOKEN

  # Scope to a specific service + environment
  python3 analyze.py --realm us1 --token $TOKEN --service my-service --environment production

  # Output as HTML report
  python3 analyze.py --realm us1 --token $TOKEN --format html --output report.html

  # Output all three formats at once
  python3 analyze.py --realm us1 --token $TOKEN --format all --output ./reports/

  # Per-environment breakdown — specific envs
  python3 analyze.py --realm us1 --token $TOKEN --environments prod,staging,dev --format html -o report.html

  # Per-environment breakdown — auto-discover (capped at 20 by default)
  python3 analyze.py --realm us1 --token $TOKEN --breakdown-by-env --format html -o report.html
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import analyze_apm, analyze_logs, analyze_metrics, check_cross_signal_correlation, discover_environments
from report.renderer import build_report, render_html, render_json, render_markdown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze Splunk Observability instrumentation gaps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required connection params
    conn = parser.add_argument_group("connection")
    conn.add_argument("--realm", required=True, help="Splunk Observability realm (e.g. us1, us0, eu0)")
    conn.add_argument("--token", default=os.environ.get("SPLUNK_ACCESS_TOKEN"),
                      help="Splunk Observability API token (or set SPLUNK_ACCESS_TOKEN env var)")

    # Scope
    scope = parser.add_argument_group("scope")
    scope.add_argument("--service", help="Filter analysis to a specific service name")
    scope.add_argument("--environment", "--env", help="Filter analysis to a specific environment")
    scope.add_argument("--lookback-hours", type=int, default=3, metavar="N",
                       help="Lookback window in hours (default: 3)")

    # Sampling
    sampling = parser.add_argument_group("sampling")
    sampling.add_argument("--apm-sample-size", type=int, default=50, metavar="N",
                          help="Number of traces to sample for APM analysis (default: 50)")
    sampling.add_argument("--metrics-sample-size", type=int, default=200, metavar="N",
                          help="Number of MTS to sample for metrics analysis (default: 200)")
    sampling.add_argument("--logs-sample-size", type=int, default=100, metavar="N",
                          help="Number of log records to sample (default: 100)")

    # Signals to analyze
    signals = parser.add_argument_group("signals")
    signals.add_argument("--skip-apm", action="store_true", help="Skip APM trace analysis")
    signals.add_argument("--skip-metrics", action="store_true", help="Skip infrastructure metrics analysis")
    signals.add_argument("--skip-logs", action="store_true", help="Skip log analysis")

    # Splunk Platform (Log Observer Connect)
    loc = parser.add_argument_group("log observer connect (Splunk Platform)")
    loc.add_argument("--splunk-url", default=os.environ.get("SPLUNK_PLATFORM_URL"),
                     metavar="URL",
                     help="Splunk Platform management endpoint "
                          "(e.g. https://prd-p-<stack>.splunkcloud.com:8089). "
                          "Required for log analysis. (or set SPLUNK_PLATFORM_URL env var)")
    loc.add_argument("--splunk-token", default=os.environ.get("SPLUNK_PLATFORM_TOKEN"),
                     metavar="TOKEN",
                     help="Splunk Platform Bearer token with search permissions. "
                          "Create in Splunk Platform: Settings → Tokens. "
                          "(or set SPLUNK_PLATFORM_TOKEN env var)")
    loc.add_argument("--splunk-index", default="*", metavar="INDEX",
                     help="Splunk index to search for logs (default: * = all accessible). "
                          "Used as fallback when --splunk-index-map has no entry for an environment.")
    loc.add_argument("--splunk-index-map", default=None, metavar="MAP",
                     help="Map deployment.environment values to Splunk indexes. "
                          "Format: env1=index1,env2=index2  "
                          "e.g. prod=tiaa_prod_logs,dev=tiaa_dev_logs,staging=tiaa_staging_logs. "
                          "Environments not in the map fall back to --splunk-index.")
    loc.add_argument("--no-verify-ssl", action="store_true",
                     help="Disable SSL certificate verification for Splunk Platform "
                          "(use for self-signed certs in Splunk Enterprise)")

    # Output
    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=["md", "json", "html", "all"], default="md",
                        help="Output format: md (default), json, html, or all")
    output.add_argument("--output", "-o", help="Output file path (or directory if --format all). "
                        "Defaults to stdout for single formats.")

    # Environment breakdown
    breakdown = parser.add_argument_group("breakdown")
    breakdown.add_argument("--breakdown-by-env", action="store_true",
                           help="Run analysis per-environment and produce a breakdown report")
    breakdown.add_argument("--environments", "--envs", metavar="ENV[,ENV...]",
                           help="Comma-separated list of environments to analyze in breakdown mode "
                                "(skips auto-discovery). Implies --breakdown-by-env.")
    breakdown.add_argument("--max-environments", type=int, default=20, metavar="N",
                           help="Max environments to analyze when auto-discovering (default: 20)")

    # Misc
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    return parser.parse_args()


def _parse_index_map(raw: str | None) -> dict[str, str]:
    """Parse 'env1=idx1,env2=idx2' into {env: index} dict."""
    if not raw:
        return {}
    result = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            env, _, idx = pair.partition("=")
            result[env.strip()] = idx.strip()
    return result


def _resolve_splunk_index(args: argparse.Namespace, environment: str | None) -> str:
    """Return the Splunk index to use for this environment."""
    index_map = _parse_index_map(args.splunk_index_map)
    if environment and environment in index_map:
        return index_map[environment]
    return args.splunk_index


def _empty_result(signal: str) -> dict:
    return {
        "error": f"{signal} analysis skipped",
        "score": 0,
        "findings": [],
    }


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.token:
        print("ERROR: --token is required (or set SPLUNK_ACCESS_TOKEN environment variable)", file=sys.stderr)
        return 1

    realm = args.realm
    token = args.token

    print(f"Analyzing instrumentation in realm={realm}" +
          (f", service={args.service}" if args.service else "") +
          (f", environment={args.environment}" if args.environment else "") +
          "...", file=sys.stderr)

    # ── Run analyzers ─────────────────────────────────────────────────────────

    if args.breakdown_by_env or args.environments:
        return _run_breakdown(args, realm, token)

    apm_result, metrics_result, logs_result = _run_signals(args, realm, token)

    # ── Cross-signal correlation ───────────────────────────────────────────────
    print("  [Correlation] checking Related Content links...", file=sys.stderr)
    correlation = check_cross_signal_correlation(apm_result, metrics_result, logs_result)

    overall = correlation.get("overall_status", "unknown")
    score = correlation.get("combined_score", 0)
    print(f"  [Done] overall_status={overall}, combined_score={score}/100", file=sys.stderr)

    # ── Build and render report ────────────────────────────────────────────────
    report = build_report(
        realm=realm,
        apm_result=apm_result,
        metrics_result=metrics_result,
        logs_result=logs_result,
        correlation_result=correlation,
        service=args.service,
        environment=args.environment,
    )
    _render_and_write(args, report)
    return 0 if overall == "ok" else 1


def _run_signals(
    args: argparse.Namespace,
    realm: str,
    token: str,
    environment: str | None = None,
) -> tuple[dict, dict, dict]:
    """Run APM, metrics, and logs analyzers and return their results."""
    env = environment if environment is not None else args.environment

    # APM, metrics, and logs are independent signal types with no data
    # dependency between them — run concurrently instead of sequentially.
    # Confirmed live: this call took 5:47 sequential on its own.
    with ThreadPoolExecutor(max_workers=3) as pool:
        apm_fut = None if args.skip_apm else pool.submit(
            analyze_apm,
            realm=realm, token=token,
            service=args.service, environment=env,
            lookback_hours=args.lookback_hours,
            sample_size=args.apm_sample_size,
        )
        metrics_fut = None if args.skip_metrics else pool.submit(
            analyze_metrics,
            realm=realm, token=token,
            service=args.service, environment=env,
            lookback_hours=args.lookback_hours,
            sample_size=args.metrics_sample_size,
        )
        logs_fut = None if args.skip_logs else pool.submit(
            analyze_logs,
            realm=realm, token=token,
            service=args.service, environment=env,
            lookback_hours=args.lookback_hours,
            sample_size=args.logs_sample_size,
            splunk_url=args.splunk_url,
            splunk_token=args.splunk_token,
            splunk_index=_resolve_splunk_index(args, env),
            verify_ssl=not args.no_verify_ssl,
        )

        apm_result = _empty_result("APM") if apm_fut is None else apm_fut.result()
        metrics_result = _empty_result("Metrics") if metrics_fut is None else metrics_fut.result()
        logs_result = _empty_result("Logs") if logs_fut is None else logs_fut.result()

    if apm_fut is not None:
        spans = apm_result.get("spans_sampled", 0)
        score = apm_result.get("score", 0)
        err = apm_result.get("error")
        if err:
            print(f"    [APM] ERROR: {err}", file=sys.stderr)
        else:
            print(f"    [APM] {spans} spans, score={score}/100", file=sys.stderr)

    if metrics_fut is not None:
        mts = metrics_result.get("mts_sampled", 0)
        score = metrics_result.get("score", 0)
        print(f"    [Metrics] {mts} MTS, score={score}/100", file=sys.stderr)

    if logs_fut is not None:
        logs = logs_result.get("logs_sampled", 0)
        mode = logs_result.get("mode", "unknown")
        score = logs_result.get("score", 0)
        print(f"    [Logs] {logs} records, mode={mode}, score={score}/100", file=sys.stderr)

    return apm_result, metrics_result, logs_result


def _run_breakdown(args: argparse.Namespace, realm: str, token: str) -> int:
    """Run analysis per-environment and produce a breakdown report."""
    if args.environments:
        environments = [e.strip() for e in args.environments.split(",") if e.strip()]
        print(f"  [Environments] using specified: {', '.join(environments)}", file=sys.stderr)
    else:
        print(f"  [Discovery] finding environments...", file=sys.stderr)
        environments = discover_environments(realm, token, max_envs=args.max_environments)
        if not environments:
            print("  [Discovery] no environments found — specify with --environments env1,env2", file=sys.stderr)
            return 1
        print(f"  [Discovery] found {len(environments)} environment(s): {', '.join(environments)}", file=sys.stderr)

    per_env_results: list[dict] = []
    any_broken = False

    for i, env in enumerate(environments, 1):
        print(f"\n  [{i}/{len(environments)}] {env}", file=sys.stderr)
        try:
            apm_result, metrics_result, logs_result = _run_signals(args, realm, token, environment=env)
        except Exception as e:
            print(f"    [ERROR] {e}", file=sys.stderr)
            apm_result = _empty_result("APM")
            metrics_result = _empty_result("Metrics")
            logs_result = _empty_result("Logs")
        correlation = check_cross_signal_correlation(apm_result, metrics_result, logs_result)

        overall = correlation.get("overall_status", "unknown")
        score = correlation.get("combined_score", 0)
        print(f"    [Correlation] overall_status={overall}, combined_score={score}/100", file=sys.stderr)

        if overall != "ok":
            any_broken = True

        per_env_results.append({
            "environment": env,
            "apm": apm_result,
            "metrics": metrics_result,
            "logs": logs_result,
            "correlation": correlation,
        })

    print(f"\n  [Done] analyzed {len(environments)} environment(s)", file=sys.stderr)

    report = build_report(
        realm=realm,
        apm_result=_empty_result("APM"),
        metrics_result=_empty_result("Metrics"),
        logs_result=_empty_result("Logs"),
        correlation_result={"overall_status": "broken" if any_broken else "ok",
                            "combined_score": 0, "links": [], "broken_count": 0,
                            "partial_count": 0, "ok_count": 0, "summary": "",
                            "top_recommendations": []},
        service=args.service,
        environment=None,
        per_env_results=per_env_results,
    )
    _render_and_write(args, report)
    return 1 if any_broken else 0


def _render_and_write(args: argparse.Namespace, report: dict) -> None:
    renderers = {"md": render_markdown, "json": render_json, "html": render_html}
    if args.format == "all":
        out_dir = Path(args.output) if args.output else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        _write_file(out_dir / "report.md", render_markdown(report))
        _write_file(out_dir / "report.json", render_json(report))
        _write_file(out_dir / "report.html", render_html(report))
        print(f"\nReports written to {out_dir}/", file=sys.stderr)
    else:
        content = renderers[args.format](report)
        if args.output:
            _write_file(Path(args.output), content)
            print(f"\nReport written to {args.output}", file=sys.stderr)
        else:
            print(content)


def _write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    print(f"  Wrote {path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
