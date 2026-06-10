from __future__ import annotations

import argparse

from vulnscanner import __version__
from vulnscanner.config import load_config, resolve_command_defaults
from vulnscanner.diffing import diff_scans
from vulnscanner.reporting import (
    render_diff_report,
    render_history_report,
    render_scan_report,
    write_csv_report,
    write_json_report,
    write_markdown_report,
)
from vulnscanner.scanner import ScannerConfig, VulnScanner
from vulnscanner.storage import find_latest_pair, load_scan_result, save_history_snapshot, list_history


def build_parser(defaults: dict | None = None) -> argparse.ArgumentParser:
    defaults = defaults or {}
    parser = argparse.ArgumentParser(
        prog="vulnscanner",
        description="A small recon style CLI for surfacing weak headers and exposed endpoints.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", help="Path to a JSON config file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    full_parser = subparsers.add_parser("scan", help="Run the full scan flow")
    add_shared_scan_arguments(full_parser, defaults=defaults)

    headers_parser = subparsers.add_parser("headers", help="Check response headers only")
    add_shared_scan_arguments(headers_parser, include_wordlist=False, defaults=defaults)

    paths_parser = subparsers.add_parser("paths", help="Check endpoint exposure only")
    add_shared_scan_arguments(paths_parser, defaults=defaults)

    history_parser = subparsers.add_parser("history", help="List saved reports")
    history_parser.add_argument("--target", default=defaults.get("target"), help="Only show history for one target")
    history_parser.add_argument("--verbose", action="store_true", default=bool(defaults.get("verbose", False)), help="Print more detail")

    diff_parser = subparsers.add_parser("diff", help="Compare two saved reports")
    diff_parser.add_argument("older", nargs="?", default=defaults.get("older"), help="Older report path")
    diff_parser.add_argument("newer", nargs="?", default=defaults.get("newer"), help="Newer report path")
    diff_parser.add_argument("--target", default=defaults.get("target"), help="Use the latest two reports for one target")
    diff_parser.add_argument("--verbose", action="store_true", default=bool(defaults.get("verbose", False)), help="Print more detail")

    return parser


def add_shared_scan_arguments(parser: argparse.ArgumentParser, include_wordlist: bool = True, defaults: dict | None = None) -> None:
    defaults = defaults or {}
    parser.add_argument("target", nargs="?", default=defaults.get("target"), help="URL or hostname to scan")
    parser.add_argument("--timeout", type=float, default=defaults.get("timeout", 5.0), help="Request timeout in seconds")
    parser.add_argument("--threads", type=int, default=defaults.get("threads", 12), help="Worker count for path checks")
    parser.add_argument("--retries", type=int, default=defaults.get("retries", 1), help="Retry count for HTTP requests")
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=bool(defaults.get("insecure", False)),
        help="Skip TLS certificate validation",
    )
    parser.add_argument(
        "--user-agent",
        default=defaults.get("user_agent", "VulnScanner/2.0"),
        help="Custom user agent",
    )
    parser.add_argument(
        "--json-out",
        default=defaults.get("json_out", "io/data.json"),
        help="Path for the JSON report",
    )
    parser.add_argument(
        "--markdown-out",
        default=defaults.get("markdown_out"),
        help="Optional path for a Markdown report",
    )
    parser.add_argument(
        "--csv-out",
        default=defaults.get("csv_out"),
        help="Optional path for a CSV report",
    )
    parser.add_argument(
        "--status",
        action="append",
        type=int,
        dest="statuses",
        default=list(defaults.get("statuses", [])),
        help="HTTP status code to keep. You can pass this more than once.",
    )
    parser.add_argument(
        "--wordlist-file",
        action="append",
        dest="wordlist_files",
        default=list(defaults.get("wordlist_files", [])),
        help="Load extra paths from a text file.",
    )
    parser.add_argument(
        "--no-content-checks",
        action="store_true",
        default=bool(defaults.get("no_content_checks", False)),
        help="Skip content leak checks on text responses.",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=defaults.get("max_body_bytes", 250000),
        help="Largest response body to inspect for content checks.",
    )
    parser.add_argument(
        "--include",
        action="append",
        dest="include_patterns",
        default=list(defaults.get("include_patterns", [])),
        help="Only keep paths that match these glob patterns.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        dest="exclude_patterns",
        default=list(defaults.get("exclude_patterns", [])),
        help="Skip paths that match these glob patterns.",
    )
    parser.add_argument(
        "--min-severity",
        choices=("info", "low", "medium", "high", "critical"),
        default=defaults.get("min_severity"),
        help="Hide header and content findings below this severity.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=bool(defaults.get("quiet", False)),
        help="Suppress the full console report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=bool(defaults.get("verbose", False)),
        help="Print more detail.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        default=bool(defaults.get("no_history", False)),
        help="Skip saving a history snapshot.",
    )
    if include_wordlist:
        parser.add_argument(
            "--path",
            action="append",
            dest="paths",
            default=list(defaults.get("paths", [])),
            help="Extra path to test. You can pass this more than once.",
        )
        parser.add_argument(
            "--max-paths",
            type=int,
            default=defaults.get("max_paths"),
            help="Cap the number of paths checked",
        )
        parser.add_argument(
            "--no-robots",
            action="store_true",
            default=bool(defaults.get("no_robots", False)),
            help="Skip robots.txt path collection",
        )
        parser.add_argument(
            "--no-sitemap",
            action="store_true",
            default=bool(defaults.get("no_sitemap", False)),
            help="Skip sitemap.xml path collection",
        )


def main() -> None:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config")
    config_args, remaining = config_parser.parse_known_args()
    command_name = next((token for token in remaining if token in {"scan", "headers", "paths", "history", "diff"}), None)

    loaded_config, config_path = load_config(config_args.config)
    defaults = resolve_command_defaults(loaded_config, command_name)

    parser = build_parser(defaults=defaults)
    args = parser.parse_args()

    if args.command == "history":
        print(render_history_report(list_history(target=args.target)))
        return

    if args.command == "diff":
        if args.target:
            latest_pair = find_latest_pair(args.target)
            if latest_pair is None:
                parser.error("Need at least two saved reports for that target.")
            older_path, newer_path = latest_pair
        else:
            if not args.older or not args.newer:
                parser.error("diff needs two report paths or a --target value.")
            older_path = args.older
            newer_path = args.newer

        older_result = load_scan_result(older_path)
        newer_result = load_scan_result(newer_path)
        print(render_diff_report(diff_scans(older_result, newer_result), verbose=args.verbose))
        return

    if not args.target:
        parser.error("target is required for scan commands.")

    scanner = VulnScanner(
        ScannerConfig(
            timeout=args.timeout,
            threads=args.threads,
            retries=args.retries,
            verify_tls=not args.insecure,
            user_agent=args.user_agent,
            include_robots=not getattr(args, "no_robots", False),
            include_sitemap=not getattr(args, "no_sitemap", False),
            max_paths=getattr(args, "max_paths", None),
            statuses=set(args.statuses) if args.statuses else None,
            wordlist_files=args.wordlist_files,
            content_checks=not args.no_content_checks,
            max_body_bytes=args.max_body_bytes,
            include_patterns=args.include_patterns,
            exclude_patterns=args.exclude_patterns,
            min_severity=args.min_severity,
        )
    )

    if args.command == "scan":
        result = scanner.full_scan(args.target, extra_paths=args.paths)
        finish_scan_command(args, result)
        return

    if args.command == "headers":
        result = scanner.headers_only(args.target)
        finish_scan_command(args, result)
        return

    if args.command == "paths":
        result = scanner.paths_only(args.target, extra_paths=args.paths)
        finish_scan_command(args, result)
        return


def finish_scan_command(args: argparse.Namespace, result) -> None:
    if not args.quiet:
        print(render_scan_report(result, verbose=args.verbose))

    json_path = write_json_report(result, args.json_out)
    print(f"Saved JSON report to {json_path}")

    if not args.no_history:
        history_path = save_history_snapshot(result)
        print(f"Saved history snapshot to {history_path}")

    if args.markdown_out:
        markdown_path = write_markdown_report(result, args.markdown_out)
        print(f"Saved Markdown report to {markdown_path}")

    if args.csv_out:
        csv_path = write_csv_report(result, args.csv_out)
        print(f"Saved CSV report to {csv_path}")
