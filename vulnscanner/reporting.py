from __future__ import annotations

import csv
import json
from pathlib import Path

from vulnscanner.diffing import ScanDiff
from vulnscanner.models import ScanResult


def render_scan_report(result: ScanResult, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append("")
    lines.append("VulnScanner")
    lines.append("=" * 50)
    lines.append(f"Target: {result.target}")
    lines.append(f"Duration: {result.duration_seconds}s")
    lines.append(f"Issues: {result.issue_count}")
    if verbose:
        lines.append(f"Started: {result.started_at.isoformat()}")
        lines.append(f"Finished: {result.finished_at.isoformat()}")

    if result.fingerprint:
        lines.append("")
        lines.append("Fingerprint")
        lines.append("=" * 50)
        lines.append(f"Final URL: {result.fingerprint.final_url}")
        lines.append(f"Status: {result.fingerprint.status}")
        if result.fingerprint.server:
            lines.append(f"Server: {result.fingerprint.server}")
        if result.fingerprint.powered_by:
            lines.append(f"X Powered By: {result.fingerprint.powered_by}")
        if result.fingerprint.content_type:
            lines.append(f"Content Type: {result.fingerprint.content_type}")
        if result.fingerprint.title:
            lines.append(f"Title: {result.fingerprint.title}")
        if result.fingerprint.technologies:
            lines.append(f"Technologies: {', '.join(result.fingerprint.technologies)}")

    lines.append("")
    lines.append("Header Findings")
    lines.append("=" * 50)
    if result.header_findings:
        for finding in result.header_findings:
            lines.append(f"[{finding.severity.upper()}] {finding.name}: {finding.detail}")
    else:
        lines.append("No header issues found.")

    lines.append("")
    lines.append("Endpoint Findings")
    lines.append("=" * 50)
    if result.endpoint_findings:
        for finding in result.endpoint_findings:
            title_text = f" | {finding.title}" if finding.title else ""
            source_text = f" | source={finding.source}" if verbose else ""
            lines.append(f"[{finding.status}] {finding.url} | {finding.length} bytes | {finding.content_type}{title_text}{source_text}")
    else:
        lines.append("No interesting endpoints found.")

    lines.append("")
    lines.append("Content Findings")
    lines.append("=" * 50)
    if result.content_findings:
        for finding in result.content_findings:
            lines.append(
                f"[{finding.severity.upper()}] {finding.url} | {finding.kind} | {finding.detail} | {finding.evidence}"
            )
    else:
        lines.append("No content issues found.")

    if result.notes:
        lines.append("")
        lines.append("Notes")
        lines.append("=" * 50)
        lines.extend(result.notes)

    return "\n".join(lines) + "\n"


def write_json_report(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=4), encoding="utf-8")
    return path


def write_markdown_report(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# VulnScanner Report",
        "",
        f"- Target: `{result.target}`",
        f"- Duration: `{result.duration_seconds}s`",
        f"- Issues: `{result.issue_count}`",
    ]

    if result.fingerprint:
        lines.extend(
            [
                "",
                "## Fingerprint",
                f"- Final URL: `{result.fingerprint.final_url}`",
                f"- Status: `{result.fingerprint.status}`",
                f"- Server: `{result.fingerprint.server or 'n/a'}`",
                f"- X Powered By: `{result.fingerprint.powered_by or 'n/a'}`",
                f"- Content Type: `{result.fingerprint.content_type or 'n/a'}`",
                f"- Title: `{result.fingerprint.title or 'n/a'}`",
                f"- Technologies: `{', '.join(result.fingerprint.technologies) or 'n/a'}`",
            ]
        )

    lines.extend(["", "## Header Findings"])
    if result.header_findings:
        for finding in result.header_findings:
            lines.append(f"- `{finding.severity}` {finding.name}: {finding.detail}")
    else:
        lines.append("- None")

    lines.extend(["", "## Endpoint Findings"])
    if result.endpoint_findings:
        for finding in result.endpoint_findings:
            lines.append(f"- `{finding.status}` {finding.url} [{finding.source}]")
    else:
        lines.append("- None")

    lines.extend(["", "## Content Findings"])
    if result.content_findings:
        for finding in result.content_findings:
            lines.append(f"- `{finding.severity}` {finding.url} {finding.kind}: {finding.evidence}")
    else:
        lines.append("- None")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_csv_report(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["section", "severity", "kind", "url", "status", "detail", "evidence"])

        for item in result.header_findings:
            writer.writerow(["header", item.severity, item.name, "", "", item.detail, ""])

        for item in result.endpoint_findings:
            writer.writerow(
                ["endpoint", "", item.source, item.url, item.status, item.content_type, item.title]
            )

        for item in result.content_findings:
            writer.writerow(
                ["content", item.severity, item.kind, item.url, "", item.detail, item.evidence]
            )

    return path


def render_history_report(paths: list[Path]) -> str:
    lines = ["", "Saved Reports", "=" * 50]
    if not paths:
        lines.append("No saved reports found.")
        return "\n".join(lines) + "\n"

    for path in paths:
        lines.append(str(path))
    return "\n".join(lines) + "\n"


def render_diff_report(diff: ScanDiff, verbose: bool = False) -> str:
    lines = ["", "Scan Diff", "=" * 50]
    lines.append(f"Older Target: {diff.older_target}")
    lines.append(f"Newer Target: {diff.newer_target}")

    if diff.note:
        lines.append("")
        lines.append("Note")
        lines.append("=" * 50)
        lines.append(diff.note)

    lines.append("")
    lines.append("Technology Changes")
    lines.append("=" * 50)
    if diff.added_technologies:
        lines.append(f"Added: {', '.join(diff.added_technologies)}")
    if diff.removed_technologies:
        lines.append(f"Removed: {', '.join(diff.removed_technologies)}")
    if not diff.added_technologies and not diff.removed_technologies:
        lines.append("No technology changes.")

    lines.append("")
    lines.append("New Header Findings")
    lines.append("=" * 50)
    if diff.added_headers:
        for item in diff.added_headers:
            lines.append(f"[{item.severity.upper()}] {item.name}: {item.detail}")
    else:
        lines.append("No new header findings.")

    lines.append("")
    lines.append("Resolved Header Findings")
    lines.append("=" * 50)
    if diff.resolved_headers:
        for item in diff.resolved_headers:
            lines.append(f"[{item.severity.upper()}] {item.name}: {item.detail}")
    else:
        lines.append("No resolved header findings.")

    lines.append("")
    lines.append("New Endpoints")
    lines.append("=" * 50)
    if diff.added_endpoints:
        for item in diff.added_endpoints:
            source_text = f" [{item.source}]" if verbose else ""
            lines.append(f"[{item.status}] {item.url}{source_text}")
    else:
        lines.append("No new endpoints.")

    lines.append("")
    lines.append("Removed Endpoints")
    lines.append("=" * 50)
    if diff.removed_endpoints:
        for item in diff.removed_endpoints:
            source_text = f" [{item.source}]" if verbose else ""
            lines.append(f"[{item.status}] {item.url}{source_text}")
    else:
        lines.append("No removed endpoints.")

    lines.append("")
    lines.append("New Content Findings")
    lines.append("=" * 50)
    if diff.added_content_findings:
        for item in diff.added_content_findings:
            lines.append(f"[{item.severity.upper()}] {item.url} | {item.kind} | {item.evidence}")
    else:
        lines.append("No new content findings.")

    lines.append("")
    lines.append("Resolved Content Findings")
    lines.append("=" * 50)
    if diff.resolved_content_findings:
        for item in diff.resolved_content_findings:
            lines.append(f"[{item.severity.upper()}] {item.url} | {item.kind} | {item.evidence}")
    else:
        lines.append("No resolved content findings.")

    lines.append("")
    lines.append("Status Changes")
    lines.append("=" * 50)
    if diff.status_changes:
        lines.extend(diff.status_changes)
    else:
        lines.append("No status changes.")

    return "\n".join(lines) + "\n"
