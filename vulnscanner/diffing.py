from __future__ import annotations

from dataclasses import dataclass

from vulnscanner.models import ContentFinding, EndpointFinding, HeaderFinding, ScanResult


@dataclass(slots=True)
class ScanDiff:
    older_target: str
    newer_target: str
    added_technologies: list[str]
    removed_technologies: list[str]
    added_headers: list[HeaderFinding]
    resolved_headers: list[HeaderFinding]
    added_endpoints: list[EndpointFinding]
    removed_endpoints: list[EndpointFinding]
    added_content_findings: list[ContentFinding]
    resolved_content_findings: list[ContentFinding]
    status_changes: list[str]
    note: str = ""


def diff_scans(older: ScanResult, newer: ScanResult) -> ScanDiff:
    older_headers = {(item.name, item.detail): item for item in older.header_findings}
    newer_headers = {(item.name, item.detail): item for item in newer.header_findings}

    older_endpoints = {item.path: item for item in older.endpoint_findings}
    newer_endpoints = {item.path: item for item in newer.endpoint_findings}

    older_content = {(item.path, item.kind, item.evidence): item for item in older.content_findings}
    newer_content = {(item.path, item.kind, item.evidence): item for item in newer.content_findings}

    added_headers = [newer_headers[key] for key in sorted(newer_headers.keys() - older_headers.keys())]
    resolved_headers = [older_headers[key] for key in sorted(older_headers.keys() - newer_headers.keys())]

    added_endpoints = [newer_endpoints[key] for key in sorted(newer_endpoints.keys() - older_endpoints.keys())]
    removed_endpoints = [older_endpoints[key] for key in sorted(older_endpoints.keys() - newer_endpoints.keys())]

    added_content_findings = [newer_content[key] for key in sorted(newer_content.keys() - older_content.keys())]
    resolved_content_findings = [older_content[key] for key in sorted(older_content.keys() - newer_content.keys())]

    changed_paths = sorted(older_endpoints.keys() & newer_endpoints.keys())
    status_changes: list[str] = []
    for path in changed_paths:
        older_item = older_endpoints[path]
        newer_item = newer_endpoints[path]
        if older_item.status != newer_item.status:
            status_changes.append(
                f"{path}: {older_item.status} -> {newer_item.status}"
            )

    note = ""
    if older.target != newer.target:
        note = "Targets differ. The diff still works, but the result is easier to trust when both reports come from the same target."

    older_tech = set(older.fingerprint.technologies if older.fingerprint else [])
    newer_tech = set(newer.fingerprint.technologies if newer.fingerprint else [])

    return ScanDiff(
        older_target=older.target,
        newer_target=newer.target,
        added_technologies=sorted(newer_tech - older_tech),
        removed_technologies=sorted(older_tech - newer_tech),
        added_headers=added_headers,
        resolved_headers=resolved_headers,
        added_endpoints=added_endpoints,
        removed_endpoints=removed_endpoints,
        added_content_findings=added_content_findings,
        resolved_content_findings=resolved_content_findings,
        status_changes=status_changes,
        note=note,
    )
