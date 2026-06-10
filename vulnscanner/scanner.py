from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatch
from typing import Iterable
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

import requests

from vulnscanner.detection import analyze_content, detect_technologies, is_text_response
from vulnscanner.http import build_session, extract_title
from vulnscanner.models import ContentFinding, EndpointFinding, Fingerprint, HeaderFinding, ScanResult
from vulnscanner.wordlists import load_common_paths, load_header_rules, load_paths_from_files


INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}


@dataclass(slots=True)
class ScannerConfig:
    timeout: float = 5.0
    threads: int = 12
    retries: int = 1
    verify_tls: bool = True
    user_agent: str = "VulnScanner/2.0"
    include_robots: bool = True
    include_sitemap: bool = True
    max_paths: int | None = None
    statuses: set[int] | None = None
    wordlist_files: list[str] | None = None
    content_checks: bool = True
    max_body_bytes: int = 250000
    include_patterns: list[str] | None = None
    exclude_patterns: list[str] | None = None
    min_severity: str | None = None


class VulnScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.session = build_session(
            user_agent=config.user_agent,
            verify_tls=config.verify_tls,
            retries=config.retries,
        )

    def full_scan(self, target: str, extra_paths: list[str] | None = None) -> ScanResult:
        started_at = datetime.now()
        target = normalize_url(target)

        fingerprint, response_note = self.fingerprint_target(target)
        header_findings = self.analyze_headers(target)
        endpoint_findings, content_findings, discovery_notes = self.scan_common_paths(target, extra_paths=extra_paths)

        notes = []
        if response_note:
            notes.append(response_note)
        notes.extend(discovery_notes)

        return ScanResult(
            target=target,
            started_at=started_at,
            finished_at=datetime.now(),
            fingerprint=fingerprint,
            header_findings=header_findings,
            endpoint_findings=endpoint_findings,
            content_findings=content_findings,
            notes=notes,
        )

    def headers_only(self, target: str) -> ScanResult:
        started_at = datetime.now()
        target = normalize_url(target)
        fingerprint, response_note = self.fingerprint_target(target)
        notes = [response_note] if response_note else []

        return ScanResult(
            target=target,
            started_at=started_at,
            finished_at=datetime.now(),
            fingerprint=fingerprint,
            header_findings=self.analyze_headers(target),
            notes=notes,
        )

    def paths_only(self, target: str, extra_paths: list[str] | None = None) -> ScanResult:
        started_at = datetime.now()
        target = normalize_url(target)
        fingerprint, response_note = self.fingerprint_target(target)
        endpoint_findings, content_findings, discovery_notes = self.scan_common_paths(target, extra_paths=extra_paths)

        notes = []
        if response_note:
            notes.append(response_note)
        notes.extend(discovery_notes)

        return ScanResult(
            target=target,
            started_at=started_at,
            finished_at=datetime.now(),
            fingerprint=fingerprint,
            endpoint_findings=endpoint_findings,
            content_findings=content_findings,
            notes=notes,
        )

    def fingerprint_target(self, target: str) -> tuple[Fingerprint | None, str | None]:
        try:
            response = self.session.get(target, timeout=self.config.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            return None, f"Base request failed: {exc}"

        fingerprint = Fingerprint(
            final_url=response.url,
            status=response.status_code,
            server=response.headers.get("Server", ""),
            powered_by=response.headers.get("X-Powered-By", ""),
            content_type=response.headers.get("Content-Type", ""),
            title=extract_title(response.text),
            technologies=detect_technologies(response.headers, response.text, response.url),
        )
        return fingerprint, None

    def analyze_headers(self, target: str) -> list[HeaderFinding]:
        try:
            response = self.session.get(target, timeout=self.config.timeout, allow_redirects=True)
        except requests.RequestException:
            return []

        findings: list[HeaderFinding] = []
        header_rules = load_header_rules()
        live_headers = {key.casefold() for key in response.headers}

        for name, (severity, detail) in header_rules.items():
            if name.casefold() not in live_headers:
                findings.append(HeaderFinding(name=name, severity=severity, detail=detail))

        server_banner = response.headers.get("Server", "")
        if server_banner:
            findings.append(
                HeaderFinding(
                    name="Server Banner",
                    severity="info",
                    detail=f"Server header exposed: {server_banner}",
                )
            )

        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(
                HeaderFinding(
                    name="Technology Banner",
                    severity="info",
                    detail=f"X-Powered-By exposed: {powered_by}",
                )
            )

        return filter_header_findings(findings, self.config.min_severity)

    def scan_common_paths(
        self,
        target: str,
        extra_paths: list[str] | None = None,
    ) -> tuple[list[EndpointFinding], list[ContentFinding], list[str]]:
        file_paths = load_paths_from_files(self.config.wordlist_files)
        base_paths = load_common_paths(extra_paths=[*(extra_paths or []), *file_paths])
        candidate_paths = list(base_paths)
        discovery_notes: list[str] = []
        robot_paths: list[tuple[str, str]] = []
        sitemap_paths: list[tuple[str, str]] = []

        if self.config.include_robots:
            robot_paths = self.collect_robots_paths(target)
            if robot_paths:
                candidate_paths.extend(path for path, _ in robot_paths)
                discovery_notes.append(f"Pulled {len(robot_paths)} paths from robots.txt")

        if self.config.include_sitemap:
            sitemap_paths = self.collect_sitemap_paths(target)
            if sitemap_paths:
                candidate_paths.extend(path for path, _ in sitemap_paths)
                discovery_notes.append(f"Pulled {len(sitemap_paths)} paths from sitemap.xml")

        deduped = []
        seen: set[str] = set()
        for path in candidate_paths:
            if path not in seen:
                seen.add(path)
                deduped.append(path)

        deduped = [path for path in deduped if path_allowed(path, self.config.include_patterns, self.config.exclude_patterns)]

        if self.config.max_paths is not None:
            deduped = deduped[: self.config.max_paths]

        source_map = {path: "wordlist" for path in base_paths}
        for path, source in robot_paths:
            source_map[path] = source
        for path, source in sitemap_paths:
            source_map[path] = source

        endpoint_findings: list[EndpointFinding] = []
        content_findings: list[ContentFinding] = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            future_map = {
                executor.submit(self.scan_path, target, path, source_map.get(path, "wordlist")): path
                for path in deduped
            }
            for future in as_completed(future_map):
                endpoint_finding, path_content_findings = future.result()
                if endpoint_finding:
                    endpoint_findings.append(endpoint_finding)
                if path_content_findings:
                    content_findings.extend(path_content_findings)

        endpoint_findings.sort(key=lambda item: (item.status, item.path))
        content_findings.sort(key=lambda item: (item.severity, item.path, item.kind))
        content_findings = filter_content_findings(content_findings, self.config.min_severity)
        return endpoint_findings, content_findings, discovery_notes

    def scan_path(self, target: str, path: str, source: str) -> tuple[EndpointFinding | None, list[ContentFinding]]:
        full_url = urljoin(f"{target.rstrip('/')}/", path.lstrip("/"))
        try:
            response = self.session.get(
                full_url,
                timeout=self.config.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            return None, []

        allowed_statuses = self.config.statuses or INTERESTING_STATUSES
        if response.status_code not in allowed_statuses:
            return None, []

        endpoint_finding = EndpointFinding(
            path=path,
            url=full_url,
            status=response.status_code,
            length=len(response.content),
            title=extract_title(response.text),
            source=source,
            content_type=response.headers.get("Content-Type", ""),
        )
        content_findings: list[ContentFinding] = []

        response_size = len(response.content)
        if (
            self.config.content_checks
            and response.status_code == 200
            and response_size <= self.config.max_body_bytes
            and is_text_response(response.headers.get("Content-Type", ""))
        ):
            content_findings = analyze_content(
                path=path,
                url=full_url,
                content_type=response.headers.get("Content-Type", ""),
                body=response.text,
            )

        return endpoint_finding, content_findings

    def collect_robots_paths(self, target: str) -> list[tuple[str, str]]:
        try:
            response = self.session.get(urljoin(target, "/robots.txt"), timeout=self.config.timeout)
        except requests.RequestException:
            return []

        if response.status_code >= 400:
            return []

        paths: list[str] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            if key.strip().casefold() not in {"allow", "disallow"}:
                continue
            candidate = value.strip()
            if candidate.startswith("/") and len(candidate) > 1:
                paths.append(candidate.lstrip("/"))
        return [(path, "robots.txt") for path in unique(paths)]

    def collect_sitemap_paths(self, target: str) -> list[tuple[str, str]]:
        try:
            response = self.session.get(urljoin(target, "/sitemap.xml"), timeout=self.config.timeout)
        except requests.RequestException:
            return []

        if response.status_code >= 400 or not response.text.strip():
            return []

        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            return []

        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}", 1)[0] + "}"

        parsed_target = urlparse(target)
        paths: list[str] = []
        for loc in root.findall(f".//{namespace}loc"):
            if not loc.text:
                continue
            parsed = urlparse(loc.text.strip())
            if parsed.netloc and parsed.netloc != parsed_target.netloc:
                continue
            if parsed.path and parsed.path != "/":
                paths.append(parsed.path.lstrip("/"))
        return [(path, "sitemap.xml") for path in unique(paths)]


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    return target.rstrip("/")


def unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        items.append(value)
    return items


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def path_allowed(path: str, include_patterns: list[str] | None, exclude_patterns: list[str] | None) -> bool:
    if include_patterns and not any(fnmatch(path, pattern) for pattern in include_patterns):
        return False
    if exclude_patterns and any(fnmatch(path, pattern) for pattern in exclude_patterns):
        return False
    return True


def filter_header_findings(findings: list[HeaderFinding], min_severity: str | None) -> list[HeaderFinding]:
    if not min_severity:
        return findings
    minimum = SEVERITY_ORDER.get(min_severity.casefold(), 0)
    return [item for item in findings if SEVERITY_ORDER.get(item.severity.casefold(), 0) >= minimum]


def filter_content_findings(findings: list[ContentFinding], min_severity: str | None) -> list[ContentFinding]:
    if not min_severity:
        return findings
    minimum = SEVERITY_ORDER.get(min_severity.casefold(), 0)
    return [item for item in findings if SEVERITY_ORDER.get(item.severity.casefold(), 0) >= minimum]
