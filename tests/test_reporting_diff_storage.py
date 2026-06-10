from __future__ import annotations

import shutil
import unittest
import uuid
from datetime import datetime
from pathlib import Path

from vulnscanner.diffing import diff_scans
from vulnscanner.models import ContentFinding, EndpointFinding, Fingerprint, HeaderFinding, ScanResult
from vulnscanner.reporting import render_diff_report, render_scan_report, write_csv_report, write_markdown_report
from vulnscanner.storage import find_latest_pair, list_history, load_scan_result, save_history_snapshot


TEST_TMP_ROOT = Path("tests_tmp")
TEST_TMP_ROOT.mkdir(exist_ok=True)


def make_test_dir(name: str) -> Path:
    path = TEST_TMP_ROOT / f"{name}_{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_result() -> ScanResult:
    return ScanResult(
        target="https://example.com",
        started_at=datetime.fromisoformat("2026-06-10T01:00:00"),
        finished_at=datetime.fromisoformat("2026-06-10T01:00:05"),
        fingerprint=Fingerprint(
            final_url="https://example.com",
            status=200,
            server="nginx",
            powered_by="Express",
            content_type="text/html",
            title="Example",
            technologies=["Express", "nginx"],
        ),
        header_findings=[HeaderFinding(name="CSP", severity="high", detail="Missing")],
        endpoint_findings=[
            EndpointFinding(
                path="admin",
                url="https://example.com/admin",
                status=403,
                length=123,
                title="",
                source="wordlist",
                content_type="text/html",
            )
        ],
        content_findings=[
            ContentFinding(
                path=".env",
                url="https://example.com/.env",
                severity="high",
                kind="env-file",
                detail="Exposed env file.",
                evidence="APP_KEY=secret",
            )
        ],
        notes=["note"],
    )


class ReportingDiffStorageTests(unittest.TestCase):
    def test_storage_round_trip_preserves_findings(self) -> None:
        result = build_result()
        tmp = make_test_dir("storage")
        try:
            saved = save_history_snapshot(result, history_dir=tmp)
            loaded = load_scan_result(saved)
            listed = list_history(history_dir=tmp, target=result.target)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertEqual(loaded.target, result.target)
        self.assertEqual(len(loaded.content_findings), 1)
        self.assertEqual(listed, [saved])

    def test_find_latest_pair_returns_last_two_reports(self) -> None:
        result = build_result()
        result_two = build_result()
        result_two.finished_at = datetime.fromisoformat("2026-06-10T01:00:06")

        tmp = make_test_dir("pair")
        try:
            first = save_history_snapshot(result, history_dir=tmp)
            second = save_history_snapshot(result_two, history_dir=tmp)
            pair = find_latest_pair(result.target, history_dir=tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertEqual(pair, (first, second))

    def test_diff_report_includes_tech_and_content_changes(self) -> None:
        older = build_result()
        newer = build_result()
        newer.fingerprint.technologies.append("Cloudflare")
        newer.endpoint_findings[0].status = 200
        newer.content_findings = []

        diff = diff_scans(older, newer)
        report = render_diff_report(diff, verbose=True)

        self.assertIn("Added: Cloudflare", report)
        self.assertIn("admin: 403 -> 200", report)
        self.assertIn("Resolved Content Findings", report)

    def test_scan_report_and_exports_include_new_sections(self) -> None:
        result = build_result()
        report = render_scan_report(result, verbose=True)
        self.assertIn("Technologies: Express, nginx", report)
        self.assertIn("Content Findings", report)
        self.assertIn("source=wordlist", report)

        tmp = make_test_dir("exports")
        try:
            markdown_path = write_markdown_report(result, Path(tmp) / "report.md")
            csv_path = write_csv_report(result, Path(tmp) / "report.csv")

            markdown_text = markdown_path.read_text(encoding="utf-8")
            csv_text = csv_path.read_text(encoding="utf-8")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        self.assertIn("## Content Findings", markdown_text)
        self.assertIn("content,high,env-file", csv_text)
