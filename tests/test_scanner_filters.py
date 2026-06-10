from __future__ import annotations

import unittest

from vulnscanner.models import ContentFinding, HeaderFinding
from vulnscanner.scanner import filter_content_findings, filter_header_findings, path_allowed


class ScannerFilterTests(unittest.TestCase):
    def test_path_allowed_respects_include_and_exclude(self) -> None:
        self.assertTrue(path_allowed("admin/login", ["admin*"], ["admin/private*"]))
        self.assertFalse(path_allowed("static/app.js", ["*"], ["static/*"]))
        self.assertFalse(path_allowed("docs/index.html", ["admin*"], None))

    def test_filter_header_findings_respects_minimum_severity(self) -> None:
        findings = [
            HeaderFinding(name="A", severity="info", detail="a"),
            HeaderFinding(name="B", severity="medium", detail="b"),
            HeaderFinding(name="C", severity="high", detail="c"),
        ]

        filtered = filter_header_findings(findings, "medium")

        self.assertEqual([item.name for item in filtered], ["B", "C"])

    def test_filter_content_findings_respects_minimum_severity(self) -> None:
        findings = [
            ContentFinding(path="a", url="u", severity="low", kind="a", detail="a", evidence="a"),
            ContentFinding(path="b", url="u", severity="high", kind="b", detail="b", evidence="b"),
        ]

        filtered = filter_content_findings(findings, "medium")

        self.assertEqual([item.kind for item in filtered], ["b"])
