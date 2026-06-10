from __future__ import annotations

import unittest

from requests.structures import CaseInsensitiveDict

from vulnscanner.detection import analyze_content, detect_technologies, is_text_response


class DetectionTests(unittest.TestCase):
    def test_detect_technologies_finds_multiple_matches(self) -> None:
        headers = CaseInsensitiveDict({"Server": "cloudflare", "X-Powered-By": "Express"})
        body = '<script src="/_next/static/app.js"></script>'

        matches = detect_technologies(headers, body, "https://example.com")

        self.assertIn("Cloudflare", matches)
        self.assertIn("Express", matches)
        self.assertIn("Next.js", matches)

    def test_analyze_content_flags_secrets_and_archives(self) -> None:
        body = "DB_PASSWORD=secret\nAKIAABCDEFGHIJKLMNOP"

        findings = analyze_content(".env", "https://example.com/.env", "text/plain", body)
        kinds = {item.kind for item in findings}

        self.assertIn("env-secret", kinds)
        self.assertIn("aws-key", kinds)
        self.assertIn("env-file", kinds)

    def test_analyze_content_flags_directory_listing(self) -> None:
        body = "<title>Index of /backup</title>"

        findings = analyze_content("backup/", "https://example.com/backup/", "text/html", body)

        self.assertTrue(any(item.kind == "directory-listing" for item in findings))

    def test_is_text_response_handles_common_types(self) -> None:
        self.assertTrue(is_text_response("application/json; charset=utf-8"))
        self.assertTrue(is_text_response("text/html"))
        self.assertFalse(is_text_response("image/png"))
