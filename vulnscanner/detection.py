from __future__ import annotations

import re

from requests.structures import CaseInsensitiveDict

from vulnscanner.models import ContentFinding


TECH_SIGNATURES = [
    ("Cloudflare", ("server:cloudflare", "__cf_bm", "cf-ray")),
    ("Fastly", ("fastly", "x-served-by: cache-",)),
    ("Akamai", ("akamai", "akamaighost",)),
    ("nginx", ("server:nginx",)),
    ("Apache", ("server:apache",)),
    ("IIS", ("server:microsoft-iis",)),
    ("Caddy", ("server:caddy",)),
    ("Tomcat", ("apache-coyote", "tomcat")),
    ("Express", ("x-powered-by:express",)),
    ("PHP", ("x-powered-by:php", "phpinfo()",)),
    ("ASP.NET", ("x-powered-by:asp.net", "__viewstate",)),
    ("Django", ("csrftoken", "__admin_media_prefix__",)),
    ("Flask", ("werkzeug",)),
    ("FastAPI", ("swagger ui", "fastapi", "openapi.json")),
    ("Laravel", ("laravel_session", "x-powered-by:php",)),
    ("Ruby on Rails", ("csrf-param", "rails",)),
    ("WordPress", ("wp-content", "wp-includes", "wordpress")),
    ("Drupal", ("drupal-settings-json", "/sites/default/", "drupal")),
    ("Joomla", ("joomla!", "com_content",)),
    ("Next.js", ("_next/static", "__next",)),
    ("React", ("reactroot", "data-reactroot",)),
    ("Vue", ("__vue__", "data-v-",)),
    ("Angular", ("ng-version", "angular")),
    ("Bootstrap", ("bootstrap.min.css", "bootstrap.min.js")),
    ("Grafana", ("grafana", "x-grafana-version")),
    ("Jenkins", ("x-jenkins", "jenkins")),
    ("Kibana", ("kibana",)),
    ("Elasticsearch", ("you know, for search", "elasticsearch")),
    ("Tailwind CSS", ("tailwindcss", "_next/static/css", "tw-")),
    ("Vite", ("/@vite/client", "vite.svg")),
    ("SvelteKit", ("sveltekit", "__sveltekit")),
    ("Shopify", ("cdn.shopify.com", "shopify")),
    ("Magento", ("mage/cookies.js", "magento")),
    ("phpMyAdmin", ("phpmyadmin", "pma_")),
]


TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/xhtml+xml",
)


SENSITIVE_PATTERNS = [
    (
        "high",
        "private-key",
        "Private key material appears to be exposed.",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "high",
        "env-secret",
        "Environment style secret values appear in the response.",
        re.compile(r"(DB_PASSWORD|API_KEY|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*=\s*.+", re.IGNORECASE),
    ),
    (
        "high",
        "aws-key",
        "An AWS access key pattern appears in the response.",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "high",
        "jwt-token",
        "A JWT style token appears in the response.",
        re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}\b"),
    ),
    (
        "high",
        "github-token",
        "A GitHub token pattern appears in the response.",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "high",
        "slack-token",
        "A Slack token pattern appears in the response.",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "medium",
        "directory-listing",
        "This looks like an open directory listing.",
        re.compile(r"(<title>\s*Index of|Directory listing for|<h1>\s*Index of)", re.IGNORECASE),
    ),
    (
        "medium",
        "git-config",
        "Git repository data may be exposed.",
        re.compile(r"\[core\]|\[remote \"origin\"\]"),
    ),
    (
        "medium",
        "phpinfo",
        "A phpinfo page appears to be exposed.",
        re.compile(r"phpinfo\(\)|PHP Version \d+\.\d+", re.IGNORECASE),
    ),
    (
        "medium",
        "openapi",
        "An OpenAPI or Swagger document appears in the response.",
        re.compile(r"\"openapi\"\s*:\s*\"3\.[0-9].*\"|swagger-ui", re.IGNORECASE),
    ),
    (
        "medium",
        "database-dump",
        "A SQL dump style response appears to be exposed.",
        re.compile(r"(CREATE TABLE|INSERT INTO|-- Dump completed on)", re.IGNORECASE),
    ),
    (
        "low",
        "stack-trace",
        "A stack trace or debug output appears in the response.",
        re.compile(r"(Traceback \(most recent call last\)|Exception in thread|at [\w.$_]+\()"),
    ),
    (
        "low",
        "debug-mode",
        "A debug page or framework error page appears in the response.",
        re.compile(r"(DEBUG\s*=\s*True|Werkzeug Debugger|Whitelabel Error Page|Detailed Error Report)", re.IGNORECASE),
    ),
]


def detect_technologies(
    headers: CaseInsensitiveDict[str],
    body: str,
    final_url: str,
) -> list[str]:
    haystack = build_tech_haystack(headers, body, final_url)
    matches: list[str] = []
    for name, tokens in TECH_SIGNATURES:
        if any(token.casefold() in haystack for token in tokens):
            matches.append(name)
    return sorted(set(matches))


def build_tech_haystack(headers: CaseInsensitiveDict[str], body: str, final_url: str) -> str:
    pieces = [final_url.casefold(), body.casefold()]
    for key, value in headers.items():
        pieces.append(f"{key}:{value}".casefold())
    return "\n".join(pieces)


def is_text_response(content_type: str) -> bool:
    content_type = (content_type or "").casefold()
    return any(token in content_type for token in TEXT_TYPES)


def analyze_content(path: str, url: str, content_type: str, body: str) -> list[ContentFinding]:
    findings: list[ContentFinding] = []

    for severity, kind, detail, pattern in SENSITIVE_PATTERNS:
        match = pattern.search(body)
        if not match:
            continue
        evidence = " ".join(match.group(0).split())[:140]
        findings.append(
            ContentFinding(
                path=path,
                url=url,
                severity=severity,
                kind=kind,
                detail=detail,
                evidence=evidence,
            )
        )

    lowered_path = path.casefold()
    if lowered_path.endswith((".zip", ".tar", ".gz", ".rar", ".bak", ".sql")):
        findings.append(
            ContentFinding(
                path=path,
                url=url,
                severity="medium",
                kind="archive-exposure",
                detail="A backup or archive style file is directly reachable.",
                evidence=path,
            )
        )

    if lowered_path.endswith(".env") and body.strip():
        findings.append(
            ContentFinding(
                path=path,
                url=url,
                severity="high",
                kind="env-file",
                detail="An environment file appears to be exposed.",
                evidence=body.splitlines()[0][:140],
            )
        )

    return unique_content_findings(findings)


def unique_content_findings(findings: list[ContentFinding]) -> list[ContentFinding]:
    seen: set[tuple[str, str, str]] = set()
    items: list[ContentFinding] = []
    for finding in findings:
        key = (finding.path, finding.kind, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        items.append(finding)
    return items
