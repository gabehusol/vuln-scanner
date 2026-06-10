from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
IO_DIR = PROJECT_ROOT / "io"
DEFAULT_HEADERS_FILE = IO_DIR / "headers.txt"
DEFAULT_PATHS_FILE = IO_DIR / "common_paths.txt"

DEFAULT_HEADER_RULES: dict[str, tuple[str, str]] = {
    "Content-Security-Policy": (
        "high",
        "No content security policy was returned.",
    ),
    "Strict-Transport-Security": (
        "medium",
        "Strict transport security is missing.",
    ),
    "X-Frame-Options": (
        "medium",
        "Clickjacking protection is missing.",
    ),
    "X-Content-Type-Options": (
        "low",
        "MIME sniffing protection is missing.",
    ),
    "Referrer-Policy": (
        "low",
        "Referrer policy is not set.",
    ),
}

DEFAULT_COMMON_PATHS = [
    "admin",
    ".env",
    ".git",
    "backup.zip",
    "config.json",
    "login",
    "dashboard",
    "status/200",
    "status/403",
    "api",
    "api/docs",
    "server-status",
    ".well-known/security.txt",
]


def load_header_rules() -> dict[str, tuple[str, str]]:
    if not DEFAULT_HEADERS_FILE.exists():
        return DEFAULT_HEADER_RULES

    names = [line.strip() for line in DEFAULT_HEADERS_FILE.read_text().splitlines() if line.strip()]
    rules = DEFAULT_HEADER_RULES.copy()
    for name in names:
        rules.setdefault(name, ("medium", f"{name} is missing."))
    return rules


def load_common_paths(extra_paths: list[str] | None = None) -> list[str]:
    paths = list(DEFAULT_COMMON_PATHS)
    if DEFAULT_PATHS_FILE.exists():
        paths.extend(
            line.strip()
            for line in DEFAULT_PATHS_FILE.read_text().splitlines()
            if line.strip()
        )
    if extra_paths:
        paths.extend(extra_paths)

    seen: set[str] = set()
    cleaned: list[str] = []
    for path in paths:
        normalized = path.strip().lstrip("/")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def load_paths_from_files(files: list[str] | None) -> list[str]:
    if not files:
        return []

    paths: list[str] = []
    for raw_file in files:
        file_path = Path(raw_file)
        if not file_path.exists():
            continue
        paths.extend(
            line.strip()
            for line in file_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return paths
