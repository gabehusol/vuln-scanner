from __future__ import annotations

import json
import re
from pathlib import Path

from vulnscanner.models import ScanResult


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HISTORY_DIR = PROJECT_ROOT / "io" / "history"


def slugify_target(target: str) -> str:
    cleaned = re.sub(r"^https?://", "", target.strip(), flags=re.IGNORECASE)
    cleaned = cleaned.strip("/").replace("/", "_")
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", cleaned)
    return cleaned or "scan"


def save_history_snapshot(result: ScanResult, history_dir: str | Path = DEFAULT_HISTORY_DIR) -> Path:
    root = Path(history_dir)
    target_dir = root / slugify_target(result.target)
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = result.finished_at.strftime("%Y%m%d_%H%M%S_%f")
    destination = target_dir / f"{timestamp}.json"
    destination.write_text(json.dumps(result.to_dict(), indent=4), encoding="utf-8")
    return destination


def load_scan_result(path: str | Path) -> ScanResult:
    file_path = Path(path)
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return ScanResult.from_dict(data)


def list_history(
    history_dir: str | Path = DEFAULT_HISTORY_DIR,
    target: str | None = None,
) -> list[Path]:
    root = Path(history_dir)
    if not root.exists():
        return []

    if target:
        root = root / slugify_target(target)
        if not root.exists():
            return []

    reports = sorted(root.glob("**/*.json"))
    return reports


def find_latest_pair(
    target: str,
    history_dir: str | Path = DEFAULT_HISTORY_DIR,
) -> tuple[Path, Path] | None:
    reports = list_history(history_dir=history_dir, target=target)
    if len(reports) < 2:
        return None
    return reports[-2], reports[-1]
