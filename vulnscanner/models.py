from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class HeaderFinding:
    name: str
    severity: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HeaderFinding":
        return cls(
            name=data.get("name", ""),
            severity=data.get("severity", ""),
            detail=data.get("detail", ""),
        )


@dataclass(slots=True)
class EndpointFinding:
    path: str
    url: str
    status: int
    length: int
    title: str
    source: str
    content_type: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointFinding":
        return cls(
            path=data.get("path", ""),
            url=data.get("url", ""),
            status=int(data.get("status", 0)),
            length=int(data.get("length", 0)),
            title=data.get("title", ""),
            source=data.get("source", ""),
            content_type=data.get("content_type", ""),
        )


@dataclass(slots=True)
class ContentFinding:
    path: str
    url: str
    severity: str
    kind: str
    detail: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContentFinding":
        return cls(
            path=data.get("path", ""),
            url=data.get("url", ""),
            severity=data.get("severity", ""),
            kind=data.get("kind", ""),
            detail=data.get("detail", ""),
            evidence=data.get("evidence", ""),
        )


@dataclass(slots=True)
class Fingerprint:
    final_url: str
    status: int
    server: str
    powered_by: str
    content_type: str
    title: str
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Fingerprint":
        return cls(
            final_url=data.get("final_url", ""),
            status=int(data.get("status", 0)),
            server=data.get("server", ""),
            powered_by=data.get("powered_by", ""),
            content_type=data.get("content_type", ""),
            title=data.get("title", ""),
            technologies=list(data.get("technologies", [])),
        )


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: datetime
    finished_at: datetime
    fingerprint: Fingerprint | None = None
    header_findings: list[HeaderFinding] = field(default_factory=list)
    endpoint_findings: list[EndpointFinding] = field(default_factory=list)
    content_findings: list[ContentFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return round((self.finished_at - self.started_at).total_seconds(), 2)

    @property
    def issue_count(self) -> int:
        return len(self.header_findings) + len(self.endpoint_findings) + len(self.content_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "issue_count": self.issue_count,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "header_findings": [item.to_dict() for item in self.header_findings],
            "endpoint_findings": [item.to_dict() for item in self.endpoint_findings],
            "content_findings": [item.to_dict() for item in self.content_findings],
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        fingerprint_data = data.get("fingerprint")
        return cls(
            target=data.get("target", ""),
            started_at=datetime.fromisoformat(data["started_at"]),
            finished_at=datetime.fromisoformat(data["finished_at"]),
            fingerprint=Fingerprint.from_dict(fingerprint_data) if fingerprint_data else None,
            header_findings=[
                HeaderFinding.from_dict(item)
                for item in data.get("header_findings", [])
            ],
            endpoint_findings=[
                EndpointFinding.from_dict(item)
                for item in data.get("endpoint_findings", [])
            ],
            content_findings=[
                ContentFinding.from_dict(item)
                for item in data.get("content_findings", [])
            ],
            notes=list(data.get("notes", [])),
        )
