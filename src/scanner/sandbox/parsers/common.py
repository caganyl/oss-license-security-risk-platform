from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
}


@dataclass
class ParseResult:
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    scan_files: list[dict[str, Any]] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)

    def extend(self, other: "ParseResult") -> None:
        self.dependencies.extend(other.dependencies)
        self.scan_files.extend(other.scan_files)
        self.parse_errors.extend(other.parse_errors)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def relative_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def manifest_dir(path: str, filename: str) -> str:
    if path == filename:
        return "."
    suffix = f"/{filename}"
    return path[: -len(suffix)] if path.endswith(suffix) else str(Path(path).parent)


def discover_manifests(root: Path, filename: str) -> list[Path]:
    manifests: list[Path] = []
    for path in root.rglob(filename):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            manifests.append(path)
    return sorted(manifests)


def scan_file_record(root: Path, ecosystem: str, path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "ecosystem": ecosystem,
        "filename": path.name,
        "file_path": relative_path(path, root),
        "file_hash": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def parse_error(ecosystem: str, root: Path, path: Path, error: Exception | str) -> dict[str, str]:
    return {
        "ecosystem": ecosystem,
        "file": relative_path(path, root),
        "error": str(error),
    }


def unique_dependencies(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for dep in dependencies:
        key = (
            str(dep.get("ecosystem", "")),
            str(dep.get("name", "")).lower(),
            str(dep.get("version", "")),
            str(dep.get("manifest_path", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    return unique


def npm_purl(name: str, version: str | None) -> str:
    encoded = quote(name, safe="@/")
    if version:
        return f"pkg:npm/{encoded}@{quote(version, safe='')}"
    return f"pkg:npm/{encoded}"


def pypi_purl(name: str, version: str | None) -> str:
    normalized = name.replace("_", "-").lower()
    if version:
        return f"pkg:pypi/{quote(normalized, safe='')}@{quote(version, safe='')}"
    return f"pkg:pypi/{quote(normalized, safe='')}"
