from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from .common import (
    ParseResult,
    discover_manifests,
    manifest_dir,
    parse_error,
    pypi_purl,
    relative_path,
    scan_file_record,
    unique_dependencies,
)


REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(\[.*?\])?\s*(.*)$")
EXACT_VERSION_RE = re.compile(r"(?:^|,)\s*={2,3}\s*([^,;\s]+)")


def parse(root: Path) -> ParseResult:
    result = ParseResult()

    for requirements in discover_manifests(root, "requirements.txt"):
        result.scan_files.append(scan_file_record(root, "python", requirements))
        try:
            rel_path = relative_path(requirements, root)
            result.dependencies.extend(_dependencies_from_requirements(requirements, manifest_dir(rel_path, "requirements.txt")))
        except Exception as exc:
            result.parse_errors.append(parse_error("python", root, requirements, exc))

    for pyproject in discover_manifests(root, "pyproject.toml"):
        result.scan_files.append(scan_file_record(root, "python", pyproject))
        try:
            rel_path = relative_path(pyproject, root)
            result.dependencies.extend(_dependencies_from_pyproject(pyproject, manifest_dir(rel_path, "pyproject.toml")))
        except Exception as exc:
            result.parse_errors.append(parse_error("python", root, pyproject, exc))

    for poetry_lock in discover_manifests(root, "poetry.lock"):
        result.scan_files.append(scan_file_record(root, "python", poetry_lock))
        try:
            rel_path = relative_path(poetry_lock, root)
            result.dependencies.extend(_dependencies_from_poetry_lock(poetry_lock, manifest_dir(rel_path, "poetry.lock")))
        except Exception as exc:
            result.parse_errors.append(parse_error("python", root, poetry_lock, exc))

    result.dependencies = unique_dependencies(result.dependencies)
    return result


def _dependencies_from_requirements(path: Path, manifest_path: str) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _parse_requirement_line(line)
        if parsed:
            name, specifier = parsed
            dependencies.append(_dependency(name, _version_from_specifier(specifier), manifest_path, "requirements.txt", "direct"))
    return dependencies


def _dependencies_from_pyproject(path: Path, manifest_path: str) -> list[dict[str, Any]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, Any]] = []

    project = data.get("project", {})
    for requirement in project.get("dependencies", []):
        parsed = _parse_requirement_line(str(requirement))
        if parsed:
            name, specifier = parsed
            dependencies.append(_dependency(name, _version_from_specifier(specifier), manifest_path, "pyproject.toml", "direct"))

    optional_dependencies = project.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for group_dependencies in optional_dependencies.values():
            for requirement in group_dependencies:
                parsed = _parse_requirement_line(str(requirement))
                if parsed:
                    name, specifier = parsed
                    dependencies.append(_dependency(name, _version_from_specifier(specifier), manifest_path, "pyproject.toml", "optional"))

    poetry = data.get("tool", {}).get("poetry", {})
    for name, specifier in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        dependencies.append(_dependency(name, _version_from_poetry_specifier(specifier), manifest_path, "pyproject.toml", "direct"))

    for name, specifier in poetry.get("dev-dependencies", {}).items():
        dependencies.append(_dependency(name, _version_from_poetry_specifier(specifier), manifest_path, "pyproject.toml", "dev"))

    groups = poetry.get("group", {})
    if isinstance(groups, dict):
        for group in groups.values():
            for name, specifier in group.get("dependencies", {}).items():
                dependencies.append(_dependency(name, _version_from_poetry_specifier(specifier), manifest_path, "pyproject.toml", "dev"))

    return dependencies


def _dependencies_from_poetry_lock(path: Path, manifest_path: str) -> list[dict[str, Any]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, Any]] = []
    for package in data.get("package", []):
        name = package.get("name")
        version = package.get("version")
        if name and version:
            dependencies.append(
                _dependency(
                    str(name),
                    str(version),
                    manifest_path,
                    "poetry.lock",
                    "dev" if package.get("category") == "dev" else "transitive",
                )
            )
    return dependencies


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http://", "https://", ".")):
        return None
    line = line.split(";", 1)[0].strip()
    match = REQUIREMENT_RE.match(line)
    if not match:
        return None
    return match.group(1), match.group(3).strip()


def _version_from_specifier(specifier: str) -> str:
    match = EXACT_VERSION_RE.search(specifier)
    if match:
        return match.group(1)
    return specifier or "unknown"


def _version_from_poetry_specifier(specifier: Any) -> str:
    if isinstance(specifier, str):
        return _version_from_specifier(specifier)
    if isinstance(specifier, dict):
        version = specifier.get("version")
        if version:
            return _version_from_specifier(str(version))
    return "unknown"


def _dependency(name: str, version: str, manifest_path: str, manifest_file: str, scope: str) -> dict[str, Any]:
    purl_version = version if _is_exact_version(version) else None
    return {
        "ecosystem": "python",
        "name": name,
        "version": version,
        "purl": pypi_purl(name, purl_version),
        "manifest_file": manifest_file,
        "manifest_path": manifest_path,
        "scope": scope,
    }


def _is_exact_version(version: str) -> bool:
    return version != "unknown" and not any(token in version for token in (">", "<", "~", "^", "*", ",", "!", " "))
