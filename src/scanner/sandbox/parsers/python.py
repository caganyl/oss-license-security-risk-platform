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
# A requirement is pinned only by a single "==X" / "===X" clause without wildcards.
EXACT_PIN_RE = re.compile(r"^\s*={2,3}\s*([^,;\s*]+)\s*$")
# Poetry treats a bare version ("1.2.3") as an exact pin.
BARE_VERSION_RE = re.compile(r"^\s*([0-9][0-9A-Za-z.+!-]*)\s*$")
# Requirements files whose packages are development/test only (ADR-003 b).
DEV_REQUIREMENTS_FILES = ("requirements-dev.txt", "requirements-test.txt")


def parse(root: Path) -> ParseResult:
    result = ParseResult()

    requirement_files = [("requirements.txt", "direct")] + [(name, "dev") for name in DEV_REQUIREMENTS_FILES]
    for filename, scope in requirement_files:
        for requirements in discover_manifests(root, filename):
            result.scan_files.append(scan_file_record(root, "python", requirements))
            try:
                rel_path = relative_path(requirements, root)
                result.dependencies.extend(
                    _dependencies_from_requirements(requirements, manifest_dir(rel_path, filename), filename, scope)
                )
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


def _dependencies_from_requirements(path: Path, manifest_path: str, manifest_file: str, scope: str) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _parse_requirement_line(line)
        if parsed:
            name, specifier = parsed
            version, declared_range = _version_from_specifier(specifier)
            dependencies.append(_dependency(name, version, declared_range, manifest_path, manifest_file, scope))
    return dependencies


def _dependencies_from_pyproject(path: Path, manifest_path: str) -> list[dict[str, Any]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, Any]] = []

    def add_requirement(requirement: Any, scope: str) -> None:
        parsed = _parse_requirement_line(str(requirement))
        if parsed:
            name, specifier = parsed
            version, declared_range = _version_from_specifier(specifier)
            dependencies.append(_dependency(name, version, declared_range, manifest_path, "pyproject.toml", scope))

    def add_poetry(name: str, specifier: Any, scope: str) -> None:
        version, declared_range = _version_from_poetry_specifier(specifier)
        dependencies.append(_dependency(name, version, declared_range, manifest_path, "pyproject.toml", scope))

    project = data.get("project", {})
    for requirement in project.get("dependencies", []):
        add_requirement(requirement, "direct")

    optional_dependencies = project.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for group_dependencies in optional_dependencies.values():
            for requirement in group_dependencies:
                add_requirement(requirement, "optional")

    poetry = data.get("tool", {}).get("poetry", {})
    for name, specifier in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        add_poetry(name, specifier, "direct")

    for name, specifier in poetry.get("dev-dependencies", {}).items():
        add_poetry(name, specifier, "dev")

    groups = poetry.get("group", {})
    if isinstance(groups, dict):
        for group in groups.values():
            for name, specifier in group.get("dependencies", {}).items():
                add_poetry(name, specifier, "dev")

    return dependencies


def _dependencies_from_poetry_lock(path: Path, manifest_path: str) -> list[dict[str, Any]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies: list[dict[str, Any]] = []
    for package in data.get("package", []):
        name = package.get("name")
        version = str(package.get("version") or "").strip()
        if name and version:
            dependencies.append(
                _dependency(
                    str(name),
                    version,
                    None,
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


def _version_from_specifier(specifier: str) -> tuple[str | None, str | None]:
    """Returns (exact version or None, declared specifier or None) for a PEP 508 specifier.

    Only a single "==X" clause is an exact version; anything else (ranges,
    wildcards, no specifier at all) leaves the version unknown (None).
    """
    specifier = specifier.strip()
    if not specifier:
        return None, None
    match = EXACT_PIN_RE.match(specifier)
    return (match.group(1) if match else None), specifier


def _version_from_poetry_specifier(specifier: Any) -> tuple[str | None, str | None]:
    if isinstance(specifier, dict):
        specifier = specifier.get("version")
    if not isinstance(specifier, str) or not specifier.strip():
        return None, None
    bare = BARE_VERSION_RE.match(specifier)
    if bare:
        return bare.group(1), specifier.strip()
    return _version_from_specifier(specifier)


def _dependency(
    name: str,
    version: str | None,
    declared_range: str | None,
    manifest_path: str,
    manifest_file: str,
    scope: str,
) -> dict[str, Any]:
    """version is an exact resolved version or None; the purl carries a version only then."""
    return {
        "ecosystem": "python",
        "name": name,
        "version": version,
        "declared_range": declared_range,
        "purl": pypi_purl(name, version),
        "manifest_file": manifest_file,
        "manifest_path": manifest_path,
        "scope": scope,
    }
