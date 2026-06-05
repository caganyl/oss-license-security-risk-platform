from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .common import (
    ParseResult,
    discover_manifests,
    manifest_dir,
    npm_purl,
    parse_error,
    read_json,
    relative_path,
    scan_file_record,
    unique_dependencies,
)


PACKAGE_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")


def parse(root: Path) -> ParseResult:
    result = ParseResult()

    for package_json in discover_manifests(root, "package.json"):
        rel_path = relative_path(package_json, root)
        result.scan_files.append(scan_file_record(root, "nodejs", package_json))

        try:
            package_data = read_json(package_json)
            manifest_path = manifest_dir(rel_path, "package.json")
            declared_scopes = _declared_scopes(package_data)

            lockfile = package_json.parent / "package-lock.json"
            if lockfile.is_file():
                result.scan_files.append(scan_file_record(root, "nodejs", lockfile))
                result.dependencies.extend(_dependencies_from_package_lock(lockfile, manifest_path, declared_scopes))

            yarn_lock = package_json.parent / "yarn.lock"
            if yarn_lock.is_file():
                result.scan_files.append(scan_file_record(root, "nodejs", yarn_lock))
                result.dependencies.extend(_dependencies_from_yarn_lock(yarn_lock, manifest_path, declared_scopes))

            if not lockfile.is_file() and not yarn_lock.is_file():
                result.dependencies.extend(_dependencies_from_package_json(package_data, manifest_path))
        except Exception as exc:
            result.parse_errors.append(parse_error("nodejs", root, package_json, exc))

    result.dependencies = unique_dependencies(result.dependencies)
    return result


def _dependencies_from_package_json(package_data: dict[str, Any], manifest_path: str) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for section in PACKAGE_SECTIONS:
        scope = _scope_for_section(section)
        for name, specifier in package_data.get(section, {}).items():
            version = str(specifier).strip()
            dependencies.append(_dependency(name, version, manifest_path, "package.json", scope))
    return dependencies


def _dependencies_from_package_lock(
    lockfile: Path,
    manifest_path: str,
    declared_scopes: dict[str, str],
) -> list[dict[str, Any]]:
    data = read_json(lockfile)
    dependencies: list[dict[str, Any]] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, package in packages.items():
            if not package_path or not isinstance(package, dict):
                continue
            name = package.get("name") or _name_from_node_modules_path(package_path)
            version = package.get("version")
            if name and version:
                dependencies.append(
                    _dependency(
                        str(name),
                        str(version),
                        manifest_path,
                        "package-lock.json",
                        declared_scopes.get(str(name), _lock_scope(package)),
                        _licenses(package),
                    )
                )

    legacy_dependencies = data.get("dependencies")
    if isinstance(legacy_dependencies, dict):
        dependencies.extend(_dependencies_from_legacy_lock(legacy_dependencies, manifest_path, declared_scopes))

    return dependencies


def _dependencies_from_legacy_lock(
    entries: dict[str, Any],
    manifest_path: str,
    declared_scopes: dict[str, str],
    inherited_scope: str = "transitive",
) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    for name, package in entries.items():
        if not isinstance(package, dict):
            continue
        version = package.get("version")
        scope = declared_scopes.get(name, "dev" if package.get("dev") else inherited_scope)
        if version:
            dependencies.append(
                _dependency(str(name), str(version), manifest_path, "package-lock.json", scope, _licenses(package))
            )
        nested = package.get("dependencies")
        if isinstance(nested, dict):
            dependencies.extend(_dependencies_from_legacy_lock(nested, manifest_path, declared_scopes, scope))
    return dependencies


def _dependencies_from_yarn_lock(
    lockfile: Path,
    manifest_path: str,
    declared_scopes: dict[str, str],
) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    current_names: list[str] = []
    current_version: str | None = None

    for raw_line in lockfile.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            if current_names and current_version:
                for name in current_names:
                    dependencies.append(
                        _dependency(name, current_version, manifest_path, "yarn.lock", declared_scopes.get(name, "transitive"))
                    )
            current_names = _names_from_yarn_key(line)
            current_version = None
            continue
        stripped = line.strip()
        if stripped.startswith("version "):
            current_version = stripped.split(" ", 1)[1].strip().strip('"')

    if current_names and current_version:
        for name in current_names:
            dependencies.append(
                _dependency(name, current_version, manifest_path, "yarn.lock", declared_scopes.get(name, "transitive"))
            )

    return dependencies


def _names_from_yarn_key(line: str) -> list[str]:
    key = line.rstrip(":")
    names: list[str] = []
    for part in _split_yarn_key(key):
        name = _name_from_yarn_descriptor(part.strip().strip('"'))
        if name:
            names.append(name)
    return names


def _split_yarn_key(key: str) -> list[str]:
    parts: list[str] = []
    current = []
    quoted = False
    for char in key:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _name_from_yarn_descriptor(descriptor: str) -> str | None:
    if descriptor.startswith("@"):
        match = re.match(r"^(@[^/]+/[^@]+)", descriptor)
    else:
        match = re.match(r"^([^@]+)", descriptor)
    return match.group(1) if match else None


def _name_from_node_modules_path(package_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    parts = package_path.split(marker)[-1].split("/")
    if parts[0].startswith("@") and len(parts) > 1:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else None


def _dependency(
    name: str,
    version: str,
    manifest_path: str,
    manifest_file: str,
    scope: str,
    licenses: list[str] | None = None,
) -> dict[str, Any]:
    dependency: dict[str, Any] = {
        "ecosystem": "nodejs",
        "name": name,
        "version": version,
        "purl": npm_purl(name, version if _is_exact_version(version) else None),
        "manifest_file": manifest_file,
        "manifest_path": manifest_path,
        "scope": scope,
    }
    if licenses:
        dependency["licenses"] = sorted(set(licenses))
    return dependency


def _declared_scopes(package_data: dict[str, Any]) -> dict[str, str]:
    scopes: dict[str, str] = {}
    for section in PACKAGE_SECTIONS:
        for name in package_data.get(section, {}):
            scopes[name] = _scope_for_section(section)
    return scopes


def _scope_for_section(section: str) -> str:
    return {
        "dependencies": "direct",
        "devDependencies": "dev",
        "peerDependencies": "peer",
        "optionalDependencies": "optional",
    }[section]


def _lock_scope(package: dict[str, Any]) -> str:
    if package.get("dev"):
        return "dev"
    if package.get("peer"):
        return "peer"
    if package.get("optional"):
        return "optional"
    return "transitive"


def _licenses(package: dict[str, Any]) -> list[str]:
    license_value = package.get("license")
    if isinstance(license_value, str) and license_value:
        return [license_value]
    if isinstance(license_value, list):
        return [str(value) for value in license_value if value]
    return []


def _is_exact_version(version: str) -> bool:
    return not any(token in version for token in ("^", "~", ">", "<", "*", "x", "X", "||", " "))
