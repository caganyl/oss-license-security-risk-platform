from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import nodejs, python
from .common import ParseResult


PARSERS = {
    "nodejs": nodejs.parse,
    "python": python.parse,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse sandbox dependency manifests.")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--ecosystems", required=True)
    args = parser.parse_args()

    result = ParseResult()
    for ecosystem in _ecosystems(args.ecosystems):
        parser_func = PARSERS.get(ecosystem)
        if parser_func is None:
            result.parse_errors.append(
                {
                    "ecosystem": ecosystem,
                    "file": "",
                    "error": f"unsupported ecosystem '{ecosystem}'",
                }
            )
            continue
        result.extend(parser_func(args.work_dir))

    output = {
        "scan_id": args.scan_id,
        "status": "completed",
        "total_deps": len(result.dependencies),
        "dependencies": result.dependencies,
        "scan_files": result.scan_files,
        "parse_errors": result.parse_errors,
    }
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


def _ecosystems(value: str) -> list[str]:
    return [ecosystem.strip() for ecosystem in value.split(",") if ecosystem.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
