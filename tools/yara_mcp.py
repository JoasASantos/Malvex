#!/usr/bin/env python3
"""Small, local-only YARA MCP compatibility server for Malvex.

It deliberately exposes analysis primitives only. Samples and rules stay on the
host; no upload, network fetch, or victim-data collection is implemented here.
"""

import base64
import json
import os
from pathlib import Path
from typing import Any

import yara
from mcp.server.fastmcp import FastMCP


mcp = FastMCP("malvex-yara")


def _rules_dir() -> Path:
    return Path(os.environ.get("MALVEX_YARA_RULES", "~/.malvex/yaraflux/data/rules")).expanduser()


def _rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.rglob("*") if p.suffix.lower() in {".yar", ".yara"})


def _compile(directory: Path) -> yara.Rules | None:
    files = _rule_files(directory)
    if not files:
        return None
    return yara.compile(filepaths={f"rule_{i}": str(p) for i, p in enumerate(files)})


def _scan(data: bytes, directory: Path) -> list[dict[str, Any]]:
    rules = _compile(directory)
    if rules is None:
        return []
    return [
        {"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags)}
        for match in rules.match(data=data)
    ]


@mcp.tool()
def list_rules() -> dict[str, Any]:
    """List local YARA rules available to the analysis workspace."""
    directory = _rules_dir()
    return {"directory": str(directory), "rules": [str(p.relative_to(directory)) for p in _rule_files(directory)]}


@mcp.tool()
def scan_file(path: str) -> dict[str, Any]:
    """Scan an existing local sample with all local YARA rules."""
    sample = Path(path).expanduser()
    data = sample.read_bytes()
    return {"path": str(sample), "size": len(data), "matches": _scan(data, _rules_dir())}


@mcp.tool()
def scan_data(data_base64: str, filename: str = "sample") -> dict[str, Any]:
    """Scan analyst-provided base64 bytes without persisting them."""
    data = base64.b64decode(data_base64, validate=True)
    return {"filename": filename, "size": len(data), "matches": _scan(data, _rules_dir())}


if __name__ == "__main__":
    mcp.run(transport="stdio")
