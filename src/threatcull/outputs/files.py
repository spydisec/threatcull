# SPDX-License-Identifier: AGPL-3.0-only
"""Where Outputs live on disk, and how they are replaced atomically."""

from __future__ import annotations

from pathlib import Path

from threatcull.store.outputs import OutputSpec

_EXTENSIONS = {
    "plain": "txt",
    "hosts": "txt",
    "adguard": "txt",
    "rpz": "rpz",
    "csv": "csv",
    "json": "json",
}


def output_path(out_dir: Path, spec: OutputSpec) -> Path:
    return out_dir / f"{spec.name}.{_EXTENSIONS[spec.format]}"


def atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
