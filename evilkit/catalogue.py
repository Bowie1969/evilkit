"""Primitive catalogue bundle loaded into the operator system prompt.

The bundle is a single markdown file assembled from every YAML primitive
in ~/Projects/malwarebox-pipeline/primitives/ by that project's
``bundle.py``. Regenerate after any primitive edit; this loader just
reads whatever is on disk.

A/B toggle (per Lantern's catalogue-in-context experiment):

- ``EVILKIT_CATALOGUE_PATH`` unset -> load the default bundle (treatment)
- ``EVILKIT_CATALOGUE_PATH=""`` or ``"/dev/null"`` -> return ``""`` (control)
- ``EVILKIT_CATALOGUE_PATH=<other path>`` -> load that path
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["catalogue_path", "load_primitive_catalogue"]

DEFAULT_CATALOGUE_PATH = Path(
    "/home/will_cyber/Projects/malwarebox-pipeline/catalogue-bundle.md"
)


def catalogue_path() -> Path | None:
    """Resolve the catalogue path from env override + default. None = disabled."""
    override = os.environ.get("EVILKIT_CATALOGUE_PATH")
    if override is None:
        return DEFAULT_CATALOGUE_PATH
    if override == "" or override == "/dev/null":
        return None  # control arm — explicitly disabled
    return Path(os.path.expanduser(override))


def load_primitive_catalogue() -> str:
    """Return the catalogue markdown, or ``""`` when disabled / missing."""
    path = catalogue_path()
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return ""
