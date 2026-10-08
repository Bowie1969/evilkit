"""Iterative operator lessons loaded into every brain run.

Lessons live in `evilkit/data/lessons.md` and are injected verbatim into the
operator system prompt. Append new lessons with `append_lesson()` or the
`evilkit lessons add` CLI subcommand.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

__all__ = ["lessons_path", "load_lessons", "append_lesson", "next_lesson_number"]


def lessons_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "lessons.md"


def load_lessons() -> str:
    """Return the lessons markdown, or an empty string if the file is missing."""
    path = lessons_path()
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").rstrip() + "\n"


def next_lesson_number(text: str | None = None) -> int:
    """Scan existing lessons for the highest L<N> heading and return N+1."""
    body = text if text is not None else load_lessons()
    highest = 0
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("## L"):
            continue
        token = line[4:].split(" ", 1)[0].rstrip(":")
        if token.isdigit():
            highest = max(highest, int(token))
    return highest + 1


def append_lesson(title: str, body: str, *, source: str | None = None) -> int:
    """Append a new lesson, return its number. Creates the file if missing."""
    title = title.strip()
    body = body.strip()
    if not title or not body:
        raise ValueError("lesson title and body are required")
    number = next_lesson_number()
    source_line = f"Source: {source.strip()}\n" if source else f"Source: run on {date.today().isoformat()}\n"
    entry = f"\n## L{number} — {title}\n{source_line}{body}\n"
    path = lessons_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    path.write_text(existing.rstrip() + "\n" + entry, encoding="utf-8")
    return number
