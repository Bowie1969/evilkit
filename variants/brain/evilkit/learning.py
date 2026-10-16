"""Self-training loop — turn each scored run into durable operator lessons.

The loop is deliberately conservative, because a lesson can hurt as easily as
help. Each finished run is scored (:mod:`evilkit.scoring`) and recorded in a
ledger tagged with the *fingerprint* of the lessons set it ran under. Score
deficits distil into candidate lessons; only lessons whose key is not already
present are appended to ``data/lessons.md``, which the operator prompt injects
on the next run. A lessons change advances the fingerprint, so the ledger forms
a sequence of generations whose mean scores can be compared.

This is why "scores higher each time" is a claim about expectation across the
gate, not a literal per-run guarantee: a newly appended batch is kept only while
its generation holds up. :func:`generation_summary` surfaces the trajectory and
:func:`rollback_last_batch` removes the most recent batch when it regressed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import lessons as lessons_mod
from .scoring import RunScore

__all__ = [
    "CandidateLesson",
    "LearnReport",
    "lessons_fingerprint",
    "distill",
    "record_run",
    "ledger_path",
    "ledger_rows",
    "generation_summary",
    "learn_from_run",
    "rollback_last_batch",
    "format_report",
]


def ledger_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "learning_ledger.jsonl"


def lessons_fingerprint() -> str:
    """Stable short hash of the injected lessons. "baseline" when there are none."""
    text = lessons_mod.load_lessons().strip()
    if not text:
        return "baseline"
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


@dataclass(frozen=True)
class CandidateLesson:
    """A lesson the loop may append. ``key`` makes it idempotent across runs."""

    key: str
    title: str
    body: str


@dataclass
class LearnReport:
    """What one pass of the loop did, for printing and for tests."""

    run_id: str
    overall: int
    fingerprint: str
    batch: str
    candidates: list[CandidateLesson] = field(default_factory=list)
    added: list[tuple[int, str]] = field(default_factory=list)  # (lesson number, title)
    skipped: list[str] = field(default_factory=list)  # keys already present


def distill(score: RunScore) -> list[CandidateLesson]:
    """Map a run's score deficits to concrete, grounded candidate lessons.

    Rules are intentionally few and specific; each cites the run's own numbers so
    an appended lesson reads like the hand-written ones, not a platitude.
    """
    rid = score.run_id or "this run"
    out: list[CandidateLesson] = []

    if score.won and not score.knew_it_won:
        out.append(CandidateLesson(
            key="recognise-completion",
            title="Declare completion the turn the objective is met",
            body=(
                f"Run {rid} achieved the objective but did not recognise it "
                f"(won=1, knew_it_won=0), then kept acting for {score.turns_used} turns. "
                "When an objective's success predicate is satisfied in the ledger, stop and "
                "declare completion that same turn instead of continuing to probe."
            ),
        ))

    if score.noise_count >= 3 or score.locked_vectors > 0:
        locked = f" and {score.locked_vectors} locked vector(s)" if score.locked_vectors else ""
        out.append(CandidateLesson(
            key="cut-noise",
            title="Replan after a repeated or locked action, never re-issue it",
            body=(
                f"Run {rid} logged {score.noise_count} futile/repeated action(s){locked}. "
                "A repetition or circuit-breaker warning means the current vector is dead: "
                "switch technique or target on the next turn. Re-issuing a command that already "
                "failed or is locked only burns the turn budget."
            ),
        ))

    if score.evidence_count < 3:
        out.append(CandidateLesson(
            key="capture-evidence",
            title="Capture a concrete artifact for every claim",
            body=(
                f"Run {rid} left only {score.evidence_count} evidence item(s). Every access claim "
                "or finding needs a concrete artifact — command output, file hash, flag, or flow "
                "record — written to the evidence journal before moving on. A thin trail scores "
                "low and cannot be audited after the fact."
            ),
        ))

    if (
        not score.won
        and score.objectives_total > 0
        and score.objectives_met < score.objectives_total
    ):
        out.append(CandidateLesson(
            key="finish-objectives",
            title="Drive the nearest unmet objective before exploring",
            body=(
                f"Run {rid} ended {score.objectives_met}/{score.objectives_total} objectives met "
                f"without winning (used {score.turns_used}/{score.max_turns} turns). Pick the single "
                "nearest unmet objective's success predicate and take the most direct action toward "
                "it each turn; stop breadth-first scanning once a path is known."
            ),
        ))

    return out


def record_run(score: RunScore, *, fingerprint: str | None = None, batch: str = "") -> None:
    """Append one scored run to the ledger, tagged with its lessons fingerprint."""
    fp = fingerprint if fingerprint is not None else lessons_fingerprint()
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": score.run_id,
        "fingerprint": fp,
        "batch": batch,
        "overall": score.overall,
        "won": score.won,
        "knew_it_won": score.knew_it_won,
        "noise": score.noise_count,
        "evidence": score.evidence_count,
        "objectives": f"{score.objectives_met}/{score.objectives_total}",
        "harness_version": score.harness_version,
    }
    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def ledger_rows() -> list[dict]:
    """Return every recorded run, oldest first. Skips any malformed line."""
    path = ledger_path()
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def generation_summary() -> list[dict]:
    """Group ledger rows into generations by fingerprint, in first-seen order.

    Each generation reports its run count, mean overall score, and the change in
    mean from the previous generation — the signal the gate reads.
    """
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for row in ledger_rows():
        fp = row.get("fingerprint", "?")
        if fp not in buckets:
            buckets[fp] = []
            order.append(fp)
        buckets[fp].append(row)

    summary: list[dict] = []
    prev_mean: float | None = None
    for fp in order:
        rows = buckets[fp]
        scores = [r.get("overall", 0) for r in rows]
        mean = sum(scores) / len(scores) if scores else 0.0
        delta = None if prev_mean is None else round(mean - prev_mean, 1)
        summary.append({
            "fingerprint": fp,
            "runs": len(rows),
            "mean_overall": round(mean, 1),
            "delta": delta,
            "batch": next((r.get("batch") for r in rows if r.get("batch")), ""),
        })
        prev_mean = mean
    return summary


def learn_from_run(score: RunScore, *, apply: bool = True) -> LearnReport:
    """Record the run, distil lessons, and append the novel ones.

    The run is always recorded against the fingerprint it ran *under* (the lessons
    active during the run). New lessons are then appended, which advances the
    fingerprint for the next run. ``apply=False`` records and distils without
    writing any lesson — useful for dry runs and tests.
    """
    fingerprint = lessons_fingerprint()
    batch = score.run_id or datetime.now(timezone.utc).strftime("auto-%Y%m%dT%H%M%S")
    record_run(score, fingerprint=fingerprint, batch=batch)

    report = LearnReport(
        run_id=score.run_id,
        overall=score.overall,
        fingerprint=fingerprint,
        batch=batch,
    )
    candidates = distill(score)
    report.candidates = candidates
    if not apply:
        return report

    present = lessons_mod.existing_keys()
    for cand in candidates:
        if cand.key in present:
            report.skipped.append(cand.key)
            continue
        number = lessons_mod.append_lesson(
            cand.title,
            cand.body,
            source=f"auto-distilled from {score.run_id or 'a run'} (overall {score.overall})",
            key=cand.key,
            batch=batch,
        )
        report.added.append((number, cand.title))
        present.add(cand.key)
    return report


def rollback_last_batch() -> tuple[str | None, list[int]]:
    """Remove the most recently appended lesson batch. Return (batch_id, numbers)."""
    batch = lessons_mod.last_batch()
    if not batch:
        return None, []
    return batch, lessons_mod.remove_batch(batch)


def format_report(report: LearnReport) -> str:
    """One compact block summarising what the loop learned from a run."""
    lines = [
        f"self-training: run {report.run_id or '(unnamed)'} scored {report.overall}/100 "
        f"[lessons {report.fingerprint}]",
    ]
    if report.added:
        for number, title in report.added:
            lines.append(f"  + learned L{number}: {title}")
    if report.skipped:
        lines.append(f"  = {len(report.skipped)} lesson(s) already known: {', '.join(report.skipped)}")
    if not report.added and not report.skipped:
        lines.append("  = nothing to learn from this run (clean score)")
    return "\n".join(lines)
