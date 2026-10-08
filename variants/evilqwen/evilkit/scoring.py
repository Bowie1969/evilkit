"""Run scoring — measures each run on four axes and diffs across harness versions.

Score axes (from the lesson):
1. Won — did the agent achieve the objective?
2. Knew it won — did it recognise completion (vs won but didn't notice)?
3. Noise made — how many futile/repeated actions?
4. Evidence left — is there a structured trail?

Usage: call `score_run()` after a controller run, or `diff_scores()` to compare
two runs across harness versions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .brain_state import MissionState
from .harness import HarnessState, Objective

__all__ = [
    "RunScore",
    "score_run",
    "diff_scores",
    "load_scores",
    "save_score",
]


@dataclass
class RunScore:
    """Score for a single run."""
    run_id: str = ""
    harness_version: str = "2.0"
    won: bool = False
    knew_it_won: bool = False
    noise_count: int = 0
    evidence_count: int = 0
    turns_used: int = 0
    max_turns: int = 50
    objectives_met: int = 0
    objectives_total: int = 0
    locked_vectors: int = 0
    stall_warnings: int = 0
    repetition_warnings: int = 0
    provenance_alerts: int = 0

    # Composite scores (0-100)
    @property
    def score_won(self) -> int:
        return 100 if self.won else 0

    @property
    def score_knew_it_won(self) -> int:
        if not self.won:
            return 50  # N/A
        return 100 if self.knew_it_won else 0

    @property
    def score_noise(self) -> int:
        """Lower noise = higher score. 0 noise = 100, 20+ = 0."""
        return max(0, 100 - (self.noise_count * 5))

    @property
    def score_evidence(self) -> int:
        """More evidence = higher score, capped at 100."""
        return min(100, self.evidence_count * 10)

    @property
    def score_objectives(self) -> int:
        if self.objectives_total == 0:
            return 50  # N/A
        return int((self.objectives_met / self.objectives_total) * 100)

    @property
    def overall(self) -> int:
        return int(
            0.30 * self.score_won
            + 0.20 * self.score_knew_it_won
            + 0.20 * self.score_noise
            + 0.15 * self.score_evidence
            + 0.15 * self.score_objectives
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "harness_version": self.harness_version,
            "won": self.won,
            "knew_it_won": self.knew_it_won,
            "noise_count": self.noise_count,
            "evidence_count": self.evidence_count,
            "turns_used": self.turns_used,
            "max_turns": self.max_turns,
            "objectives_met": self.objectives_met,
            "objectives_total": self.objectives_total,
            "locked_vectors": self.locked_vectors,
            "stall_warnings": self.stall_warnings,
            "repetition_warnings": self.repetition_warnings,
            "provenance_alerts": self.provenance_alerts,
            "scores": {
                "won": self.score_won,
                "knew_it_won": self.score_knew_it_won,
                "noise": self.score_noise,
                "evidence": self.score_evidence,
                "objectives": self.score_objectives,
                "overall": self.overall,
            },
        }


def score_run(
    state: MissionState,
    harness: HarnessState,
    run_id: str = "",
    harness_version: str = "2.0",
) -> RunScore:
    """Score a completed run from its final state and harness."""
    won = state.completed and bool(state.completion_reason)
    knew_it_won = won and "objective" in state.completion_reason.lower()

    # Count noise: repetition warnings + thrashing entries
    noise = harness.loop_detector.recent_commands.count(harness.loop_detector.recent_commands[-1]) if harness.loop_detector.recent_commands else 0
    noise += len(harness.budget.locked_vectors)

    # Evidence count
    evidence_count = len(state.evidence)

    # Objectives
    objectives_met = sum(1 for o in harness.objectives if o.met)
    objectives_total = len(harness.objectives)

    return RunScore(
        run_id=run_id,
        harness_version=harness_version,
        won=won,
        knew_it_won=knew_it_won,
        noise_count=noise,
        evidence_count=evidence_count,
        turns_used=state.turns,
        max_turns=state.turns,
        objectives_met=objectives_met,
        objectives_total=objectives_total,
        locked_vectors=len(harness.budget.locked_vectors),
        stall_warnings=harness.loop_detector.recent_thoughts.count("") if hasattr(harness.loop_detector, "recent_thoughts") else 0,
        repetition_warnings=0,  # Would need to track from harness warnings log
        provenance_alerts=0,  # Would need to track from harness warnings log
    )


def diff_scores(old: RunScore, new: RunScore) -> dict[str, str]:
    """Compare two runs and return a diff of scores."""
    diff = {}
    for key in ["won", "knew_it_won", "noise", "evidence", "objectives", "overall"]:
        old_val = getattr(old, f"score_{key}", 0) if hasattr(old, f"score_{key}") else getattr(old, key, 0)
        new_val = getattr(new, f"score_{key}", 0) if hasattr(new, f"score_{key}") else getattr(new, key, 0)
        delta = new_val - old_val
        sign = "+" if delta >= 0 else ""
        diff[key] = f"{old_val} -> {new_val} ({sign}{delta})"
    return diff


def save_score(score: RunScore, path: Path | str) -> Path:
    """Save a score to a JSON file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(score.to_dict(), indent=2) + "\n", encoding="utf-8")
    return p


def load_scores(dir: Path | str) -> list[RunScore]:
    """Load all score files from a directory."""
    d = Path(dir)
    scores = []
    if not d.is_dir():
        return scores
    for p in sorted(d.glob("score-*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            scores.append(RunScore(**{k: v for k, v in data.items() if k != "scores"}))
        except (json.JSONDecodeError, TypeError):
            continue
    return scores
