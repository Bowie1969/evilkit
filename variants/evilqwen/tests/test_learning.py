"""Tests for the self-training loop — evilkit.learning and the lessons it writes."""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit import learning as learning_mod  # noqa: E402
from evilkit import lessons as lessons_mod  # noqa: E402
from evilkit.scoring import RunScore  # noqa: E402


class LearningTestCase(EvilkitTestCase):
    """Redirect the package-relative lessons/ledger files into the temp dir."""

    def setUp(self) -> None:
        super().setUp()
        self.lessons_file = self.tmp / "lessons.md"
        self.ledger_file = self.tmp / "ledger.jsonl"
        for target in ("evilkit.lessons.lessons_path", "evilkit.learning.lessons_mod.lessons_path"):
            p = mock.patch(target, return_value=self.lessons_file)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("evilkit.learning.ledger_path", return_value=self.ledger_file)
        p.start()
        self.addCleanup(p.stop)


def _won_but_blind() -> RunScore:
    return RunScore(run_id="r1", won=True, knew_it_won=False, turns_used=5,
                    evidence_count=5, objectives_met=1, objectives_total=1)


def _messy_loss() -> RunScore:
    return RunScore(run_id="r2", won=False, noise_count=10, locked_vectors=2,
                    evidence_count=1, objectives_met=0, objectives_total=3,
                    turns_used=50, max_turns=50)


class TestDistill(LearningTestCase):
    def test_won_but_blind_yields_only_completion_lesson(self):
        cands = learning_mod.distill(_won_but_blind())
        self.assertEqual([c.key for c in cands], ["recognise-completion"])
        self.assertIn("5 turns", cands[0].body)

    def test_messy_loss_yields_three_lessons(self):
        keys = {c.key for c in learning_mod.distill(_messy_loss())}
        self.assertEqual(keys, {"cut-noise", "capture-evidence", "finish-objectives"})

    def test_clean_win_yields_nothing(self):
        clean = RunScore(run_id="ok", won=True, knew_it_won=True, evidence_count=9,
                         objectives_met=2, objectives_total=2)
        self.assertEqual(learning_mod.distill(clean), [])


class TestLearnFromRun(LearningTestCase):
    def test_appends_novel_lessons_and_records_ledger(self):
        report = learning_mod.learn_from_run(_messy_loss())
        self.assertEqual(len(report.added), 3)
        self.assertEqual(report.skipped, [])
        # ledger recorded the run under the baseline fingerprint (lessons were
        # empty *during* the run; they are appended afterwards).
        rows = learning_mod.ledger_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["fingerprint"], "baseline")
        self.assertEqual(rows[0]["run_id"], "r2")

    def test_second_identical_run_dedups(self):
        learning_mod.learn_from_run(_messy_loss())
        report = learning_mod.learn_from_run(_messy_loss())
        self.assertEqual(report.added, [])
        self.assertEqual(set(report.skipped), {"cut-noise", "capture-evidence", "finish-objectives"})

    def test_apply_false_records_but_writes_no_lesson(self):
        report = learning_mod.learn_from_run(_messy_loss(), apply=False)
        self.assertEqual(report.added, [])
        self.assertEqual(report.candidates and len(report.candidates), 3)
        self.assertFalse(self.lessons_file.exists())
        self.assertEqual(len(learning_mod.ledger_rows()), 1)

    def test_fingerprint_advances_after_learning(self):
        before = learning_mod.lessons_fingerprint()
        learning_mod.learn_from_run(_messy_loss())
        self.assertEqual(before, "baseline")
        self.assertNotEqual(learning_mod.lessons_fingerprint(), "baseline")


class TestGate(LearningTestCase):
    def test_generation_summary_tracks_delta(self):
        # Generation A: two runs under baseline.
        learning_mod.record_run(RunScore(run_id="a1", won=False, evidence_count=1),
                                 fingerprint="baseline")
        learning_mod.record_run(RunScore(run_id="a2", won=False, evidence_count=1),
                                 fingerprint="baseline")
        # Generation B: one strong run under new lessons.
        learning_mod.record_run(RunScore(run_id="b1", won=True, knew_it_won=True,
                                          evidence_count=9, objectives_met=1, objectives_total=1),
                                 fingerprint="abc123")
        summary = learning_mod.generation_summary()
        self.assertEqual([g["fingerprint"] for g in summary], ["baseline", "abc123"])
        self.assertIsNone(summary[0]["delta"])
        self.assertGreater(summary[1]["delta"], 0)

    def test_rollback_removes_last_batch_only(self):
        learning_mod.learn_from_run(_won_but_blind())      # batch r1 -> 1 lesson
        learning_mod.learn_from_run(_messy_loss())         # batch r2 -> 3 lessons
        batch, removed = learning_mod.rollback_last_batch()
        self.assertEqual(batch, "r2")
        self.assertEqual(len(removed), 3)
        # The r1 lesson survives.
        self.assertEqual(lessons_mod.existing_keys(), {"recognise-completion"})

    def test_rollback_with_no_batches(self):
        batch, removed = learning_mod.rollback_last_batch()
        self.assertIsNone(batch)
        self.assertEqual(removed, [])


class TestLessonsMarkers(LearningTestCase):
    def test_load_lessons_strips_metadata(self):
        lessons_mod.append_lesson("T", "body text", key="k1", batch="b1")
        injected = lessons_mod.load_lessons()
        self.assertIn("body text", injected)
        self.assertNotIn("Key:", injected)
        self.assertNotIn("Batch:", injected)
        # But the raw file keeps them for dedup/rollback.
        self.assertEqual(lessons_mod.existing_keys(), {"k1"})
        self.assertEqual(lessons_mod.last_batch(), "b1")

    def test_numbering_is_stable_across_rollback(self):
        lessons_mod.append_lesson("A", "a", key="ka", batch="b1")
        lessons_mod.append_lesson("B", "b", key="kb", batch="b2")
        lessons_mod.remove_batch("b1")
        # Next number is still 3: numbering never reuses a retired slot.
        self.assertEqual(lessons_mod.next_lesson_number(), 3)


class TestLearnCli(LearningTestCase):
    def test_status_empty(self):
        code, out, err = self.call_main(["learn", "status"])
        self.assertEqual(code, 1)
        self.assertIn("no runs recorded", err)

    def test_status_after_runs(self):
        learning_mod.learn_from_run(_messy_loss())
        code, out, err = self.call_main(["learn", "status"])
        self.assertEqual(code, 0)
        self.assertIn("baseline", out)

    def test_rollback_cli(self):
        learning_mod.learn_from_run(_messy_loss())
        code, out, err = self.call_main(["learn", "rollback"])
        self.assertEqual(code, 0)
        self.assertIn("rolled back batch r2", out)
        self.assertEqual(lessons_mod.existing_keys(), set())


if __name__ == "__main__":
    unittest.main()
