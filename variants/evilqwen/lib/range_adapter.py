"""Typed adapter for the Chainbreaker cage command-line controller."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


DEFAULT_RANGE_ROOT = Path(
    "/home/will_cyber/orca/workspaces/home lab/"
    "Most-Dangerous-Thing-We-Can-Build-And-Test-Safetly"
)
DEFAULT_CAGE_ROOT = Path(".chainbreaker/cage")
DEFAULT_MANIFEST = Path("campaign/chainbreaker.json")
DEFAULT_SPEC = Path("range/compose.json")
DEFAULT_INTAKE = Path("campaign/intake.example.json")
DEFAULT_RELAY_ENTRY = "10.99.99.21:9001"
DEFAULT_RELAY_UPSTREAM = "10.99.50.11:8080"


@dataclass(frozen=True)
class CageResult:
    """One cage operation, including structured output or a safe error."""

    ok: bool
    operation: str
    command: tuple[str, ...] = ()
    data: Any = None
    error: str = ""
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""

    @property
    def success(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class CampaignResult:
    """Results from a composed prepare/start/stop/score lifecycle."""

    ok: bool
    run_id: str | None = None
    prepared: CageResult | None = None
    mission: CageResult | None = None
    started: CageResult | None = None
    relay_intent: CageResult | None = None
    relay_path: CageResult | None = None
    stopped: CageResult | None = None
    score: CageResult | None = None
    error: str = ""

    @property
    def success(self) -> bool:
        return self.ok


def _absolute(path: str | Path, range_root: Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = range_root / candidate
    return candidate.resolve()


def _valid_run_id(run_id: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{16}", run_id) is not None


def _run_cage(
    operation: str,
    arguments: Sequence[str],
    *,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 120.0,
) -> CageResult:
    root = Path(range_root).expanduser().resolve()
    if not root.is_dir():
        return CageResult(False, operation, error=f"range root does not exist: {root}")

    command = (
        "python3",
        "-m",
        "cage",
        "--root",
        str(_absolute(cage_root, root)),
        "--manifest",
        str(_absolute(manifest, root)),
        *arguments,
    )
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return CageResult(False, operation, command, error=str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CageResult(
            False,
            operation,
            command,
            error=f"cage command timed out after {timeout:g} seconds",
            stdout=stdout,
            stderr=stderr,
        )
    except (OSError, ValueError) as exc:
        return CageResult(False, operation, command, error=f"could not run cage: {exc}")

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        detail = stderr or stdout or "cage returned no output"
        return CageResult(
            False,
            operation,
            command,
            error=f"cage returned invalid JSON: {detail[:1000]}",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    if not isinstance(envelope, dict):
        return CageResult(
            False,
            operation,
            command,
            error="cage returned a non-object JSON response",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    ok = completed.returncode == 0 and envelope.get("ok") is True
    error = "" if ok else str(envelope.get("error") or stderr or "cage command failed")
    return CageResult(
        ok,
        operation,
        command,
        data=envelope.get("data"),
        error=error,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def prepare_run(
    intake: str | Path = DEFAULT_INTAKE,
    *,
    spec: str | Path = DEFAULT_SPEC,
    clean_paths: Sequence[str | Path] = (),
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 120.0,
) -> CageResult:
    root = Path(range_root).expanduser().resolve()
    arguments = [
        "prepare-run",
        str(_absolute(intake, root)),
        "--spec",
        str(_absolute(spec, root)),
    ]
    for path in clean_paths:
        arguments.extend(("--clean-path", str(_absolute(path, root))))
    return _run_cage(
        "prepare-run",
        arguments,
        range_root=root,
        cage_root=cage_root,
        manifest=manifest,
        timeout=timeout,
    )


def _run_operation(
    operation: str,
    run_id: str,
    *,
    spec: str | Path = DEFAULT_SPEC,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 120.0,
) -> CageResult:
    if not _valid_run_id(run_id):
        return CageResult(False, operation, error=f"invalid run ID {run_id!r}")
    root = Path(range_root).expanduser().resolve()
    return _run_cage(
        operation,
        (operation, run_id, "--spec", str(_absolute(spec, root))),
        range_root=root,
        cage_root=cage_root,
        manifest=manifest,
        timeout=timeout,
    )


def start_run(run_id: str, **kwargs: Any) -> CageResult:
    return _run_operation("start-run", run_id, **kwargs)


def stop_run(run_id: str, **kwargs: Any) -> CageResult:
    return _run_operation("stop-run", run_id, **kwargs)


def score_run(run_id: str, **kwargs: Any) -> CageResult:
    return _run_operation("score-run", run_id, **kwargs)


def record_relay_intent(
    run_id: str,
    reason: str,
    *,
    entry: str = DEFAULT_RELAY_ENTRY,
    upstream: str = DEFAULT_RELAY_UPSTREAM,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 30.0,
) -> CageResult:
    if not _valid_run_id(run_id):
        return CageResult(False, "record-relay-intent", error=f"invalid run ID {run_id!r}")
    if not reason.strip():
        return CageResult(False, "record-relay-intent", error="relay intent requires a reason")
    return _run_cage(
        "record-relay-intent",
        (
            "record-relay-intent",
            run_id,
            "--entry",
            entry,
            "--upstream",
            upstream,
            "--reason",
            reason,
        ),
        range_root=range_root,
        cage_root=cage_root,
        manifest=manifest,
        timeout=timeout,
    )


def record_relay_path(
    run_id: str,
    path: str,
    *,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 30.0,
) -> CageResult:
    if not _valid_run_id(run_id):
        return CageResult(False, "record-relay-path", error=f"invalid run ID {run_id!r}")
    if not path.strip():
        return CageResult(False, "record-relay-path", error="relay path is required")
    return _run_cage(
        "record-relay-path",
        ("record-relay-path", run_id, path),
        range_root=range_root,
        cage_root=cage_root,
        manifest=manifest,
        timeout=timeout,
    )


def get_mission(
    run_id: str,
    *,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
) -> CageResult:
    operation = "get-mission"
    if not _valid_run_id(run_id):
        return CageResult(False, operation, error=f"invalid run ID {run_id!r}")
    root = Path(range_root).expanduser().resolve()
    mission_path = _absolute(cage_root, root) / "runs" / run_id / "mission.json"
    try:
        mission = json.loads(mission_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return CageResult(False, operation, error=f"mission not found for run {run_id!r}")
    except OSError as exc:
        return CageResult(False, operation, error=f"could not read mission: {exc}")
    except json.JSONDecodeError as exc:
        return CageResult(False, operation, error=f"mission JSON is invalid: {exc}")
    if not isinstance(mission, dict):
        return CageResult(False, operation, error="mission JSON is not an object")
    return CageResult(True, operation, data=mission)


def run_campaign(
    intake: str | Path = DEFAULT_INTAKE,
    *,
    spec: str | Path = DEFAULT_SPEC,
    clean_paths: Sequence[str | Path] = (),
    relay_reason: str = "",
    relay_path: str = "",
    auto_stop: bool = True,
    range_root: str | Path = DEFAULT_RANGE_ROOT,
    cage_root: str | Path = DEFAULT_CAGE_ROOT,
    manifest: str | Path = DEFAULT_MANIFEST,
    timeout: float = 120.0,
) -> CampaignResult:
    common = {
        "range_root": range_root,
        "cage_root": cage_root,
        "manifest": manifest,
        "timeout": timeout,
    }
    prepared = prepare_run(
        intake,
        spec=spec,
        clean_paths=clean_paths,
        **common,
    )
    if not prepared.ok:
        return CampaignResult(False, prepared=prepared, error=prepared.error)

    run_id = prepared.data.get("run_id") if isinstance(prepared.data, dict) else None
    if not isinstance(run_id, str) or not _valid_run_id(run_id):
        error = "prepare-run did not return a valid run ID"
        return CampaignResult(False, prepared=prepared, error=error)

    mission = get_mission(run_id, range_root=range_root, cage_root=cage_root)
    if not mission.ok:
        return CampaignResult(
            False,
            run_id=run_id,
            prepared=prepared,
            mission=mission,
            error=mission.error,
        )
    started = start_run(run_id, spec=spec, **common)
    if not started.ok:
        return CampaignResult(
            False,
            run_id=run_id,
            prepared=prepared,
            mission=mission,
            started=started,
            error=started.error,
        )

    intent_result = None
    path_result = None
    failure = ""
    if relay_reason:
        intent_result = record_relay_intent(
            run_id,
            relay_reason,
            range_root=range_root,
            cage_root=cage_root,
            manifest=manifest,
            timeout=min(timeout, 30.0),
        )
        if not intent_result.ok:
            failure = intent_result.error
    if relay_path and not failure:
        path_result = record_relay_path(
            run_id,
            relay_path,
            range_root=range_root,
            cage_root=cage_root,
            manifest=manifest,
            timeout=min(timeout, 30.0),
        )
        if not path_result.ok:
            failure = path_result.error

    stopped = None
    score = None
    if auto_stop:
        stopped = stop_run(run_id, spec=spec, **common)
        if not stopped.ok and not failure:
            failure = stopped.error
        if stopped.ok:
            score = score_run(run_id, spec=spec, **common)
            if not score.ok and not failure:
                failure = score.error

    return CampaignResult(
        not failure,
        run_id=run_id,
        prepared=prepared,
        mission=mission,
        started=started,
        relay_intent=intent_result,
        relay_path=path_result,
        stopped=stopped,
        score=score,
        error=failure,
    )
