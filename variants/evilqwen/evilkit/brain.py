"""Operator-auditor controller for the EvilKit brain proof-of-concept.

The controller owns the canonical mission state. It asks the operator (GLM) for
an intention, executes it through the configured executor, records raw evidence,
asks the auditor (DeepSeek) for a verdict, and deterministically applies the
verdict. It never lets either model mutate state directly.

Optional JSONL tracing writes one line per event (intention, execute, auditor,
state_delta) so external viewers (pentest-viewer, claw3d-style 3D) can consume
a live turn-by-turn stream.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .brain_state import (
    MissionState,
    add_credential,
    add_finding,
    add_host,
    add_service,
    classify_evidence,
    detect_thrashing,
    record_evidence,
    state_from_json,
    state_to_json,
    update_coverage,
)
from .harness import (
    EvidenceJournal,
    FactsLedger,
    HarnessState,
    LoopDetector,
    Objective,
    ProvenanceChecker,
    _extract_technique,
    _extract_host,
    _extract_credential,
)
from .models import ChatCompletionClient, ChatMessage, ChatRequest
from .prompts import (
    auditor_system_prompt,
    auditor_user_prompt,
    operator_system_prompt,
    operator_user_prompt,
)
from .tools import ExecutionResult, Executor

__all__ = [
    "Controller",
    "ControllerResult",
    "RunOptions",
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit_trace(path: str, turn: int, kind: str, data: dict) -> None:
    """Append a single JSONL line to the trace file."""
    line = json.dumps(
        {
            "ts": _utc_now_iso(),
            "turn": turn,
            "kind": kind,
            "data": data,
        },
        default=str,
    )
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass  # silent fail — tracing must not break the loop


class ControllerResult:
    """Result of a single controller turn or a full run."""

    def __init__(self, state: MissionState, log: list[str]) -> None:
        self.state = state
        self.log = log


@dataclass
class RunOptions:
    max_turns: int = 50
    state_path: str | None = None
    trace_path: str | None = None
    dry_run_models: bool = False
    objectives: list[Objective] | None = None
    evidence_dir: str | None = None
    stall_timeout: int = 120


class _NullExecutor:
    """Placeholder used when no executor is injected."""

    def execute(self, command: str) -> ExecutionResult:
        return ExecutionResult(command=command, returncode=0, stdout="", stderr="")


def _json_extract(text: str) -> dict:
    """Extract a JSON object from text, tolerating markdown fences."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        lines = text.splitlines()
        if lines and lines[0].lower().startswith("json"):
            lines = lines[1:]
        text = "\n".join(lines).strip("`")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last resort: grab the first { ... } block.
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def _summarize_state(state: MissionState) -> str:
    lines = [
        f"Turns: {state.turns}",
        f"Scope: {', '.join(state.scope)}",
        f"Hosts: {len(state.hosts)}",
    ]
    for address, host in sorted(state.hosts.items()):
        services = ", ".join(f"{s.port}/{s.protocol}" for s in host.services) or "none"
        lines.append(f"  {address} ({host.hostname or 'unknown'}) services: {services}")
    lines.append(f"Credentials: {len(state.credentials)}")
    lines.append(f"Findings: {len(state.findings)}")
    for finding in state.findings:
        verified = "verified" if finding.verified else "unverified"
        lines.append(f"  [{finding.severity}] {finding.title} ({verified})")
    lines.append(f"Attack paths: {len(state.attack_paths)}")
    for path in state.attack_paths:
        status = "completed" if path.completed else "open"
        if path.blocked:
            status = "blocked"
        lines.append(f"  {path.source} -> {path.target} via {path.technique} ({status})")
    lines.append(f"Evidence entries: {len(state.evidence)}")
    for idx, entry in enumerate(state.evidence[-5:]):
        lines.append(
            f"  [{len(state.evidence) - 5 + idx}] ({entry.classification}) {entry.claim}"
        )
    return "\n".join(lines)


def _update_state_from_output(state: MissionState, command: str, output: str) -> None:
    """Apply simple heuristics to derive state from raw tool output."""
    lower = command.lower()

    # Ping success -> host up.
    if "ping" in lower and "64 bytes" in output:
        target = _first_target(lower, output)
        if target:
            ref = len(state.evidence) - 1
            add_host(state, target, evidence_ref=ref)
            update_coverage(state, target, "icmp", "recon")

    # Nmap open ports -> services.
    if "nmap" in lower:
        target = _first_target(lower, output)
        if target:
            ref = len(state.evidence) - 1
            add_host(state, target, evidence_ref=ref)
            for line in output.splitlines():
                match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
                if match:
                    port, protocol, name = match.groups()
                    add_service(
                        state,
                        target,
                        int(port),
                        protocol,
                        name=name,
                        evidence_ref=ref,
                    )
                    update_coverage(state, target, f"{port}/{protocol}", "enumeration")

    # Curl / wget -> http service.
    if "curl" in lower or "wget" in lower:
        target = _first_target(lower, output)
        if target and ("<html>" in output.lower() or "http" in output.lower()):
            ref = len(state.evidence) - 1
            add_host(state, target, evidence_ref=ref)
            add_service(state, target, 80, "tcp", name="http", evidence_ref=ref)
            update_coverage(state, target, "80/tcp", "enumeration")


def _first_target(command: str, output: str) -> str | None:
    """Crude target extraction from a command string."""
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", command)
    if ip_match:
        return ip_match.group(0)
    host_match = re.search(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}\b",
        command,
    )
    if host_match:
        return host_match.group(0)
    return None


def _default_operator_response(state_summary: str, turn: int) -> dict:
    """Fallback operator response used when parsing fails or in dry run."""
    if turn == 0:
        return {
            "goal": "confirm loopback host is reachable",
            "command": "ping -c 1 127.0.0.1",
            "expected_result": "one reply from 127.0.0.1",
            "reasoning": "start with a safe in-scope reconnaissance command",
        }
    return {
        "goal": "enumerate services on known host",
        "command": "nmap -sV 127.0.0.1",
        "expected_result": "list of open ports and services",
        "reasoning": "after confirming host is up, enumerate services",
    }


def _default_auditor_response() -> dict:
    return {
        "verdict": "CONTINUE",
        "reason": "default auditor response (no model configured)",
        "confidence": "low",
        "urgency": "later",
        "evidence_refs": [],
        "required_test": "",
        "recommendation": "continue with the operator's planned action",
        "claim_classifications": {},
    }


class Controller:
    """Run the operator-auditor loop with canonical state ownership."""

    def __init__(
        self,
        operator: ChatCompletionClient,
        auditor: ChatCompletionClient,
        executor: Executor,
        scope: list[str],
        options: RunOptions | None = None,
    ) -> None:
        self.operator = operator
        self.auditor = auditor
        self.executor = executor
        self.scope = scope
        self.options = options or RunOptions()
        self._log: list[str] = []

        # Harness integration
        ev_dir = Path(self.options.evidence_dir) if self.options.evidence_dir else Path("evidence")
        self.harness = HarnessState(
            objectives=self.options.objectives or [],
            evidence_journal=EvidenceJournal(evidence_dir=ev_dir),
        )
        self.harness.loop_detector.stall_timeout = self.options.stall_timeout

    def validate_launch(self) -> list[str]:
        """Validate the launch configuration — assert pivot/interpreter gates are set.
        Returns a list of warnings (empty = all good)."""
        warnings = []
        # Check that the executor is not the null executor
        if isinstance(self.executor, _NullExecutor):
            warnings.append("WARNING: using NullExecutor — no commands will actually run")
        # Check scope is not /0
        if "0.0.0.0/0" in self.scope or "::/0" in self.scope:
            warnings.append("WARNING: /0 scope authorizes every address — verify this is intended")
        # Check objectives are defined
        if not self.harness.objectives:
            warnings.append("INFO: no objectives defined — add --objective for machine-readable goals")
        return warnings

    def _say(self, message: str) -> None:
        self._log.append(message)

    def _load_or_create_state(self) -> MissionState:
        if self.options.state_path:
            path = self.options.state_path
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    return state_from_json(handle.read())
            except (OSError, json.JSONDecodeError) as exc:
                self._say(f"could not load state from {path}: {exc}; starting fresh")
        return MissionState(scope=self.scope)

    def _save_state(self, state: MissionState) -> None:
        if self.options.state_path:
            try:
                with open(self.options.state_path, "w", encoding="utf-8") as handle:
                    handle.write(state_to_json(state))
            except OSError as exc:
                self._say(f"could not write state: {exc}")

    def _ask_operator(self, state: MissionState, auditor_feedback: str, harness_context: str = "") -> dict:
        system_content = operator_system_prompt(",".join(self.scope))
        if harness_context:
            system_content += f"\n\nHARNESS CONTEXT:\n{harness_context}"
        messages = [
            ChatMessage(role="system", content=system_content),
            ChatMessage(
                role="user",
                content=operator_user_prompt(
                    state.turns, ",".join(self.scope), _summarize_state(state), auditor_feedback
                ),
            ),
        ]
        try:
            content = self.operator.complete(
                ChatRequest(messages=messages, response_format={"type": "json_object"})
            )
            return _json_extract(content)
        except Exception as exc:
            self._say(f"operator request failed: {exc}")
            return _default_operator_response(_summarize_state(state), state.turns)

    def _execute_tool(self, tool_call: dict) -> ExecutionResult:
        """Execute an MCP tool call via the malware generator MCP server."""
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("arguments", {})

        if not tool_name:
            return ExecutionResult(command="", returncode=1, stdout="", stderr="empty tool name")

        # Build the MCP request
        mcp_request = {
            "method": "tools/call",
            "id": 1,
            "params": {
                "name": tool_name,
                "arguments": tool_args,
            },
        }

        try:
            # Import and call the MCP server directly
            import importlib.util
            mcp_path = Path(__file__).parent.parent / "mcp-malware-generator.py"
            spec = importlib.util.spec_from_file_location("mcp_server", str(mcp_path))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            response = mod.handle_request(mcp_request)

            if "error" in response:
                return ExecutionResult(
                    command=json.dumps(tool_call),
                    returncode=1,
                    stdout="",
                    stderr=response["error"].get("message", "unknown error"),
                )

            # Extract text content from response
            content = ""
            for item in response.get("result", {}).get("content", []):
                if item.get("type") == "text":
                    content += item.get("text", "")

            return ExecutionResult(
                command=json.dumps(tool_call),
                returncode=0,
                stdout=content,
                stderr="",
            )

        except Exception as exc:
            return ExecutionResult(
                command=json.dumps(tool_call),
                returncode=1,
                stdout="",
                stderr=f"MCP tool execution failed: {str(exc)}",
            )

    def _ask_auditor(
        self,
        state: MissionState,
        operator_intention: dict,
        raw_output: str,
    ) -> dict:
        intention_text = json.dumps(operator_intention, indent=2)
        messages = [
            ChatMessage(role="system", content=auditor_system_prompt()),
            ChatMessage(
                role="user",
                content=auditor_user_prompt(
                    state.turns,
                    ",".join(self.scope),
                    intention_text,
                    raw_output,
                    _summarize_state(state),
                ),
            ),
        ]
        try:
            content = self.auditor.complete(
                ChatRequest(messages=messages, response_format={"type": "json_object"})
            )
            return _json_extract(content)
        except Exception as exc:
            self._say(f"auditor request failed: {exc}")
            return _default_auditor_response()

    def _execute(self, command: str) -> ExecutionResult:
        if not command:
            return ExecutionResult(command="", returncode=0, stdout="", stderr="")
        return self.executor.execute(command)

    def run(self) -> ControllerResult:
        state = self._load_or_create_state()
        auditor_feedback = "No previous feedback."

        for turn in range(self.options.max_turns):
            if state.completed or state.paused:
                break
            state.turns = turn

            # Harness: inject enriched context (ledger, budget, objectives)
            harness_context = self.harness.inject_context(_summarize_state(state))

            # Harness: check for stalled loop
            stall = self.harness.loop_detector.check_stall()
            if stall:
                self._say(f"[turn {turn}] {stall}")

            intention = self._ask_operator(state, auditor_feedback, harness_context=harness_context)
            goal = intention.get("goal", "")
            command = intention.get("command", "")
            tool_call = intention.get("tool")
            expected = intention.get("expected_result", "")
            reasoning = intention.get("reasoning", "")
            access_claim = intention.get("access_claim")
            phase = intention.get("phase", 0)

            self._say(f"[turn {turn}] operator: {goal}")
            if command:
                self._say(f"[turn {turn}] command: {command}")
            if tool_call:
                self._say(f"[turn {turn}] tool: {tool_call.get('name', '')}")
            if reasoning:
                self._say(f"[turn {turn}] reasoning: {reasoning}")
            if phase:
                self._say(f"[turn {turn}] phase: {phase}")

            # Harness: pre-action check (circuit breaker, budget, tool nudge)
            host = _extract_host(command) if command else ""
            credential = _extract_credential(command) if command else ""
            pre_block = self.harness.pre_action_check(
                host=host, credential=credential, command=command,
            )
            if pre_block:
                self._say(f"[turn {turn}] HARNESS BLOCK: {pre_block}")
                auditor_feedback = f"HARNESS BLOCKED: {pre_block}"
                if self.options.trace_path:
                    _emit_trace(self.options.trace_path, turn, "harness_block", {"message": pre_block})
                continue

            # Harness: validate access claims
            if access_claim and isinstance(access_claim, dict):
                claim_host = access_claim.get("host", "")
                claim_level = access_claim.get("level", "")
                if claim_host and claim_level:
                    prov_block = self.harness.provenance.check_access_claim(claim_host, claim_level, command)
                    if prov_block:
                        self._say(f"[turn {turn}] {prov_block}")
                        auditor_feedback = f"PROVENANCE BLOCK: {prov_block}"
                        continue

            # Trace: operator intention
            if self.options.trace_path:
                _emit_trace(
                    self.options.trace_path,
                    turn,
                    "intention",
                    {"goal": goal, "command": command, "tool": tool_call, "expected_result": expected,
                     "reasoning": reasoning, "phase": phase, "access_claim": access_claim},
                )

            # Execute command and/or tool
            raw_output = ""
            result = None

            if tool_call:
                result = self._execute_tool(tool_call)
                raw_output = result.stdout
                if result.stderr:
                    raw_output += "\n" + result.stderr
                self._say(
                    f"[turn {turn}] tool result: exit={result.returncode} "
                    f"stdout={len(result.stdout)} chars stderr={len(result.stderr)} chars"
                )

            if command:
                result = self._execute(command)
                cmd_output = result.stdout
                if result.stderr:
                    cmd_output += "\n" + result.stderr
                raw_output += "\n" + cmd_output if raw_output else cmd_output
                self._say(
                    f"[turn {turn}] result: exit={result.returncode} "
                    f"stdout={len(result.stdout)} chars stderr={len(result.stderr)} chars"
                )

            if not result:
                result = ExecutionResult(command="", returncode=0, stdout="", stderr="")

            # Trace: execution result
            if self.options.trace_path:
                _emit_trace(
                    self.options.trace_path,
                    turn,
                    "execute",
                    {
                        "command": command,
                        "returncode": result.returncode,
                        "stdout_chars": len(result.stdout),
                        "stderr_chars": len(result.stderr),
                    },
                )

            record_evidence(
                state,
                claim=goal or "operator action",
                command=command,
                raw_output=raw_output,
                provenance="operator",
            )
            evidence_index = len(state.evidence) - 1

            _update_state_from_output(state, command, raw_output)

            # Harness: record action + generate warnings (loop, budget, objectives, provenance)
            warnings = self.harness.record_action(
                turn, command, result.stdout, result.stderr, result.returncode,
                goal=goal, reasoning=reasoning, tool_call=tool_call,
            )
            for w in warnings:
                self._say(f"[turn {turn}] HARNESS: {w}")

            # Harness: update access level on successful auth
            if access_claim and isinstance(access_claim, dict):
                claim_host = access_claim.get("host", "")
                claim_level = access_claim.get("level", "")
                if claim_host and claim_level and result.returncode == 0:
                    self.harness.ledger.set_access_level(claim_host, claim_level)

            # Harness: check if any objective newly met
            obj_injection = self.harness.check_objectives(raw_output, turn=turn)
            if obj_injection:
                self._say(f"[turn {turn}] {obj_injection}")

            # The auditor gets the raw output, not a summary.
            auditor_response = self._ask_auditor(state, intention, raw_output)
            verdict = (auditor_response.get("verdict") or "CONTINUE").upper()
            reason = auditor_response.get("reason", "")
            required_test = auditor_response.get("required_test", "")
            recommendation = auditor_response.get("recommendation", "")
            claim_classifications = auditor_response.get("claim_classifications", {}) or {}

            self._say(f"[turn {turn}] auditor verdict: {verdict}")
            if reason:
                self._say(f"[turn {turn}] auditor reason: {reason}")

            # Trace: auditor verdict
            if self.options.trace_path:
                _emit_trace(
                    self.options.trace_path,
                    turn,
                    "auditor",
                    {
                        "verdict": verdict,
                        "reason": reason,
                        "required_test": required_test,
                        "recommendation": recommendation,
                        "claim_classifications": claim_classifications,
                    },
                )

            # Apply auditor classifications to the last evidence entry.
            if "disputed" in claim_classifications.values():
                classify_evidence(state, evidence_index, "disputed")
            elif all(v == "confirmed" for v in claim_classifications.values()) and claim_classifications:
                classify_evidence(state, evidence_index, "confirmed")

            # Trace: deterministic state delta after EvilKit applied the turn.
            if self.options.trace_path:
                # Collect actual host addresses and new attack paths for the viewer.
                new_paths = []
                for ap in state.attack_paths:
                    if ap.completed:
                        new_paths.append({
                            "source": ap.source,
                            "target": ap.target,
                            "technique": ap.technique,
                        })
                all_hosts = sorted(state.hosts.keys())
                _emit_trace(
                    self.options.trace_path,
                    turn,
                    "state_delta",
                    {
                        "turns": state.turns,
                        "hosts": len(state.hosts),
                        "host_list": all_hosts,
                        "services": sum(len(h.services) for h in state.hosts.values()),
                        "credentials": len(state.credentials),
                        "findings": len(state.findings),
                        "attack_paths": len(state.attack_paths),
                        "new_attack_paths": new_paths,
                        "evidence": len(state.evidence),
                        "last_evidence_classification": (
                            state.evidence[-1].classification if state.evidence else None
                        ),
                    },
                )

            # Thrashing check is deterministic and owned by EvilKit.
            for warning in detect_thrashing(state):
                self._say(f"[turn {turn}] thrashing warning: {warning}")

            # Harness: objective-met hard stop (operator must still justify)
            if obj_injection and verdict in ("CONTINUE", "ADVISE"):
                state.completed = True
                state.completion_reason = obj_injection
                break

            if verdict == "PAUSE":
                state.paused = True
                state.completion_reason = f"paused by auditor: {reason}"
                if required_test:
                    state.completion_reason += f" required test: {required_test}"
                auditor_feedback = f"PAUSE: {reason}"
                break

            if verdict == "CHALLENGE":
                auditor_feedback = (
                    f"CHALLENGE: {reason}"
                )
                if required_test:
                    auditor_feedback += f" Run this test before proceeding: {required_test}"
                continue

            if verdict == "ADVISE":
                auditor_feedback = f"ADVISE: {reason}"
                if recommendation:
                    auditor_feedback += f" Recommended next action: {recommendation}"
                continue

            # CONTINUE
            auditor_feedback = f"CONTINUE: {reason}" if reason else "CONTINUE"

            # Completion gate: the operator can only declare completion if the
            # auditor also agrees. Without a model, the default auditor never
            # allows completion, so the loop runs until max_turns.
            if not command and "complete" in goal.lower():
                if verdict == "CONTINUE" and all(
                    v == "confirmed" for v in claim_classifications.values()
                ):
                    state.completed = True
                    state.completion_reason = "operator declared completion and auditor confirmed"
                else:
                    auditor_feedback = (
                        "Completion was requested but not confirmed. "
                        "Continue gathering evidence before declaring done."
                    )

        if not (state.completed or state.paused):
            state.completion_reason = f"reached max_turns ({self.options.max_turns})"

        # Harness: build final report skeleton from evidence
        if self.harness.evidence_journal:
            report = self.harness.evidence_journal.build_report_skeleton(
                self.harness.ledger, self.harness.objectives,
            )
            report_path = self.harness.evidence_journal.evidence_dir / "REPORT-skeleton.md"
            report_path.write_text(report, encoding="utf-8")
            self._say(f"Evidence report skeleton: {report_path}")

        self._save_state(state)
        return ControllerResult(state, self._log)
