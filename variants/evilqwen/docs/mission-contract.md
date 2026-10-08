# The mission contract, the declaration gate and the proof ledger

Three ideas, one module (`lib/mission_contract.py`), four MCP tools.

## Why it exists

Run 11's agent did real work — it authored a three-stage chain, deployed it across
four guests, installed persistence on each, and took crown01's records — and still
scored zero, because the scoreboard is built from *proven* outcomes and the run's
evidence never connected to them. Two habits caused most of the loss:

- **Identification after access.** Crown data was read before the asset was named,
  so the access counted as an accident rather than a decision.
- **Activity mistaken for proof.** "Persistence installed" was a file on disk. It
  was never shown to activate, call home, or survive a restart.

The contract layer makes both habits fail in code rather than in a rubric.

## The contract

`contracts/mission.json` is derived from the run's brief and contains only what
the brief already tells the operator: the objectives, what each depends on, the
witness set that proves each one, the approved sink, and the budget. It
deliberately does **not** contain the scorer's sequences, penalties or ground
truth.

`mission_contract` loads it and prints every prerequisite, so the plan comes from
what is scored rather than from what is reachable.

## The declaration gate

`malware_persist`, `malware_c2`, `malware_worm` and `malware_classify` are
refused until the matching objective has a declaration on file:

```
error: DECLARATION REQUIRED: persistence is a sensitive objective and no intent
has been declared. Call mission_declare with the objective, the concrete action
and the rationale first. A claim made after the action is not credited.
```

Declarations are appended with a monotonic sequence number and written to disk, so
one cannot be added after the action it is supposed to precede. The gate also
refuses a dependent objective whose prerequisite is not **verified** — the crown
objective opens on a proven implant, not on a plan for one.

## The objective state machine

```
blocked → ready → attempted → partial → verified
                     ↘ failed (branch stopped after equivalent failures)
```

An objective with witnesses is `partial` until every witness in the contract has
been recorded. `persistence` is the clearest case: four facts, not one.

| Witness | Means |
|---|---|
| `persistence_installed` | the mechanism exists **on the named host** |
| `persistence_activated` | it started the payload without a fresh login |
| `persistence_callback` | the persisted process called home |
| `persistence_survived_restart` | it re-activated after an authorised cycle |

## Proof of outcome, not of activity

`malware_persist` deploys on the named host over an injected transport
(`lib/persistence_lifecycle.py`) and probes the four facts. The callback is
**never** established by the deployer — it is recorded from the collection
point's own evidence via `mission_verify`. Without SSH credentials the tool
refuses rather than installing on the MCP host, and a local-only result is
labelled `LOCAL ONLY — NOT HOST EVIDENCE` and records no witness.

Two equivalent failures stop a branch instead of retrying it, and a slice of the
action budget (`verification_reserve`) is held back from exploitation for proving
what was already done.

## Tools

| Tool | Purpose |
|---|---|
| `mission_contract` | Load objectives, prerequisites, witnesses, sink, budget |
| `mission_declare` | Record intent before a sensitive action |
| `mission_status` | Objective states, missing witnesses, stopped branches, budget |
| `mission_verify` | Record one observed witness, with its evidence |

## Tests

`tests/test_mission_contract.py` — 42 tests across the contract model, the gate,
the state machine, failure classification, the budget, reconciliation, the
lifecycle probe and the MCP wiring. Transport is injected everywhere, so nothing
touches the network or the developer's machine.
