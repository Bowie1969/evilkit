# Malware Lab Topology

## Two isolated ranges — no cross-traffic except the designed pivot chain.

### (A) DETONATION CAGE — E7470 laptop (det-host), libvirt, air-gapped

Network: `det-net` 10.99.99.0/24, `<forward mode='none'/>` — no uplink, no NAT.

| IP            | Host           | Role |
|---------------|----------------|------|
| 10.99.99.1    | detbr0         | Host bridge, no service listening |
| 10.99.99.10   | inetsim VM     | Fake DNS/HTTP/SMTP — victim's only "internet" |
| 10.99.99.100  | victim-linux   | Infection target, Debian/Ubuntu, snapshot "clean" |

Management link: 10.99.1.0/24 (det-host .1, desktop .2, no gateway, autoconnect no).
Desktop initiates only; det-host never opens outbound.

Delivery: Arduino UNO R4 Minima BadUSB via USB passthrough to victim.
Keystrokes traced over UART outside the victim (compromised guest cannot rewrite trace).

Reset: `virsh snapshot-revert victim-linux clean` before every run.

### (B) PIVOT RANGE — Proxmox brain, isolated bridge vmbr9

Network: 10.99.50.0/24, NO uplink, no route to house LAN / VM 100 / internet.

| IP             | Host       | Role |
|----------------|------------|------|
| 10.99.50.254   | range-gw   | SSH jump host; drops vmbr9→vmbr0, no NAT |
| 10.99.50.11    | edge01     | Initial access: weak web app + known SSH credential |
| 10.99.50.21    | bot01      | Pivot 1: forwarding/proxy service |
| 10.99.50.22    | bot02      | Pivot 2: different service and credential |
| 10.99.50.31    | crown01    | Crown jewel: payroll + client accounts + financial data (files + local DB), reachable ONLY from bot02 |

Pivot chain: edge01 → bot01 → bot02 → crown01.

Reset: revert every guest to clean snapshot before every run.

### Target data (crown01)
- Payroll records (CSV/DB)
- Client account database
- Financial transaction logs

### Telemetry
- Host-side pcap on vmbr9 (range B) and detbr0 (range A)
- In-guest auditd + guest agent pull
- Disk diff vs clean snapshot
- Host and console logs
- UART keystroke trace (range A, outside victim)
