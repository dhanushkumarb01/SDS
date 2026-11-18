# AEGIS-ZT

**Adaptive, Explainable, Graded Isolation System for Zero Trust SDN.** An SDN-based Zero Trust micro-segmentation and dynamic access control framework (Software Defined Security, BMU).

Design: `docs/SDS_Phase2_Design.md` (approved Phase 2 document). Section numbers in code comments refer to it. Deviations found during implementation are listed in `docs/IMPLEMENTATION_NOTES.md`.

## What it does
1. **Walls:** 4 zones + services. Default-deny per *service* (even inside a zone). Identity-bound admission (port + MAC + IP). The controller answers ARP only for permitted peers, so forbidden hosts are invisible.
2. **Watch:** every host has a 0–100 trust score fed by 7 explainable signals (denied attempts, scan fan-out, flood rate, role violation, spoofing, packet-in flood, out-of-schedule). Fast drop, slow recovery, hysteresis, probation.
3. **Act:** tiers TRUSTED / NORMAL / RESTRICTED / QUARANTINED map to graded access profiles and trust-proportional flow leases. On a downgrade the host's flows are purged instantly by cookie.

## Status: all milestones complete

| Milestone | What | Verified by |
|---|---|---|
| M1 | Environment (Mininet 2.3, OVS 2.17, Ryu 4.34, tools) | `scripts/check_env.sh` |
| M2 | Topology, 4-table pipeline, admission, proxy ARP, forwarding | `scripts/selftest.sh open` (7/7) |
| M3 | Policy engine, default-deny micro-segmentation (B1) | `scripts/selftest.sh B1` (14/14) |
| M4 | Monitor, detectors, trust engine, tier enforcement (B2) | `scripts/selftest.sh B2` (14/14 + scan contained) |
| M5 | Leases per tier, REST API, live dashboard | REST tests, dashboard at `/aegis/dashboard` |
| M6 | Attacks S1–S6, traffic, experiments, metrics, figures | `eval/run_all.sh` → `results/` |
| Tests | 44 unit tests (pure-Python core) | `pytest -q` |

## Quick start

```bash
cd ~/aegis-zt
bash scripts/clean.sh                          # only if a previous run crashed
AEGIS_MODE=B2 bash scripts/run_controller.sh   # terminal 1 (modes: open | B0 | B1 | B2)
bash scripts/run_topology.sh                   # terminal 2: Mininet CLI
```
Dashboard: open **http://localhost:8080/aegis/dashboard** in a Windows browser.

**Never run `sudo mn -c` while the controller is running.** It kills `ryu-manager`.

### Self-tests (controller + network + checks, then clean up)
```bash
bash scripts/selftest.sh B1     # micro-segmentation matrix, 14 checks
bash scripts/selftest.sh B2     # same + a live scan that must be contained automatically
```

### Full evaluation (Phase 5)
```bash
bash eval/run_all.sh            # ~1.5 h with 3 repetitions; REPS=10 for the full design
```
Outputs: `results/summary/summary.md` (tables), `results/summary/*.csv`, `results/figures/*.png`.

## Live demo (Mininet CLI, controller in B2)
```
u1 curl -s http://10.0.2.10/                 # allowed (R1)
u1 ping -c2 10.0.1.12                        # blocked + invisible (no laptop-to-laptop)
cam1 nc -zv 10.0.2.30 1883                   # IoT -> collector allowed (R4)
cam1 nmap -sS -T4 -n -Pn -p 1-1000 10.0.2.0/24   # watch cam1 go RESTRICTED -> QUARANTINED on the dashboard
cam1 nc -zv 10.0.2.30 1883                   # now blocked
cam1 nc -zv 10.0.9.10 8080                   # remediation still reachable
sh ovs-ofctl -O OpenFlow13 dump-flows s3 table=1   # the quarantine rules
```
REST: `curl localhost:8080/aegis/hosts`, `curl -X POST -d '{"tier":null}' localhost:8080/aegis/hosts/cam1/override`.

## Modes (env `AEGIS_MODE`, or `config/trust.yaml`)
- `open`: bring-up; admitted hosts reach each other
- `B0`: flat baseline, no admission, ARP broadcast (the "castle")
- `B1`: static zones, policy + admission, trust frozen
- `B2`: full AEGIS-ZT

## REST API
| Method | Path | Purpose |
|---|---|---|
| GET | `/aegis/hosts`, `/aegis/hosts/{name}` | hosts, scores, tiers (+ last 20 ledger events) |
| GET | `/aegis/events?since=SEQ` | explainable trust ledger |
| GET | `/aegis/policy` · POST `/aegis/policy/reload` | view / hot-reload `policy.yaml` |
| POST | `/aegis/hosts/{name}/override` | `{"tier":"QUARANTINED"}` or `{"tier":null}` |
| GET | `/aegis/stats`, `/aegis/mode` | decisions, latency, CPU, flows, mode |
| GET | `/aegis/dashboard` | live dashboard |

## Layout
```
config/      topology.yaml (enrolment), policy.yaml (8 rules), trust.yaml (mode, trust model, leases)
controller/  aegis_app.py      Ryu app: pipeline, decisions, reply recognition, enforcement, monitoring loop
             policy_engine.py  zone policy decisions (pure Python)
             trust_engine.py   scores, tiers, hysteresis, probation, overrides, ledger (pure Python)
             detectors.py      signals E1-E7 (pure Python)
             monitor.py        initiator-attributed traffic features from flow stats (pure Python)
             flow_manager.py   OpenFlow rule builders, cookies, purge
             arp_proxy.py      proxy ARP + invisibility + ARP-spoof detection
             inventory.py, models.py, metrics.py, rest_api.py
topology/    aegis_topo.py (Mininet from topology.yaml, --test / --hold), services.py (service simulator)
traffic/     benign.py (background traffic per role)
attacks/     scenarios.py (S1-S6), lateral.sh, arp_spoof.py
eval/        run_experiment.py, compute_metrics.py, plot_results.py, run_all.sh
dashboard/   index.html
scripts/     install_ryu.sh, patch_ryu.py, check_env.sh, run_controller.sh, run_topology.sh, selftest.sh, clean.sh
tests/       44 pytest unit tests
results/     raw/ (per run), summary/ (tables), figures/ (PNG)
```

## Environment
WSL2 Ubuntu 22.04, Python venv `~/aegis-venv`. Fresh machine: `bash scripts/install_ryu.sh`. The Ryu 4.34 install needs special handling on Python 3.10 (see the comments in that script).
Open from Windows: `\\wsl.localhost\Ubuntu\home\dhanush_700810\aegis-zt` (best: VS Code + WSL extension).
