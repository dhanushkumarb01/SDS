# AEGIS-ZT implementation notes (Phase 3)

These notes cover what was built, what changed from the Phase 2 design, and why. The report and viva teams should use them alongside `SDS_Phase2_Design.md`. Every change below came from a test or experiment that exposed a real problem. That makes good viva material: "how did you debug it?"

## 1. Corrections to the Phase 2 document
| Item | Phase 2 said | Actual | Action for the report/PPT |
|---|---|---|---|
| Host count | 14 hosts | **13 hosts** (u1–u3, web1, db1, col1, dns1, cam1, cam2, sen1, adm1, rem1, hp1) | Use 13 |
| Policy rules | R1–R7 | **R1–R8**. R8 "users upload backups to web1:8000" was added for the throughput test and the heavy-but-legitimate scenario S6 | Mention R8 |
| Services | web1 22/80, db1 22/3306, col1 1883, dns1 53 | col1 and dns1 also listen on tcp/22, so admin SSH (R5) is testable on every server | Minor |

## 2. Design refinements discovered during testing

### 2.1 Initiator-attributed flood detection (E3), the most important fix
- **Problem found:** in the first SYN-flood trial, the **victim** (col1) was quarantined together with the attacker. Its SYN-ACK replies looked like a flood: high rate, small packets. An attacker could abuse this to get any server isolated just by flooding it.
- **Fix:** traffic is attributed to the host that **initiated** each flow, using the rule cookies. Forward rules (`C_ALLOW`) and drop rules (`C_DENY`) count as what the initiator sends. Reply rules (new type `C_REV`) count as what it gets back. A flood is a high initiated packet rate of small packets (mean < 300 B) that is **not** answered by much larger replies (reply bytes < 5 × sent bytes).
- **Result:** only the attacker is punished. Collector availability during the flood went from 59% to 100%. A 34 Gbit/s legitimate upload (S6) triggers nothing.
- Unit tests: `tests/test_monitor.py`, `tests/test_detectors.py`.

### 2.2 Stateless reply recognition
- **Problem found:** after the attacker was quarantined, the victim's retransmitted replies hit the controller and were counted as "forbidden attempts" by the victim.
- **Fix:** a packet that answers a request covered by a policy rule (for example from web1:80 to u1) is recognised as a **reply**. If the initiator still has access, the flow is re-authorised as the initiator's. If not, the reply is dropped **silently with no penalty to anyone**. The responder is never blamed.
- This is also what keeps long connections working when a lease (rule timeout) expires mid-connection.
- Limitation, kept honest: replies are recognised by source port, not tracked statefully. OVS conntrack is future work (design §18).

### 2.3 Spoofing response at Table 0
- After a spoofed or unenrolled packet, a short Table-0 drop rule is installed for that switch port (idle 30 s). Further spoofed packets then never reach the controller (DoS protection), and the device still gets the E5 penalty.

### 2.4 Quarantine profile
- Table 1 sends a quarantined host's remediation traffic to **Table 2** (not straight to forwarding), so the policy engine still decides and logs it (rule R7).

### 2.5 Flat baseline (B0) made realistic
- In B0 the controller **broadcasts ARP** like a normal flat network, instead of answering it. Without this, B0 would have quietly enjoyed our ARP protection, and the comparison would be unfair. Effect: in B0 the spoofer delivered about 2,300 forged packets and poisoned a user's ARP cache. In B1/B2: 0 and 0.
- Side effect, worth noting in the report: in B0 the Python controller does the broadcasting, so during scan storms its monitoring loop runs slower. B0 has no detection anyway.

### 2.6 Monitoring uses flow statistics only
- Port statistics were dropped. Per-flow counters with cookie attribution give per-host rates **and** direction (2.1), so port counters added nothing.

## 3. Engineering issues solved (for "troubleshooting and debugging" questions)
| Issue | Symptom | Root cause | Fix |
|---|---|---|---|
| Ryu won't install | `get_script_args` error, version 0.0.0 | Ryu 4.34's setup.py vs modern setuptools / pbr | Build with `setuptools<58` + `pbr`, `--no-build-isolation`, `PBR_VERSION=4.34` |
| Ryu crashes on start | `cannot set 'is_timeout'` | eventlet 0.30.2 incompatible with Python 3.10 | eventlet 0.33.3 + dnspython 2.2.1 |
| REST import fails | `cannot import ALREADY_HANDLED` | removed from eventlet 0.33 | `scripts/patch_ryu.py` (uses `WSGI_LOCAL.already_handled`) |
| Apt install hangs | waits forever | hidden Wireshark debconf question | preseed `wireshark-common/install-setuid=false` |
| Switches never connect | "Unable to contact controller" | `sudo mn -c` also kills `ryu-manager` | clean before starting the controller (`scripts/clean.sh`) |
| Attack ran 0 s | experiment trial | Mininet `popen(executable=...)` replaced mnexec | wrap scripts with `bash -c` |
| Override response wrong | `"override": null` after quarantine | `Tier.QUARANTINED == 0` is falsy in Python | `is not None` checks |
| Victim quarantined | see 2.1 | direction-blind rate signal | initiator attribution |

## 4. Verification evidence
- **Unit tests:** 44 passing (`pytest -q`). They cover policy (the whole acceptance matrix), trust maths (caps, recovery, hysteresis, probation, override, ledger), detectors (flood vs bulk transfer), and monitor attribution.
- **Acceptance:** `scripts/selftest.sh B1` and `B2` give 14/14. That includes the rogue device, spoofed IP, DNS replies, intra-zone deny and the admin window.
- **Live containment:** a fast scan by a hacked camera was quarantined about 3 s after it started. The bystander was unaffected, and remediation stayed reachable.
- **Experiments:** `results/summary/summary.md` and `results/figures/`.

## 5. How each rubric item maps to code
| Rubric (Phases 3–4) | Where |
|---|---|
| Correct, complete implementation | `controller/`, acceptance tests |
| Good coding practice, modular design | pure-Python core + thin Ryu layer, 44 tests, config in YAML |
| Firewall / access control / policy enforcement | `policy_engine.py`, `flow_manager.py` Tables 0–2 |
| IDS / IPS | `detectors.py` + `trust_engine.py` + enforcement in `aegis_app._enforce` |
| DDoS detection and mitigation | E3 (initiator-attributed), E6 packet-in flood, deny caching, spoof drop |
| Zero Trust | identity admission, default-deny, continuous verification (leases), NIST PE/PA/PEP mapping |
| Innovation | graded tiers, trust-proportional leases, explainable ledger, invisibility, initiator attribution, reply recognition |

## 6. Evaluation results (Phase 5 input; generated by `eval/run_all.sh`, 3 repetitions)
Full tables: `results/summary/summary.md`. Figures: `results/figures/F1…F10`. Setups: **B0** flat network, **B1** static zones, **B2** AEGIS-ZT.

### Headline results (means over 3 repetitions)
| Question | B0 flat | B1 static zones | B2 AEGIS-ZT |
|---|---|---|---|
| Services a hacked camera's scan finds (S1) | 10 | 0.7 | **0** |
| Successful lateral connections from a phished laptop (S2) | 525 | 4 | **0** |
| Spoofed packets delivered to web1 (S4) | 2,338 | 0 | **0** |
| Users whose ARP cache was poisoned (S4) | 2 | 0 | **0** |
| Legitimate user's packet loss during ARP spoofing (S4) | 82.5 % | 0 % | **0 %** |
| Attacker still has its normal access after the attack (S1–S5) | 100 % | 100 % | **0 %** |
| Legitimate 34 Gbit/s bulk upload wrongly restricted (S6) | no | no | **no (0 false alarms)** |

**Containment (B2), seconds after attack start:** detection 3.0–3.1 s (spoofing 0.8 s); quarantine S1 3.1 s, S4 3.0 s, S2 13.0 s, S3 13.1 s, S5 19.8 ± 5.9 s. No bystander lost a tier in any run (collateral = 0).

**Detection (B2, per host per 5 s window, 3 reps):** precision, recall and F1 all 1.000; FPR = FNR = 0 (133 attack windows, 3,517 benign windows).

**Cost:**
- First packet of a new flow: B0 6.1 ms, B1 9.7 ms, B2 9.3 ms. That is about **+3 ms** for the one-time ARP + controller decision + rule install. Later packets: 0.10 ms in all three, so no difference.
- Controller decision time: median 0.6 ms (13 hosts) to 0.8–0.9 ms (49 hosts); 95th percentile ≤ 1.5 ms.
- Controller CPU: 0.7 % (13 hosts) to 2.3 % (49 hosts); memory flat at about 70 MB.
- Zero false alarms in the benign scalability runs (13, 25, 49 hosts).

### What the results do NOT show (state these openly in the report and viva)
1. **Detection scores are saturated and should not be oversold.** Perfect precision/recall come from loud, scripted attacks, a coarse per-window truth, and one topology. "Predicted malicious" follows design §13.3 (penalty applied OR host in RESTRICTED/QUARANTINED tier). Time-to-detect and time-to-contain are the more informative numbers. A first version of the metric counted only new penalties, scored a contained attacker as "missed", and was corrected to the design's definition. The raw runs were not changed.
2. **Throughput comparison is inconclusive.** Single runs swing between about 13 and 29 Gbit/s within the same mode (std ≈ 7.5 Gbit/s). That is emulator CPU scheduling, so no overhead claim for bulk throughput can be made, either way.
3. **The SYN flood did not degrade the collector, even in B0** (availability 100 % in all modes). The emulated 5k pps flood is too weak to hurt a Linux host. S3 therefore demonstrates detection and containment of the flood source, **not** a service-availability benefit.
4. **The first-packet gap includes B0's own overhead:** in B0 the Python controller broadcasts ARP, so B0 is not a bare switch.
5. **Recovery was unit-tested but not measured end to end.** Experiments end shortly after quarantine; slow recovery (about +1 point per 5 s window after 30 s quiet) and probation are covered by `tests/test_trust_engine.py` only.
6. **Single emulated network, single controller, stateless reply matching, hand-tuned weights**, as in design §18.

### Reproduce
`bash eval/run_all.sh` (about 1.5 h, REPS=3). `REPS=10` matches the design.
