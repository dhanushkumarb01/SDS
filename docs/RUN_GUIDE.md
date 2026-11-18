# AEGIS-ZT: How to run and see everything (baby steps)

Everything runs inside **WSL Ubuntu** on your laptop. You will use up to **three windows**:
- **Terminal A** (Ubuntu): the controller (the "brain")
- **Terminal B** (Ubuntu): the virtual network (Mininet) where you type attack and test commands
- **Browser** (Windows): the live dashboard

> **Golden rules**
> 1. Always start the **controller first** (Terminal A), then the network (Terminal B).
> 2. **Never run `sudo mn -c` while the controller is running.** It kills the controller. Use `bash scripts/clean.sh` when nothing is running.
> 3. **Do not type `pingall` in the Mininet CLI in modes B1/B2.** Zones deliberately block most pairs, and all those blocked attempts count as suspicious behaviour and will lower trust scores.
> 4. If a host gets quarantined, that is the system working. To reset everything, stop the controller (Ctrl+C) and start it again. Scores restart at about 75.

---

## Part 0: Open an Ubuntu terminal
1. Press the **Windows key**, type **Ubuntu**, press Enter.
2. A black window opens with a prompt like `dhanush_700810@LAPTOP-1AMQCORD:~$`.
3. Go to the project:
```bash
cd ~/aegis-zt
```
(To open a second Ubuntu terminal later, just repeat steps 1 and 2.)

---

## Part 1: Check that everything is installed (1 minute)
```bash
bash scripts/check_env.sh
```
You should see: `ryu-manager 4.34`, `RYU_AND_WSGI_IMPORT_OK`, `OVS_RUNNING`, and a path for each tool (nmap, hping3, iperf3, tcpdump, tshark, curl, nc, arping).

If it says `OVS_NOT_RUNNING`:
```bash
sudo service openvswitch-switch start
```
(WSL sometimes restarts in the background and stops Open vSwitch. This fixes it.)

---

## Part 2: Run the unit tests (10 seconds)
```bash
source ~/aegis-venv/bin/activate
pytest -q
deactivate
```
Expected: `44 passed`. These test the policy rules, trust-score maths and detectors without needing a network.

---

## Part 3: Run the automatic self-tests (about 1 to 2 minutes each)
These start the controller and the network by themselves, run checks, print PASS/FAIL, and clean up.

**Static zones (B1): the micro-segmentation matrix, 14 checks:**
```bash
bash scripts/selftest.sh B1
```
Expected: 14 lines starting with `[PASS]`, then `--- 14/14 acceptance checks passed`.

**Full AEGIS-ZT (B2): same 14 checks plus a live attack:**
```bash
bash scripts/selftest.sh B2
```
Expected after the 14 checks:
```
*** t=  0.0s  cam2 -> NORMAL ...
*** t=  3.0s  cam2 -> QUARANTINED ...
*** time-to-contain: 3.0 s
[PASS] quarantined cam2 blocked from collector
[PASS] quarantined cam2 can still reach remediation
[PASS] bystander unaffected (u3 -> web1)
```
Logs of these runs are saved in `logs/selftest_B1/` and `logs/selftest_B2/`.

---

## Part 4: The live demo with the dashboard (the main show)

### Step 1: Start the controller (Terminal A)
```bash
cd ~/aegis-zt
bash scripts/clean.sh
AEGIS_MODE=B2 bash scripts/run_controller.sh
```
You will see lines like `AEGIS-ZT started: mode=B2, 13 enrolled hosts, 5 switches`. **Leave this window open.** It prints a log as things happen.

### Step 2: Start the network (Terminal B)
Open a **second Ubuntu terminal** (Part 0), then:
```bash
cd ~/aegis-zt
bash scripts/run_topology.sh
```
Wait about 10 seconds. The controller window prints `Pipeline installed on s0 ... s4`. The Mininet window ends with a prompt: `mininet>`.

### Step 3: Open the dashboard (Windows browser)
Go to **http://localhost:8080/aegis/dashboard**.
You should see five boxes (User, Server, IoT, Admin, Services) with host cards. Each card shows a coloured trust bar, a score and a tier label. On the right is the "Trust ledger".

*If the page does not load:* in an Ubuntu terminal run `hostname -I`, take the first number (for example 172.20.1.5) and open `http://172.20.1.5:8080/aegis/dashboard`.

### Step 4: Show the walls (type each line at the `mininet>` prompt)
```
u1 curl -s http://10.0.2.10/
```
→ prints `web1 says hello (port 80)`. **Allowed** (a user may use the web server).
```
u1 ping -c2 10.0.2.20
```
→ no reply. **Invisible:** users cannot even see the database.
```
u1 ping -c2 10.0.1.12
```
→ no reply. **Laptops cannot talk to each other.**
```
cam1 nc -zv -w2 10.0.2.30 1883
```
→ connection succeeded. **The camera may talk to its collector.**
```
cam1 nc -zv -w2 10.0.3.22 22
```
→ fails. **Camera to camera is blocked.**

### Step 5: Look at the rules inside a switch
```
sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=0
sh ovs-ofctl -O OpenFlow13 dump-flows s1 table=2
```
Table 0 is identity admission, and table 2 holds the allow and deny rules with their timeouts (the "leases").

### Step 6: The attack (watch the dashboard while you type this)
```
cam1 nmap -sS -T4 -n -Pn -p 1-1000 10.0.2.10 10.0.2.20 10.0.2.30
```
What you will see:
- **Dashboard:** the cam1 card turns amber (RESTRICTED) then red (QUARANTINED) within seconds, and the ledger on the right explains why (for example "scanning: 87 ports on 3 hosts").
- **Controller window:** `TIER cam1: NORMAL -> RESTRICTED` then `RESTRICTED -> QUARANTINED`.

### Step 7: Prove the quarantine
```
cam1 nc -zv -w2 10.0.2.30 1883
```
→ **now fails** (earlier it worked).
```
cam1 nc -zv -w2 10.0.9.10 8080
```
→ **still works.** A quarantined device can reach only the remediation server.
```
u3 curl -s http://10.0.2.10/
```
→ **still works.** Other devices are unaffected.
```
sh ovs-ofctl -O OpenFlow13 dump-flows s3 table=1
```
→ shows the quarantine rules for cam1 (`priority=190 ... actions=drop`).

### Step 8: Try the other attacks (use a *fresh* host for each, because a quarantined host stays quarantined)
**IP spoofing (u1 pretends to be the database):**
```
u1 ip addr add 10.0.2.20/16 dev u1-eth0
u1 ping -c1 -W2 -I 10.0.2.20 10.0.2.10
u1 ip addr del 10.0.2.20/16 dev u1-eth0
```
→ Controller prints `SPOOF/UNENROLLED from u1 ...` and u1 drops sharply on the dashboard (spoofing costs 40 points at once).

**SYN flood (cam2 floods the collector for 10 seconds):**
```
cam2 timeout 10 hping3 -S -p 1883 -i u200 10.0.2.30
```
→ cam2 is quarantined after a few windows. **col1 (the victim) is not punished.**

**Lateral movement (laptop u3 probes others):**
```
u3 nc -zv -w1 10.0.2.20 3306
u3 nc -zv -w1 10.0.4.10 22
u3 nc -zv -w1 10.0.1.12 22
```
→ all blocked; repeat a few times and watch u3's score fall.

### Step 9: Release a quarantined host from the admin side (open a **third** Ubuntu terminal)
```bash
curl -s -X POST -d '{"tier":"NORMAL"}' localhost:8080/aegis/hosts/cam1/override
```
→ cam1 is pinned to NORMAL and its quarantine rules are removed. To un-pin later:
```bash
curl -s -X POST -d '{"tier":null}' localhost:8080/aegis/hosts/cam1/override
```
Or force a quarantine by hand: `{"tier":"QUARANTINED"}`.
*(Known quirk: the dashboard's "release" button only clears a manual pin. It does not undo a quarantine that came from the trust score. Use the NORMAL command above, or wait for slow recovery.)*

### Step 10: Show the comparison (restart in other modes)
In Terminal B type `exit` (and `sudo mn -c` is **not** needed). In Terminal A press **Ctrl+C**. Then:
```bash
bash scripts/clean.sh
AEGIS_MODE=B0 bash scripts/run_controller.sh      # Terminal A: flat network, no protection
bash scripts/run_topology.sh                      # Terminal B
```
At `mininet>`:
```
u1 nc -zv -w2 10.0.2.20 3306
```
→ **succeeds in B0** (the "castle"), while it fails in B1 and B2.
Repeat with `AEGIS_MODE=B1` to show static zones: the scan from cam1 finds nothing, but cam1 keeps its access afterwards (nothing quarantines it).

### Step 11: Finish
- Terminal B: type `exit`
- Terminal A: press **Ctrl+C**
- Then:
```bash
bash scripts/clean.sh
```

---

## Part 5: Look at the REST API while the controller runs
In a third terminal:
```bash
curl -s localhost:8080/aegis/mode
curl -s localhost:8080/aegis/hosts | python3 -m json.tool | head -40
curl -s localhost:8080/aegis/stats
curl -s localhost:8080/aegis/policy | python3 -m json.tool | head -30
curl -s -X POST localhost:8080/aegis/policy/reload      # hot-reload policy.yaml without restarting
curl -s "localhost:8080/aegis/events?since=0" | python3 -m json.tool | head -40   # the trust ledger
```

## Part 6: Watch the trust ledger and logs live
```bash
tail -f ~/aegis-zt/logs/trust_ledger.jsonl        # every score change with its reason
tail -f ~/aegis-zt/logs/decisions.csv             # every allow/deny decision
```
Other files in `logs/`: `tier_changes.csv`, `windows.csv`, `perf.csv`, `events.csv`.

---

## Part 7: See the experiment results (no need to re-run anything)
**In Windows File Explorer** open `C:\Users\Dhanush\AEGIS-ZT_results`:
- `summary.md`: all tables (detection, containment, blast radius, performance, scalability)
- `figures\`: 11 PNG graphs (F1 trust timeline, F2 blast radius, F3 containment time, F4 detection, F5 latency, F6 throughput, F7 controller load, F8 scalability, F9 legitimate-user loss, F10 retained access)
- `tables\`: the same data as CSV (for Excel)
- `IMPLEMENTATION_NOTES.md`: what changed from the design, bugs found, and honest limitations

**Or from Ubuntu:**
```bash
cat ~/aegis-zt/results/summary/summary.md | less      # press q to quit
explorer.exe ~/aegis-zt/results/figures               # opens the figures folder in Windows
```

## Part 8: Re-run the experiments (optional)
**One quick experiment (about 1.5 minutes): scan against full AEGIS-ZT**
```bash
cd ~/aegis-zt
bash scripts/clean.sh
sudo python3 eval/run_experiment.py attacks --modes B2 --scenarios S1 --reps 1
bash scripts/peek.sh S1
```
**Everything (about 1.5 hours, leave the laptop plugged in):**
```bash
bash eval/run_all.sh                 # 3 repetitions
REPS=10 bash eval/run_all.sh         # the full design (about 4.5 hours)
```
Progress: `tail -f logs/run_all.log` (open a second terminal). To stop it: `bash scripts/stop_experiments.sh`.
When it finishes, tables and figures are regenerated automatically in `results/summary` and `results/figures`.

To regenerate only the tables and figures from existing runs:
```bash
source ~/aegis-venv/bin/activate
python eval/compute_metrics.py
python eval/plot_results.py
deactivate
```

---

## Part 9: Open the code
From an Ubuntu terminal (needs VS Code with the "WSL" extension):
```bash
cd ~/aegis-zt && code .
```
Or in File Explorer: `\\wsl.localhost\Ubuntu\home\dhanush_700810\aegis-zt`

Where to look:
| File | What it is |
|---|---|
| `config/topology.yaml` | the 13 enrolled devices, switches, links |
| `config/policy.yaml` | the zone rules (R1 to R8), the whole security policy |
| `config/trust.yaml` | trust weights, tiers, leases, mode |
| `controller/aegis_app.py` | the main controller: decisions, enforcement, monitoring loop |
| `controller/policy_engine.py` | allow/deny decisions |
| `controller/trust_engine.py` | scores, tiers, hysteresis, ledger |
| `controller/detectors.py` | the seven detection signals |
| `controller/flow_manager.py` | the OpenFlow rules and cookies |
| `controller/arp_proxy.py` | proxy ARP (network invisibility) |
| `topology/aegis_topo.py` | builds the network and runs the acceptance tests |
| `attacks/scenarios.py` | the six attack scenarios |
| `eval/` | experiment runner, metrics, graphs |
| `docs/` | Phase 2 design, implementation notes, this guide |

---

## Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| `Unable to contact the remote controller` | controller not running (or killed by `mn -c`) | Start Terminal A first. If unsure: `bash scripts/clean.sh`, then restart both |
| Dashboard page will not load | wrong address or controller down | Try `http://localhost:8080/aegis/mode`. If that fails, use the WSL address from `hostname -I` |
| Mininet errors about existing devices or files | leftover from a crash | `bash scripts/clean.sh`, then retry |
| `OVS_NOT_RUNNING` or switch errors | WSL restarted | `sudo service openvswitch-switch start` |
| Everything is quarantined | you ran `pingall` or many blocked commands | stop the controller (Ctrl+C) and restart it to reset scores |
| A command prints nothing and hangs | blocked traffic times out | add `-w2` (nc) or `-W2 -c2` (ping) as in the examples |
| `Permission denied` on a script | file not executable | `chmod +x scripts/*.sh` |
| Disk almost full | WSL stores files on C: | free space on C: (keep at least 5 GB free) |
| Sudo asks for a password | the sudo rule was removed | `echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/aegis-project` |

## When you are completely done with the project
```bash
sudo rm /etc/sudoers.d/aegis-project      # removes the password-free sudo rule
```
