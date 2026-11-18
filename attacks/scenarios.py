"""Attack scenarios S1-S6 (SDS_Phase2_Design.md section 13.2).

Each scenario names the attacker host and the shell command run inside it.
Commands are written to stop on their own after DUR seconds ({dur}).
Outputs go to {out} (a per-run directory) so eval/compute_metrics.py can
measure blast radius. Used by eval/run_experiment.py; the same commands can
be pasted into the Mininet CLI for a live demo (replace {dur}/{out}/{root}).
"""
TARGETS = "10.0.1.11-13 10.0.2.10 10.0.2.20 10.0.2.30 10.0.2.53 10.0.3.21-23 10.0.4.10"

# After each attack: can the attacker STILL use its normal, legitimate service?
# Static zones (B1) leave a compromised device its access; AEGIS-ZT (B2) should not.
RETAINED_ACCESS = {
    "cam1": ("10.0.2.30", 1883), "cam2": ("10.0.2.30", 1883), "sen1": ("10.0.2.30", 1883),
    "u1": ("10.0.2.10", 80), "u3": ("10.0.2.10", 80),
}

SCENARIOS = {
    "S1": {
        "name": "Port/host scan from a compromised camera",
        "attacker": "cam1",
        "cmd": "timeout {dur} nmap -sS -T4 -n -Pn --max-retries 1 -p 1-1024,1883,3306,8000,8080 "
               + TARGETS.replace("10.0.3.21-23", "10.0.3.22-23") + " -oG {out}/scan.gnmap > /dev/null 2>&1",
    },
    "S2": {
        "name": "Lateral movement attempts from a phished laptop",
        "attacker": "u1",
        "cmd": "timeout {dur} bash {root}/attacks/lateral.sh {out}/lateral.txt",
    },
    "S3": {
        "name": "SYN flood from a compromised camera on the collector",
        "attacker": "cam2",
        "cmd": "timeout {dur} hping3 -S -p 1883 -i u200 10.0.2.30 > /dev/null 2>&1",
    },
    "S4": {
        "name": "IP spoofing + ARP poisoning from a compromised sensor",
        "attacker": "sen1",
        "cmd": "timeout {dur} hping3 -a 10.0.2.20 -S -p 80 -i u20000 10.0.2.10 > /dev/null 2>&1 & "
               "timeout {dur} {venv}/bin/python {root}/attacks/arp_spoof.py --claim 10.0.2.10 "
               "--victims 10.0.1.11,10.0.1.12,10.0.1.13 > /dev/null 2>&1; wait",
    },
    "S5": {
        "name": "Low-and-slow scan from an insider laptop",
        "attacker": "u3",
        "cmd": "timeout {dur} nmap -sT -n -Pn --scan-delay 1s --max-retries 0 "
               "-p 21,22,23,25,80,443,1883,3306,8000,8080 10.0.2.10 10.0.2.20 10.0.2.30 10.0.2.53 10.0.4.10 "
               "-oG {out}/scan.gnmap > /dev/null 2>&1",
    },
    "S6": {
        "name": "Heavy but legitimate backup upload (must NOT be punished)",
        "attacker": None,                      # benign: there is no attacker
        "actor": "u2",
        "cmd": "iperf3 -c 10.0.2.10 -p 8000 -t {dur} -J > {out}/iperf_s6.json 2>/dev/null",
    },
}
