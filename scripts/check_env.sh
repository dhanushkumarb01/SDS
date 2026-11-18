#!/bin/bash
# Quick health check of the AEGIS-ZT environment.
source "$HOME/aegis-venv/bin/activate"
echo "--- python: $(python --version 2>&1)"
pip list 2>/dev/null | grep -iE "^(ryu|eventlet|dnspython|networkx|PyYAML|psutil|pandas|matplotlib|pytest|scapy) "
echo "--- ryu"
ryu-manager --version 2>&1 | tail -1
python - <<'PY' 2>&1 | tail -3
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
print("RYU_AND_WSGI_IMPORT_OK")
PY
echo "--- mininet / ovs"
mn --version
ovs-vsctl --version | head -1
sudo service openvswitch-switch status >/dev/null 2>&1 && echo "OVS_RUNNING" || echo "OVS_NOT_RUNNING (run: sudo service openvswitch-switch start)"
echo "--- tools"
for t in nmap hping3 iperf3 tcpdump tshark curl nc arping; do printf "%-8s %s\n" "$t" "$(command -v $t || echo MISSING)"; done
