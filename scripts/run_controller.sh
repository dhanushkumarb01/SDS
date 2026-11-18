#!/bin/bash
# Start the AEGIS-ZT Ryu controller (terminal 1).
# OpenFlow on :6653, REST API on :8080. Extra args are passed to ryu-manager (e.g. --verbose).
cd "$(dirname "$0")/.." || exit 1
source "$HOME/aegis-venv/bin/activate"
sudo service openvswitch-switch status >/dev/null 2>&1 || sudo service openvswitch-switch start
exec ryu-manager --ofp-tcp-listen-port 6653 --wsapi-port 8080 "$@" controller/aegis_app.py
