#!/bin/bash
# Start the AEGIS-ZT Mininet network (terminal 2). Controller must be running first.
# Extra args go to aegis_topo.py (e.g. --test, --tc).
# NOTE: do not call "mn -c" here, it also kills ryu-manager. Use scripts/clean.sh
# before starting the controller if a previous run crashed.
cd "$(dirname "$0")/.." || exit 1
exec sudo python3 topology/aegis_topo.py "$@"
