#!/bin/bash
# Reset everything: Mininet leftovers, service simulators, controller.
sudo mn -c >/dev/null 2>&1
sudo pkill -f "topology/services.py" 2>/dev/null
pkill -f "ryu-manager" 2>/dev/null
echo "clean"
