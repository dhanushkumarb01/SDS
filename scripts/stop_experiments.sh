#!/bin/bash
# Stop a running evaluation batch and clean up the network/controller.
for p in $(pgrep -f "eval/run_all\.sh|eval/run_experiment\.py"); do
  [ "$p" != "$$" ] && sudo kill "$p" 2>/dev/null
done
sleep 2
bash "$(dirname "$0")/clean.sh"
pgrep -fa "eval/run_experiment\.py|ryu-manager" | grep -v pgrep || echo "all stopped"
