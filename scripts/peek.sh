#!/bin/bash
# Quick look at finished attack runs: bash scripts/peek.sh [SCENARIO]
cd "$(dirname "$0")/.." || exit 1
S=${1:-S1}
for d in results/raw/attacks/*_${S}_r*; do
  [ -f "$d/scenario.json" ] || continue
  ret=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['attacker_retains_access'])" "$d/scenario.json")
  open=$( [ -f "$d/scan.gnmap" ] && grep -o '[0-9]*/open/' "$d/scan.gnmap" | wc -l || echo -)
  q=$(grep -c QUARANTINED "$d/tier_changes.csv")
  echo "$(basename "$d")  retains_access=$ret  open_services_found=$open  quarantine_events=$q"
done
tail -2 logs/run_all.log
