#!/bin/bash
# Full Phase 5 evaluation (about 1.5 h with REPS=3). Results in results/.
#   bash eval/run_all.sh            # REPS=3
#   REPS=10 bash eval/run_all.sh    # as in the design (about 4.5 h)
REPS=${REPS:-3}
cd "$(dirname "$0")/.." || exit 1
bash scripts/clean.sh >/dev/null
sudo rm -rf results/raw
echo "[$(date +%T)] attacks: B0 B1 B2 x S1-S6 x $REPS"
sudo python3 eval/run_experiment.py attacks --reps "$REPS"
echo "[$(date +%T)] performance"
sudo python3 eval/run_experiment.py perf --reps "$REPS"
echo "[$(date +%T)] scalability"
sudo python3 eval/run_experiment.py scale --reps "$REPS" --extra 0 12 36
echo "[$(date +%T)] metrics + figures"
source "$HOME/aegis-venv/bin/activate"
python eval/compute_metrics.py && python eval/plot_results.py
echo "[$(date +%T)] ALL DONE"
