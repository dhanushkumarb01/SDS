#!/bin/bash
# Self-test: start the controller in a given mode, run the topology checks, stop.
#   bash scripts/selftest.sh B1      (open | B0 | B1 | B2)
MODE=${1:-B1}
cd "$(dirname "$0")/.." || exit 1
bash scripts/clean.sh >/dev/null
mkdir -p logs/selftest_$MODE && rm -f logs/selftest_$MODE/*
AEGIS_MODE=$MODE AEGIS_LOG_DIR=logs/selftest_$MODE bash scripts/run_controller.sh > logs/selftest_$MODE/ryu.log 2>&1 &
for i in $(seq 1 20); do curl -s -m1 localhost:8080/aegis/mode >/dev/null && break; sleep 1; done
bash scripts/run_topology.sh --test 2>&1 | grep -E "PASS|FAIL|passed|^\*\*\* (controller mode|t=|cam|time-to)|Traceback|Error"
RC=${PIPESTATUS[0]}
echo "--- controller warnings/errors:"
grep -E "ERROR|Traceback|Exception|TIER|SPOOF" logs/selftest_$MODE/ryu.log | head -15
bash scripts/clean.sh >/dev/null
exit $RC
