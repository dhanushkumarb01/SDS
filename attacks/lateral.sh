#!/bin/bash
# S2 lateral movement: a phished laptop keeps trying to reach machines it
# should never touch (and one it may). Successful (host:port) pairs are
# appended to $1 so the blast radius can be measured.
OUT=${1:-/tmp/lateral.txt}
TARGETS="10.0.1.12:22 10.0.1.13:22 10.0.2.20:3306 10.0.2.20:22 10.0.4.10:22 10.0.3.21:22 10.0.2.30:1883 10.0.2.10:22 10.0.2.53:22 10.0.2.10:80"
: > "$OUT"
while true; do
  for t in $TARGETS; do
    ip=${t%:*}; port=${t#*:}
    if nc -z -w1 "$ip" "$port" 2>/dev/null; then echo "$(date +%s.%N) $t" >> "$OUT"; fi
  done
  sleep 0.5
done
