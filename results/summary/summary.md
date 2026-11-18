# AEGIS-ZT evaluation summary

Attack runs: 54 (3 repetitions per mode × scenario). Times are seconds after attack start; values are means over repetitions.

## Detection (per host-window, pooled over repetitions)

| mode | scenario | tp | fp | tn | fn | accuracy | precision | recall | f1 | fpr | fnr |
|---|---|---|---|---|---|---|---|---|---|---|---|
| B0 | ALL | 0 | 0 | 3363 | 108 | 0.969 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S1 | 0 | 0 | 540 | 6 | 0.989 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S2 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S3 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S4 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S5 | 0 | 0 | 540 | 12 | 0.978 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B0 | S6 | 0 | 0 | 663 | 0 | 1.000 | – | – | – | 0.000 | – |
| B1 | ALL | 0 | 0 | 3337 | 128 | 0.963 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S1 | 0 | 0 | 540 | 26 | 0.954 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S2 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S3 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S4 | 0 | 0 | 540 | 30 | 0.947 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S5 | 0 | 0 | 540 | 12 | 0.978 | – | 0.000 | 0.000 | 0.000 | 1.000 |
| B1 | S6 | 0 | 0 | 637 | 0 | 1.000 | – | – | – | 0.000 | – |
| B2 | ALL | 133 | 0 | 3517 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S1 | 30 | 0 | 576 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S2 | 30 | 0 | 576 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S3 | 30 | 0 | 576 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S4 | 30 | 0 | 576 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S5 | 13 | 0 | 576 | 0 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| B2 | S6 | 0 | 0 | 637 | 0 | 1.000 | – | – | – | 0.000 | – |

## Containment (AEGIS-ZT, mode B2)

| scenario | ttd_s | ttd_s_std | ttr_s | ttc_s | ttc_s_std | collateral_hosts | legit_loss_pct |
|---|---|---|---|---|---|---|---|
| S1 | 3.1 | 0.1 | 3.1 | 3.1 | 0.2 | 0.0 | 0.0 |
| S2 | 3.0 | 0.1 | 8.0 | 13.0 | 0.1 | 0.0 | 0.0 |
| S3 | 3.1 | 0.1 | 3.1 | 13.1 | 0.1 | 0.0 | 0.0 |
| S4 | 0.8 | 0.2 | 0.8 | 3.0 | 0.1 | 0.0 | 0.0 |
| S5 | 3.1 | 0.1 | 8.2 | 19.8 | 5.9 | 0.0 | 0.0 |
| S6 | – | – | – | – | – | 0.0 | 0.0 |

## Blast radius and attack success by mode

| scenario | metric | B0 | B1 | B2 |
|---|---|---|---|---|
| S1 | attacker still has its normal access after attack (% runs) | 100.0 | 100.0 | 0.0 |
| S2 | attacker still has its normal access after attack (% runs) | 100.0 | 100.0 | 0.0 |
| S3 | attacker still has its normal access after attack (% runs) | 100.0 | 100.0 | 0.0 |
| S4 | attacker still has its normal access after attack (% runs) | 100.0 | 100.0 | 0.0 |
| S5 | attacker still has its normal access after attack (% runs) | 100.0 | 100.0 | 0.0 |
| S1 | open services found by scan | 10.0 | 0.7 | 0.0 |
| S5 | open services found by slow scan | 8.0 | 2.0 | 1.0 |
| S2 | targets reached by lateral movement | 7.0 | 1.0 | 0.0 |
| S2 | successful lateral connections | 525.0 | 4.0 | 0.0 |
| S3 | collector availability for real sensor (%) | 100.0 | 100.0 | 100.0 |
| S4 | spoofed packets delivered to web1 | 2338.0 | 0.0 | 0.0 |
| S4 | users with poisoned ARP cache | 2.0 | 0.0 | 0.0 |
| S6 | legit bulk upload throughput (Mbit/s) | 31180.7 | 33092.3 | 33783.3 |
| S6 | hosts wrongly restricted (false alarms) | 0.0 | 0.0 | 0.0 |

## Legitimate user (u2 → web1 ping) during attacks: loss %

| scenario | B0 | B1 | B2 |
|---|---|---|---|
| S1 | 0.0 | 0.0 | 0.0 |
| S2 | 0.0 | 0.0 | 0.0 |
| S3 | 0.0 | 0.0 | 0.0 |
| S4 | 82.5 | 0.0 | 0.0 |
| S5 | 0.0 | 0.0 | 0.0 |
| S6 | 0.0 | 0.0 | 0.0 |

## Performance overhead

| mode | first_rtt_ms_mean | steady_rtt_ms_mean | throughput_mbps_mean | throughput_vs_B0_pct | decision_us_mean_mean |
|---|---|---|---|---|---|
| B0 | 6.05 | 0.10 | 20027.01 | 100.00 | – |
| B1 | 9.72 | 0.10 | 17839.07 | 89.08 | 780.10 |
| B2 | 9.31 | 0.11 | 19935.73 | 99.54 | 678.10 |

first_rtt = first packet of a brand-new flow (ARP + controller decision + rule install); steady = later packets switched in the data plane.

## Scalability (B2, benign traffic, 45 s)

| hosts | decisions | decision_us_median | decision_us_p95 | cpu_mean | mem_mb | flows_max | false_alarms |
|---|---|---|---|---|---|---|---|
| 13.0 | 14.0 | 623.2 | 1106.4 | 0.7 | 69.4 | 149.0 | 0.0 |
| 25.0 | 38.7 | 914.0 | 1502.7 | 1.2 | 69.3 | 269.0 | 0.0 |
| 49.0 | 89.3 | 823.1 | 1542.2 | 2.3 | 70.0 | 509.0 | 0.0 |

