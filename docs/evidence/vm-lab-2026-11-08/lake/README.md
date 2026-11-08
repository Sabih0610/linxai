# Medallion lake and learned baseline — VM validation, 8 November 2026

`security/lake.py` turns monitor evidence into bronze (raw + SHA-256 provenance),
silver (validated, de-duplicated, generalized; invalid rows quarantined) and gold
(per-account behaviour baseline). Training excludes simulated sources, incomplete
kernel identity and events that matched a deterministic incident. Novelty uses a
Good-Turing estimate of unseen-key probability (alert below 1/64 once an account/kind
has ≥200 trained events). Output is an advisory `anomaly` record: never an incident,
response trigger, digest input or authority.

Run on the Ubuntu 24.04.4 VM with the real BCC sensor and the independent monitor:
first cycle on existing evidence — 1000 bronze/silver, 0 quarantined, 994 trained.
`lake_demo.sh` then built a stable `linxai` exec baseline (three 1000-event cycles),
reloaded the monitor and ran `/usr/bin/factor` for the first time: one anomaly
(`/usr/bin/factor`, 8.6 bits over a 3095-event baseline, severity `info`), zero
incidents, monitor `ready`. See `lake-demo.log`.

Limits: the demo baseline is deliberately stable; real accounts are more varied and
Good-Turing then suppresses novelty alerts. Baselines can be poisoned by behaviour
during training that no deterministic rule flags. False-positive rate on real
workloads is not yet measured.
