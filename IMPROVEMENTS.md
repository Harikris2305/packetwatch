# Detection-quality improvements

These changes fix feature-counting and input-selection errors. They do not claim
an increase in real-world classifier accuracy: Windows Application Control still
blocks this machine's native NumPy/scikit-learn modules, so full ML evaluation
and the complete simulation remain unverified.

## Measured before and after

Compared with commit `ff5b253859c943a4c24cbca5934816ac62c30188`, using the same
crafted inputs and the old/new `SourceWindow` implementations:

| Input | Previous result | Corrected result |
|---|---:|---:|
| Same 30 ports in each of ten seconds | 256 distinct ports | 30 |
| Same 8 destination IPs in each of ten seconds | 64 distinct IPs | 8 |
| Saturated scan window, then all buckets expire | 256 distinct ports | 0 |

The old implementation summed bucket set sizes to decide when to mark the whole
window saturated. This counted a repeated value again in each second. Its
saturation flags could also survive expiry. The new implementation deduplicates
the union of live buckets and caps the result. At a calibrated scan threshold of
200, the 30-port example no longer falsely satisfies the port-scan rule. With the
stock threshold of 10, 30 ports still correctly crosses the configured threshold.

Storage is bounded **per bucket**: at most 256 ports and 64 destinations for each
of ten seconds, or 2,560 port entries and 640 destination entries per source.
This improves counting correctness but raises the worst-case storage bound.
Existing `BENCHMARK.md` memory and throughput numbers describe the previous
implementation and must be remeasured before quoting them for this revision.

## Live host scope and calibration

The live CLI now supplies actual local IPv4 addresses as an explicit destination
scope. Packets addressed to other machines, multicast or broadcast destinations
are excluded from this single-host detector. The router remains a protected
source by default, but is not treated as a local destination. If local addresses
cannot be discovered, startup stops with an explanation rather than silently
classifying all observed traffic.

Calibration uses the same local destination scope and excludes local/gateway
sources, so unrelated or outgoing traffic no longer trains its thresholds.
The explicit offline `Pipeline` and `Collector` APIs retain their previous
unscoped behaviour when no destination scope is supplied. Actual scans addressed
to the protected host still trigger the rule/response path in regression tests.
Broadcast/multicast attack detection is outside this single-host unicast scope.

## Calibration-file validation

All three saved thresholds must be present and integer-valued within the same
floors/ceilings used by calibration. Booleans, strings, fractions, negatives,
zeroes, missing fields and out-of-range values are rejected. Invalid files cause
one warning and restore **all** stock thresholds; a valid first field can no
longer partially change configuration before a later invalid field fails.

## Validation and how to run later

`tests/test_detection_quality.py` contains regressions for repeated values,
saturation and expiry, bounded storage, randomized reference comparisons,
host-only decisions, live CLI wiring, calibration scope and configuration loading.
These tests use a fixed detector and dry-run response to isolate correctness;
they are not substitutes for testing Decision Tree/Naive Bayes accuracy.

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_detection_quality tests.test_dashboard tests.test_vuln
```

After the Windows policy permits the installed ML libraries:

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
.\.venv\Scripts\python.exe -m packetwatch --train
.\.venv\Scripts\python.exe -m packetwatch --simulate --dashboard
```

Then evaluate precision, recall, F1 and false-positive rate on independently
labelled local traffic before enabling real blocking. Do not use the same
recordings for training and final evaluation, and do not interpret the synthetic
training report as real deployment accuracy. Recalibrate on normal inbound traffic
after the feature/scope fixes. See [VALIDATION.md](VALIDATION.md) for the machine
blocker and [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for running instructions.
