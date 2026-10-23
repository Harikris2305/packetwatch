# PacketWatch: 100-point study guide

This guide describes the inspected code, including the team snapshot
`ec2fef115eede26dc84e714ec5b3e7f0d67c771b`. Original team source:
[Aadharsh-s/packetwatch](https://github.com/Aadharsh-s/packetwatch).
The learning/setup additions are maintained in
[Harikris2305/packetwatch](https://github.com/Harikris2305/packetwatch).
Published evaluation numbers are repository reports, not a guarantee for your PC.

## 1–10: Start from networking basics

1. **The problem:** a Windows computer can receive suspicious network traffic. PacketWatch watches its patterns and can block the source address when its decision conditions are met.
2. **A packet** is a unit of network data. Its headers describe addresses, protocol and, for TCP/UDP, ports. PacketWatch uses these headers and length rather than understanding message contents.
3. **An IP address** identifies a network endpoint. Here, a source IP is the main grouping key: packets from that source contribute to the same feature window.
4. **A port** identifies a transport endpoint. TCP 443 commonly carries HTTPS; TCP 3389 is commonly RDP. A port number alone does not prove an attack.
5. **TCP** is connection-oriented. A SYN flag is associated with connection initiation; many SYN packets to different ports can resemble scanning.
6. **UDP** sends datagrams without TCP's connection handshake. Large packet bursts can resemble a UDP flood.
7. **ICMP** carries network control messages, including echo requests/replies. Very high observed ICMP rates can resemble flooding.
8. **A port scan** probes multiple ports to discover services. PacketWatch approximates this using distinct destination ports within a short window.
9. **A flood** is a high-volume pattern. This project tests peak packets in a one-second bucket against a threshold; it does not measure the sender's intent.
10. **IDS versus IPS:** detection produces an alert; prevention takes an action. PacketWatch acts as an IPS when actual Windows Firewall blocking is enabled.

## 11–20: Understand the complete system

11. **The project is a Python application.** Run it with `python -m packetwatch`; this invokes `packetwatch/__main__.py`.
12. **Its scope is one host.** It is not an enterprise inline gateway or a replacement for every endpoint protection tool.
13. **The main flow** is capture → source window → ten numeric features → two classifiers → rules → response and alert.
14. **“Hybrid” has a concrete meaning:** the decision uses both machine-learning outputs and deterministic rules. There are also two ML models, joined by an OR condition.
15. **Capture uses Scapy and Npcap.** `capture.py` checks privileges and capture support, then calls `sniff()`.
16. **Packets are not retained by sniffing.** `store=False` discards Scapy's capture history; aggregated counters remain in memory.
17. **The capture filter is `ip`.** The current detection path handles IPv4; the presence of `::1` in a whitelist does not imply IPv6 detection coverage.
18. **Local/protected sources are skipped.** `Pipeline.handle()` filters by source address. It does not explicitly require every captured packet's destination to equal the protected PC, which matters on unusual capture interfaces.
19. **Evaluation is periodic.** Sweeps run at most once per second by default; a background ticker also evaluates short bursts after traffic stops.
20. **Detection is not instantaneous packet rejection.** Traffic is observed and summarized before a decision; a firewall rule affects subsequent traffic, not packets already received.

## 21–30: Learn the ten input features in order

21. **`pkt_count`:** total packets for the source in the current window.
22. **`pkts_per_sec`:** the largest packet count in any single second of the window. It is not the ten-second total divided by ten.
23. **`unique_dst_ports`:** how many distinct destination ports the source contacted, subject to tracking limits.
24. **`unique_dst_ips`:** how many distinct destination IPs were observed for the source, also subject to limits.
25. **`tcp_count`:** number of TCP packets in the window.
26. **`udp_count`:** number of UDP packets in the window.
27. **`icmp_count`:** number of ICMP packets in the window.
28. **`syn_only_count`:** TCP packets with SYN set and ACK absent. The implementation checks these two bits; the name does not require every other flag to be zero.
29. **`suspicious_port_hits`:** packets whose destination port belongs to the configured set, including 22, 445 and 3389. It counts packets, not unique ports or proven failed logins.
30. **`avg_len_bucket`:** `floor(average packet length / 100)`. An average of 940 bytes becomes 9. This is a coarse non-negative integer, not a byte count.

## 31–40: Understand windows and resource use

31. **`features.py` owns aggregation.** `SourceWindow.add()` updates counts; `extract()` returns the ten features in the exact order expected by the models.
32. **The default window is ten seconds.** It is implemented as integer-second buckets, not a perfectly continuous per-packet timestamp list.
33. **A ring reuses storage.** A bucket index is `second % window`; a bucket is cleared when reused for a newer second.
34. **Pruning removes stale buckets.** Quiet sources should not retain old traffic as current evidence.
35. **Counters avoid per-packet memory growth.** A burst increases numbers rather than storing every packet object.
36. **Source tracking has a cap of 4,096.** The pipeline uses an ordered dictionary and evicts the least recently updated source when necessary.
37. **Idle sources expire after 60 seconds.** This releases inactive source windows.
38. **Port and destination tracking are bounded.** Configured caps are 256 port entries and 64 destination entries; saturated feature values should be understood as capped summaries, not exact unlimited counts.
39. **Predictions are batched.** Each sweep collects pending feature vectors and calls `predict_many()` once, reducing repeated library-call overhead.
40. **Not every structure has the same bound.** The main source windows and dashboard buffers have explicit limits; active firewall rules/timers can still grow with distinct confirmed sources. Avoid claiming the entire process has an absolute fixed memory ceiling.

## 41–50: Understand machine learning

41. **A feature vector** is one ordered list of ten numbers. A label tells training whether an example is benign (`0`) or attack (`1`).
42. **A Decision Tree** learns comparisons that split the input space. This implementation uses `max_depth=6` and `random_state=42` with no class weighting.
43. **Multinomial Naive Bayes** is a probability-based classifier using non-negative inputs and a simplified conditional-independence assumption. The project's feature mixture is a practical heuristic, not a perfect model of independent word-like counts.
44. **The deployed training data is synthetic.** `generate_training_data()` builds normal browsing, DNS, streaming and LAN patterns, plus scan/flood/suspicious-port patterns.
45. **Synthetic examples are useful for a demo.** They make it easy to learn intended behaviour, but they do not establish general accuracy on real networks.
46. **Training splits data 75/25.** `train_test_split(..., test_size=0.25, stratify=y, random_state=42)` creates a training set and a held-out test set from those examples.
47. **Model reports are separate.** `--train` prints a classification report for each classifier, not a direct measurement of complete live firewall effectiveness.
48. **Models are saved with joblib.** `packetwatch/models/dt.joblib` and `nb.joblib` are generated locally. `Detector()` trains automatically if both saved models are not available.
49. **Flags use probability ≥ 0.5.** Either model meeting this condition makes `flagged=True`; both agreeing is not required.
50. **A displayed probability is a model score.** It is not a calibrated guarantee that the source is malicious. Decisions still pass through the rules.

## 51–60: Learn the exact decision logic

51. **Port-scan rule:** `unique_dst_ports >= 10` with stock settings.
52. **Flood rule:** `pkts_per_sec >= 100` with stock settings.
53. **Suspicious-port rule:** `suspicious_port_hits >= 3` with stock settings.
54. **Rules are shared.** `verify.py` defines the checks used by the runtime and evaluation code, avoiding separate threshold definitions.
55. **Normal confirmation:** if either ML model flags the source and at least one rule fires, the pipeline attempts a block.
56. **Independent rule confirmation:** two distinct rules firing together can trigger a block even when both classifiers miss. “ML must always approve” is therefore incorrect.
57. **ML alone is insufficient.** A flagged window with no rule hit is recorded as unverified and does not trigger blocking.
58. **One rule alone is normally insufficient.** If the ML flag is false and only one rule fires, the standard path does not block; an actionable risk map is an exception.
59. **Example:** a vector `[20, 20, 15, 1, 20, 0, 0, 20, 0, 0]` crosses the port rule. It blocks if ML flags it. If both ML models say benign, that single rule alone is insufficient. At 120 peak packets/sec plus 15 ports, two rules can confirm independently.
60. **Severity is separate from confirmation.** A confirmed alert starts HIGH; the correlator can make it CRITICAL when the source has triggered at least two distinct rule types within 60 seconds.

## 61–70: Understand response and dashboard

61. **`response.py` manages actions.** `FirewallBlocker` calls `netsh advfirewall firewall` to add inbound and outbound rules for a source IP.
62. **Source strings are validated as IPs.** Subprocess arguments are passed without a shell. This prevents an address string being treated as a shell command.
63. **Whitelist checks come first.** Loopback, local addresses, the gateway and user-supplied trusted addresses are protected in the normal live path.
64. **Upstream adds `--block-gateway`.** This is a deliberate lab override for a hotspot demonstration. Keep it disabled during ordinary monitoring.
65. **`--dry-run` logs proposed commands.** It still tracks simulated block state in memory, so a dashboard block count does not by itself prove firewall enforcement.
66. **Block expiry depends on a running process.** Timers remove rules after 30 minutes by default. Exiting or killing the process leaves rules until cleanup.
67. **Alerts are JSON lines.** Each includes source, time, severity, model outputs, rule evidence, trigger and action. Read `action`, because confirmation can be followed by a failed firewall operation.
68. **Log rotation limits disk use.** `alerts.log` rolls at about 5 MB and keeps three backups. These are runtime outputs, not source code.
69. **The dashboard is local.** `dashboard.py` serves `dashboard.html` on `127.0.0.1:8787`, checks the Host header and requires a custom control header for unblock requests.
70. **The funnel counts judgments.** A source judged across several sweeps contributes several windows. Compare judged → ML-flagged → unverified/confirmed, and do not interpret every counter as unique attackers.

## 71–80: Run and explore the code

71. **Read `WINDOWS_SETUP.md` first.** It contains exact Windows commands, installation details and troubleshooting.
72. **Use an isolated environment.** `.venv` contains this project's Python packages, keeping them separate from unrelated projects.
73. **Train once:** `.\.venv\Scripts\python.exe -m packetwatch --train`. Inspect the two reports and generated model files.
74. **Run the simulation:** `.\.venv\Scripts\python.exe -m packetwatch --simulate`. `simulate.py` builds packets and feeds them directly to the pipeline using a virtual clock; it does not send them over your network.
75. **Explain the normal cases.** The demo includes HTTPS replies and DNS replies; their patterns should remain allowed under stock settings.
76. **Explain the attack-pattern cases.** The six scenarios include a SYN scan, UDP flood, ICMP flood, RDP/SMB attempts, a suspicious-port sweep and an aggressive scan. These are crafted header patterns, not actual credential cracking.
77. **Open the dashboard:** add `--dashboard`. Keep the terminal running, browse to the printed localhost URL, and use Ctrl+C when finished.
78. **Run the test suite:** `.\.venv\Scripts\python.exe -m unittest discover tests`. Tests cover features, decisions, responses, dashboard and vulnerability logic with controlled inputs; they do not prove every real-world attack is stopped.
79. **Try live dry-run next.** List interfaces, select the active one, run as Administrator with `--dry-run --timeout 60`, and browse normally while watching the dashboard.
80. **Enable real blocking last.** Remove `--dry-run` only after understanding alerts and keep the `--unblock-all` cleanup command available. A working simulation alone does not verify Npcap capture or real firewall changes.

## 81–90: Calibration, optional module and evaluations

81. **Calibration learns rule thresholds.** It takes a 99.9th percentile of observed feature values and clamps the results to configured floors and ceilings. It does not retrain either ML model.
82. **Calibrate on normal traffic.** `--calibrate 300` writes `models/thresholds.json` for subsequent starts. Teaching it attack traffic can make later decisions too permissive.
83. **Recorded rows need human labels.** `--record rows.csv` writes features with an empty label; `--train --csv rows.csv` expects labels and adds these rows to synthetic training examples.
84. **The vulnerability module reads reports.** `python -m packetwatch.vuln --report scan.xml` parses an OpenVAS/Greenbone XML export. PacketWatch does not itself implement the OpenVAS scanner.
85. **Ranking uses a cascade:** CISA known-exploited information, then EPSS when available, then a tree if suitable model/input data are supplied, then fallback scoring. The normal CLI passes no NVD lookup, so the tree path is not automatically exercised merely by reading an XML report.
86. **Ranking bands are implementation-specific.** Any available EPSS score maps into this implementation's HIGH band, even a small probability. With a CVE but no NVD/feed data, the CVSS fallback may score zero; scanner severity still breaks ties. Do not describe these bands as universal severity standards.
87. **`--validate` checks exposure.** It connects to reported services and checks reachability/banners; it is not proof that a vulnerability can be exploited. Use reports and validation targets you are authorized to assess.
88. **Risk maps alter decisions.** HIGH/CRITICAL entries can make one rule sufficient without ML and escalate severity. The current map is keyed by port, not host plus protocol, so use a report scoped to the protected host and understand potential over-matching.
89. **Evaluation scripts are separate experiments.** CIC-IDS2017, UNSW-NB15 and TON_IoT use dataset-specific processing. Their results are not interchangeable with the default synthetic-model training report or live packet-capture performance.
90. **Know the metrics:** precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2PR/(P+R); false-positive rate = FP/(FP+TN). TP means correctly detected attack; FP means normal traffic incorrectly flagged; FN means missed attack; TN means correctly accepted normal traffic. Class balance and test splits affect interpretation.

## 91–100: Present, review and extend the project

91. **State the main limitation:** header volume and port patterns cannot reliably detect low-rate payload attacks such as SQL injection or XSS. Encrypted contents are not inspected either.
92. **Do not promise universal accuracy.** `EVALUATION.md` reports F1 0.923 per flow but 0.057 per aggregated window for the shipped decision strategy on its random split. Flows inherit their window's verdict, so these are different units of measurement. Its aggregation uses 60-second windows and average packet rates, unlike the live ten-second windows and peak rates. Cite the unit, split and transformation, not just the headline score.
93. **Read benchmark claims carefully.** Offline processing throughput and virtual/replayed scenarios are not identical to end-to-end live capture and firewall latency on this PC. Reproduce before making performance claims.
94. **Read the code in this order:** `__main__.py`, `config.py`, `capture.py`, `features.py`, `model.py`, `verify.py`, `pipeline.py`, `response.py`, `simulate.py`, then `dashboard.py` and the optional vulnerability modules.
95. **Trace one packet on paper.** Choose a source/destination/port, update its bucket, write the feature vector, identify rule hits, supply the two model flags, apply the confirmation formula, then explain the resulting alert/action.
96. **Prepare a short demonstration.** Show setup, train, run tests, simulate, inspect the decision funnel and explain one allowed case and one confirmed case. Clearly label the demo as offline/dry-run.
97. **Answer “why two models?”** OR fusion can increase sensitivity by letting either model flag a pattern; it can also increase false alarms, motivating rule verification. The chosen trade-off requires measurement, not just intuition.
98. **Answer “why a hybrid system?”** It joins learned patterns with explicit, explainable constraints and a rule-only fallback, balancing detection coverage and understandable actions. Rules can also suppress real attacks that never cross thresholds.
99. **Propose improvements from actual gaps.** Examples include IPv6 support, safer reconciliation/expiry of firewall rules across restarts, host/protocol-aware risk mapping, better labelled local data and separate time-based evaluation. Treat these as future work, not existing features.
100. **Your final explanation:** “PacketWatch is a single-host Windows IDS/IPS. It summarizes observed IPv4 traffic per source, uses a Decision Tree and Multinomial Naive Bayes to flag patterns, verifies evidence with threshold rules, and can block sources through Windows Firewall. It includes explainable alerts, a local dashboard, offline demonstrations and an optional vulnerability-ranking module. Its effectiveness depends on traffic patterns, thresholds and training data.”

## Decision summary

```text
ML flag = (DT attack probability >= 0.5) OR (NB attack probability >= 0.5)
Standard confirmation = (ML flag AND at least 1 rule) OR (at least 2 rules)
With actionable risk = (ML flag AND at least 1 rule) OR (at least 1 rule)
Confirmed -> attempt block -> record the actual action and explanation
```

## Suggested study sessions

| Session | Points | Practical exercise |
|---|---|---|
| 1 | 1–20 | Explain packet, IP, port, IDS and IPS in your own words |
| 2 | 21–40 | Construct a feature vector and trace a rolling window |
| 3 | 41–60 | Train models and manually evaluate three decision cases |
| 4 | 61–80 | Run tests and the offline dashboard; inspect an alert |
| 5 | 81–100 | Explain evaluation limitations and give a project demonstration |
