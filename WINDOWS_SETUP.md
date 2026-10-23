# Run PacketWatch on Windows

Start with the offline demo, then try live capture in dry-run mode, then enable
blocking only after reviewing what your normal traffic looks like.

**Current machine status (23 October 2026):** dependencies are installed, but
Windows Application Control blocks compiled NumPy/scikit-learn modules. Training
and simulation cannot start until the machine's policy permits those libraries.
See [VALIDATION.md](VALIDATION.md) for the completed checks and exact remaining steps.

## Requirements

| Requirement | Purpose | Needed for offline demo? |
|---|---|---|
| Python 3.10+ (64-bit) | Runs the application | Yes |
| scapy | Represents packets and captures live traffic | Yes |
| scikit-learn | Decision Tree and Multinomial Naive Bayes | Yes |
| numpy | Numeric arrays used by ML and calibration | Yes |
| joblib | Saves and loads trained models | Yes |
| Npcap | Windows packet capture driver | No |
| Administrator PowerShell | Required by live capture preflight and firewall changes | No |
| Git | Downloads and updates source history | No, a source ZIP also works |

There is no Node.js, npm, React, database server, GPU or paid API requirement.
The dashboard uses Python's built-in HTTP server and plain HTML/JavaScript.

Official installers: [Python](https://www.python.org/downloads/windows/),
[Git for Windows](https://git-scm.com/download/win), and
[Npcap](https://npcap.com/#download). Enable Npcap's WinPcap API-compatible option
if installing it for Scapy. Existing working installations do not need reinstalling.

## This workspace

The local repository is:

```text
C:\Users\Hp\Documents\ChatGPT\hybrid intrustion prevention system\packetwatch
```

Use its `.venv\Scripts\python.exe` directly. Activation is optional, and using the
explicit path avoids selecting the Windows Store alias or the wrong Python.
The environment was created using the Codex-bundled Python 3.12 runtime because
the system Python launcher had no installed interpreter. A virtual environment
depends on its base interpreter: if that bundled runtime is later removed, install
standalone Python and recreate the environment with the setup script.

## Fresh installation on another Windows PC

Open PowerShell in the folder where you want the project:

```powershell
git clone https://github.com/Harikris2305/packetwatch.git
cd packetwatch
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-windows.ps1
```

`Bypass` here applies to that PowerShell process; it does not change the saved
system execution policy. The script creates `.venv`, installs dependencies,
checks package compatibility, and trains the two models. It stops on errors.

If Python is installed under a specific path, supply it explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-windows.ps1 -PythonExe "C:\path\to\python.exe" -IncludeEvaluation
```

`-IncludeEvaluation` also installs pandas, pyarrow, LightGBM, psutil and matplotlib.
These are for dataset experiments, benchmarks and diagrams. Large datasets are
not included and are not required for the demo. See README.md for dataset sources.

Equivalent manual setup:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m packetwatch --train
```

## First run: offline simulation

```powershell
cd "C:\Users\Hp\Documents\ChatGPT\hybrid intrustion prevention system\packetwatch"
.\.venv\Scripts\python.exe -m packetwatch --simulate
.\.venv\Scripts\python.exe -m packetwatch --simulate --dashboard
```

For the dashboard, open **http://127.0.0.1:8787** and keep the terminal running.
You can also double-click `run-demo.cmd`. Use Ctrl+C in that terminal to stop.
Simulation builds packets in memory; it does not send attack traffic or execute
firewall block commands. “BLOCKED” in the simulation means a dry-run decision.
Normal HTTPS and DNS should be allowed; the six attack-pattern scenarios should
be marked blocked with the stock models and thresholds.

## Verify the installation

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
.\.venv\Scripts\python.exe -m packetwatch --list-ifaces
.\.venv\Scripts\python.exe -m packetwatch.vuln --report tests\fixtures\openvas_report.xml --json risk.json
```

The fixture command parses a saved report; it does not scan a network. Without
downloaded feeds it reports that exploitation data is missing. The report's
addresses are examples, not the current machine's vulnerabilities.

## Live monitoring

Open PowerShell **as Administrator**, change into the repository, and list adapters.
Use the exact adapter name from your output in place of `Wi-Fi`:

```powershell
.\.venv\Scripts\python.exe -m packetwatch --list-ifaces
.\.venv\Scripts\python.exe -m packetwatch --dry-run --dashboard --iface "Wi-Fi" --timeout 60
```

Use normal browsing during that minute. Confirm the dashboard reports live packets
and review any flagged sources. A dry run prints proposed firewall operations.
For actual protection, remove `--dry-run`:

```powershell
.\.venv\Scripts\python.exe -m packetwatch --dashboard --iface "Wi-Fi"
```

Own addresses, loopback and the gateway are protected by default. Additional
trusted addresses can be supplied using `--whitelist`. The imported
`--block-gateway` flag deliberately disables gateway protection for a lab demo;
leave it off for ordinary use because blocking the gateway disconnects the PC.

Blocks have a 30-minute timer **while the process remains running**. Stopping the
program does not remove existing rules, and its timers cannot run after it exits.
To remove PacketWatch rules, use Administrator PowerShell:

```powershell
.\.venv\Scripts\python.exe -m packetwatch --unblock-all
```

## Calibration and your own training data

```powershell
.\.venv\Scripts\python.exe -m packetwatch --calibrate 300 --iface "Wi-Fi"
.\.venv\Scripts\python.exe -m packetwatch --dry-run --record rows.csv --iface "Wi-Fi" --timeout 300
```

Calibration learns threshold values from ordinary traffic and writes
`packetwatch/models/thresholds.json`. Do not generate scans during calibration.
Recorded rows contain the ten features plus an empty `label`. Fill every label
with `0` (known benign) or `1` (known attack), then run:

```powershell
.\.venv\Scripts\python.exe -m packetwatch --train --csv rows.csv
```

This adds labelled rows to the synthetic training data; it does not replace it.
Keep private traffic recordings and generated risk reports out of public commits.

## Common problems

| Symptom | Fix |
|---|---|
| `python` opens Microsoft Store | Use `.venv\Scripts\python.exe`, or install standalone Python |
| `py` says no installed Pythons | Install Python or pass a working executable to the setup script |
| `No module named scapy/sklearn` | Install requirements using the same environment's `python -m pip` |
| Npcap not detected | Install/repair Npcap and restart the terminal; verify Scapy capture support |
| Administrator error | Run an elevated PowerShell for live capture; offline simulation needs no elevation |
| No live packets | Select the active adapter, then generate ordinary traffic |
| Port 8787 already in use | Stop the earlier dashboard, or pass `--dashboard 8788` |
| Browser cannot connect | Keep the dashboard process running and use its printed localhost URL |
| Git executable fails to start | Repair Git for Windows; the local checkout can still run without Git |
| Unwanted firewall block | Run `--unblock-all` as Administrator and return to dry-run mode |
| Model incompatible after package changes | Retrain using `--train` in the current environment |
| `An Application Control policy has blocked this file` | Ask the machine's policy administrator to review Code Integrity events and approve the required libraries through the applicable policy; running as Administrator alone did not solve it on this machine |

For the concepts and code walkthrough, read [STUDY_GUIDE.md](STUDY_GUIDE.md).
