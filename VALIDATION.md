# Local setup and validation — 23 October 2026

## Follow-up detection-quality changes

The fixes described in [IMPROVEMENTS.md](IMPROVEMENTS.md) add 19 passing regressions
for feature counts, expiry, host scope, CLI wiring and calibration validation.
The existing 35 dashboard/vulnerability tests also passed (50 tests were run
together before four additional scope/wiring tests were added; the final set of
19 new tests passed separately). Syntax compilation and whitespace checks passed.
An isolated old/new feature comparison measured 256→30 for repeated ports,
64→8 for repeated destinations, and 256→0 after expiry. These are counting
corrections, not classifier accuracy scores. The Windows native-library policy
blocker was rechecked and remains; full ML tests and simulation are still blocked.

## Repository changes

- Imported the three differences from the team snapshot `ec2fef115eede26dc84e714ec5b3e7f0d67c771b`: `demo_server.py`, `packetwatch/__main__.py`, and `packetwatch/response.py`.
- The imported source tree matches the team snapshot's tree `b63d73055797e5671c8c9347ebe3fdfa8d762c49` before adding learning/setup resources.
- Added a 100-point code-based study guide, Windows instructions, an environment setup script and an offline demo launcher.
- Kept original team attribution and the destination repository's existing history.

## Completed on this Windows machine

| Check | Result |
|---|---|
| Local repository download | Completed using bundled Git 2.53.0 |
| Python environment | Created `.venv` using bundled Python 3.12.14 |
| Runtime and evaluation dependencies | Installed from `requirements-eval.txt`, which includes `requirements.txt` |
| `python -m pip check` | Passed: no broken requirements |
| Npcap | Existing driver/library detected; Scapy listed adapters |
| Active wireless adapter | Listed as `Wi-Fi 2` |
| Dashboard and vulnerability tests | 35 tests passed using `python -m unittest tests.test_dashboard tests.test_vuln` |
| Offline XML report parsing | Passed: four findings parsed from the provided fixture and `risk.json` written |
| PowerShell setup script | Parsed without syntax errors; complete execution remains dependent on ML imports |
| Study-guide structure | Verified points 1 through 100 in order |
| Whitespace check | `git diff --check` passed |

The successful test subset emitted a ResourceWarning about an unclosed test
socket. It did not fail the assertions. Firewall operations in these tests use
test doubles; they do not establish real firewall enforcement.

## Blocked checks — not passed

The full suite could not import `test_pipeline`, and `--train` and `--simulate`
could not load scikit-learn. Windows returned:

```text
ImportError: DLL load failed while importing _check_build:
An Application Control policy has blocked this file.
```

Recent Windows Code Integrity event 3077 entries also identify NumPy's
`_multiarray_umath.cp312-win_amd64.pyd` as blocked by policy. The same ML import
failure occurred outside the execution sandbox. This is distinct from the
sandbox's earlier temporary-directory/socket restrictions, which were resolved
for the successful test subset by running it outside the sandbox.

The existing bundled Python does not contain an alternative scikit-learn
installation. Security policy was not changed. No model training, complete
simulation, live capture session or actual firewall enforcement has been verified.
No running project dashboard is being claimed.

## Remaining machine action

Have the machine's Windows policy administrator review the relevant blocked
libraries in **Event Viewer → Applications and Services Logs → Microsoft → Windows
→ CodeIntegrity → Operational**, and determine the permitted way to run them.
Microsoft documents this diagnostic workflow in its
[App Control troubleshooting guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting).
Do not treat a successful pip install as evidence that Windows will allow native
modules to load. No global security disablement is part of this setup.

After the policy issue is resolved, run these commands from the repository:

```powershell
.\.venv\Scripts\python.exe -c "import numpy, sklearn; print('ML imports OK')"
.\.venv\Scripts\python.exe -m unittest discover tests
.\.venv\Scripts\python.exe -m packetwatch --train
.\.venv\Scripts\python.exe -m packetwatch --simulate --dashboard
```

Open http://127.0.0.1:8787 only after the last command prints its dashboard address.
For live monitoring, use Administrator PowerShell after the offline checks pass:

```powershell
.\.venv\Scripts\python.exe -m packetwatch --dry-run --dashboard --iface "Wi-Fi 2" --timeout 60
```

Installed primary package versions: Scapy 2.8.0, scikit-learn 1.9.1, NumPy 2.5.4,
joblib 1.6.0, SciPy 1.18.1. Evaluation packages include pandas 3.1.0, pyarrow 26.0.0,
LightGBM 4.7.0, psutil 7.2.2 and matplotlib 3.11.2. These are an installation
record, not a claim that the blocked ML stack passed runtime validation.

Large benchmark datasets, external vulnerability feeds and a standalone OpenVAS
scanner were not downloaded; they are optional and are not needed for the offline
IDS demonstration. The generated fixture risk report describes sample hosts and
must not be mistaken for a scan of this PC.
