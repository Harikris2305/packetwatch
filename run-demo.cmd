@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup-windows.ps1 first. See WINDOWS_SETUP.md.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:8787 after the simulation starts.
echo Press Ctrl+C to stop. This demo does not change Windows Firewall.
".venv\Scripts\python.exe" -m packetwatch --simulate --dashboard
if errorlevel 1 pause
