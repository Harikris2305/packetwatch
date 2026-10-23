param(
    [string]$PythonExe = "py",
    [switch]$IncludeEvaluation
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed: $Executable $Arguments" }
}
if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    Invoke-Checked $PythonExe @("-m", "venv", ".venv")
}
$ProjectPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
Invoke-Checked $ProjectPython @("-c", "import sys; assert sys.version_info >= (3, 10), 'Python 3.10 or newer is required'")
Invoke-Checked $ProjectPython @("-m", "ensurepip", "--upgrade")
$Requirements = if ($IncludeEvaluation) { "requirements-eval.txt" } else { "requirements.txt" }
Invoke-Checked $ProjectPython @("-m", "pip", "install", "-r", $Requirements)
Invoke-Checked $ProjectPython @("-m", "pip", "check")
Invoke-Checked $ProjectPython @("-m", "packetwatch", "--train")
Write-Host "Setup complete. Run .\run-demo.cmd for the offline dashboard."
