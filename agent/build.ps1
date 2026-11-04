# Builds bw-agent.exe in Docker and copies it to dist\ at the repo root.
# Run from anywhere:  powershell -File agent\build.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    docker compose --profile tools build agent-build
    if ($LASTEXITCODE) { throw 'build failed' }
    docker compose --profile tools rm -f agent-build | Out-Null
    docker compose --profile tools create agent-build | Out-Null
    New-Item -ItemType Directory -Force dist | Out-Null
    docker compose cp agent-build:/out/bw-agent.exe dist/bw-agent.exe
    docker compose cp agent-build:/out/Cargo.lock agent/Cargo.lock
    docker compose --profile tools rm -f agent-build | Out-Null
    $exe = Get-Item dist\bw-agent.exe
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash
    "built $($exe.FullName)  $([math]::Round($exe.Length / 1MB, 2)) MB  sha256 $hash"
} finally {
    Pop-Location
}
