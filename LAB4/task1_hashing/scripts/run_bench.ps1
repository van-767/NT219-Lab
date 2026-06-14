# LAB4 performance evaluation (Windows).
# Required algorithms: SHA-256, SHA-512, SHA3-256, SHA3-512.
# Benchmark sizes: 1 MiB, 8 MiB, 50 MiB, 100 MiB.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$exe = ".\bin\windows\hashtool.exe"
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe not found. Build first: cmake --build build -j" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path logs\windows | Out-Null

$N = 30
$BLOCK = 1000
$SIZES = @(
    @{name="1MiB";    bytes=1048576},
    @{name="8MiB";    bytes=8388608},
    @{name="50MiB";   bytes=52428800},
    @{name="100MiB";  bytes=104857600}
)

$ALGOS = @("sha256","sha512","sha3-256","sha3-512")

function Run-Bench {
    param([string]$Name, [string[]]$CmdArgs)
    $start = Get-Date
    Write-Host "`n[$([DateTime]::Now.ToString('HH:mm:ss'))] >>> $Name" -ForegroundColor Cyan
    Write-Host "    $exe $($CmdArgs -join ' ')"
    & $exe @CmdArgs
    $elapsed = (Get-Date) - $start
    Write-Host ("    done in {0:hh\:mm\:ss}" -f $elapsed) -ForegroundColor Green
}

$total_start = Get-Date

foreach ($alg in $ALGOS) {
    foreach ($s in $SIZES) {
        $tag = $alg -replace '-','_'
        Run-Bench "$alg @ $($s.name), block=$BLOCK" @(
            "bench",
            "--algo", $alg,
            "--size", $s.bytes,
            "--n", $N,
            "--block", $BLOCK,
            "--log", "logs\windows\${tag}_$($s.name).csv"
        )
    }
}

$total_elapsed = (Get-Date) - $total_start
Write-Host "`n=============================================" -ForegroundColor Yellow
Write-Host ("TOTAL elapsed: {0:hh\:mm\:ss}" -f $total_elapsed) -ForegroundColor Yellow
Write-Host "Logs: $root\logs\windows\" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow
