# Lab 4 Task 1+5 — Hash benchmark (Windows).
# Spec literal: 1s warm-up, n=30 blocks, block=1000 ops.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$exe = ".\bin\windows\hashtool.exe"
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe not found. Build trước: cmake --build build -j" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path logs\windows | Out-Null

$N = 30
$BLOCK = 1000
$SIZES = @(
    @{name="1KiB";    bytes=1024},
    @{name="64KiB";   bytes=65536},
    @{name="1MiB";    bytes=1048576},
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
        Run-Bench "$alg @ $($s.name)" @("bench","--algo",$alg,"--size",$s.bytes,"--n",$N,"--block",$BLOCK,"--log","logs\windows\${tag}_$($s.name).csv")
    }
}

$total_elapsed = (Get-Date) - $total_start
Write-Host "`n=============================================" -ForegroundColor Yellow
Write-Host ("TOTAL elapsed: {0:hh\:mm\:ss}" -f $total_elapsed) -ForegroundColor Yellow
Write-Host "Logs o: $root\logs\windows\" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow
