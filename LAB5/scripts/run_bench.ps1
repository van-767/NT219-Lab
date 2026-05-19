# Auto-run toàn bộ benchmark cho Lab 5 (Windows / PowerShell).
# Spec literal: n=30 blocks, block=1000 ops, warm-up 1s.
# Cách chạy: chuột phải -> "Run with PowerShell"  HOẶC
#            powershell -ExecutionPolicy Bypass -File scripts\run_bench.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$ecdsa  = ".\bin\windows\ECDSA.exe"
$rsapss = ".\bin\windows\RSAPSS.exe"
foreach ($e in @($ecdsa, $rsapss)) {
    if (-not (Test-Path $e)) {
        Write-Host "ERROR: $e not found. Build trước: cmake --build build -j" -ForegroundColor Red
        exit 1
    }
}

New-Item -ItemType Directory -Force -Path logs\windows | Out-Null

$N = 30
$BLOCK = 1000
$SIZES = @(
    @{name="1KiB";  bytes=1024},
    @{name="16KiB"; bytes=16384},
    @{name="1MiB";  bytes=1048576},
    @{name="8MiB";  bytes=8388608}
)

function Run-Bench {
    param([string]$Name, [string]$Exe, [string[]]$CmdArgs)
    $start = Get-Date
    Write-Host "`n[$([DateTime]::Now.ToString('HH:mm:ss'))] >>> $Name" -ForegroundColor Cyan
    Write-Host "    $Exe $($CmdArgs -join ' ')"
    & $Exe @CmdArgs
    $elapsed = (Get-Date) - $start
    Write-Host ("    done in {0:hh\:mm\:ss}" -f $elapsed) -ForegroundColor Green
}

$total_start = Get-Date

# ---------- ECDSA P-256 (required) ----------
Run-Bench "ECDSA-P256 keygen" $ecdsa @("bench","--op","keygen","--algo","ecdsa-p256","--n",$N,"--block",$BLOCK,"--log","logs\windows\ecdsa_p256_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "ECDSA-P256 sign $($s.name)"   $ecdsa @("bench","--op","sign","--algo","ecdsa-p256","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\ecdsa_p256_sign_$($s.name).csv")
    Run-Bench "ECDSA-P256 verify $($s.name)" $ecdsa @("bench","--op","verify","--algo","ecdsa-p256","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\ecdsa_p256_verify_$($s.name).csv")
}

# ---------- ECDSA P-384 (optional, +5 spec) ----------
Run-Bench "ECDSA-P384 keygen" $ecdsa @("bench","--op","keygen","--algo","ecdsa-p384","--n",$N,"--block",$BLOCK,"--log","logs\windows\ecdsa_p384_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "ECDSA-P384 sign $($s.name)"   $ecdsa @("bench","--op","sign","--algo","ecdsa-p384","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\ecdsa_p384_sign_$($s.name).csv")
    Run-Bench "ECDSA-P384 verify $($s.name)" $ecdsa @("bench","--op","verify","--algo","ecdsa-p384","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\ecdsa_p384_verify_$($s.name).csv")
}

# ---------- RSA-PSS 3072 (required) ----------
Run-Bench "RSA-PSS-3072 keygen" $rsapss @("bench","--op","keygen","--bits","3072","--n",$N,"--block",$BLOCK,"--log","logs\windows\rsapss_3072_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "RSA-PSS-3072 sign $($s.name)"   $rsapss @("bench","--op","sign","--bits","3072","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\rsapss_3072_sign_$($s.name).csv")
    Run-Bench "RSA-PSS-3072 verify $($s.name)" $rsapss @("bench","--op","verify","--bits","3072","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\rsapss_3072_verify_$($s.name).csv")
}

# ---------- RSA-PSS 4096 (so sánh, song song Lab 3) ----------
Run-Bench "RSA-PSS-4096 keygen" $rsapss @("bench","--op","keygen","--bits","4096","--n",$N,"--block",$BLOCK,"--log","logs\windows\rsapss_4096_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "RSA-PSS-4096 sign $($s.name)"   $rsapss @("bench","--op","sign","--bits","4096","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\rsapss_4096_sign_$($s.name).csv")
    Run-Bench "RSA-PSS-4096 verify $($s.name)" $rsapss @("bench","--op","verify","--bits","4096","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\rsapss_4096_verify_$($s.name).csv")
}

$total_elapsed = (Get-Date) - $total_start
Write-Host "`n=============================================" -ForegroundColor Yellow
Write-Host ("TOTAL elapsed: {0:hh\:mm\:ss}" -f $total_elapsed) -ForegroundColor Yellow
Write-Host "Logs o: $root\logs\windows\" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow
