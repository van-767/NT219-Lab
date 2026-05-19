# Auto-run toàn bộ benchmark cho Lab 3 (Windows / PowerShell).
# Đúng spec: block=1000 cho mọi op. Tổng thời gian dự kiến 6-8 giờ.
# Cách chạy: chuột phải -> "Run with PowerShell"  HOẶC
#            powershell -ExecutionPolicy Bypass -File scripts\run_bench.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$exe = ".\bin\windows\rsatool.exe"
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe not found. Build trước: cmake --build build -j" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path logs\windows | Out-Null

# n = 30 sample (spec: 30..100), block = 1000 ops/block (spec literal).
$N = 30
$BLOCK = 1000

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

# ---------- RSA (Section 5.1) ----------
Run-Bench "RSA keygen 3072"  @("bench","--op","keygen","--bits","3072","--n",$N,"--block",$BLOCK,"--log","logs\windows\keygen_3072.csv")
Run-Bench "RSA keygen 4096"  @("bench","--op","keygen","--bits","4096","--n",$N,"--block",$BLOCK,"--log","logs\windows\keygen_4096.csv")
Run-Bench "RSA encrypt 3072" @("bench","--op","enc","--bits","3072","--n",$N,"--block",$BLOCK,"--log","logs\windows\enc_3072.csv")
Run-Bench "RSA encrypt 4096" @("bench","--op","enc","--bits","4096","--n",$N,"--block",$BLOCK,"--log","logs\windows\enc_4096.csv")
Run-Bench "RSA decrypt 3072" @("bench","--op","dec","--bits","3072","--n",$N,"--block",$BLOCK,"--log","logs\windows\dec_3072.csv")
Run-Bench "RSA decrypt 4096" @("bench","--op","dec","--bits","4096","--n",$N,"--block",$BLOCK,"--log","logs\windows\dec_4096.csv")

# ---------- Hybrid Mode / AES-GCM throughput (Section 5.2) ----------
$sizes = @(
    @{name="1KiB";   bytes=1024},
    @{name="4KiB";   bytes=4096},
    @{name="16KiB";  bytes=16384},
    @{name="256KiB"; bytes=262144},
    @{name="1MiB";   bytes=1048576},
    @{name="8MiB";   bytes=8388608}
)
foreach ($s in $sizes) {
    Run-Bench "AES-GCM encrypt $($s.name)" @("bench","--op","gcm_enc","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\gcm_enc_$($s.name).csv")
    Run-Bench "AES-GCM decrypt $($s.name)" @("bench","--op","gcm_dec","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\gcm_dec_$($s.name).csv")
}

$total_elapsed = (Get-Date) - $total_start
Write-Host "`n=============================================" -ForegroundColor Yellow
Write-Host ("TOTAL elapsed: {0:hh\:mm\:ss}" -f $total_elapsed) -ForegroundColor Yellow
Write-Host "Logs o: $root\logs\windows\" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow
