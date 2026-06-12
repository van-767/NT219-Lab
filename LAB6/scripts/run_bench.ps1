# Auto-run benchmark Lab 6 (Windows / PowerShell).
# Spec literal: n=30 blocks, block=1000 ops, warm-up 1s.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$mldsa = ".\bin\windows\MLDSA.exe"
$mlkem = ".\bin\windows\MLKEM.exe"
foreach ($e in @($mldsa, $mlkem)) {
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

# ---------- ML-DSA-44 (required) ----------
Run-Bench "ML-DSA-44 keygen" $mldsa @("bench","--op","keygen","--algo","mldsa-44","--n",$N,"--block",$BLOCK,"--log","logs\windows\mldsa_44_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "ML-DSA-44 sign $($s.name)"   $mldsa @("bench","--op","sign","--algo","mldsa-44","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\mldsa_44_sign_$($s.name).csv")
    Run-Bench "ML-DSA-44 verify $($s.name)" $mldsa @("bench","--op","verify","--algo","mldsa-44","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\mldsa_44_verify_$($s.name).csv")
}

# ---------- ML-DSA-65 (bonus +5) ----------
Run-Bench "ML-DSA-65 keygen" $mldsa @("bench","--op","keygen","--algo","mldsa-65","--n",$N,"--block",$BLOCK,"--log","logs\windows\mldsa_65_keygen.csv")
foreach ($s in $SIZES) {
    Run-Bench "ML-DSA-65 sign $($s.name)"   $mldsa @("bench","--op","sign","--algo","mldsa-65","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\mldsa_65_sign_$($s.name).csv")
    Run-Bench "ML-DSA-65 verify $($s.name)" $mldsa @("bench","--op","verify","--algo","mldsa-65","--n",$N,"--block",$BLOCK,"--size",$s.bytes,"--log","logs\windows\mldsa_65_verify_$($s.name).csv")
}

# ---------- ML-KEM-512 (required) ----------
Run-Bench "ML-KEM-512 keygen" $mlkem @("bench","--op","keygen","--algo","mlkem-512","--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_512_keygen.csv")
Run-Bench "ML-KEM-512 encaps" $mlkem @("bench","--op","encaps","--algo","mlkem-512","--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_512_encaps.csv")
Run-Bench "ML-KEM-512 decaps" $mlkem @("bench","--op","decaps","--algo","mlkem-512","--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_512_decaps.csv")

# ---------- ML-KEM-768 / 1024 (so sánh) ----------
foreach ($alg in @("mlkem-768","mlkem-1024")) {
    $tag = $alg -replace 'mlkem-',''
    Run-Bench "ML-KEM-$tag keygen" $mlkem @("bench","--op","keygen","--algo",$alg,"--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_${tag}_keygen.csv")
    Run-Bench "ML-KEM-$tag encaps" $mlkem @("bench","--op","encaps","--algo",$alg,"--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_${tag}_encaps.csv")
    Run-Bench "ML-KEM-$tag decaps" $mlkem @("bench","--op","decaps","--algo",$alg,"--n",$N,"--block",$BLOCK,"--log","logs\windows\mlkem_${tag}_decaps.csv")
}

$total_elapsed = (Get-Date) - $total_start
Write-Host "`n=============================================" -ForegroundColor Yellow
Write-Host ("TOTAL elapsed: {0:hh\:mm\:ss}" -f $total_elapsed) -ForegroundColor Yellow
Write-Host "Logs o: $root\logs\windows\" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Yellow
