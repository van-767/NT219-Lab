@echo off
REM Double-click vào file này để chạy benchmark trên Windows.
REM Wrapper gọi PowerShell với ExecutionPolicy Bypass để không bị block.
cd /d "%~dp0\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_bench.ps1"
pause
