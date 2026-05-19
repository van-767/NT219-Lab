@echo off
REM Double-click vào file này để chạy benchmark Lab 5 trên Windows.
cd /d "%~dp0\.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_bench.ps1"
pause
