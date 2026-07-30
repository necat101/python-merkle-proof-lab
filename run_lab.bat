@echo off
setlocal
cd /d "%~dp0"

echo === python-merkle-proof-lab ===
echo.

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo error: python not found in PATH
    exit /b 1
)

echo Python:
python --version
echo.

echo === compile ===
python -m compileall merkle_proof
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
echo.

echo === run_lab.py ===
python run_lab.py
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
echo.

echo === unittest ===
python -m unittest tests.test_merkle_independent -v
if %ERRORLEVEL% NEQ 0 exit /b %ERRORLEVEL%
echo.

echo All checks passed.
