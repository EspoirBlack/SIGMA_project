@echo off
title SIGMA Security Monitor
color 0A

echo ========================================
echo    SIGMA Security Monitor
echo ========================================
echo.

:: Go to the batch file's location
cd /d "%~dp0"

echo [1] Checking Python...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python not found!
    echo Please install Python from python.org
    pause
    exit /b 1
)
python --version
echo.

echo [2] Checking required packages...
python -c "import flask" >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing required packages...
    pip install flask flask-socketio pywin32 psutil pandas requests reportlab
    echo.
) else (
    echo Required packages already installed.
)
echo.

echo [3] Starting SIGMA...
echo.
echo ========================================
echo    Dashboard: http://localhost:5000
echo    Press Ctrl+C to stop
echo ========================================
echo.

python app.py

pause