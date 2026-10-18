@echo off
title AI LIKE HUB - server
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on this PC.
  echo Install Python 3.10 or newer from python.org, then run this file again.
  pause
  exit /b 1
)
python server.py
if errorlevel 1 (
  echo.
  echo The server stopped with an error. Read the messages above.
  pause
)
