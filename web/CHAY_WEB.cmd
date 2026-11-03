@echo off
cd /d "%~dp0"
py -B app.py
if errorlevel 1 pause
