@echo off
cd /d "%~dp0"
python email_backup_manager.py
if errorlevel 1 pause
