@echo off
echo Starting VulnScan GUI Backend...
cd /d "%~dp0backend"
pip install -r requirements.txt
python api_server.py
pause
