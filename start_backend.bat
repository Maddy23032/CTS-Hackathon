@echo off
echo Starting VulnPy GUI Backend...
cd /d "%~dp0backend"
pip install -r requirements.txt
python api_server.py
pause
