@echo off
echo Starting VulnPy GUI Frontend...
cd /d "%~dp0"
npm install
npm run dev
pause
