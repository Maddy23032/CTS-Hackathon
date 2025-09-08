@echo off
echo Starting VulnScan GUI Frontend...
cd /d "%~dp0"
npm install
npm run dev
pause
