@echo off
cd /d "%~dp0"
echo Applying pending migrations to the local D1 database...
uv run pywrangler d1 migrations apply systematics-black-midi-db --local
echo Starting the local Worker at http://localhost:8787 ...
uv run pywrangler dev
pause
