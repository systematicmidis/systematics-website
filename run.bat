@echo off
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
echo.
echo Starting Systematics Black Midi site...
echo Open http://127.0.0.1:5000
echo Admin: http://127.0.0.1:5000/admin/login
echo.
python app.py
pause
