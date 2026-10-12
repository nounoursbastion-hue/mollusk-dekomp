@echo off
chcp 65001 >nul
setlocal
if defined MOLLUSK_PY goto custom
if exist "%~dp0.venv\Scripts\python.exe" (
 set "MOLLUSK_PY=%~dp0.venv\Scripts\python.exe"
 goto custom
)
py -3 -c "import sys,tkinter; assert sys.version_info >= (3,12)" >nul 2>&1
if not errorlevel 1 (
 py -3 -X utf8 "%~dp0mollusk_dekomp.py" %*
 goto done
)
python -c "import sys,tkinter; assert sys.version_info >= (3,12)" >nul 2>&1
if not errorlevel 1 (
 python -X utf8 "%~dp0mollusk_dekomp.py" %*
 goto done
)
echo Python 3.12+ with Tk is required. Read README_EN.md.
pause
exit /b 1
:custom
"%MOLLUSK_PY%" -X utf8 "%~dp0mollusk_dekomp.py" %*
:done
if errorlevel 1 pause
