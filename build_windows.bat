@echo off
setlocal
cd /d "%~dp0"

REM Builds ONE single file: dist\ProxyToolkit.exe  (no extra folders needed)
REM Usage:  build_windows.bat            -> NO console window (default)
REM         build_windows.bat console    -> with console window (to see errors)

set WIN_FLAG=--windowed
if /i "%~1"=="console" set WIN_FLAG=

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo Install Python 3.12 from python.org and tick "Add python.exe to PATH".
    goto :fail
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating virtualenv...
    python -m venv .venv || goto :fail
)

echo [2/3] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip || goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller pillow || goto :fail

set APPVER=unknown
for /f "tokens=2 delims==" %%v in ('findstr /b "__version__" core\version.py') do set APPVER=%%v
set APPVER=%APPVER:"=%
set APPVER=%APPVER: =%

echo [3/3] Building single-file ProxyToolkit.exe (version %APPVER%) ...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile ^
    --name ProxyToolkit ^
    --icon "assets\icons\256.png" ^
    --add-data "assets;assets" ^
    --collect-submodules aiohttp_socks ^
    --collect-submodules python_socks ^
    %WIN_FLAG% ^
    main.py || goto :fail

echo.
echo DONE.  Proxy Toolkit %APPVER%  -  your file:  dist\ProxyToolkit.exe
echo Copy that single .exe anywhere and run it.
pause
exit /b 0

:fail
echo.
echo [FAILED] See the message above.
pause
exit /b 1
