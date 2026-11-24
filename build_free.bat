@echo off
setlocal enabledelayedexpansion
title CubScanner Free - Build

echo.
echo  ============================================================
echo    CubScanner Free - Full Build
echo  ============================================================
echo.

echo [1/4] Checking Python...
python --version >nul 2>&1
if errorlevel 1 goto :error_python
echo        Python OK.

echo.
echo [2/4] Installing dependencies...
python -m pip install --quiet scapy psutil pyinstaller
if errorlevel 1 goto :error_pip
echo        Dependencies OK.

echo.
echo [3/4] Preparing Npcap bundle...
if exist "npcap-1.79.exe" (
    echo        Npcap cached.
) else (
    echo        Downloading Npcap...
    powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.79.exe' -OutFile 'npcap-1.79.exe' -UseBasicParsing } catch { exit 1 }"
)

echo.
echo [4/4] Compiling CubScannerFree.exe...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
pyinstaller cubscanner_free.spec --clean --noconfirm
if errorlevel 1 goto :error_pyinstaller
if not exist "dist\CubScannerFree.exe" goto :error_pyinstaller
echo        Portable: dist\CubScannerFree.exe

echo.
echo Compiling installer with Inno Setup...
set ISCC=
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set ISCC=C:\Program Files\Inno Setup 6\ISCC.exe
if exist "C:\Program Files (x86)\Inno Setup 7\ISCC.exe" set ISCC=C:\Program Files (x86)\Inno Setup 7\ISCC.exe
if exist "C:\Program Files\Inno Setup 7\ISCC.exe" set ISCC=C:\Program Files\Inno Setup 7\ISCC.exe

if "!ISCC!"=="" goto :error_inno
"!ISCC!" installer.iss
if not exist "dist\CubScannerFree_Setup.exe" goto :error_inno

echo.
echo  ============================================================
echo    BUILD COMPLETE
echo  ============================================================
echo    Portable:  dist\CubScannerFree.exe
echo    Installer: dist\CubScannerFree_Setup.exe
echo.
pause
exit /b 0

:error_python
echo [ERROR] Python not found.
pause & exit /b 1

:error_pip
echo [ERROR] pip failed.
pause & exit /b 1

:error_pyinstaller
echo [ERROR] PyInstaller failed.
pause & exit /b 1

:error_inno
echo [ERROR] Inno Setup ISCC.exe not found.
pause & exit /b 1