@echo off
rem Terminal UI. See README.md.
rem ASCII-only: cmd.exe reads .bat in the console codepage, not UTF-8.
cd /d "%~dp0"

rem Locate python via `where` and invoke it by FULL PATH.
rem Bare "python" fails when PATH is very long (Windows breaks executable
rem resolution past ~2047 chars) -- common on jump boxes with many tools.
rem `where` tolerates long PATH even when direct invocation does not.
set "PYEXE="
for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
if not defined PYEXE (
  echo Python not found. Install Python 3.8+ and check "Add Python to PATH".
  pause
  exit /b 1
)

"%PYEXE%" -m forge %*
if errorlevel 1 pause
