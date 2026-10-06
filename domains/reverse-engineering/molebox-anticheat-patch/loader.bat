@echo off
chcp 65001 >nul
REM ============================================
REM compile Loader.exe (x86, windowed, no console)
REM ============================================

call "E:\Program Files\Microsoft Visual Studio\VC\Auxiliary\Build\vcvars32.bat"

cl.exe /MT /O1 /GS- /source-charset:utf-8 /D _WIN32_WINNT=0x0601 /D WINVER=0x0601 Loader.cpp /link /SUBSYSTEM:WINDOWS /OUT:Loader.exe /NXCOMPAT:NO

if exist Loader.obj del Loader.obj

echo.
echo Done: Loader.exe
pause