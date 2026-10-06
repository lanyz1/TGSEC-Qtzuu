@echo off
chcp 65001 >nul
REM ============================================
REM build patch.dll (x86, low Win version compat)
REM ============================================

REM setup VS 2026 x86 env
call "E:\Program Files\Microsoft Visual Studio\VC\Auxiliary\Build\vcvars32.bat"

REM compile (/source-charset:utf-8 for Chinese comments)
cl.exe /MT /O1 /GS- /source-charset:utf-8 /D _WIN32_WINNT=0x0601 /D WINVER=0x0601 /LD AntiCheatPatch.c /link /SUBSYSTEM:WINDOWS /OUT:patch.dll /NXCOMPAT:NO /SAFESEH:NO

REM clean up intermediate files
if exist AntiCheatPatch.obj del AntiCheatPatch.obj
if exist patch.lib del patch.lib
if exist patch.exp del patch.exp

echo.
echo Done: patch.dll
pause