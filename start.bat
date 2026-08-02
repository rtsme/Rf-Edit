@echo off
setlocal enabledelayedexpansion

rem Launch the RF server data workbench.
rem
rem cd to this file's own folder first: the tool imports rf_repo / rf_dat /
rem schemas_extra as plain modules, so it only works with this folder as the
rem working directory. Double-clicking a .bat starts in the folder it lives in,
rem but running it from a shortcut or another shell does not, hence /d "%~dp0".
cd /d "%~dp0"

rem Resolve python.exe off PATH rather than calling it directly, so a missing
rem install gives a readable message instead of "'python' is not recognized".
rem There are several Pythons on this machine; PATH order picks 3.12, which is
rem the one this tool was built and tested against.
set "PYEXE="
for %%P in (python.exe) do if not defined PYEXE set "PYEXE=%%~$PATH:P"

if not defined PYEXE (
    echo.
    echo Could not find python.exe on PATH.
    echo.
    echo Install Python 3, or set PYEXE below to a full path, e.g.
    echo     set "PYEXE=C:\Users\Me\AppData\Local\Programs\Python\Python312\python.exe"
    echo.
    pause
    exit /b 1
)

"%PYEXE%" rf_workbench.py
set "RC=!errorlevel!"

rem Only hold the window open when something went wrong -- on a clean exit the
rem console just closes with the app.
if not "!RC!"=="0" (
    echo.
    echo The workbench exited with code !RC!. The error is above.
    echo.
    pause
)
exit /b !RC!
