@echo off
REM Thin wrapper so the build can be run from cmd.exe / double-click.
REM Forwards any arguments straight to build.ps1 (e.g. build.cmd -SkipZip).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
exit /b %ERRORLEVEL%
