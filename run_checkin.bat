@echo off
chcp 65001 >nul
title AnyRouter 自动签到

cd /d "%~dp0"

set LOG_DIR=logs
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set DATETIME=%%I
set TIMESTAMP=%DATETIME:~0,4%-%DATETIME:~4,2%-%DATETIME:~6,2%_%DATETIME:~8,2%-%DATETIME:~10,2%-%DATETIME:~12,2%
set LOG_FILE=%LOG_DIR%\checkin_%TIMESTAMP%.log

echo ============================================
echo  AnyRouter 自动签到
echo  时间: %DATE% %TIME%
echo  日志: %LOG_FILE%
echo ============================================
echo.

powershell -Command "uv run checkin.py 2>&1 | Tee-Object -FilePath '%LOG_FILE%'"

echo.
echo ============================================
if %ERRORLEVEL% EQU 0 (
    echo  签到完成！
) else (
    echo  签到异常（部分账号可能失败）
)
echo  日志已保存: %LOG_FILE%
echo ============================================

if not "%1"=="--no-pause" (
    echo.
    pause
)
