@echo off
setlocal EnableDelayedExpansion

REM ============================================================
REM  signtool — Demo Script (Windows)
REM  Demonstrates the full signing workflow
REM ============================================================

echo.
echo ============================================================
echo   signtool Demo — Windows
echo ============================================================
echo.

REM --- Setup: make sure we are in the signtool project root ---
cd /d "%~dp0"

REM --- Install dependencies (if needed) -----------------------
echo [1/7] Installing dependencies...
pip install -e . --quiet
if errorlevel 1 (
    echo ERROR: pip install failed.
    exit /b 1
)
echo        Done.
echo.

REM --- Create a demo workspace --------------------------------
set DEMO_DIR=demo_workspace
if exist "%DEMO_DIR%" rmdir /s /q "%DEMO_DIR%"
mkdir "%DEMO_DIR%"
mkdir "%DEMO_DIR%\keys"
mkdir "%DEMO_DIR%\docs"
mkdir "%DEMO_DIR%\sigs"

REM --- Create sample files ------------------------------------
echo Hello, signtool! This is document 1. > "%DEMO_DIR%\docs\document1.txt"
echo Another document for signing demo.   > "%DEMO_DIR%\docs\document2.txt"
echo Contract version 1.0 — CONFIDENTIAL  > "%DEMO_DIR%\docs\contract.txt"

echo [2/7] Sample files created in %DEMO_DIR%\docs\
echo.

REM --- Step 1: Generate a default 2048-bit key pair ----------
echo [3/7] Generating RSA-2048 key pair...
signtool keygen --bits 2048 --output-dir "%DEMO_DIR%\keys" --name mykey
if errorlevel 1 ( echo ERROR in keygen & exit /b 1 )
echo.

REM --- Step 2: Generate a 4096-bit key pair ------------------
echo [4/7] Generating RSA-4096 key pair (stronger)...
signtool keygen --bits 4096 --output-dir "%DEMO_DIR%\keys" --name strongkey
if errorlevel 1 ( echo ERROR in keygen (4096) & exit /b 1 )
echo.

REM --- Step 3: Sign a single file ----------------------------
echo [5/7] Signing document1.txt...
signtool sign --key "%DEMO_DIR%\keys\mykey_private.pem" ^
              --file "%DEMO_DIR%\docs\document1.txt" ^
              --output-dir "%DEMO_DIR%\sigs"
if errorlevel 1 ( echo ERROR in sign & exit /b 1 )
echo.

REM --- Step 4: Sign multiple files ---------------------------
echo [5b/7] Signing all .txt files in docs\...
signtool sign --key "%DEMO_DIR%\keys\mykey_private.pem" ^
              --file "%DEMO_DIR%\docs\document2.txt" ^
              --file "%DEMO_DIR%\docs\contract.txt" ^
              --output-dir "%DEMO_DIR%\sigs"
if errorlevel 1 ( echo ERROR in batch sign & exit /b 1 )
echo.

REM --- Step 5: Inspect a .sig file ---------------------------
echo [6/7] Inspecting document1.txt.sig...
signtool info "%DEMO_DIR%\sigs\document1.txt.sig"
echo.

REM --- Step 6: Verify valid signature ------------------------
echo [7/7] Verifying document1.txt (should be VALID)...
signtool verify --key "%DEMO_DIR%\keys\mykey_public.pem" ^
                --file "%DEMO_DIR%\docs\document1.txt" ^
                --sig  "%DEMO_DIR%\sigs\document1.txt.sig"
if errorlevel 1 (
    echo UNEXPECTED: verification failed for an unmodified file!
) else (
    echo    Verification passed as expected.
)
echo.

REM --- Step 7: Tamper with a file and verify (should FAIL) ---
echo [BONUS] Tampering with document1.txt to demonstrate tamper detection...
echo TAMPERED CONTENT >> "%DEMO_DIR%\docs\document1.txt"
signtool verify --key "%DEMO_DIR%\keys\mykey_public.pem" ^
                --file "%DEMO_DIR%\docs\document1.txt" ^
                --sig  "%DEMO_DIR%\sigs\document1.txt.sig"
if errorlevel 1 (
    echo    Tamper detected as expected — signature is INVALID.
) else (
    echo UNEXPECTED: tampered file passed verification!
)
echo.

echo ============================================================
echo   Demo complete! Files are in: %DEMO_DIR%\
echo ============================================================
echo.
endlocal
