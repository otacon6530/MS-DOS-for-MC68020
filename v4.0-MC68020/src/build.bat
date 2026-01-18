# build.bat - Build script for MS-DOS-for-MC68020 using vasm
# Usage: Double-click or run from command line

@echo off
setlocal

REM Set VASM path if not in PATH
set VASM=vasmm68k_mot.exe

REM Output directory
set OUTDIR=..\..\bin
if not exist %OUTDIR% mkdir %OUTDIR%

REM Assemble all BIOS ASM files
for %%F in (BIOS\*.ASM) do (
    echo Assembling %%F...
    %VASM% -Fbin -o %OUTDIR%\%%~nF.bin %%F
    if errorlevel 1 exit /b 1
)

echo Build complete.
endlocal
