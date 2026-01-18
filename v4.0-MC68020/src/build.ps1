# build.ps1 - PowerShell build script for MS-DOS-for-MC68020 using vasm
# Usage: Run in PowerShell from src directory

$vasm = "vasmm68k_mot.exe"
$outdir = "..\..\bin"
$biosDir = "BIOS"

if (!(Test-Path $outdir)) {
    New-Item -ItemType Directory -Path $outdir | Out-Null
}

Get-ChildItem -Path $biosDir -Filter *.ASM | ForEach-Object {
    $src = $_.FullName
    $out = Join-Path $outdir ("$($_.BaseName).bin")
    Write-Host "Assembling $src ..."
    & $vasm -Fbin -o $out $src
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error assembling $src" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Build complete." -ForegroundColor Green
