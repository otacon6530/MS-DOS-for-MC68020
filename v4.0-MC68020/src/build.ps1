# build.ps1 - PowerShell build script for MS-DOS-for-MC68020 using vasm
# Usage: Run in PowerShell from src directory

$vasm = "vasmm68k_STD.exe"
$outdir = "..\..\bin"
$biosDir = "BIOS"

if (!(Test-Path $outdir)) {
    New-Item -ItemType Directory -Path $outdir | Out-Null
}




# Assemble BIOS ASM files in original MSBIO.LNK order
$biosOrder = @(
    'INIT.ASM'
)
$binFiles = @()
foreach ($asm in $biosOrder) {
    $src = Join-Path $biosDir $asm
    if (!(Test-Path $src)) {
        Write-Host "Warning: $src not found, skipping." -ForegroundColor Yellow
        continue
    }
    $out = Join-Path $outdir ("$([System.IO.Path]::GetFileNameWithoutExtension($asm)).bin")
    Write-Host "Assembling $src ..."
    & $vasm -Fbin -o $out $src
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error assembling $src" -ForegroundColor Red
        exit 1
    }
    $binFiles += $out
}

# Concatenate all .bin files into one buffer (in memory)
[byte[]]$allBytes = @()
foreach ($file in $binFiles) {
    $allBytes += [System.IO.File]::ReadAllBytes($file)
}


# Split into 4 interleaved ROMs: h, p, m, k (using List[byte] for safe appending)
$romNames = @('2.0_68020_max-a51_kit_3h.3h','2.0_68020_max-a51_kit_3p.3p','2.0_68020_max-a51_kit_3m.3m','2.0_68020_max-a51_kit_3k.3k')
$romFiles = $romNames | ForEach-Object { Join-Path $outdir ("$_") }
$romData = @()
for ($i = 0; $i -lt 4; $i++) {
    $romData += ,([System.Collections.Generic.List[byte]]::new())
}
for ($i = 0; $i -lt $allBytes.Length; $i++) {
    $romData[$i % 4].Add($allBytes[$i])
}
Write-Host "Total bytes: $($allBytes.Length)" -ForegroundColor Yellow
for ($i = 0; $i -lt 4; $i++) {
    Write-Host "ROM $($romNames[$i]) length: $($romData[$i].Count)" -ForegroundColor Yellow
}

# Patch: 0x418 offset, value 0x4E754E75 (big endian)
$patchOffset = 0x418
$patchValue = 0x4E754E75
$patchBytes = [BitConverter]::GetBytes([System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($patchValue),0))
if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($patchBytes) }

$fileOffset = [int]($patchOffset / 4)

# Pad each ROM to exactly 512 KB (524288 bytes) if needed
$romSize = 512KB
for ($i = 0; $i -lt 4; $i++) {
    while ($romData[$i].Count -lt $romSize) {
        $romData[$i].Add(0)
    }
    $romData[$i][$fileOffset] = $patchBytes[$i]
    [System.IO.File]::WriteAllBytes($romFiles[$i], $romData[$i].ToArray())
    Write-Host "Wrote $($romFiles[$i]) ($($romData[$i].Count) bytes), patched at $fileOffset with $($patchBytes[$i].ToString("X2"))"
}

Write-Host "Build complete. Created 4 split and patched ROMs: $($romFiles -join ', ')" -ForegroundColor Green
