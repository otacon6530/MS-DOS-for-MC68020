# run_mame.ps1
Set-Location "g:\Users\onlin\Downloads\"

$MameExe = "mame.exe"
$RomName = "area51mx"  # Change to your ROM name
$ScriptPath = "g:\Dev\msdos\MS-DOS-for-MC68020\area51-original\cpu_stepper.lua"

# Example arguments
$args = @(
    "-debug",
    "-window",
    "-script", $ScriptPath,
    $RomName
)

# Run MAME
Start-Process -FilePath $MameExe -ArgumentList $args