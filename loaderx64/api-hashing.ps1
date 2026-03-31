$APIsToHash = @(
    "CloseHandle",
    "CreateThread",
    "ExitProcess",
    "FlushInstructionCache",
    "GetExitCodeThread",
    "IsDebuggerPresent",
    "RtlMoveMemory",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "WaitForSingleObject"
)


$mask32 = [long]([uint32]::MaxValue)

foreach ($api in $APIsToHash) {
    $hash = [long]0x35
    $i = 0
    foreach ($ch in $api.ToCharArray()) {
        $c = [long][int]$ch
        $hash = ($hash * [long]0xAB10F29F + $c) -band $mask32
        $i++
        Write-Host ("Iteration {0} : {1} : 0x{2:X2} : 0x{3:X8}" -f $i, $ch, $c, $hash)
    }
    Write-Host ("#define HASH_{0,-25} 0x{1:X8}" -f $api.ToUpper(), $hash)
    Write-Host ""
}
