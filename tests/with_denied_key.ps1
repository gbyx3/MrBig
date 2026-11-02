# Disposable test key only. Keep a parent handle so its ACL can always be restored.
param(
    [Parameter(Mandatory)][string]$KeyName,
    [Parameter(Mandatory)][string]$Probe
)
$ErrorActionPreference = 'Stop'
$ProbeArguments = [string[]]([Console]::ReadLine() | ConvertFrom-Json)
if (-not $KeyName.StartsWith('MrBig-test-')) { throw 'Refusing a non-test key' }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class TestCngAcl {
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptGetProperty(SafeNCryptKeyHandle key, string name,
        byte[] output, int length, out int used, int flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
    public static extern int NCryptSetProperty(SafeNCryptKeyHandle key, string name,
        byte[] input, int length, int flags);
}
'@
$key = [Security.Cryptography.CngKey]::Open($KeyName,
    [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,
    [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
$original = $null
$changed = $false
$result = 2
try {
    $size = 0
    $status = [TestCngAcl]::NCryptGetProperty($key.Handle, 'Security Descr', $null, 0, [ref]$size, 4)
    if ($status -ne 0) { throw 'Cannot size disposable key ACL' }
    $original = [byte[]]::new($size)
    if ([TestCngAcl]::NCryptGetProperty($key.Handle, 'Security Descr', $original,
            $original.Length, [ref]$size, 4) -ne 0) { throw 'Cannot preserve disposable key ACL' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
        "D:P(D;;GR;;;$sid)(A;;GA;;;SY)(A;;GA;;;BA)")
    $bytes = [byte[]]::new($descriptor.BinaryLength)
    $descriptor.GetBinaryForm($bytes, 0)
    if ([TestCngAcl]::NCryptSetProperty($key.Handle, 'Security Descr', $bytes,
            $bytes.Length, 4) -ne 0) { throw 'Cannot deny disposable key use' }
    $changed = $true
    & $Probe @ProbeArguments
    $result = $LASTEXITCODE
} finally {
    if ($changed -and [TestCngAcl]::NCryptSetProperty($key.Handle, 'Security Descr',
            $original, $original.Length, 4) -ne 0) { throw 'Disposable key ACL restore failed' }
    $key.Dispose()
}
exit $result
