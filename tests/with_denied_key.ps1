# Disposable Microsoft Software KSP machine key only. Never read its key bytes.
param(
    [Parameter(Mandatory)][string]$KeyName,
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$ProbeArgumentsFile
)
$ErrorActionPreference = 'Stop'
if (-not $KeyName.StartsWith('MrBig-test-')) { throw 'Refusing a non-test key' }
$ProbeArguments = [string[]](Get-Content -LiteralPath $ProbeArgumentsFile -Raw | ConvertFrom-Json)
$key = [Security.Cryptography.CngKey]::Open($KeyName,
    [Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider,
    [Security.Cryptography.CngKeyOpenOptions]::MachineKey)
try {
    if (-not $key.IsMachineKey) { throw 'Expected a disposable machine key' }
    $file = [IO.FileInfo]::new((Join-Path $env:ProgramData ('Microsoft\Crypto\Keys\' + $key.UniqueName)))
} finally { $key.Dispose() }
if (-not $file.Exists) { throw 'Disposable Software KSP key file missing' }
$section = [Security.AccessControl.AccessControlSections]::Access
$original = [IO.FileSystemAclExtensions]::GetAccessControl($file).GetSecurityDescriptorSddlForm($section)
$denied = [IO.FileSystemAclExtensions]::GetAccessControl($file)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$denied.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, [Security.AccessControl.FileSystemRights]::Read,
    [Security.AccessControl.AccessControlType]::Deny))
$changed = $false
$result = 2
try {
    # Preserve the existing owner and inheritance/protection state; add one denial.
    [IO.FileSystemAclExtensions]::SetAccessControl($file, $denied)
    $changed = $true
    [Console]::Error.WriteLine('Test ACL fixture: denial applied; starting probe')
    & $Probe @ProbeArguments
    $result = $LASTEXITCODE
} finally {
    if ($changed) {
        $restore = [Security.AccessControl.FileSecurity]::new()
        $restore.SetSecurityDescriptorSddlForm($original, $section)
        [IO.FileSystemAclExtensions]::SetAccessControl($file, $restore)
        $actual = [IO.FileSystemAclExtensions]::GetAccessControl($file).GetSecurityDescriptorSddlForm($section)
        if ($actual -ne $original) { throw 'Disposable key ACL restore/readback mismatch' }
        [Console]::Error.WriteLine('Test ACL fixture: original ACL restored and read back')
    }
}
exit $result
