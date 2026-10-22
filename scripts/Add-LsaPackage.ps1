<#
Loads a security package into the running LSASS with AddSecurityPackage, without touching the
"Security Packages" registry value, so it is gone after the next reboot.

Run it elevated, on a test machine. The DLL is copied to System32 under a new name each time: LSA
remembers a package path until reboot and would not load the same path twice.

  .\Add-LsaPackage.ps1 ..\bin\x64\Release\LsaIfDump.dll
  Get-Content C:\Windows\Temp\LsaIfDump.txt
#>
param([Parameter(Mandatory)][string]$Path)

$ppl = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
if ($ppl) { Write-Warning "LSA protection is on (RunAsPPL=$ppl): LSASS will refuse an unsigned DLL." }

Add-Type -Namespace LsaInterface -Name Sspi -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct SECURITY_PACKAGE_OPTIONS { public uint Size, Type, Flags, SignatureSize; public IntPtr Signature; }
[DllImport("sspicli.dll", CharSet = CharSet.Unicode)] public static extern int AddSecurityPackageW(string name, ref SECURITY_PACKAGE_OPTIONS options);
'@

$name = [IO.Path]::GetFileNameWithoutExtension($Path)
$copy = Join-Path $env:SystemRoot "System32\$name-$([guid]::NewGuid().ToString('N').Substring(0, 8)).dll"
[IO.File]::Copy((Resolve-Path $Path).Path, $copy)

$options = New-Object LsaInterface.Sspi+SECURITY_PACKAGE_OPTIONS
$options.Size = [Runtime.InteropServices.Marshal]::SizeOf($options)
$status = [LsaInterface.Sspi]::AddSecurityPackageW($copy, [ref]$options)
"AddSecurityPackage($copy) = 0x{0:x8}" -f $status
