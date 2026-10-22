# LsaInterface

`lsass.exe` exports four functions that are not documented anywhere:

```
LsaGetInterface
LsaImpersonateKsecCaller
LsaRegisterExtension
LsaRegisterInterface
```

Two of them, `LsaRegisterInterface` and `LsaGetInterface`, form a small registry of function tables
that the DLLs loaded in LSASS use to talk to each other without importing each other. netlogon and
DPAPI get a set of lsasrv helpers through it, lsasrv gets DPAPI, and pku2u gets the "identity provider
extension" it needs to accept a certificate. I ran into it while looking at how PKU2U works and wanted
to know what else was in there.

This repository contains what I found:

- `include/LsaInterface.h`: prototypes of the four exports, the interface ids, and the layout of each
  table with the Microsoft function names (they all come from the public symbols).
- `lib/lsass.def`: builds `lsass.lib`, the import library you need to call these functions. The
  solution generates it for x64 and ARM64.
- `samples/LsaIfDump`: a minimal security package. Once loaded into LSASS it writes every registered
  interface and every entry of each table to `C:\Windows\Temp\LsaIfDump.txt`.
- `scripts/Add-LsaPackage.ps1`: loads a package into the running LSASS with `AddSecurityPackage`.
- `docs/interfaces.md`: the details, table by table, and how they changed since Windows Server 2016.

## What is registered

| Id | Registered by | Table | Used by |
|---:|---|---|---|
| 0 | lsass.exe | `gLsapRmFunctions`: `LsapCallRm` | lsasrv (logon sessions in the kernel) |
| 1 | lsass.exe | `gLsapCallbackFunctions`: client callback, ksecdd IOCTL, System pid | lsasrv |
| 1001 | lsasrv.dll | `LsapLsasrvIfTable`: 18 entries | netlogon, dpapisrv |
| 1002 | dpapisrv.dll | `g_pDPAPIIfTable`: 9 entries | lsasrv (`LsaICryptProtectData`...) |
| 1003 | lsasrv.dll | `LsapIdProvExtIfTable`: 3 entries | pku2u |

Ids 1001 and 1002 are not hardcoded in lsass. They are declared in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\1001
    Extension = lsasrv.dll
    Name      = LsaLsasrvInterface
HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\1002
    Extension = dpapisrv.dll
    Name      = LsaDpapiInterface
```

lsass loads the DLL named there and asks its `QueryLsaInterface` export for the table. Id 1003 is
registered by lsasrv at run time, and only when the machine is not a domain controller, so on a DC
`LsaGetInterface(1003)` fails with `STATUS_NOT_FOUND` and PKU2U has nothing to work with.

To check that the list is complete, the sample does not trust the ids above. It finds the list head
(`gLsapIfList`) from the code of `LsaGetInterface` and walks it, then asks `LsaGetInterface` for every
id from 0 to 0xFFFF. On Windows 11 24H2 both give the same five ids, and nothing else.

## Building

Open `LsaInterface.sln` with Visual Studio 2022 or later and build. The projects use the v143 toolset;
Visual Studio retargets them if you have a newer one.

If you only want the import library:

```
lib /def:lib\lsass.def /machine:x64 /out:lsass.lib
```

## Using it

Only code that runs inside lsass.exe can call these functions: an authentication package, a security
package, or an LSA extension. Include the header after the usual LSA headers and link with `lsass.lib`:

```c
#include "LsaInterface.h"

PLSA_IDPROV_EXT_INTERFACE idprov;
if (NT_SUCCESS(LsaGetInterface(LSA_INTERFACE_IDPROV_EXT, (PVOID*)&idprov)))
{
    BOOLEAN pac = idprov->ShouldBuildClientPac(&LSA_IDPROV_CONTAINER_CERT_ISSUER);
}
```

`LsaRegisterInterface` also works for your own ids, which is a simple way for two packages of the same
product to share a table. There is no way to unregister an id. It stays until LSASS stops, so the
table must too. The sample shows what happens if you ignore this: load it twice and the second copy
gets `STATUS_ALREADY_REGISTERED`, while the registered table still points into the first DLL.

## Running the sample

On a test machine, never on one you care about:

1. Turn LSA protection off (`RunAsPPL` = 0 under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`) and
   reboot. LSASS refuses unsigned DLLs otherwise.
2. From an elevated PowerShell:

   ```
   .\scripts\Add-LsaPackage.ps1 .\bin\x64\Release\LsaIfDump.dll
   Get-Content C:\Windows\Temp\LsaIfDump.txt
   ```

The package stays loaded until the next reboot. Nothing is written to the registry.

Here is the output on Windows 11 24H2 (26100.1742). The addresses are module + RVA, and you can resolve
them with the public symbols of that build:

```
0 rm: table lsass.exe+0xd000
  [ 0] lsass.exe+0x2660
1 callback: table lsass.exe+0xd008
  [ 0] lsass.exe+0x55f0
  [ 1] lsass.exe+0x27c0
  [ 2] lsass.exe+0x55d0
1001 lsasrv: table lsasrv.dll+0x18d150
  [ 0] lsasrv.dll+0x8ded0
  ...
1003 idprov-ext: table lsasrv.dll+0x18dd08
  [ 0] lsasrv.dll+0x1215f0
  [ 1] lsasrv.dll+0x121250
  [ 2] lsasrv.dll+0x122c10
callback GetSystemInfo: 0x00000000, 4
idprov-ext ShouldBuildClientPac: local 0, container 1

registry: gLsapIfList at lsass.exe+0xd740
  id 0 (0x0): table lsass.exe+0xd000, owner -
  id 1 (0x1): table lsass.exe+0xd008, owner -
  id 1003 (0x3eb): table lsasrv.dll+0x18dd08, owner -
  id 1001 (0x3e9): table lsasrv.dll+0x18d150, owner lsasrv.dll+0xd3e30
  id 1002 (0x3ea): table dpapisrv.dll+0x47000, owner dpapisrv.dll+0x230e0
scan 0-0xFFFF: 0 1 1001 1002 1003
```

## How this was found

The function and table names come from Microsoft's public symbols. Most prototypes too: lsasrv and
dpapisrv are partly C++, and a decorated name carries the full signature. Seven entries of interface
1001 are the same functions LSA puts in `LSA_SECPKG_FUNCTION_TABLE`, so the `ntsecpkg.h` typedefs
apply. The rest are C functions with no signature in the symbols. For those, I read the code and its
callers in netlogon, dpapisrv, lsasrv and pku2u. Every prototype in the header says which of the
three it is. For interface 1003, I also recorded LSASS with Time Travel Debugging during a PKU2U logon
to see the real arguments. The lsasrv tables (1001 and 1003) were compared on
Windows Server 2016, 2019, 2022 and 2025 and on Windows 11 24H2 and 25H2. The sample itself ran on Windows 11 24H2.

## Caveats

None of this is documented or supported by Microsoft. It can change with any update. The ids and
table layouts have been stable since 2016, but that is an observation, not a promise. Do not ship
anything that depends on it without checking the build you run on. The list walk in the sample
recognizes a specific instruction sequence and only exists for x64.

More context, and how PKU2U uses interface 1003:
https://www.mysmartlogon.com/service/lsagetinterface-lsass-interface-registry/

## License

MIT, see [LICENSE](LICENSE).
