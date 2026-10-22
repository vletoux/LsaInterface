# The interfaces, one by one

Names in the tables are Microsoft's, from the public symbols. The prototypes are in
`include/LsaInterface.h`, and each one says where it comes from:

- **symbols**: the function is C++ and its decorated name in the public PDB gives the full signature,
  for example `long LsapGetCredentialKey(struct _LUID *, struct _GUID *, struct _CREDENTIAL_KEY **)`.
  The types are exact. The parameter names are mine.
- **sdk**: the same function is in the `LSA_SECPKG_FUNCTION_TABLE` that LSA gives to every security
  package (`lsasrv!LsapSecpkgFunctionTable`), so the `ntsecpkg.h` typedef applies.
- **reversed**: a C function, whose symbol has no signature. I read it from its code and its callers.

## The registry itself

`lsass!LsapRegisterInterface` allocates one 0x38-byte entry per id and links it into `gLsapIfList`,
under the resource `gLsaIfLock`:

| Offset | Field |
|---|---|
| 0x00 | `LIST_ENTRY` in `gLsapIfList` |
| 0x10 | id |
| 0x18 | owner: the extension record when the id came from `LsaExtensionConfig`, else NULL |
| 0x20 | `LIST_ENTRY` in the owner's own list |
| 0x30 | the table |

Registering an id twice returns `STATUS_ALREADY_REGISTERED` (0xC0000718). Nothing removes an entry.
`LsaGetInterface` returns `STATUS_NOT_FOUND` (0xC0000225) for an unknown id, and
`STATUS_INTERNAL_ERROR` if it is called before lsass has set the registry up.

`LsaRegisterExtension(Type, Table)` is a different mechanism. It stores one of lsasrv's own dispatch
tables in lsass.exe (0 `gLsapRmExtension`, 2 `gLsapSspiExtension`, 3 `gLsapLookupExtension`). It is
how lsass, which is very small, forwards its RPC and reference monitor work to lsasrv.

## How the extensions start

`LsaExtensionConfig` lists the extensions (lsasrv.dll, then dpapisrv.dll). For each one lsass:

1. loads the DLL, and for every id declared under `LsaExtensionConfig\Interfaces` with that DLL, calls
   its `QueryLsaInterface(enum _LSA_INTERFACE_TYPE, void **)` export and registers the result;
2. calls `InitializeLsaExtension(enum _LSA_EXTENSION_INIT_STAGE)` on every extension, stage by stage:

| Stage | lsasrv | dpapisrv |
|---|---|---|
| 0 | `LsapLsaExtensionLoad`: takes interfaces 0 and 1 | nothing |
| 1 | `LsapLsaExtensionLoadComplete`: takes 1002 into `LsapDpapiIfTable` | takes 1001, then `DPAPIInitialize` |
| 2 | `LsapLsaExtensionStart` | nothing |

That is all there is to "initializing DPAPI". dpapisrv and lsasrv each get the other's table at
stage 1, and lsass only puts them in touch. No security package is involved. pku2u, for instance,
never calls DPAPI. When it reads its client certificate with `CrediReadDomainCredentials` (from the
`LSA_SECPKG_FUNCTION_TABLE`), it is the credential manager in lsasrv that uses DPAPI, through 1002,
when it reads or writes its credential files (`CredpReadCredentialFromFile`,
`CredpWriteCredentialToFile`). In a TTD trace of a PKU2U logon, both reads were served from the
credential manager's cache, and DPAPI was not called at all.

## 0: reference monitor (lsass.exe, `gLsapRmFunctions`)

| # | Function | Source |
|---|---|---|
| 0 | `LsapCallRm(Command, Params, ParamsLength, Reply, ReplyLength)` | reversed |

The command goes to the kernel Security Reference Monitor. lsasrv sends 2 (create a logon session),
3 (delete it), 4 (session information changed), and 8 and 9 (logon session leak check).

## 1: callbacks (lsass.exe, `gLsapCallbackFunctions`)

| # | Function | Source |
|---|---|---|
| 0 | `LsapIfClientCallback`: the `ClientCallback` of `LSA_SECPKG_FUNCTION_TABLE`, with the client id in front. If the client is in kernel mode (bit 24), the call goes to ksecdd through IOCTL 0x39003C. Otherwise it goes to `sspisrv!SspiSrvClientCallback`. | reversed |
| 1 | `LsapCallKsec`: `NtDeviceIoControlFile` on lsass's handle to `\Device\KsecDD`. lsasrv uses it to allocate, copy and free memory in kernel-mode clients (IOCTLs 0x390028, 0x390030, 0x39004C, 0x390054). | reversed |
| 2 | `LsapGetSystemInfo`: writes one ULONG, the id of the System process (4). | reversed |

## 1001: lsasrv for its extensions (`LsapLsasrvIfTable`, "LsaLsasrvInterface")

Same 18 entries on every build looked at (14393, 17763, 20348, 26100, 26200). Only the names of
entries 3 and 16 change, because the linker folds identical functions together. Seven entries are
the very functions LSA puts in the security package table.

| # | Function | Source |
|---|---|---|
| 0 | `LsaProtectMemory` | sdk (`LsaProtectMemory`) |
| 1 | `LsaUnprotectMemory` | sdk (`LsaUnprotectMemory`) |
| 2 | `LsaIFreeReturnBuffer` | sdk (`FreeReturnBuffer`) |
| 3 | `LsapFreeLsaHeap` / `LsapFree` / `LsapSubProv_FreeRoutine` | sdk (`FreeLsaHeap`) |
| 4 | `LsaICallPackage` | sdk (`CallPackage`) |
| 5 | `LsaIfGetAuthDataForUser` | symbols, identical to `PLSA_GET_AUTH_DATA_FOR_USER` |
| 6 | `LsaConvertAuthDataToToken` | sdk (`ConvertAuthDataToToken`) |
| 7 | `LsaIQueryPackageAttrInLogonSession(LUID *, ULONG *Attributes)` | reversed |
| 8 | `LsaINotifyPasswordChanged`: SID, then the six strings the credential manager and DPAPI are told about, then `Impersonating` | reversed |
| 9 | `LsaINoMoreWin2KDomain(void)`, BOOLEAN | reversed |
| 10 | `LsaIAuditDPAPIEvent`: master key backup and recovery audits | reversed, from the audit parameters it builds |
| 11 | `LsaIQueryInformationPolicyTrusted` | reversed, same as the lsasrv export |
| 12 | `LsaIFree_LSAPR_POLICY_INFORMATION` | reversed, same as the lsasrv export |
| 13 | `LsapGetCredentialKey(LUID *, GUID *, CREDENTIAL_KEY **)` | symbols |
| 14 | `LsapIsDomainUserDPAPI(PSID)`, BOOLEAN | symbols |
| 15 | `LsapDPAPIPasswordChangeForGMSA(PWSTR, PWSTR, UNICODE_STRING, UNICODE_STRING)`, called by netlogon | symbols |
| 16 | `LsapAllocateLsaHeap` / `LsapAllocateULong` | sdk (`AllocateLsaHeap`) |
| 17 | `LsapDecryptDPAPIMasterKey(LUID *, LSAI_DPAPI_KEY_TYPE, PUCHAR, ULONG, PUCHAR, ULONG, PUCHAR *, ULONG *)` | symbols |

## 1002: DPAPI (`g_pDPAPIIfTable` in dpapisrv.dll, "LsaDpapiInterface")

dpapisrv is C++, so all nine signatures are in the symbols.

| # | Function |
|---|---|
| 0 | `BOOLEAN DPAPICryptProtectData(void *, ULONG, UNICODE_STRING *, void *, ULONG, void *, void *, ULONG, void **, ULONG *)` |
| 1 | `BOOLEAN DPAPICryptUnprotectData(void *, ULONG, void *, ULONG, void *, void *, ULONG, UNICODE_STRING *, void **, ULONG *)` |
| 2 | `BOOLEAN DPAPICryptProtectDataEx(...)`: the same plus `(unsigned char *, ULONG)` before the output |
| 3 | `BOOLEAN DPAPICryptUnprotectDataEx(...)`: the same plus `(unsigned char *, ULONG)` |
| 4 | `void DPAPINotifyLogonTerminated(LUID *)` |
| 5 | `long DPAPINotifyCredentialKeyChange(void *, CREDENTIAL_KEY *, CREDENTIAL_KEY *, ULONG)` |
| 6 | `long LsaIfSynchronizeMasterKeys(void *, CREDENTIAL_KEY *, ULONG *, ULONG *)` |
| 7 | `long LsaIfIsDcTargetForRecovery(LUID *, const wchar_t *, int *)` |
| 8 | `ULONG LsaIfGetCurrentCredentialKeyId(void *, GUID *)` |

The crypt entries mirror `CryptProtectData` and `CryptUnprotectData`: data in, description, entropy,
reserved, prompt, flags, data out. The header names the parameters that way. lsasrv's
`LsaICryptProtectData`, `LsaICryptUnprotectData` and their `Ex` versions forward to entries 0 to 3. The
credential manager calls 0 and 1 directly, with flags 0x20000001 and 0x20000041.

## 1003: identity provider extension (`LsapIdProvExtIfTable` in lsasrv.dll)

| # | Function | Since |
|---|---|---|
| 0 | `long LsapGetIdProvCertFromCred(LUID *, GUID *, void *, ULONG, void **)` | WS2016 |
| 1 | `long LsapAcceptPeerCertificate(GUID *, int, const CERT_CONTEXT *, void **)` | WS2016 |
| 2 | `int LsapShouldBuildClientPac(GUID *)` | WS2022 |

`LsapInitIdProvExtension` registers it only if `RtlGetNtProductType` does not return `NtProductLanManNt`.
On a domain controller the id does not exist.

Every call carries the GUID of the identity provider the certificate belongs to. certpoleng has two
built-in providers, and lsasrv handles those itself:

| Provider | `GetIdProvCertFromCred` | `AcceptPeerCertificate`, role 0 | `ShouldBuildClientPac` |
|---|---|---|---|
| `{6D0F37E4-4FAC-4E44-9C07-6B8343FE4953}` Local Cert Issuer | `STATUS_NOT_SUPPORTED` | `LsapGetS4ULogonUserToken(cert, 0x2A, &info)`: S4U logon of the local account the certificate names | FALSE |
| `{E6284137-3900-4B85-97D1-51C9FF2ACEF0}` Container Cert Issuer | `STATUS_NOT_SUPPORTED` | same, with 0x2B | TRUE |

Any other GUID is passed on to the identity provider lsasrv knows under that GUID
(`LsapRefIdProvByGuidEx`), through that provider's own function table. The call is only made if the
provider's table is large enough to contain the function.

What a PKU2U logon looks like from this interface (TTD recording of LSASS, client and server on the
same Windows 11 24H2 machine, local provider):

1. Server side, `pku2u!Pku2uCreatePac` calls `AcceptPeerCertificate(local provider, 0, client
   certificate, &info)`. lsasrv runs `LsapGetS4ULogonUserToken` with 0x2A and returns the logon
   information pku2u turns into a PAC.
2. Client side, `pku2u!Pku2uHandlePeer2PeerAsReply` calls `AcceptPeerCertificate(local provider, 1,
   server certificate, &info)`. For a built-in provider that returns success and nothing else.
3. Client side, `pku2u!Pku2uBuildApRequest` asks `ShouldBuildClientPac(local provider)` and gets FALSE.

`GetIdProvCertFromCred` is not called with the built-in providers. pku2u reads their certificates from
the credential manager itself, and passes what the call returns to `certpoleng!PstAcquirePrivateKey`.

## Related: the two "DummyFunction" slots of the security package table

While matching interface 1001 against `lsasrv!LsapSecpkgFunctionTable`, two slots stood out. They are
named `DummyFunction6` and `DummyFunction7` in `ntsecpkg.h`, but lsasrv fills them:

| Slot | lsasrv function |
|---|---|
| `DummyFunction6` | `long LsapRegisterIdentityProvider(GUID *, void *, ULONG, LSA_IDENTITY_PROVIDER_FUNCTION_TABLE *, LSA_IDENTITY_PROVIDER_HOST_FUNCTION_TABLE **, void **)` |
| `DummyFunction7` | `long LsapUpdateLogonSessionData(LUID *, unsigned __int64, ULONG, void *, ULONG)` |

The first one is how an identity provider plugs into lsasrv. It hands over its function table and
gets back the host's (`LsapIdProvHost*`: allocate and free, look up and save user info, update a
credential key...). These are presumably the providers interface 1003 forwards to. That deserves a
study of its own.
