// LsaInterface.h - the private interface registry of lsass.exe (LsaGetInterface / LsaRegisterInterface)
//
// Undocumented, reversed from Windows binaries and their public symbols (WS2016 14393 to Win11 26200).
// Link with lsass.lib (generated from lsass.def). Only code running inside lsass.exe can call these
// functions: an authentication package, a security package or an LSA extension.
//
// Function, table, enum and struct names are Microsoft's. Each prototype says where it comes from:
//   [symbols]  the public symbols carry the C++ signature: the types are exact, the parameter names ours
//   [sdk]      the same function LSA puts in LSA_SECPKG_FUNCTION_TABLE: the ntsecpkg.h typedef applies
//   [reversed] C function (no signature in the symbols): read from the code and its callers
//
// Include after <windows.h> (WIN32_NO_STATUS + <ntstatus.h>), SECURITY_WIN32, <sspi.h>, <ntsecapi.h>,
// <ntsecpkg.h> and <wincrypt.h>.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Opaque: their layout is not in the public symbols.
typedef struct _CREDENTIAL_KEY CREDENTIAL_KEY, *PCREDENTIAL_KEY;
typedef struct _LSA_IDENTITY_PROVIDER_FUNCTION_TABLE LSA_IDENTITY_PROVIDER_FUNCTION_TABLE;
typedef struct _LSA_IDENTITY_PROVIDER_HOST_FUNCTION_TABLE LSA_IDENTITY_PROVIDER_HOST_FUNCTION_TABLE;

// ---------------------------------------------------------------------------------------------------------
// Interface identifiers (enum _LSA_INTERFACE_TYPE in the symbols; the value names are ours)
// ---------------------------------------------------------------------------------------------------------
// 0 and 1 are registered by lsass.exe itself at start-up. 1001 and 1002 come from
// HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\Interfaces\<Id> (values Extension, Name):
// lsass loads the DLL and calls its QueryLsaInterface export. 1003 is registered at run time by lsasrv.
typedef enum _LSA_INTERFACE_TYPE {
    LSA_INTERFACE_RM = 0,               // lsass.exe  gLsapRmFunctions        LSA_RM_INTERFACE
    LSA_INTERFACE_CALLBACK = 1,         // lsass.exe  gLsapCallbackFunctions  LSA_CALLBACK_INTERFACE
    LSA_INTERFACE_LSASRV = 1001,        // lsasrv.dll LsapLsasrvIfTable       LSA_LSASRV_INTERFACE  "LsaLsasrvInterface"
    LSA_INTERFACE_DPAPI = 1002,         // dpapisrv   g_pDPAPIIfTable         LSA_DPAPI_INTERFACE   "LsaDpapiInterface"
    LSA_INTERFACE_IDPROV_EXT = 1003,    // lsasrv.dll LsapIdProvExtIfTable    LSA_IDPROV_EXT_INTERFACE (not on DCs)
} LSA_INTERFACE_TYPE;

// ---------------------------------------------------------------------------------------------------------
// lsass.exe exports [reversed]
// ---------------------------------------------------------------------------------------------------------

// Looks Id up in the registry of interfaces (gLsapIfList) and returns the table registered for it.
// STATUS_INVALID_PARAMETER if Interface is NULL, STATUS_NOT_FOUND if nothing is registered under Id,
// STATUS_INTERNAL_ERROR before lsass has initialized the registry.
NTSTATUS NTAPI LsaGetInterface(_In_ ULONG Id, _Out_ PVOID* Interface);

// Registers Interface under Id. STATUS_ALREADY_REGISTERED if Id is taken: there is no way to unregister,
// so the table must stay valid until lsass exits (packages are never unloaded anyway).
NTSTATUS NTAPI LsaRegisterInterface(_In_ ULONG Id, _In_ PVOID Interface);

// Hands lsass.exe one of lsasrv's own dispatch tables (lsass forwards its RPC and RM work to them).
// Used by lsasrv only; anything else would replace lsasrv's table.
#define LSA_EXTENSION_RM     0  // gLsapRmExtension
#define LSA_EXTENSION_SSPI   2  // gLsapSspiExtension
#define LSA_EXTENSION_LOOKUP 3  // gLsapLookupExtension
NTSTATUS NTAPI LsaRegisterExtension(_In_ ULONG Type, _In_ PVOID Table);

// Duplicates the token of the thread that ksecdd is serving (kernel-mode caller of a package).
NTSTATUS NTAPI LsaImpersonateKsecCaller(_Out_ PHANDLE Token);

// ---------------------------------------------------------------------------------------------------------
// Exports of an LSA extension (lsasrv.dll and dpapisrv.dll have both) [symbols]
// ---------------------------------------------------------------------------------------------------------
// lsass calls InitializeLsaExtension on every extension at each stage, in LsaExtensionConfig order.
typedef enum _LSA_EXTENSION_INIT_STAGE {
    LsaExtensionLoad = 0,           // lsasrv: LsapLsaExtensionLoad, takes interfaces 0 and 1
    LsaExtensionLoadComplete = 1,   // lsasrv takes 1002, dpapisrv takes 1001 then runs DPAPIInitialize
    LsaExtensionStart = 2,          // lsasrv: LsapLsaExtensionStart
} LSA_EXTENSION_INIT_STAGE;         // value names are ours

typedef NTSTATUS (NTAPI* PLSA_INITIALIZE_LSA_EXTENSION)(_In_ LSA_EXTENSION_INIT_STAGE Stage);        // "InitializeLsaExtension"
typedef NTSTATUS (NTAPI* PLSA_QUERY_LSA_INTERFACE)(_In_ LSA_INTERFACE_TYPE Id, _Out_ PVOID* Interface);  // "QueryLsaInterface"

// ---------------------------------------------------------------------------------------------------------
// 0 - reference monitor (lsass.exe) [reversed]
// ---------------------------------------------------------------------------------------------------------
// LsapCallRm: sends a command to the kernel Security Reference Monitor over the LSA command port.
// Commands lsasrv sends: 2 create logon session, 3 delete logon session, 4 logon session information
// changed, 8 and 9 logon session leak check.
typedef NTSTATUS (NTAPI* PLSA_CALL_RM)(_In_ ULONG Command, _In_reads_bytes_opt_(ParamsLength) PVOID Params,
    _In_ ULONG ParamsLength, _Out_writes_bytes_opt_(ReplyLength) PVOID Reply, _In_ ULONG ReplyLength);

typedef struct _LSA_RM_INTERFACE {
    PLSA_CALL_RM CallRm;  // LsapCallRm
} LSA_RM_INTERFACE, *PLSA_RM_INTERFACE;

// ---------------------------------------------------------------------------------------------------------
// 1 - client callbacks and ksecdd (lsass.exe) [reversed]
// ---------------------------------------------------------------------------------------------------------
// LsapIfClientCallback: PLSA_CLIENT_CALLBACK of ntsecpkg.h with the client in front. Bit 24 of Client marks a
// kernel-mode client: the call then goes to ksecdd (IOCTL 0x39003C), else to sspisrv!SspiSrvClientCallback.
#define LSA_CLIENT_KERNEL_MODE 0x01000000
typedef NTSTATUS (NTAPI* PLSA_IF_CLIENT_CALLBACK)(_In_ ULONG Client, _In_ PCHAR Callback, _In_ ULONG_PTR Argument1,
    _In_ ULONG_PTR Argument2, _In_ PSecBuffer Input, _Out_ PSecBuffer Output);
// LsapCallKsec: NtDeviceIoControlFile on lsass's handle to \Device\KsecDD. lsasrv allocates, copies and frees
// memory of kernel-mode clients with it (IOCTLs 0x390028, 0x390030, 0x39004C, 0x390054).
typedef NTSTATUS (NTAPI* PLSA_CALL_KSEC)(_In_ ULONG IoControlCode, _In_reads_bytes_opt_(InputLength) PVOID Input,
    _In_ ULONG InputLength, _Out_writes_bytes_opt_(OutputLength) PVOID Output, _In_ ULONG OutputLength);
// LsapGetSystemInfo: process id of System (4).
typedef NTSTATUS (NTAPI* PLSA_GET_SYSTEM_INFO)(_Out_ PULONG SystemProcessId);

typedef struct _LSA_CALLBACK_INTERFACE {
    PLSA_IF_CLIENT_CALLBACK ClientCallback;  // LsapIfClientCallback
    PLSA_CALL_KSEC CallKsec;                 // LsapCallKsec
    PLSA_GET_SYSTEM_INFO GetSystemInfo;      // LsapGetSystemInfo
} LSA_CALLBACK_INTERFACE, *PLSA_CALLBACK_INTERFACE;

// ---------------------------------------------------------------------------------------------------------
// 1001 - lsasrv services for netlogon and DPAPI (lsasrv.dll), 18 entries since WS2016
// ---------------------------------------------------------------------------------------------------------
// [reversed] (LUID, the package attributes of that logon session).
typedef NTSTATUS (NTAPI* PLSA_IF_QUERY_PACKAGE_ATTR_IN_LOGON_SESSION)(_In_ PLUID LogonId, _Out_ PULONG Attributes);
// [reversed] The six strings are forwarded to the credential manager (CredpNotifyPasswordChange) and the
// domain, user and passwords to DPAPI (LsapDPAPINotifyPasswordChange); dpapisrv passes Impersonating = TRUE
// after a local password reset. UserSid: when NULL, the DPAPI notification looks the user up and returns it.
typedef NTSTATUS (NTAPI* PLSA_IF_NOTIFY_PASSWORD_CHANGED)(_In_opt_ PSID UserSid, _In_opt_ PUNICODE_STRING NetbiosDomainName,
    _In_ PUNICODE_STRING UserName, _In_opt_ PUNICODE_STRING DnsDomainName, _In_opt_ PUNICODE_STRING Upn,
    _In_opt_ PUNICODE_STRING OldPassword, _In_ PUNICODE_STRING NewPassword, _In_ BOOLEAN Impersonating);
// [reversed]
typedef BOOLEAN (NTAPI* PLSA_IF_NO_MORE_WIN2K_DOMAIN)(VOID);
// [reversed] Writes a DPAPI master key backup/recovery audit (category 0x88, audit id 0x1000 + AuditId).
// Parameters in the event, in this order: user SID (NULL sid if UserSid is NULL), LogonId, the three
// strings, then *RecoveryReason and *FailureReason as hex; a non-zero *FailureReason makes it a failure
// audit. The parameter names follow the "Key Information" fields of events 4692 to 4695.
typedef NTSTATUS (NTAPI* PLSA_IF_AUDIT_DPAPI_EVENT)(_In_ ULONG AuditId, _In_opt_ PSID UserSid,
    _In_opt_ PUNICODE_STRING MasterKeyId, _In_opt_ PUNICODE_STRING RecoveryServer, _In_opt_ PULONG RecoveryReason,
    _In_opt_ PUNICODE_STRING RecoveryKeyId, _In_opt_ PULONG FailureReason, _In_opt_ PLUID LogonId);
// [reversed] Same as the lsasrv exports of the same name; Buffer is a PLSAPR_POLICY_INFORMATION (lsarpc).
typedef NTSTATUS (NTAPI* PLSA_IF_QUERY_INFORMATION_POLICY_TRUSTED)(_In_ POLICY_INFORMATION_CLASS InformationClass,
    _Out_ PVOID* Buffer);
typedef VOID (NTAPI* PLSA_IF_FREE_POLICY_INFORMATION)(_In_ POLICY_INFORMATION_CLASS InformationClass, _In_opt_ PVOID Buffer);
// [symbols] LsapGetCredentialKey(struct _LUID *, struct _GUID *, struct _CREDENTIAL_KEY **): credential key
// of a logon session, from the SID cache or else from the user's identity provider. dpapisrv passes NULL.
typedef NTSTATUS (NTAPI* PLSA_IF_GET_CREDENTIAL_KEY)(_In_ PLUID LogonId, _In_opt_ GUID* KeyId,
    _Out_ PCREDENTIAL_KEY* CredentialKey);
// [symbols] unsigned char (void *): a domain account SID (S-1-5-21-...), never TRUE on a DC.
typedef BOOLEAN (NTAPI* PLSA_IF_IS_DOMAIN_USER_DPAPI)(_In_ PSID UserSid);
// [symbols] long (unsigned short *, unsigned short *, struct _UNICODE_STRING, struct _UNICODE_STRING): the
// two strings go by value. Called by netlogon (NetpUpdateLSASecretCreds) when a gMSA password changes.
typedef NTSTATUS (NTAPI* PLSA_IF_DPAPI_PASSWORD_CHANGE_FOR_GMSA)(_In_ PWSTR String1, _In_ PWSTR String2,
    _In_ UNICODE_STRING Value1, _In_ UNICODE_STRING Value2);
// [symbols] long (struct _LUID *, enum LSAI_DPAPI_KEY_TYPE, unsigned char *, unsigned long, unsigned char *,
// unsigned long, unsigned char **, unsigned long *). dpapisrv!RestoreMasterKey calls it.
typedef ULONG LSAI_DPAPI_KEY_TYPE;  // enum LSAI_DPAPI_KEY_TYPE, values not in the symbols
typedef NTSTATUS (NTAPI* PLSA_IF_DECRYPT_DPAPI_MASTER_KEY)(_In_ PLUID LogonId, _In_ LSAI_DPAPI_KEY_TYPE KeyType,
    _In_reads_bytes_(Input1Size) PUCHAR Input1, _In_ ULONG Input1Size, _In_reads_bytes_opt_(Input2Size) PUCHAR Input2,
    _In_ ULONG Input2Size, _Out_ PUCHAR* Output, _Out_ PULONG OutputSize);

typedef struct _LSA_LSASRV_INTERFACE {
    PLSA_PROTECT_MEMORY ProtectMemory;                    // 0  LsaProtectMemory                    [sdk] LsaProtectMemory
    PLSA_PROTECT_MEMORY UnprotectMemory;                  // 1  LsaUnprotectMemory                  [sdk] LsaUnprotectMemory
    PLSA_FREE_LSA_HEAP FreeReturnBuffer;                  // 2  LsaIFreeReturnBuffer                [sdk] FreeReturnBuffer
    PLSA_FREE_LSA_HEAP FreeLsaHeap;                       // 3  LsapFreeLsaHeap / LsapSubProv_FreeRoutine  [sdk] FreeLsaHeap
    PLSA_CALL_PACKAGE CallPackage;                        // 4  LsaICallPackage                     [sdk] CallPackage
    PLSA_GET_AUTH_DATA_FOR_USER GetAuthDataForUser;       // 5  LsaIfGetAuthDataForUser             [symbols], same signature
    PLSA_CONVERT_AUTH_DATA_TO_TOKEN ConvertAuthDataToToken; // 6 LsaConvertAuthDataToToken          [sdk] ConvertAuthDataToToken
    PLSA_IF_QUERY_PACKAGE_ATTR_IN_LOGON_SESSION QueryPackageAttrInLogonSession; // 7 LsaIQueryPackageAttrInLogonSession
    PLSA_IF_NOTIFY_PASSWORD_CHANGED NotifyPasswordChanged; // 8  LsaINotifyPasswordChanged
    PLSA_IF_NO_MORE_WIN2K_DOMAIN NoMoreWin2KDomain;       // 9  LsaINoMoreWin2KDomain
    PLSA_IF_AUDIT_DPAPI_EVENT AuditDPAPIEvent;            // 10 LsaIAuditDPAPIEvent
    PLSA_IF_QUERY_INFORMATION_POLICY_TRUSTED QueryInformationPolicyTrusted; // 11 LsaIQueryInformationPolicyTrusted
    PLSA_IF_FREE_POLICY_INFORMATION FreePolicyInformation; // 12 LsaIFree_LSAPR_POLICY_INFORMATION
    PLSA_IF_GET_CREDENTIAL_KEY GetCredentialKey;          // 13 LsapGetCredentialKey
    PLSA_IF_IS_DOMAIN_USER_DPAPI IsDomainUserDPAPI;       // 14 LsapIsDomainUserDPAPI
    PLSA_IF_DPAPI_PASSWORD_CHANGE_FOR_GMSA DPAPIPasswordChangeForGMSA; // 15 LsapDPAPIPasswordChangeForGMSA
    PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap;               // 16 LsapAllocateLsaHeap / LsapAllocateULong  [sdk] AllocateLsaHeap
    PLSA_IF_DECRYPT_DPAPI_MASTER_KEY DecryptDPAPIMasterKey; // 17 LsapDecryptDPAPIMasterKey
} LSA_LSASRV_INTERFACE, *PLSA_LSASRV_INTERFACE;

// ---------------------------------------------------------------------------------------------------------
// 1002 - DPAPI (dpapisrv.dll), 9 entries [symbols]
// ---------------------------------------------------------------------------------------------------------
// lsasrv!LsaICryptProtectData, LsaICryptUnprotectData and their Ex forms call entries 0 to 3; the credential
// manager calls 0 and 1 itself to encrypt and decrypt its files (flags 0x20000001 and 0x20000041).
// The crypt entries return BOOLEAN. Their parameter names follow CryptProtectData / CryptUnprotectData,
// which they mirror; ExtraData/ExtraSize of the Ex forms are not identified.
typedef BOOLEAN (NTAPI* PLSA_DPAPI_CRYPT_PROTECT_DATA)(_In_reads_bytes_(DataInSize) PVOID DataIn, _In_ ULONG DataInSize,
    _In_opt_ PUNICODE_STRING Description, _In_reads_bytes_opt_(EntropySize) PVOID Entropy, _In_ ULONG EntropySize,
    _In_opt_ PVOID Reserved, _In_opt_ PVOID PromptStruct, _In_ ULONG Flags, _Out_ PVOID* DataOut, _Out_ PULONG DataOutSize);
typedef BOOLEAN (NTAPI* PLSA_DPAPI_CRYPT_UNPROTECT_DATA)(_In_reads_bytes_(DataInSize) PVOID DataIn, _In_ ULONG DataInSize,
    _In_reads_bytes_opt_(EntropySize) PVOID Entropy, _In_ ULONG EntropySize, _In_opt_ PVOID Reserved,
    _In_opt_ PVOID PromptStruct, _In_ ULONG Flags, _Out_opt_ PUNICODE_STRING Description, _Out_ PVOID* DataOut,
    _Out_ PULONG DataOutSize);
typedef BOOLEAN (NTAPI* PLSA_DPAPI_CRYPT_PROTECT_DATA_EX)(_In_reads_bytes_(DataInSize) PVOID DataIn, _In_ ULONG DataInSize,
    _In_opt_ PUNICODE_STRING Description, _In_reads_bytes_opt_(EntropySize) PVOID Entropy, _In_ ULONG EntropySize,
    _In_opt_ PVOID Reserved, _In_opt_ PVOID PromptStruct, _In_ ULONG Flags, _In_reads_bytes_opt_(ExtraSize) PUCHAR ExtraData,
    _In_ ULONG ExtraSize, _Out_ PVOID* DataOut, _Out_ PULONG DataOutSize);
typedef BOOLEAN (NTAPI* PLSA_DPAPI_CRYPT_UNPROTECT_DATA_EX)(_In_reads_bytes_(DataInSize) PVOID DataIn, _In_ ULONG DataInSize,
    _In_reads_bytes_opt_(EntropySize) PVOID Entropy, _In_ ULONG EntropySize, _In_opt_ PVOID Reserved,
    _In_opt_ PVOID PromptStruct, _In_ ULONG Flags, _In_reads_bytes_opt_(ExtraSize) PUCHAR ExtraData, _In_ ULONG ExtraSize,
    _Out_opt_ PUNICODE_STRING Description, _Out_ PVOID* DataOut, _Out_ PULONG DataOutSize);
typedef VOID (NTAPI* PLSA_DPAPI_NOTIFY_LOGON_TERMINATED)(_In_ PLUID LogonId);
// lsasrv passes the user's token (it queries it with NtQueryInformationToken just before).
typedef NTSTATUS (NTAPI* PLSA_DPAPI_NOTIFY_CREDENTIAL_KEY_CHANGE)(_In_ HANDLE Token, _In_opt_ PCREDENTIAL_KEY Key1,
    _In_opt_ PCREDENTIAL_KEY Key2, _In_ ULONG Flags);
typedef NTSTATUS (NTAPI* PLSA_DPAPI_SYNCHRONIZE_MASTER_KEYS)(_In_ PVOID Context, _In_ PCREDENTIAL_KEY Key,
    _Out_ PULONG Value1, _Out_ PULONG Value2);
typedef NTSTATUS (NTAPI* PLSA_DPAPI_IS_DC_TARGET_FOR_RECOVERY)(_In_ PLUID LogonId, _In_ PCWSTR Target, _Out_ PBOOL IsDc);
// Win32 error code. lsasrv's identity-provider host (LsapIdProvHostGetCurrentKeyIdForUser) uses it.
typedef DWORD (NTAPI* PLSA_DPAPI_GET_CURRENT_CREDENTIAL_KEY_ID)(_In_ PVOID User, _Out_ GUID* KeyId);

typedef struct _LSA_DPAPI_INTERFACE {
    PLSA_DPAPI_CRYPT_PROTECT_DATA CryptProtectData;                 // 0 DPAPICryptProtectData
    PLSA_DPAPI_CRYPT_UNPROTECT_DATA CryptUnprotectData;             // 1 DPAPICryptUnprotectData
    PLSA_DPAPI_CRYPT_PROTECT_DATA_EX CryptProtectDataEx;            // 2 DPAPICryptProtectDataEx
    PLSA_DPAPI_CRYPT_UNPROTECT_DATA_EX CryptUnprotectDataEx;        // 3 DPAPICryptUnprotectDataEx
    PLSA_DPAPI_NOTIFY_LOGON_TERMINATED NotifyLogonTerminated;       // 4 DPAPINotifyLogonTerminated
    PLSA_DPAPI_NOTIFY_CREDENTIAL_KEY_CHANGE NotifyCredentialKeyChange; // 5 DPAPINotifyCredentialKeyChange
    PLSA_DPAPI_SYNCHRONIZE_MASTER_KEYS SynchronizeMasterKeys;       // 6 LsaIfSynchronizeMasterKeys
    PLSA_DPAPI_IS_DC_TARGET_FOR_RECOVERY IsDcTargetForRecovery;     // 7 LsaIfIsDcTargetForRecovery
    PLSA_DPAPI_GET_CURRENT_CREDENTIAL_KEY_ID GetCurrentCredentialKeyId; // 8 LsaIfGetCurrentCredentialKeyId
} LSA_DPAPI_INTERFACE, *PLSA_DPAPI_INTERFACE;

// ---------------------------------------------------------------------------------------------------------
// 1003 - identity-provider extension (lsasrv.dll), used by pku2u.dll [symbols]
// ---------------------------------------------------------------------------------------------------------
// Registered by LsapInitIdProvExtension when the product type is not LanManNt: absent on domain
// controllers. 2 entries on WS2016/WS2019, 3 from WS2022. Each call is routed by ProviderId:
//   - the two certificate providers built into certpoleng are handled by lsasrv itself;
//   - any other GUID goes to the identity provider registered for it (see LSA_REGISTER_IDENTITY_PROVIDER
//     below), through that provider's own function table; STATUS_NOT_SUPPORTED if it has no such function.
// {6D0F37E4-4FAC-4E44-9C07-6B8343FE4953}  "Local Cert Issuer", store LocalMachine\Local Cert Issuer
// {E6284137-3900-4B85-97D1-51C9FF2ACEF0}  "Container Cert Issuer"
DEFINE_GUID(LSA_IDPROV_LOCAL_CERT_ISSUER, 0x6D0F37E4, 0x4FAC, 0x4E44, 0x9C, 0x07, 0x6B, 0x83, 0x43, 0xFE, 0x49, 0x53);
DEFINE_GUID(LSA_IDPROV_CONTAINER_CERT_ISSUER, 0xE6284137, 0x3900, 0x4B85, 0x97, 0xD1, 0x51, 0xC9, 0xFF, 0x2A, 0xCE, 0xF0);

// LsapGetIdProvCertFromCred: the certificate an identity provider associates with a credential of a logon
// session (the symbols say void **; pku2u passes the result to certpoleng!PstAcquirePrivateKey).
// STATUS_NOT_SUPPORTED for the two built-in providers, whose certificates pku2u reads from the credential
// manager itself.
typedef NTSTATUS (NTAPI* PLSA_IDPROV_GET_CERT_FROM_CRED)(_In_ PLUID LogonId, _In_ GUID* ProviderId,
    _In_reads_bytes_(CredentialSize) PVOID Credential, _In_ ULONG CredentialSize, _Out_ PCCERT_CONTEXT* Certificate);
// LsapAcceptPeerCertificate: what the peer's validated certificate means locally.
//   Role 0 (acceptor, pku2u!Pku2uCreatePac): the peer is the user. Built-in providers: S4U logon of the
//     local account the certificate names, LsapGetS4ULogonUserToken(const CERT_CONTEXT *, ULONG, void **)
//     with 0x2A for the local issuer and 0x2B for the container issuer; *LogonInformation is allocated by
//     lsasrv.
//   Role 1 (initiator, pku2u!Pku2uHandlePeer2PeerAsReply): the peer is the server. Built-in providers:
//     STATUS_SUCCESS and nothing returned.
typedef NTSTATUS (NTAPI* PLSA_IDPROV_ACCEPT_PEER_CERTIFICATE)(_In_ GUID* ProviderId, _In_ int Role,
    _In_ PCCERT_CONTEXT PeerCertificate, _Out_ PVOID* LogonInformation);
// LsapShouldBuildClientPac: TRUE only for the container provider.
typedef BOOL (NTAPI* PLSA_IDPROV_SHOULD_BUILD_CLIENT_PAC)(_In_ GUID* ProviderId);

typedef struct _LSA_IDPROV_EXT_INTERFACE {
    PLSA_IDPROV_GET_CERT_FROM_CRED GetIdProvCertFromCred;      // 0 LsapGetIdProvCertFromCred
    PLSA_IDPROV_ACCEPT_PEER_CERTIFICATE AcceptPeerCertificate; // 1 LsapAcceptPeerCertificate
    PLSA_IDPROV_SHOULD_BUILD_CLIENT_PAC ShouldBuildClientPac;  // 2 LsapShouldBuildClientPac (WS2022 and later)
} LSA_IDPROV_EXT_INTERFACE, *PLSA_IDPROV_EXT_INTERFACE;

// ---------------------------------------------------------------------------------------------------------
// Related: the two "DummyFunction" slots of LSA_SECPKG_FUNCTION_TABLE [symbols]
// ---------------------------------------------------------------------------------------------------------
// ntsecpkg.h names them DummyFunction6 and DummyFunction7. lsasrv fills them with:
//   DummyFunction6 = LsapRegisterIdentityProvider: an identity provider gives lsasrv its function table and
//     receives the host's (LsapIdProvHost*). These are presumably the providers interface 1003 forwards to.
//   DummyFunction7 = LsapUpdateLogonSessionData.
// Only ProviderId and the two tables are identified.
typedef NTSTATUS (NTAPI* PLSA_REGISTER_IDENTITY_PROVIDER)(_In_ GUID* ProviderId, _In_opt_ PVOID Context,
    _In_ ULONG Value, _In_ LSA_IDENTITY_PROVIDER_FUNCTION_TABLE* FunctionTable,
    _Out_ LSA_IDENTITY_PROVIDER_HOST_FUNCTION_TABLE** HostFunctionTable, _Out_ PVOID* Handle);
typedef NTSTATUS (NTAPI* PLSA_UPDATE_LOGON_SESSION_DATA)(_In_ PLUID LogonId, _In_ ULONG64 Value,
    _In_ ULONG DataType, _In_reads_bytes_opt_(DataSize) PVOID Data, _In_ ULONG DataSize);

#ifdef __cplusplus
}
#endif
