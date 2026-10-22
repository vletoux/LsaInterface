// LsaIfDump - a security package that lists the interfaces registered in lsass.exe, from inside LSASS.
//
// Load it with AddSecurityPackage (scripts\Add-LsaPackage.ps1). SpInitialize writes
// C:\Windows\Temp\LsaIfDump.txt:
//   - the known interfaces and their entries, as module+RVA (resolve them with public symbols);
//   - every entry of the registry itself (gLsapIfList, x64 only), so ids nobody documented show up too;
//   - a scan of ids 0-0xFFFF through LsaGetInterface, to cross-check the list walk;
//   - an interface of our own, registered then read back.
#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <wincrypt.h>
#include <initguid.h>
#include <stdio.h>
#include "LsaInterface.h"

#define LSAIFDUMP_INTERFACE_ID 0x4D534C00  // 'MSL\0', any id nobody else uses

typedef struct _LSAIFDUMP_INTERFACE {
    ULONG Version;
    PCWSTR (NTAPI* GetName)(VOID);
} LSAIFDUMP_INTERFACE;

static PCWSTR NTAPI DumpGetName(VOID) { return L"LsaIfDump"; }
static LSAIFDUMP_INTERFACE g_ownInterface = { 1, DumpGetName };

static FILE* g_out;

// module+rva of an address, and whether it lies in an executable section of that module.
static BOOL Describe(PVOID p, PWSTR text, SIZE_T cch)
{
    HMODULE module;
    WCHAR path[MAX_PATH];
    PWSTR name;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER section;
    ULONG_PTR rva;
    WORD i;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (PCWSTR)p, &module))
    {
        swprintf_s(text, cch, L"%p", p);
        return FALSE;
    }
    GetModuleFileNameW(module, path, ARRAYSIZE(path));
    name = wcsrchr(path, L'\\') ? wcsrchr(path, L'\\') + 1 : path;
    rva = (ULONG_PTR)p - (ULONG_PTR)module;
    swprintf_s(text, cch, L"%s+0x%Ix", name, rva);
    nt = (PIMAGE_NT_HEADERS)((PBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
    section = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
            return (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    return FALSE;
}

// Entries are listed up to Count, or the first NULL: 1003 has 2 entries before WS2022.
static void DumpInterface(ULONG id, PCWSTR label, ULONG count)
{
    PVOID table = NULL;
    WCHAR text[MAX_PATH + 32];
    NTSTATUS status = LsaGetInterface(id, &table);
    ULONG i;
    if (!NT_SUCCESS(status))
    {
        fwprintf(g_out, L"%lu %s: 0x%08lx\n", id, label, status);
        return;
    }
    Describe(table, text, ARRAYSIZE(text));
    fwprintf(g_out, L"%lu %s: table %s\n", id, label, text);
    for (i = 0; i < count && ((PVOID*)table)[i]; i++)
    {
        Describe(((PVOID*)table)[i], text, ARRAYSIZE(text));
        fwprintf(g_out, L"  [%2lu] %s\n", i, text);
    }
}

#if defined(_M_X64)
// An entry of gLsapIfList, as lsass!LsapRegisterInterface allocates it (0x38 bytes).
typedef struct _LSAP_INTERFACE_ENTRY {
    LIST_ENTRY Link;        // gLsapIfList
    ULONG Id;
    PVOID Owner;            // the extension (LsaExtensionConfig) that provided it, NULL for lsass and LsaRegisterInterface
    LIST_ENTRY OwnerLink;   // the owner's own list of interfaces
    PVOID Interface;
} LSAP_INTERFACE_ENTRY;

// rip-relative target of the instruction at p whose disp32 is at p + offset.
static PBYTE RipTarget(PBYTE p, int offset, int length)
{
    return p + length + *(LONG UNALIGNED*)(p + offset);
}

// LsaGetInterface calls LsapFindRegisteredInterface, which starts with
//   mov rax, [gLsapIfList]  (48 8B 05 disp32)
//   lea rdx, gLsapIfList    (48 8D 15 disp32)
static PLIST_ENTRY FindInterfaceList(void)
{
    // Not &LsaGetInterface: without dllimport that is the import thunk in this DLL.
    PBYTE p = (PBYTE)GetProcAddress(GetModuleHandleW(L"lsass.exe"), "LsaGetInterface");
    int i;
    for (i = 0; p && i < 0x100; i++)
    {
        PBYTE target;
        if (p[i] != 0xE8)
            continue;
        target = RipTarget(p + i, 1, 5);
        if (target[0] == 0x48 && target[1] == 0x8B && target[2] == 0x05 && target[7] == 0x48 && target[8] == 0x8D && target[9] == 0x15)
            return (PLIST_ENTRY)RipTarget(target + 7, 3, 7);
    }
    return NULL;
}

// Walked without lsass's lock (gLsaIfLock): the list only grows, and almost only at start-up.
static void WalkInterfaceList(void)
{
    PLIST_ENTRY head = FindInterfaceList();
    PLIST_ENTRY link;
    WCHAR table[MAX_PATH + 32], owner[MAX_PATH + 32];
    if (!head)
    {
        fwprintf(g_out, L"registry: LsapFindRegisteredInterface not recognized\n");
        return;
    }
    Describe(head, table, ARRAYSIZE(table));
    fwprintf(g_out, L"registry: gLsapIfList at %s\n", table);
    __try
    {
        for (link = head->Flink; link != head; link = link->Flink)
        {
            LSAP_INTERFACE_ENTRY* entry = CONTAINING_RECORD(link, LSAP_INTERFACE_ENTRY, Link);
            Describe(entry->Interface, table, ARRAYSIZE(table));
            owner[0] = L'-';
            owner[1] = 0;
            // The owner record keeps the extension's QueryLsaInterface at +0x50: name the DLL from it.
            if (entry->Owner)
                Describe(((PVOID*)entry->Owner)[10], owner, ARRAYSIZE(owner));
            fwprintf(g_out, L"  id %lu (0x%lx): table %s, owner %s\n", entry->Id, entry->Id, table, owner);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fwprintf(g_out, L"  walk stopped: exception 0x%08lx\n", GetExceptionCode());
    }
}
#endif

static void ScanIds(void)
{
    ULONG id;
    PVOID table;
    fwprintf(g_out, L"scan 0-0xFFFF:");
    for (id = 0; id <= 0xFFFF; id++)
    {
        if (NT_SUCCESS(LsaGetInterface(id, &table)))
            fwprintf(g_out, L" %lu", id);
    }
    fwprintf(g_out, L"\n");
}

static void Dump(void)
{
    PVOID own = NULL;
    NTSTATUS status;
    if (_wfopen_s(&g_out, L"C:\\Windows\\Temp\\LsaIfDump.txt", L"w, ccs=UTF-8") || !g_out)
        return;

    status = LsaRegisterInterface(LSAIFDUMP_INTERFACE_ID, &g_ownInterface);
    fwprintf(g_out, L"LsaRegisterInterface(0x%08lx): 0x%08lx\n", LSAIFDUMP_INTERFACE_ID, status);
    status = LsaGetInterface(LSAIFDUMP_INTERFACE_ID, &own);
    fwprintf(g_out, L"LsaGetInterface(0x%08lx): 0x%08lx, %s\n\n", LSAIFDUMP_INTERFACE_ID, status,
        NT_SUCCESS(status) ? ((LSAIFDUMP_INTERFACE*)own)->GetName() : L"-");

    DumpInterface(LSA_INTERFACE_RM, L"rm", 1);
    DumpInterface(LSA_INTERFACE_CALLBACK, L"callback", 3);
    DumpInterface(LSA_INTERFACE_LSASRV, L"lsasrv", 18);
    DumpInterface(LSA_INTERFACE_DPAPI, L"dpapi", 9);
    DumpInterface(LSA_INTERFACE_IDPROV_EXT, L"idprov-ext", 3);

    {
        PLSA_CALLBACK_INTERFACE callback;
        ULONG systemPid = 0;
        if (NT_SUCCESS(LsaGetInterface(LSA_INTERFACE_CALLBACK, (PVOID*)&callback)))
        {
            status = callback->GetSystemInfo(&systemPid);
            fwprintf(g_out, L"callback GetSystemInfo: 0x%08lx, %lu\n", status, systemPid);
        }
    }
    {
        PLSA_IDPROV_EXT_INTERFACE idprov;
        if (NT_SUCCESS(LsaGetInterface(LSA_INTERFACE_IDPROV_EXT, (PVOID*)&idprov)) && idprov->ShouldBuildClientPac)
        {
            fwprintf(g_out, L"idprov-ext ShouldBuildClientPac: local %d, container %d\n",
                idprov->ShouldBuildClientPac((GUID*)&LSA_IDPROV_LOCAL_CERT_ISSUER),
                idprov->ShouldBuildClientPac((GUID*)&LSA_IDPROV_CONTAINER_CERT_ISSUER));
        }
    }

    fwprintf(g_out, L"\n");
#if defined(_M_X64)
    WalkInterfaceList();
#endif
    ScanIds();
    fclose(g_out);
}

static NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, PSECPKG_PARAMETERS Parameters, PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    UNREFERENCED_PARAMETER(PackageId);
    UNREFERENCED_PARAMETER(Parameters);
    UNREFERENCED_PARAMETER(FunctionTable);
    Dump();
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpShutdown(VOID)
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI SpGetInfo(PSecPkgInfo PackageInfo)
{
    PackageInfo->fCapabilities = 0;
    PackageInfo->wVersion = 1;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = L"LsaIfDump";
    PackageInfo->Comment = L"Lists the interfaces of lsass.exe";
    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE g_table;

NTSTATUS NTAPI SpLsaModeInitialize(ULONG LsaVersion, PULONG PackageVersion, PSECPKG_FUNCTION_TABLE* ppTables, PULONG pcTables)
{
    UNREFERENCED_PARAMETER(LsaVersion);
    g_table.Initialize = SpInitialize;
    g_table.Shutdown = SpShutdown;
    g_table.GetInfo = SpGetInfo;
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &g_table;
    *pcTables = 1;
    return STATUS_SUCCESS;
}
