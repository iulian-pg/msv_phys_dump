#pragma once
#include <Windows.h>
#include <psapi.h>
#include <ntstatus.h>
#include <stdio.h>
#include "header.h"
#include <bcrypt.h>

#pragma comment( lib, "ntdll.lib" )
#pragma comment(lib, "bcrypt.lib")
#pragma warning(disable:4996)



typedef struct {
	CHAR  ImageFileName[15];
} EPROCESS_NEEDLE;

typedef struct {
	ULONGLONG id;
	ULONGLONG vaddress;
	ULONGLONG start;
	ULONGLONG end;
	ULONGLONG size;
	char image[MAX_PATH];
} VAD;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


#define DEVICE_NAME "\\\\.\\GLCKIo"
#define IOCTL_WINIO_MAPPHYSTOLIN 0x80102040
#define IOCTL_WINIO_UNMAPPHYSADDR 0x80102044




typedef LARGE_INTEGER PHYSICAL_ADDRESS;

typedef struct _INPUTBUF
{
	ULONG64 Size;
	ULONG64 val2;
	ULONG64 val3;
	ULONG64 MappingAddress;
	ULONG64 val5;

} INPUTBUF;






typedef struct {
	CHAR LogonSessionList[12];
} LOGONSESSIONLIST_NEEDLE;

typedef struct {
	CHAR LsaInitialize[16];
} LSAINITIALIZE_NEEDLE;

typedef struct _nt_HARD_KEY {
	ULONG cbSecret;
	BYTE data[100]; // etc...
} nt_HARD_KEY, * pnt_HARD_KEY;

typedef struct _nt_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	nt_HARD_KEY hardkey;
} nt_BCRYPT_KEY81, * pnt_BCRYPT_KEY81;


typedef struct _nt_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	nt_HARD_KEY hardkey;
} nt_BCRYPT_KEY, * pnt_BCRYPT_KEY;

typedef struct _nt_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	pnt_BCRYPT_KEY key;
	PVOID unk0;
} nt_BCRYPT_HANDLE_KEY, * pnt_BCRYPT_HANDLE_KEY;


typedef struct _nt_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} nt_BCRYPT_GEN_KEY, * pnt_BCRYPT_GEN_KEY;




typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

#define LM_NTLM_HASH_LENGTH 16
#define SHA_DIGEST_LENGTH 20

typedef struct _PRIMARY_CREDENTIALS_10 {
	UNICODE_STRING LogonDomainName;
	UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} PRIMARY_CREDENTIALS_10, * PPRIMARY_CREDENTIALS_10;