#ifndef __NTAPI_DBG_H_INCLUDED
#define __NTAPI_DBG_H_INCLUDED

/******************************************************************
 * Debugger API
 *****************************************************************/

/*
 * Types
 */

/* Ref: http://www.openrce.org/articles/full_view/25 */
/* Ref: http://native-nt-toolkit.googlecode.com/svn/trunk/ndk/dbgktypes.h */

#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseOfDll;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        struct
        {
            HANDLE HandleToThread;
            DBGKM_CREATE_THREAD NewThread;
        } CreateThread;
        struct
        {
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            DBGKM_CREATE_PROCESS NewProcess;
        } CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_EXCEPTION Exception;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateDebugObject(
    PHANDLE DebugHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Flags);

NTSYSAPI NTSTATUS NTAPI NtDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugHandle);

NTSYSAPI NTSTATUS NTAPI NtWaitForDebugEvent(
    HANDLE DebugHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout,
    PDBGUI_WAIT_STATE_CHANGE StateChange);

NTSYSAPI NTSTATUS NTAPI NtDebugContinue(
    HANDLE DebugHandle,
    PCLIENT_ID AppClientId,
    NTSTATUS ContinueStatus);

NTSYSAPI NTSTATUS NTAPI NtRemoveProcessDebug(
    HANDLE ProcessHandle,
    HANDLE DebugHandle);


/******************************************************************
 * System debugger API
 *****************************************************************/

/*
 * Types
 */

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation = 0x0,
    SysDbgQueryTraceInformation = 0x1,
    SysDbgSetTracepoint = 0x2,
    SysDbgSetSpecialCall = 0x3,
    SysDbgClearSpecialCalls = 0x4,
    SysDbgQuerySpecialCalls = 0x5,
    SysDbgBreakPoint = 0x6,
    SysDbgQueryVersion = 0x7,
    SysDbgReadVirtual = 0x8,
    SysDbgWriteVirtual = 0x9,
    SysDbgReadPhysical = 0xA,
    SysDbgWritePhysical = 0xB,
    SysDbgReadControlSpace = 0xC,
    SysDbgWriteControlSpace = 0xD,
    SysDbgReadIoSpace = 0xE,
    SysDbgWriteIoSpace = 0xF,
    SysDbgReadMsr = 0x10,
    SysDbgWriteMsr = 0x11,
    SysDbgReadBusData = 0x12,
    SysDbgWriteBusData = 0x13,
    SysDbgCheckLowMemory = 0x14,
    SysDbgEnableKernelDebugger = 0x15,
    SysDbgDisableKernelDebugger = 0x16,
    SysDbgGetAutoKdEnable = 0x17,
    SysDbgSetAutoKdEnable = 0x18,
    SysDbgGetPrintBufferSize = 0x19,
    SysDbgSetPrintBufferSize = 0x1A,
    SysDbgGetKdUmExceptionEnable = 0x1B,
    SysDbgSetKdUmExceptionEnable = 0x1C,
#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
    SysDbgGetTriageDump = 0x1D,
    SysDbgGetKdBlockEnable = 0x1E,
    SysDbgSetKdBlockEnable = 0x1F,
#endif
} SYSDBG_COMMAND;

typedef struct _SYSDBG_PHYSICAL {
    LARGE_INTEGER Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_PHYSICAL, *PSYSDBG_PHYSICAL;

typedef struct _SYSDBG_VIRTUAL {
    UINT_PTR Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef struct _SYSDBG_MSR {
    ULONG Msr;
    ULONGLONG Data;
} SYSDBG_MSR, *PSYSDBG_MSR;

typedef struct _SYSDBG_TRIAGE_DUMP {
    ULONG Flags;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParam1;
    ULONG_PTR BugCheckParam2;
    ULONG_PTR BugCheckParam3;
    ULONG_PTR BugCheckParam4;
    ULONG ProcessHandles;
    ULONG ThreadHandles;
    PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, *PSYSDBG_TRIAGE_DUMP;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtSystemDebugControl(
    SYSDBG_COMMAND Command,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtQueryDebugFilterState(
    ULONG ComponentId,
    ULONG Level);

NTSYSAPI NTSTATUS NTAPI NtSetDebugFilterState(
    ULONG ComponentId,
    ULONG Level,
    BOOLEAN State);


/******************************************************************
 * Profile API
 *****************************************************************/

/*
 * Types
 */

typedef enum _KPROFILE_SOURCE {
    ProfileTime = 0x0,
    ProfileAlignmentFixup = 0x1,
    ProfileTotalIssues = 0x2,
    ProfilePipelineDry = 0x3,
    ProfileLoadInstructions = 0x4,
    ProfilePipelineFrozen = 0x5,
    ProfileBranchInstructions = 0x6,
    ProfileTotalNonissues = 0x7,
    ProfileDcacheMisses = 0x8,
    ProfileIcacheMisses = 0x9,
    ProfileCacheMisses = 0xA,
    ProfileBranchMispredictions = 0xB,
    ProfileStoreInstructions = 0xC,
    ProfileFpInstructions = 0xD,
    ProfileIntegerInstructions = 0xE,
    Profile2Issue = 0xF,
    Profile3Issue = 0x10,
    Profile4Issue = 0x11,
    ProfileSpecialInstructions = 0x12,
    ProfileTotalCycles = 0x13,
    ProfileIcacheIssues = 0x14,
    ProfileDcacheAccesses = 0x15,
    ProfileMemoryBarrierCycles = 0x16,
    ProfileLoadLinkedIssues = 0x17,
    ProfileMaximum = 0x18,
} KPROFILE_SOURCE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateProfile(
    PHANDLE ProfileHandle,
    HANDLE Process OPTIONAL,
    PVOID ImageBase,
    ULONG ImageSize,
    ULONG BucketSize,
    PVOID Buffer,
    ULONG BufferSize,
    KPROFILE_SOURCE ProfileSource,
    KAFFINITY Affinity);

NTSYSAPI NTSTATUS NTAPI NtStartProfile(
    HANDLE ProfileHandle);

NTSYSAPI NTSTATUS NTAPI NtStopProfile(
    HANDLE ProfileHandle);

NTSYSAPI NTSTATUS NTAPI NtSetIntervalProfile(
    ULONG Interval,
    KPROFILE_SOURCE Source);

NTSYSAPI NTSTATUS NTAPI NtQueryIntervalProfile(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval);


#endif
