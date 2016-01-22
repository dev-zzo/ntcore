#ifndef __NTAPI_PS_H_INCLUDED
#define __NTAPI_PS_H_INCLUDED

/******************************************************************
 * Process API
 *****************************************************************/

/*
 * Types
 */

typedef struct _PEB PEB, *PPEB;

typedef enum _PROCESS_INFORMATION_CLASS {
    /* Q: PROCESS_BASIC_INFORMATION */
    ProcessBasicInformation = 0x0,
    ProcessQuotaLimits = 0x1,
    ProcessIoCounters = 0x2,
    ProcessVmCounters = 0x3,
    ProcessTimes = 0x4,
    ProcessBasePriority = 0x5,
    ProcessRaisePriority = 0x6,
    /* Q: HANDLE */
    ProcessDebugPort = 0x7,
    ProcessExceptionPort = 0x8,
    ProcessAccessToken = 0x9,
    ProcessLdtInformation = 0xA,
    ProcessLdtSize = 0xB,
    ProcessDefaultHardErrorMode = 0xC,
    ProcessIoPortHandlers = 0xD,
    ProcessPooledUsageAndLimits = 0xE,
    ProcessWorkingSetWatch = 0xF,
    ProcessUserModeIOPL = 0x10,
    ProcessEnableAlignmentFaultFixup = 0x11,
    ProcessPriorityClass = 0x12,
    ProcessWx86Information = 0x13,
    ProcessHandleCount = 0x14,
    ProcessAffinityMask = 0x15,
    ProcessPriorityBoost = 0x16,
    ProcessDeviceMap = 0x17,
    ProcessSessionInformation = 0x18,
    ProcessForegroundInformation = 0x19,
    /* Q: ULONG_PTR */
    ProcessWow64Information = 0x1A,
    ProcessImageFileName = 0x1B,
    ProcessLUIDDeviceMapsEnabled = 0x1C,
    ProcessBreakOnTermination = 0x1D,
    ProcessDebugObjectHandle = 0x1E,
    ProcessDebugFlags = 0x1F,
    ProcessHandleTracing = 0x20,
    MaxProcessInfoClass_NT500 = 0x21,

    ProcessIoPriority = 0x21,
    ProcessExecuteFlags = 0x22,
    ProcessTlsInformation = 0x23,
    ProcessCookie = 0x24,
    ProcessImageInformation = 0x25,
    MaxProcessInfoClass_NT520 = 0x26,

    ProcessCycleTime = 0x26,
    ProcessPagePriority = 0x27,
    ProcessInstrumentationCallback = 0x28,
    ProcessThreadStackAllocation = 0x29,
    ProcessWorkingSetWatchEx = 0x2A,
    ProcessImageFileNameWin32 = 0x2B,
    ProcessImageFileMapping = 0x2C,
    ProcessAffinityUpdateMode = 0x2D,
    ProcessMemoryAllocationMode = 0x2E,
    ProcessGroupInformation = 0x2F,
    ProcessTokenVirtualizationEnabled = 0x30,
    ProcessConsoleHostProcess = 0x31,
    ProcessWindowInformation = 0x32,
    MaxProcessInfoClass_NT610 = 0x33,

    ProcessHandleInformation = 0x33,
    ProcessMitigationPolicy = 0x34,
    ProcessDynamicFunctionTableInformation = 0x35,
    ProcessHandleCheckingMode = 0x36,
    ProcessKeepAliveCount = 0x37,
    ProcessRevokeFileHandles = 0x38,
    ProcessWorkingSetControl = 0x39,
    MaxProcessInfoClass_NT620 = 0x3A,
} PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;

/* ProcessBasicInformation */

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    KAFFINITY AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

/* ProcessDeviceMap */

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            PVOID DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            CHAR DriveType[32];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _PROCESS_DEVICEMAP_INFORMATION_EX {
    union {
        struct {
            PVOID DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            CHAR DriveType[32];
        } Query;
    };
    ULONG Flags;
} PROCESS_DEVICEMAP_INFORMATION_EX, *PPROCESS_DEVICEMAP_INFORMATION_EX;

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

typedef enum _PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#endif

/*
 * Functions
 */

#define NtCurrentProcess() ((HANDLE)-1)

NTSYSAPI NTSTATUS NTAPI NtCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
NTSYSAPI NTSTATUS NTAPI NtCreateProcessEx(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE InheritFromProcessHandle,
    BOOLEAN InheritHandles,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)
NTSYSAPI NTSTATUS NTAPI NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
    POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PVOID ProcessParameters OPTIONAL,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);
#endif

NTSYSAPI NTSTATUS NTAPI NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSuspendProcess(
    HANDLE ProcessHandle);

NTSYSAPI NTSTATUS NTAPI NtResumeProcess(
    HANDLE ProcessHandle);

NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(
    HANDLE ProcessHandle,
    HANDLE JobHandle);
#endif

NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus);


/******************************************************************
 * Thread API
 *****************************************************************/

/*
 * Types
 */

typedef struct _TEB TEB, *PTEB;

typedef struct _USER_STACK {
    PVOID FixedStackBase;
    PVOID FixedStackLimit;
    PVOID ExpandableStackBase;
    PVOID ExpandableStackLimit;
    PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

/* Current: 6.1 */
typedef enum _THREAD_INFORMATION_CLASS {        // Q/S
    ThreadBasicInformation = 0x0,               // Y/N
    ThreadTimes = 0x1,                          // Y/N
    ThreadPriority = 0x2,                       // N/Y
    ThreadBasePriority = 0x3,                   // N/Y
    ThreadAffinityMask = 0x4,                   // N/Y
    ThreadImpersonationToken = 0x5,             // N/Y
    ThreadDescriptorTableEntry = 0x6,           // Y/N
    ThreadEnableAlignmentFaultFixup = 0x7,      // N/Y
    ThreadEventPair_Reusable = 0x8,             // N/Y
    ThreadQuerySetWin32StartAddress = 0x9,      // Y/Y
    ThreadZeroTlsCell = 0xA,                    // N/Y
    ThreadPerformanceCount = 0xB,               // Y/N
    ThreadAmILastThread = 0xC,                  // Y/N
    ThreadIdealProcessor = 0xD,                 // N/Y
    ThreadPriorityBoost = 0xE,                  // Y/Y
    ThreadSetTlsArrayAddress = 0xF,             // N/Y
    ThreadIsIoPending = 0x10,                   // Y/N
    ThreadHideFromDebugger = 0x11,              // N/Y
    ThreadBreakOnTermination = 0x12,
#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
    ThreadSwitchLegacyState = 0x13,
#endif
#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)
    ThreadIsTerminated = 0x14,
    ThreadLastSystemCall = 0x15,
    ThreadIoPriority = 0x16,
    ThreadCycleTime = 0x17,
    ThreadPagePriority = 0x18,
    ThreadActualBasePriority = 0x19,
    ThreadTebInformation = 0x1A,
    ThreadCSwitchMon = 0x1B,
    ThreadCSwitchPmu = 0x1C,
    ThreadWow64Context = 0x1D,
    ThreadGroupInformation = 0x1E,
    ThreadUmsInformation = 0x1F,
    ThreadCounterProfiling = 0x20,
    ThreadIdealProcessorEx = 0x21,
#endif
#if (NTAPI_LEVEL >= NTAPI_LEVEL_WIN7)
    ThreadCpuAccountingInformation = 0x22,
#endif
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

/* ThreadBasicInformation */

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

/*
 * Functions
 */

#define  NtCurrentThread() ((HANDLE)-2)

#if __INCLUDE_WINNT_DEFINES
NTSYSAPI PTEB NTAPI NtCurrentTeb(void);
#endif

NTSYSAPI NTSTATUS NTAPI NtCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PUSER_STACK UserStack,
    BOOLEAN CreateSuspended);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)
NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument OPTIONAL,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);
#endif

NTSYSAPI NTSTATUS NTAPI NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationThread(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength);

NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext);

NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext);

NTSYSAPI NTSTATUS NTAPI NtRaiseException(
    PEXCEPTION_RECORD ExceptionRecord,
    PCONTEXT ThreadContext,
    BOOLEAN HandleException);

NTSYSAPI NTSTATUS NTAPI NtContinue(
    PCONTEXT ThreadContext,
    BOOLEAN RaiseAlert);

NTSYSAPI NTSTATUS NTAPI NtCallbackReturn(
    PVOID Result OPTIONAL,
    ULONG ResultLength,
    NTSTATUS Status);

#if 0
NTSYSAPI NTSTATUS NTAPI NtSetLdtEntries(
    ULONG Selector1,
    LDT_ENTRY LdtEntry1,
    ULONG Selector2,
    LDT_ENTRY LdtEntry2);
#endif

NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount);

NTSYSAPI NTSTATUS NTAPI NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount);

NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus);

NTSYSAPI NTSTATUS NTAPI NtImpersonateThread(
    HANDLE ThreadHandle,
    HANDLE ThreadToImpersonate,
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

NTSYSAPI NTSTATUS NTAPI NtImpersonateAnonymousToken(
    HANDLE ThreadHandle);

NTSYSAPI NTSTATUS NTAPI NtRegisterThreadTerminatePort(
    HANDLE PortHandle);

/*
    This function alerts the target thread using the previous mode
    as the mode of the alert.
*/
NTSYSAPI NTSTATUS NTAPI NtAlertThread(
    HANDLE ThreadHandle);

NTSYSAPI NTSTATUS NTAPI NtAlertResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount);

/*
    This function tests the alert flag inside the current thread. If
    an alert is pending for the previous mode, then the alerted status
    is returned, pending APC's may also be delivered at this time.
*/
NTSYSAPI NTSTATUS NTAPI NtTestAlert(VOID);

NTSYSAPI NTSTATUS NTAPI NtQueueApcThread(
    HANDLE ThreadHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WIN7)
NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx(
    HANDLE ThreadHandle,
    HANDLE ApcReserveHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);
#endif

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

NTSYSAPI NTSTATUS NTAPI NtYieldExecution(VOID);


/******************************************************************
 * Job API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef enum _JOBOBJECTINFOCLASS {
    JobObjectBasicAccountingInformation = 1,
    JobObjectBasicLimitInformation,
    JobObjectBasicProcessIdList,
    JobObjectBasicUIRestrictions,
    JobObjectSecurityLimitInformation,
    JobObjectEndOfJobTimeInformation,
    JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAndIoAccountingInformation,
    JobObjectExtendedLimitInformation,
    JobObjectJobSetInformation,
    MaxJobObjectInfoClass,
} JOBOBJECTINFOCLASS;

typedef struct _JOB_SET_ARRAY {
    HANDLE JobHandle;
    ULONG MemberLevel;
    ULONG Flags;
} JOB_SET_ARRAY, *PJOB_SET_ARRAY;
#endif /* __INCLUDE_WINNT_DEFINES */

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtCreateJobSet(
    ULONG NumJob,
    PJOB_SET_ARRAY UserJobSet,
    ULONG Flags);

NTSYSAPI NTSTATUS NTAPI NtOpenJobObject(
    PHANDLE JobHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtAssignProcessToJobObject(
    HANDLE JobHandle,
    HANDLE ProcessHandle);

NTSYSAPI NTSTATUS NTAPI NtTerminateJobObject(
    HANDLE JobHandle,
    NTSTATUS ExitStatus);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationJobObject(
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobInformationClass,
    PVOID JobInformation,
    ULONG JobInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationJobObject(
    HANDLE JobHandle,
    JOBOBJECTINFOCLASS JobInformationClass,
    PVOID JobInformation,
    ULONG JobInformationLength);

#endif


/******************************************************************
 * Worker factory API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

struct _FILE_IO_COMPLETION_INFORMATION;

typedef enum _WORKERFACTORYINFOCLASS {
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation,
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation,
    WorkerFactoryThreadBasePriority,
    WorkerFactoryTimeoutWaiters,
    WorkerFactoryFlags,
    WorkerFactoryThreadSoftMaximum,
    MaxWorkerFactoryInfoClass,
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateWorkerFactory(
    PHANDLE WorkerFactoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE CompletionPortHandle,
    HANDLE WorkerProcessHandle,
    PVOID StartRoutine,
    PVOID StartParameter OPTIONAL,
    ULONG MaxThreadCount OPTIONAL,
    SIZE_T StackReserve OPTIONAL,
    SIZE_T StackCommit OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength);

NTSYSAPI NTSTATUS NTAPI NtShutdownWorkerFactory(
    HANDLE WorkerFactoryHandle,
    PLONG PendingWorkerCount);

NTSYSAPI NTSTATUS NTAPI NtReleaseWorkerFactoryWorker(
    HANDLE WorkerFactoryHandle);

NTSYSAPI NTSTATUS NTAPI NtWorkerFactoryWorkerReady(
    HANDLE WorkerFactoryHandle);

NTSYSAPI NTSTATUS NTAPI NtWaitForWorkViaWorkerFactory(
    HANDLE WorkerFactoryHandle,
    struct _FILE_IO_COMPLETION_INFORMATION *MiniPacket);

#endif


#endif
