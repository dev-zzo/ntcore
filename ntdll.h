#ifndef __NTDLL_H_INCLUDED
#define __NTDLL_H_INCLUDED

//#include <winternl.h>

/* Change to 1 to include stuff defined in winnt.h */
#define __INCLUDE_WINNT_DEFINES 0

#ifndef OPTIONAL
#define OPTIONAL
#endif

/* Stuff not defined for userland programs */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_ALERTED
#define STATUS_ALERTED                      ((NTSTATUS)0x00000101L)
#define STATUS_INFO_LENGTH_MISMATCH         ((NTSTATUS)0xC0000004L)
#endif

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

#if __INCLUDE_WINNT_DEFINES
typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;
#endif

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
} VM_COUNTERS_EX;


typedef struct _KAPC KAPC, *PKAPC;

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    PKAPC Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(PKAPC Apc);


/******************************************************************
 * General object API
 *****************************************************************/

/*
 * Types
 */

typedef enum _OBJECT_INFORMATION_CLASS {    // Q/S
    ObjectBasicInformation = 0,             // Y/N
    ObjectNameInformation = 1,              // Y/N
    ObjectTypeInformation = 2,              // Y/N
    ObjectTypesInformation = 3,             // Y/N
    ObjectHandleFlagInformation = 4,        // Y/Y
    MaxObjectInfoClass_NT500 = 0x5,

    ObjectSessionInformation = 5,           // N/Y
    MaxObjectInfoClass = 6,
} OBJECT_INFORMATION_CLASS;

/* ObjectBasicInformation */

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG Reserved[3];
    ULONG NameInfoSize;
    ULONG TypeInfoSize;
    ULONG SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

/* ObjectNameInformation */

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
    /* Name buffer follows */
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

/* ObjectTypeInformation */

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

/* ObjectTypesInformation */

typedef struct _OBJECT_TYPES_INFORMATION {
    ULONG NumberOfTypes;
    /* Not in original definition, added for convenience */
    OBJECT_TYPE_INFORMATION Types[0];
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

/* ObjectHandleFlagInformation */

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

typedef enum _OBJECT_WAIT_TYPE {
    WaitAllObject,
    WaitAnyObject,
} OBJECT_WAIT_TYPE, *POBJECT_WAIT_TYPE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtDuplicateObject(
    HANDLE SourceProcessHandle,
    PHANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN InheritHandle,
    ULONG Options);

NTSYSAPI NTSTATUS NTAPI NtQueryObject(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationObject(
    HANDLE ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength);

NTSYSAPI NTSTATUS NTAPI NtWaitForSingleObject(
    HANDLE ObjectHandle,
    BOOLEAN Alertable,
    PLARGE_INTEGER TimeOut OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtWaitForMultipleObjects(
    ULONG ObjectCount,
    PHANDLE ObjectsArray,
    OBJECT_WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER TimeOut OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQuerySecurityObject(
    HANDLE ObjectHandle,
    SECURITY_INFORMATION SecurityInformationClass,
    PSECURITY_DESCRIPTOR DescriptorBuffer,
    ULONG DescriptorBufferLength,
    PULONG RequiredLength);

NTSYSAPI NTSTATUS NTAPI NtSetSecurityObject(
    HANDLE ObjectHandle,
    SECURITY_INFORMATION SecurityInformationClass,
    PSECURITY_DESCRIPTOR DescriptorBuffer);

NTSYSAPI NTSTATUS NTAPI NtClose(
    HANDLE ObjectHandle);


/******************************************************************
 * System related API
 *****************************************************************/

/*
 * Types
 */

/* Current version: 5.1 */
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xA,
    SystemModuleInformation = 0xB,
    SystemLocksInformation = 0xC,
    SystemStackTraceInformation = 0xD,
    SystemPagedPoolInformation = 0xE,
    SystemNonPagedPoolInformation = 0xF,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1A,
    SystemUnloadGdiDriverInformation = 0x1B,
    SystemTimeAdjustmentInformation = 0x1C,
    SystemSummaryMemoryInformation = 0x1D,
    SystemMirrorMemoryInformation = 0x1E,
    SystemPerformanceTraceInformation = 0x1F,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2A,
    SystemLegacyDriverInformation = 0x2B,
    SystemCurrentTimeZoneInformation = 0x2C,
    SystemLookasideInformation = 0x2D,
    SystemTimeSlipNotification = 0x2E,
    SystemSessionCreate = 0x2F,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3A,
    SystemComPlusPackage = 0x3B,
    SystemNumaAvailableMemory = 0x3C,
    SystemProcessorPowerInformation = 0x3D,
    SystemEmulationBasicInformation = 0x3E,
    SystemEmulationProcessorInformation = 0x3F,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    MaxSystemInfoClass_NT500 = 0x4A,

    SystemWow64SharedInformation = 0x4A,
    MaxSystemInfoClass_NT513 = 0x4B,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

/* SystemBasicInformation */

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    ULONG ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

/* SystemProcessorInformation */

typedef struct _SYSTEM_PROCESSOR_INFORMATION {
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

/* SystemPerformanceInformation */

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG AvailablePagedPoolPages;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

/* SystemTimeOfDayInformation */

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

/* SystemProcessInformation*/

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG UniqueProcessKey;
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters;
    /* Array of SYSTEM_THREAD follows */
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/* SystemProcessorPerformanceInformation*/

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

/* SystemFlagsInformation */

typedef enum _SYSTEM_GLOBAL_FLAGS {
    FLG_STOP_ON_EXCEPTION           = 0x00000001,
    FLG_SHOW_LDR_SNAPS              = 0x00000002,
    FLG_DEBUG_INITIAL_COMMAND       = 0x00000004,
    FLG_STOP_ON_HUNG_GUI            = 0x00000008,
    FLG_HEAP_ENABLE_TAIL_CHECK      = 0x00000010,
    FLG_HEAP_ENABLE_FREE_CHECK      = 0x00000020,
    FLG_HEAP_VALIDATE_PARAMETERS    = 0x00000040,
    FLG_HEAP_VALIDATE_ALL           = 0x00000080,
    FLG_APPLICATION_VERIFIER        = 0x00000100,
    FLG_MONITOR_SILENT_PROCESS_EXIT = 0x00000200,
    FLG_POOL_ENABLE_TAGGING         = 0x00000400,
    FLG_HEAP_ENABLE_TAGGING         = 0x00000800,
    FLG_USER_STACK_TRACE_DB         = 0x00001000,
    FLG_KERNEL_STACK_TRACE_DB       = 0x00002000,
    FLG_MAINTAIN_OBJECT_TYPELIST    = 0x00004000,
    FLG_HEAP_ENABLE_TAG_BY_DLL      = 0x00008000,
    FLG_DISABLE_STACK_EXTENSION     = 0x00010000,
    FLG_ENABLE_CSRDEBUG             = 0x00020000,
    FLG_ENABLE_KDEBUG_SYMBOL_LOAD   = 0x00040000,
    FLG_DISABLE_PAGE_KERNEL_STACKS  = 0x00080000,
    FLG_ENABLE_SYSTEM_CRIT_BREAKS   = 0x00100000,
    FLG_HEAP_DISABLE_COALESCING     = 0x00200000,
    FLG_ENABLE_CLOSE_EXCEPTIONS     = 0x00400000,
    FLG_ENABLE_EXCEPTION_LOGGING    = 0x00800000,
    FLG_ENABLE_HANDLE_TYPE_TAGGING  = 0x01000000,
    FLG_HEAP_PAGE_ALLOCS            = 0x02000000,
    FLG_DEBUG_INITIAL_COMMAND_EX    = 0x04000000,
    FLG_DISABLE_DBGPRINT            = 0x08000000,
    FLG_CRITSEC_EVENT_CREATION      = 0x10000000,
    FLG_ENABLE_HANDLE_EXCEPTIONS    = 0x40000000,
    FLG_DISABLE_PROTDLLS            = 0x80000000,
} SYSTEM_GLOBAL_FLAGS;

typedef struct _SYSTEM_FLAGS_INFORMATION {
    SYSTEM_GLOBAL_FLAGS Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

/* SystemHandleInformation */

typedef enum _SYSTEM_HANDLE_FLAGS {
    PROTECT_FROM_CLOSE=1,
    INHERIT=2
} SYSTEM_HANDLE_FLAGS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

/* SystemExtendedHandleInformation: since 5.1 */

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength);

/* INCOMPLETE SIGNATURE */
/* Since: NT 5.1 */
NTSYSAPI NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx(
    ULONG InformationClass,
    PVOID Buffer,
    ULONG BufferLength);

NTSYSAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValue(
    PUNICODE_STRING VariableName,
    PWSTR ValueBuffer,
    ULONG ValueBufferLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    PULONG ReturnLength,
    PULONG Attributes);

NTSYSAPI NTSTATUS NTAPI NtSetSystemEnvironmentValue(
    PUNICODE_STRING VariableName,
    PUNICODE_STRING Value);

NTSYSAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    PULONG ReturnLength,
    PULONG Attributes);


/******************************************************************
 * Directory API
 *****************************************************************/

/*
 * Types
 */

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer OPTIONAL,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength OPTIONAL);


/******************************************************************
 * Process API
 *****************************************************************/

/*
 * Types
 */

typedef enum _PROCESS_INFORMATION_CLASS {
    ProcessBasicInformation = 0x0,
    ProcessQuotaLimits = 0x1,
    ProcessIoCounters = 0x2,
    ProcessVmCounters = 0x3,
    ProcessTimes = 0x4,
    ProcessBasePriority = 0x5,
    ProcessRaisePriority = 0x6,
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

struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            PVOID DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            CHAR DriveType[32];
        } Query;
    };
};

struct _PROCESS_DEVICEMAP_INFORMATION_EX
{
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
};

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

/* Since: NT 5.1 */
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

/* Since: NT 5.1 */
NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(
    HANDLE ProcessHandle,
    HANDLE JobHandle);

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
    MaxThreadInfoClass_NT500 = 0x13,

    ThreadSwitchLegacyState = 0x13,
    MaxThreadInfoClass_NT520 = 0x14,

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
    MaxThreadInfoClass_NT610 = 0x22,

    ThreadCpuAccountingInformation = 0x22,
    MaxThreadInfoClass_NT620 = 0x23,

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

NTSYSAPI NTSTATUS NTAPI NtCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PUSER_STACK UserStack,
    BOOLEAN CreateSuspended);

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

NTSYSAPI NTSTATUS NTAPI NtContinue(
    PCONTEXT ThreadContext,
    BOOLEAN RaiseAlert);

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

/* Since: 6.1 */
NTSYSAPI NTSTATUS NTAPI NtQueueApcThreadEx(
    HANDLE ThreadHandle,
    HANDLE ApcReserveHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

NTSYSAPI NTSTATUS NTAPI NtYieldExecution(VOID);


/******************************************************************
 * Job API
 *****************************************************************/

/* Since: NT 5.1 */

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


/******************************************************************
 * Event API
 *****************************************************************/

/*
 * Types
 */

typedef enum _EVENT_TYPE {
    NotificationEvent = 0x0,
    SynchronizationEvent = 0x1,
} EVENT_TYPE;

typedef enum _EVENT_INFORMATION_CLASS {
    EventBasicInformation = 0x0,
} EVENT_INFORMATION_CLASS;

typedef struct _EVENT_BASIC_INFORMATION {
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType,
    BOOLEAN InitialState);

NTSYSAPI NTSTATUS NTAPI NtOpenEvent(
    PHANDLE EventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes );

NTSYSAPI NTSTATUS NTAPI NtClearEvent(
    HANDLE EventHandle );

NTSYSAPI NTSTATUS NTAPI NtSetEvent(
    HANDLE EventHandle,
    PLONG PreviousState);

NTSYSAPI NTSTATUS NTAPI NtResetEvent(
    HANDLE EventHandle,
    PLONG PreviousState);

NTSYSAPI NTSTATUS NTAPI NtPulseEvent(
    HANDLE EventHandle,
    PLONG PreviousState);

NTSYSAPI NTSTATUS NTAPI NtSetEventBoostPriority(
    HANDLE EventHandle );

NTSYSAPI NTSTATUS NTAPI NtQueryEvent(
    HANDLE EventHandle,
    EVENT_INFORMATION_CLASS EventInformationClass,
    PVOID EventInformation,
    ULONG EventInformationLength,
    PULONG ReturnLength);


/******************************************************************
 * Event pair API
 *****************************************************************/

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtOpenEventPair(
    PHANDLE EventPairHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtSetHighEventPair(
    HANDLE EventPairHandle);

NTSYSAPI NTSTATUS NTAPI NtSetHighWaitLowEventPair(
    HANDLE EventPairHandle);

NTSYSAPI NTSTATUS NTAPI NtWaitLowEventPair(
    HANDLE EventPairHandle);

NTSYSAPI NTSTATUS NTAPI NtSetLowEventPair(
    HANDLE EventPairHandle);

NTSYSAPI NTSTATUS NTAPI NtSetLowWaitHighEventPair(
    HANDLE EventPairHandle);

NTSYSAPI NTSTATUS NTAPI NtWaitHighEventPair(
    HANDLE EventPairHandle);


/******************************************************************
 * Keyed event API
 *****************************************************************/

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG Flags);

NTSYSAPI NTSTATUS NTAPI NtOpenKeyedEvent(
    PHANDLE KeyedEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtReleaseKeyedEvent(
    HANDLE KeyedEventHandle,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtWaitForKeyedEvent(
    HANDLE KeyedEventHandle,
    PVOID KeyValue,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout OPTIONAL);


/******************************************************************
 * Timer API
 *****************************************************************/

/*
 * Types
 */

typedef enum _TIMER_TYPE {
    NotificationTimer = 0x0,
    SynchronizationTimer = 0x1,
} TIMER_TYPE;

typedef enum _TIMER_INFORMATION_CLASS {
    TimerBasicInformation = 0x0,
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION {
    LARGE_INTEGER RemainingTime;
    BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

typedef VOID (*PTIMER_APC_ROUTINE)(PVOID TimerContext, ULONG TimerLowValue, LONG TimerHighValue);

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TIMER_TYPE TimerType);

NTSYSAPI NTSTATUS NTAPI NtOpenTimer(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtSetTimer(
    HANDLE TimerHandle,
    PLARGE_INTEGER DueTime,
    PTIMER_APC_ROUTINE TimerApcRoutine,
    PVOID TimerContext,
    BOOLEAN ResumeTimer,
    LONG Period,
    PBOOLEAN PreviousState);

NTSYSAPI NTSTATUS NTAPI NtCancelTimer(
    HANDLE TimerHandle,
    PBOOLEAN CurrentState);

NTSYSAPI NTSTATUS NTAPI NtQueryTimer(
    HANDLE TimerHandle,
    TIMER_INFORMATION_CLASS TimerInformationClass,
    PVOID TimerInformation,
    ULONG TimerInformationLength,
    PULONG ReturnLength);


/******************************************************************
 * Mutant API
 *****************************************************************/

/*
 * Types
 */

typedef enum _MUTANT_INFORMATION_CLASS {
    MutantBasicInformation = 0x0,
} MUTANT_INFORMATION_CLASS;

typedef struct _MUTANT_BASIC_INFORMATION {
    LONG CurrentCount;
    BOOLEAN OwnedByCaller;
    BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

/*
 * Functions
 */

/*
    This function creates a mutant object, sets its initial count to one
    (signaled), and opens a handle to the object with the specified desired
    access.
*/
NTSYSAPI NTSTATUS NTAPI NtCreateMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN InitialOwner);

/*
    This function opens a handle to a mutant object with the specified
    desired access.
*/
NTSYSAPI NTSTATUS NTAPI NtOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtQueryMutant(
    HANDLE MutantHandle,
    MUTANT_INFORMATION_CLASS MutantInformationClass,
    PVOID MutantInformation,
    ULONG MutantInformationLength,
    PULONG ResultLength);

NTSYSAPI NTSTATUS NTAPI NtReleaseMutant(
    HANDLE MutantHandle,
    PLONG PreviousCount);


/******************************************************************
 * Semaphore API
 *****************************************************************/

/*
 * Types
 */

typedef enum _SEMAPHORE_INFORMATION_CLASS {
    SemaphoreBasicInformation = 0x0,
} SEMAPHORE_INFORMATION_CLASS;

typedef struct _SEMAPHORE_BASIC_INFORMATION {
    LONG CurrentCount;
    LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG InitialCount,
    ULONG MaximumCount);

NTSYSAPI NTSTATUS NTAPI NtOpenSemaphore(
    PHANDLE SemaphoreHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtReleaseSemaphore(
    HANDLE SemaphoreHandle,
    ULONG ReleaseCount,
    PULONG PreviousCount);

NTSYSAPI NTSTATUS NTAPI NtQuerySemaphore(
    HANDLE SemaphoreHandle,
    SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    PVOID SemaphoreInformation,
    ULONG SemaphoreInformationLength,
    PULONG ReturnLength);


/******************************************************************
 * Key API
 *****************************************************************/

/*
 * Types
 */

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0x0,
    KeyNodeInformation = 0x1,
    KeyFullInformation = 0x2,
    KeyNameInformation = 0x3,
    KeyCachedInformation = 0x4,
    KeyFlagsInformation = 0x5,
    MaxKeyInfoClass = 0x6,
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct __declspec(align(4)) _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

typedef struct _KEY_FLAGS_INFORMATION {
    ULONG UserFlags;
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef enum _KEY_SET_INFORMATION_CLASS {
    KeyWriteTimeInformation = 0x0,
    KeyUserFlagsInformation = 0x1,
    MaxKeySetInfoClass = 0x2,
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef struct _KEY_USER_FLAGS_INFORMATION {
    ULONG UserFlags;
} KEY_USER_FLAGS_INFORMATION, *PKEY_USER_FLAGS_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0x0,
    KeyValueFullInformation = 0x1,
    KeyValuePartialInformation = 0x2,
    KeyValueFullInformationAlign64 = 0x3,
    KeyValuePartialInformationAlign64 = 0x4,
    MaxKeyValueInfoClass = 0x5,
} KEY_VALUE_INFORMATION_CLASS;

/* KeyValueBasicInformation */

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

/* KeyValueFullInformation */

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

/* KeyValuePartialInformation */

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    BYTE Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG DataLength;
    ULONG DataOffset;
    ULONG Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    PULONG Disposition OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtRenameKey(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName);

NTSYSAPI NTSTATUS NTAPI NtFlushKey(
    HANDLE KeyHandle);

NTSYSAPI NTSTATUS NTAPI NtDeleteKey(
    HANDLE KeyHandle);

NTSYSAPI NTSTATUS NTAPI NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSYSAPI NTSTATUS NTAPI NtLockRegistryKey(
    HANDLE KeyHandle);

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeKey(
    HANDLE KeyHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer,
    ULONG BufferSize,
    BOOLEAN Asynchronous);

NTSYSAPI NTSTATUS NTAPI NtNotifyChangeMultipleKeys(
    HANDLE MasterKeyHandle,
    ULONG Count OPTIONAL,
    OBJECT_ATTRIBUTES SlaveObjects[] OPTIONAL,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CompletionFilter,
    BOOLEAN WatchTree,
    PVOID Buffer OPTIONAL,
    ULONG BufferSize,
    BOOLEAN Asynchronous);

NTSYSAPI NTSTATUS NTAPI NtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationKey(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength);

NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeys(
    POBJECT_ATTRIBUTES TargetKey,
    PULONG HandleCount);

NTSYSAPI NTSTATUS NTAPI NtQueryOpenSubKeysEx(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG BufferLength,
    PVOID Buffer,
    PULONG RequiredSize OPTIONAL);


NTSYSAPI NTSTATUS NTAPI NtLoadKey(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile);

NTSYSAPI NTSTATUS NTAPI NtLoadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags);

NTSYSAPI NTSTATUS NTAPI NtLoadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtUnloadKey(
    POBJECT_ATTRIBUTES TargetKey);

NTSYSAPI NTSTATUS NTAPI NtUnloadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    ULONG Flags);

NTSYSAPI NTSTATUS NTAPI NtUnloadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    HANDLE Event OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtReplaceKey(
    POBJECT_ATTRIBUTES NewFile,
    HANDLE TargetHandle,
    POBJECT_ATTRIBUTES OldFile);



NTSYSAPI NTSTATUS NTAPI NtSaveKey(
    HANDLE KeyHandle,
    HANDLE FileHandle);

NTSYSAPI NTSTATUS NTAPI NtSaveKeyEx(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format);

NTSYSAPI NTSTATUS NTAPI NtSaveMergedKeys(
    HANDLE HighPrecedenceKeyHandle,
    HANDLE LowPrecedenceKeyHandle,
    HANDLE FileHandle);

NTSYSAPI NTSTATUS NTAPI NtRestoreKey(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Flags);


NTSYSAPI NTSTATUS NTAPI NtEnumerateValueKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSYSAPI NTSTATUS NTAPI NtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex OPTIONAL,
    ULONG Type,
    PVOID Data,
    ULONG DataSize);

NTSYSAPI NTSTATUS NTAPI NtDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName);

NTSYSAPI NTSTATUS NTAPI NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength);

NTSYSAPI NTSTATUS NTAPI NtQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength OPTIONAL);


/******************************************************************
 * Virtual Memory Manager API
 *****************************************************************/

/*
 * Types
 */

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

#if __INCLUDE_WINNT_DEFINES
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
#endif /* __INCLUDE_WINNT_DEFINES*/

typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

/*
 * Functions
 */

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff566416%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

NTSYSAPI NTSTATUS NTAPI NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesRead);

NTSYSAPI NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    ULONG MemoryInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);

NTSYSAPI NTSTATUS NTAPI NtLockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    OUT PULONG NumberOfBytesToLock,
    ULONG LockOption);

NTSYSAPI NTSTATUS NTAPI NtUnlockVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    OUT PULONG NumberOfBytesToUnlock,
    ULONG LockOption);

NTSYSAPI NTSTATUS NTAPI NtFlushVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PULONG NumberOfBytesToFlush,
    PIO_STATUS_BLOCK IoStatusBlock);

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff566460%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

NTSYSAPI NTSTATUS NTAPI NtAllocateUserPhysicalPages(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray);

NTSYSAPI NTSTATUS NTAPI NtMapUserPhysicalPages(
    PVOID VirtualAddresses,
    ULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray);

NTSYSAPI NTSTATUS NTAPI NtMapUserPhysicalPagesScatter(
    PVOID *VirtualAddresses,
    ULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray);

NTSYSAPI NTSTATUS NTAPI NtFreeUserPhysicalPages(
    HANDLE ProcessHandle,
    PULONG_PTR NumberOfPages,
    PULONG_PTR UserPfnArray);

NTSYSAPI NTSTATUS NTAPI NtGetWriteWatch(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID BaseAddress,
    SIZE_T RegionSize,
    PVOID *UserAddressArray,
    PULONG_PTR EntriesInUserAddressArray,
    PULONG Granularity);

NTSYSAPI NTSTATUS NTAPI NtResetWriteWatch(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    SIZE_T RegionSize);


/******************************************************************
 * Section API
 *****************************************************************/

/*
 * Types
 */

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2,
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation = 0x0,
    SectionImageInformation = 0x1,
    MaxSectionInfoClass = 0x2,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

/* SectionBasicInformation */

typedef struct _SECTION_BASIC_INFORMATION {
    PVOID BaseAddress;
    ULONG AllocationAttributes;
    LARGE_INTEGER MaximumSize;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

/* SectionImageInformation */

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    ULONG_PTR MaximumStackSize;
    ULONG_PTR CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    BOOLEAN Spare1;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG Reserved[1];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

NTSYSAPI NTSTATUS NTAPI NtOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtExtendSection(
    HANDLE SectionHandle,
    PLARGE_INTEGER NewSectionSize);

NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

NTSYSAPI NTSTATUS NTAPI NtQuerySection(
    HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS InformationClass,
    PVOID InformationBuffer,
    ULONG InformationBufferSize,
    PULONG ResultLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtAreMappedFilesTheSame(
    PVOID File1MappedAsAnImage,
    PVOID File2MappedAsFile);


/******************************************************************
 * File API
 *****************************************************************/

/*
 * Types
 */

/* Current: 6.1 */
typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 0x1,
    FileFullDirectoryInformation = 0x2,
    FileBothDirectoryInformation = 0x3,
    FileBasicInformation = 0x4,
    FileStandardInformation = 0x5,
    FileInternalInformation = 0x6,
    FileEaInformation = 0x7,
    FileAccessInformation = 0x8,
    FileNameInformation = 0x9,
    FileRenameInformation = 0xA,
    FileLinkInformation = 0xB,
    FileNamesInformation = 0xC,
    FileDispositionInformation = 0xD,
    FilePositionInformation = 0xE,
    FileFullEaInformation = 0xF,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13,
    FileEndOfFileInformation = 0x14,
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FilePipeInformation = 0x17,
    FilePipeLocalInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileMailslotQueryInformation = 0x1A,
    FileMailslotSetInformation = 0x1B,
    FileCompressionInformation = 0x1C,
    FileObjectIdInformation = 0x1D,
    FileCompletionInformation = 0x1E,
    FileMoveClusterInformation = 0x1F,
    FileQuotaInformation = 0x20,
    FileReparsePointInformation = 0x21,
    FileNetworkOpenInformation = 0x22,
    FileAttributeTagInformation = 0x23,
    FileTrackingInformation = 0x24,
    FileIdBothDirectoryInformation = 0x25,
    FileIdFullDirectoryInformation = 0x26,
    FileValidDataLengthInformation = 0x27,
    FileShortNameInformation = 0x28,
    FileMaximumInformation_NT500 = 0x29,

    FileIoCompletionNotificationInformation = 0x29,
    FileIoStatusBlockRangeInformation = 0x2A,
    FileIoPriorityHintInformation = 0x2B,
    FileSfioReserveInformation = 0x2C,
    FileSfioVolumeInformation = 0x2D,
    FileHardLinkInformation = 0x2E,
    FileProcessIdsUsingFileInformation = 0x2F,
    FileNormalizedNameInformation = 0x30,
    FileNetworkPhysicalNameInformation = 0x31,
    FileIdGlobalTxDirectoryInformation = 0x32,
    FileIsRemoteDeviceInformation = 0x33,
    FileAttributeCacheInformation = 0x34,
    FileNumaNodeInformation = 0x35,
    FileStandardLinkInformation = 0x36,
    FileRemoteProtocolInformation = 0x37,
    FileMaximumInformation_NT610 = 0x38,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

/*
 * Functions
 */

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

NTSYSAPI NTSTATUS NTAPI NtCreateMailslotFile(
    PHANDLE MailslotFileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG CreateOptions,
    ULONG MailslotQuota,
    ULONG MaxMessageSize,
    PLARGE_INTEGER ReadTimeOut);

NTSYSAPI NTSTATUS NTAPI NtCreateNamedPipeFile(
    PHANDLE NamedPipeFileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    BOOLEAN WriteModeMessage,
    BOOLEAN ReadModeMessage,
    BOOLEAN NonBlocking,
    ULONG MaxInstances,
    ULONG InBufferSize,
    ULONG OutBufferSize,
    PLARGE_INTEGER DefaultTimeOut);

NTSYSAPI NTSTATUS NTAPI NtCreatePagingFile(
    PUNICODE_STRING PageFileName,
    PLARGE_INTEGER MiniumSize,
    PLARGE_INTEGER MaxiumSize,
    PLARGE_INTEGER ActualSize OPTIONAL);

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff567011%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

NTSYSAPI NTSTATUS NTAPI NtLockFile(
    HANDLE FileHandle,
    HANDLE LockGrantedEvent OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    PULONG Key,
    BOOLEAN ReturnImmediately,
    BOOLEAN ExclusiveLock);

NTSYSAPI NTSTATUS NTAPI NtUnlockFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length,
    PULONG Key);

NTSYSAPI NTSTATUS NTAPI NtReadFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset OPTIONAL,
    PULONG Key OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtFlushBuffersFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock);

NTSYSAPI NTSTATUS NTAPI NtDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE UserApcRoutine OPTIONAL,
    PVOID UserApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength);

NTSYSAPI NTSTATUS NTAPI NtFsControlFile(
    HANDLE FileHandle,
    HANDLE Event OPTIONAL,
    PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    PVOID ApcContext OPTIONAL,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength);

NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);


/******************************************************************
 * Symbolic link API
 *****************************************************************/

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING LinkTarget);

NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength OPTIONAL);


/******************************************************************
 * Security token API
 *****************************************************************/

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef struct _ACL {
    CHAR AclRevision;
    CHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL, *PACL;

typedef struct _SID_IDENTIFIER_AUTHORITY {
    CHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    CHAR Revision;
    CHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[1];
} SID, *PSID;

typedef struct _SID_AND_ATTRIBUTES {
    PVOID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES;

typedef struct _TOKEN_OWNER {
    PVOID Owner;
} TOKEN_OWNER;

typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _TOKEN_PRIMARY_GROUP {
    PVOID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;

typedef struct _TOKEN_GROUPS {
    ULONG GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

typedef struct _TOKEN_DEFAULT_DACL {
    ACL *DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_SOURCE {
    CHAR SourceName[8];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;
#endif /* __INCLUDE_WINNT_DEFINES */

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateToken(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER TokenUser,
    PTOKEN_GROUPS TokenGroups,
    PTOKEN_PRIVILEGES TokenPrivileges,
    PTOKEN_OWNER TokenOwner,
    PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
    PTOKEN_DEFAULT_DACL TokenDefaultDacl,
    PTOKEN_SOURCE TokenSource);

NTSYSAPI NTSTATUS NTAPI NtDuplicateToken(
    HANDLE ExistingToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE NewToken );

NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle);

/* Since: 5.1 */
NTSYSAPI NTSTATUS NTAPI NtOpenProcessTokenEx(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle);

NTSYSAPI NTSTATUS NTAPI NtOpenThreadToken(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle);

/* Since: 5.1 */
NTSYSAPI NTSTATUS NTAPI NtOpenThreadTokenEx(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle);

NTSYSAPI NTSTATUS NTAPI NtAdjustGroupsToken(
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS TokenGroups,
    ULONG PreviousGroupsLength,
    PTOKEN_GROUPS PreviousGroups OPTIONAL,
    PULONG RequiredLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES TokenPrivileges,
    ULONG PreviousPrivilegesLength,
    PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
    PULONG RequiredLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength);

NTSYSAPI NTSTATUS NTAPI NtQuerySecurityAttributesToken(
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer,
    ULONG Length,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtCompareTokens(
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal);

NTSYSAPI NTSTATUS NTAPI NtFilterToken(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    PHANDLE NewTokenHandle);

NTSYSAPI NTSTATUS NTAPI NtAccessCheck(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtAccessCheckByType(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtAccessCheckByTypeResultList(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtPrivilegeCheck(
    HANDLE TokenHandle,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result);

NTSYSAPI NTSTATUS NTAPI NtAllocateLocallyUniqueId(
    PLUID LocallyUniqueId);

NTSYSAPI NTSTATUS NTAPI NtAllocateUuids(
    PLARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence);


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
    /* NT 5.0.0 ends */
    SysDbgGetTriageDump = 0x1D,
    SysDbgGetKdBlockEnable = 0x1E,
    SysDbgSetKdBlockEnable = 0x1F,
    /* NT 5.2.0 ends */
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


/******************************************************************
 * Port API
 *****************************************************************/

/*
 * Types
 */

typedef struct _PORT_VIEW
{
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    ULONG ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
    ULONG Length;
    ULONG ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef struct _PORT_MESSAGE
{
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    };
    ULONG MessageId;
    union {
        ULONG ClientViewSize;               // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    };
    //  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxDataSize,
    ULONG MaxMessageSize,
    ULONG Reserved);

NTSYSAPI NTSTATUS NTAPI NtCreateWaitablePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxConnectInfoLength,
    ULONG MaxDataLength,
    ULONG MaxPoolUsage);

NTSYSAPI NTSTATUS NTAPI NtAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView,
    PREMOTE_PORT_VIEW ClientView);

NTSYSAPI NTSTATUS NTAPI NtListenPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest);

NTSYSAPI NTSTATUS NTAPI NtConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView,
    PREMOTE_PORT_VIEW ServerView,
    PULONG MaxMessageLength,
    PVOID ConnectionInformation,
    PULONG ConnectionInformationLength);

NTSYSAPI NTSTATUS NTAPI NtCompleteConnectPort(
    HANDLE PortHandle);

NTSYSAPI NTSTATUS NTAPI NtReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage);

NTSYSAPI NTSTATUS NTAPI NtReplyWaitReceivePortEx(
    HANDLE PortHandle,
    PVOID *PortContext OPTIONAL,
    PPORT_MESSAGE ReplyMessage OPTIONAL,
    PPORT_MESSAGE ReceiveMessage,
    DWORD ReceiveMessageLen);

NTSYSAPI NTSTATUS NTAPI NtReplyWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage);

NTSYSAPI NTSTATUS NTAPI NtRequestPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage);

NTSYSAPI NTSTATUS NTAPI NtRequestWaitReplyPortEx(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage,
    DWORD ReplyMessageLength);

NTSYSAPI NTSTATUS NTAPI NtClosePort(
    HANDLE PortHandle);

NTSYSAPI NTSTATUS NTAPI NtWriteRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten);

NTSYSAPI NTSTATUS NTAPI NtReadRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesRead);


/******************************************************************
 * Advanced LPC API
 *****************************************************************/

/*
 * Types
 */

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    ULONG MaxMessageLength;
    ULONG MemoryBandwidth;
    ULONG MaxPoolUsage;
    ULONG MaxSectionSize;
    ULONG MaxViewSize;
    ULONG MaxTotalSectionSize;
    ULONG DupObjectTypes;
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtAlpcCreatePort(
    PHANDLE PortObject,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES pPortInformation);

/******************************************************************
 * Input/Output Manager API
 *****************************************************************/

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(
    PHANDLE ReserveHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG ObjectType);


/******************************************************************
 * Input/Output Completion API
 *****************************************************************/

/*
 * Types
 */

typedef enum _IO_COMPLETION_INFORMATION_CLASS {
    IoCompletionBasicInformation = 0x0,
} IO_COMPLETION_INFORMATION_CLASS;

typedef struct _IO_COMPLETION_BASIC_INFORMATION {
    LONG Depth;
} IO_COMPLETION_BASIC_INFORMATION, *PIO_COMPLETION_BASIC_INFORMATION;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG NumberOfConcurrentThreads);

NTSYSAPI NTSTATUS NTAPI NtOpenIoCompletion(
    PHANDLE IoCompletionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI NtSetIoCompletion(
    HANDLE IoCompletionHandle,
    ULONG CompletionKey,
    PIO_STATUS_BLOCK IoStatusBlock,
    NTSTATUS CompletionStatus,
    ULONG NumberOfBytesTransfered);

/* Since: NT 6.1 */
NTSYSAPI NTSTATUS NTAPI NtSetIoCompletionEx(
    HANDLE IoCompletionHandle,
    HANDLE ReserveHandle,
    PVOID CompletionKey,
    PVOID CompletionContext,
    NTSTATUS CompletionStatus,
    ULONG CompletionInformation);

NTSYSAPI NTSTATUS NTAPI NtRemoveIoCompletion(
    HANDLE IoCompletionHandle,
    PULONG CompletionKey,
    PULONG CompletionValue,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER Timeout OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryIoCompletion(
    HANDLE IoCompletionHandle,
    IO_COMPLETION_INFORMATION_CLASS InformationClass,
    PVOID IoCompletionInformation,
    ULONG InformationBufferLength,
    PULONG RequiredLength OPTIONAL);


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


/******************************************************************
 * Transaction manager API
 *****************************************************************/

/* Since: 6.0 */

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef enum _TRANSACTIONMANAGER_INFORMATION_CLASS { 
    TransactionManagerBasicInformation = 0,
    TransactionManagerLogInformation = 1,
    TransactionManagerLogPathInformation = 2,
    TransactionManagerRecoveryInformation = 4,
} TRANSACTIONMANAGER_INFORMATION_CLASS;

typedef enum _KTMOBJECT_TYPE { 
    KTMOBJECT_TRANSACTION = 0,
    KTMOBJECT_TRANSACTION_MANAGER = 1,
    KTMOBJECT_RESOURCE_MANAGER = 2,
    KTMOBJECT_ENLISTMENT = 3,
    KTMOBJECT_INVALID = 4,
} KTMOBJECT_TYPE, *PKTMOBJECT_TYPE;

typedef struct _KTMOBJECT_CURSOR {
    GUID LastQuery;
    ULONG ObjectIdCount;
    GUID ObjectIds[1];
} KTMOBJECT_CURSOR, *PKTMOBJECT_CURSOR;
#endif

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG CommitStrength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenTransactionManager(
    PHANDLE TmHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PUNICODE_STRING LogFileName OPTIONAL,
    LPGUID TmIdentity OPTIONAL,
    ULONG OpenOptions OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtRenameTransactionManager(
    PUNICODE_STRING LogFileName,
    LPGUID ExistingTransactionManagerGuid);

NTSYSAPI NTSTATUS NTAPI NtRollforwardTransactionManager(
    HANDLE TransactionManagerHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtRecoverTransactionManager(
    HANDLE TransactionManagerHandle);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationTransactionManager(
    HANDLE TransactionManagerHandle,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetInformationTransactionManager(
    HANDLE TmHandle OPTIONAL,
    TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    PVOID TransactionManagerInformation,
    ULONG TransactionManagerInformationLength);


NTSYSAPI NTSTATUS NTAPI NtEnumerateTransactionObject(
    HANDLE RootObjectHandle OPTIONAL,
    KTMOBJECT_TYPE QueryType,
    PKTMOBJECT_CURSOR ObjectCursor,
    ULONG ObjectCursorLength,
    PULONG ReturnLength);


/******************************************************************
 * Transaction API
 *****************************************************************/

/* Since: 6.0 */

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef enum _TRANSACTION_INFORMATION_CLASS { 
    TransactionBasicInformation = 0,
    TransactionPropertiesInformation,
    TransactionEnlistmentInformation,
    TransactionSuperiorEnlistmentInformation,
} TRANSACTION_INFORMATION_CLASS;
#endif

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    LPGUID Uow OPTIONAL,
    HANDLE TmHandle OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    ULONG IsolationLevel OPTIONAL,
    ULONG IsolationFlags OPTIONAL,
    PLARGE_INTEGER Timeout OPTIONAL,
    PUNICODE_STRING Description OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenTransaction(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID Uow,
    HANDLE TmHandle OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetInformationTransaction(
    HANDLE TransactionHandle,
    TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    PVOID TransactionInformation,
    ULONG TransactionInformationLength);

NTSYSAPI NTSTATUS NTAPI NtCommitTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait);

NTSYSAPI NTSTATUS NTAPI NtRollbackTransaction(
    HANDLE TransactionHandle,
    BOOLEAN Wait);

NTSYSAPI NTSTATUS NTAPI NtFreezeTransactions(
    PLARGE_INTEGER FreezeTimeout,
    PLARGE_INTEGER ThawTimeout);

NTSYSAPI NTSTATUS NTAPI NtThawTransactions(VOID);


/******************************************************************
 * Transaction enlistment API
 *****************************************************************/

/* Since: 6.0 */

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef enum _ENLISTMENT_INFORMATION_CLASS { 
    EnlistmentBasicInformation = 0,
    EnlistmentRecoveryInformation,
    EnlistmentCrmInformation,
} ENLISTMENT_INFORMATION_CLASS;
#endif

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    HANDLE TransactionHandle,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    NOTIFICATION_MASK NotificationMask,
    PVOID EnlistmentKey OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenEnlistment(
    PHANDLE EnlistmentHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE ResourceManagerHandle,
    LPGUID EnlistmentGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationEnlistment(
    HANDLE EnlistmentHandle,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetInformationEnlistment(
    HANDLE EnlistmentHandle OPTIONAL,
    ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    PVOID EnlistmentInformation,
    ULONG EnlistmentInformationLength);

NTSYSAPI NTSTATUS NTAPI NtRecoverEnlistment(
    HANDLE EnlistmentHandle,
    PVOID EnlistmentKey OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtPrePrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtPrepareEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtCommitEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtRollbackEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtPrePrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtPrepareComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtCommitComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtReadOnlyEnlistment(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtRollbackComplete(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSinglePhaseReject(
    HANDLE EnlistmentHandle,
    PLARGE_INTEGER TmVirtualClock OPTIONAL);


/******************************************************************
 * Resource manager API
 *****************************************************************/

/* Since: 6.0 */

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef enum _RESOURCEMANAGER_INFORMATION_CLASS { 
    ResourceManagerBasicInformation = 0,
    ResourceManagerCompletionInformation = 1,
} RESOURCEMANAGER_INFORMATION_CLASS;

typedef struct _TRANSACTION_NOTIFICATION {
    PVOID TransactionKey;
    ULONG TransactionNotification;
    LARGE_INTEGER TmVirtualClock;
    ULONG ArgumentLength;
} TRANSACTION_NOTIFICATION, *PTRANSACTION_NOTIFICATION;
#endif

typedef GUID CRM_PROTOCOL_ID, *PCRM_PROTOCOL_ID;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID RmGuid,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    ULONG CreateOptions OPTIONAL,
    PUNICODE_STRING Description OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenResourceManager(
    PHANDLE ResourceManagerHandle,
    ACCESS_MASK DesiredAccess,
    HANDLE TmHandle,
    LPGUID ResourceManagerGuid OPTIONAL,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtRecoverResourceManager(
    HANDLE ResourceManagerHandle);

NTSYSAPI NTSTATUS NTAPI NtGetNotificationResourceManager(
    HANDLE ResourceManagerHandle,
    PTRANSACTION_NOTIFICATION TransactionNotification,
    ULONG NotificationLength,
    PLARGE_INTEGER Timeout OPTIONAL,
    PULONG ReturnLength OPTIONAL,
    ULONG Asynchronous,
    ULONG_PTR AsynchronousContext OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength,
    PULONG ReturnLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetInformationResourceManager(
    HANDLE ResourceManagerHandle,
    RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    PVOID ResourceManagerInformation,
    ULONG ResourceManagerInformationLength);

NTSYSAPI NTSTATUS NTAPI NtRegisterProtocolAddressInformation(
    HANDLE ResourceManager,
    PCRM_PROTOCOL_ID ProtocolId,
    ULONG ProtocolInformationSize,
    PVOID ProtocolInformation,
    ULONG CreateOptions OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtPropagationComplete(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    ULONG BufferLength,
    PVOID Buffer);

NTSYSAPI NTSTATUS NTAPI NtPropagationFailed(
    HANDLE ResourceManagerHandle,
    ULONG RequestCookie,
    NTSTATUS PropStatus);


/******************************************************************
 * Drivers API
 *****************************************************************/

NTSYSAPI NTSTATUS NTAPI NtLoadDriver(
    PUNICODE_STRING DriverServiceName);

NTSYSAPI NTSTATUS NTAPI NtUnloadDriver(
    PUNICODE_STRING DriverServiceName);


/******************************************************************
 * Time API
 *****************************************************************/

NTSYSAPI ULONG NTAPI NtGetTickCount();

NTSYSAPI NTSTATUS NTAPI NtQueryPerformanceCounter(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQuerySystemTime(
    PLARGE_INTEGER SystemTime);

NTSYSAPI NTSTATUS NTAPI NtQueryTimerResolution(
    PULONG MinimumResolution,
    PULONG MaximumResolution,
    PULONG CurrentResolution);

NTSYSAPI NTSTATUS NTAPI NtSetSystemTime(
    PLARGE_INTEGER SystemTime,
    PLARGE_INTEGER PreviousTime OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtSetTimerResolution(
    ULONG DesiredResolution,
    BOOLEAN SetResolution,
    PULONG CurrentResolution);

/******************************************************************
 * C runtime API
 *****************************************************************/

int vsprintf(
   char *buffer,
   const char *format,
   va_list argptr);

#endif // __NTDLL_H_INCLUDED
