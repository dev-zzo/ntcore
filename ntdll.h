#ifndef __NTDLL_H_INCLUDED
#define __NTDLL_H_INCLUDED

//#include <winternl.h>

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

#if 0
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
#ifdef _WIN64
// the following was inferred by painful reverse engineering
	SIZE_T		   PeakVirtualSize;	// not actually
    SIZE_T         PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         VirtualSize;		// not actually
#else
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
#endif
} VM_COUNTERS;

typedef struct _KAPC KAPC;
typedef KAPC *PKAPC;

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


/*
 * Object Manager
 */

 /* NOTE: Verify enumeration values. */
typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation,
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK DesiredAccess;
    ULONG HandleCount;
    ULONG ReferenceCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
    WCHAR NameBuffer[1];
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

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

NTSYSAPI NTSTATUS NTAPI NtClose(
    HANDLE ObjectHandle);


/*
 * SYSTEM
 */

/* http://www.exploit-monday.com/2013/06/undocumented-ntquerysysteminformation.html */
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation=0x0000,
    SystemProcessorInformation=0x0001,
    SystemPerformanceInformation=0x0002,
    SystemTimeOfDayInformation=0x0003,
    SystemPathInformation=0x0004,
    SystemProcessInformation=0x0005,
    SystemCallCountInformation=0x0006,
    SystemDeviceInformation=0x0007,
    SystemProcessorPerformanceInformation=0x0008,
    SystemFlagsInformation=0x0009,
    SystemCallTimeInformation=0x000A,
    SystemModuleInformation=0x000B,
    SystemLocksInformation=0x000C,
    SystemStackTraceInformation=0x000D,
    SystemPagedPoolInformation=0x000E,
    SystemNonPagedPoolInformation=0x000F,
    SystemHandleInformation=0x0010,
    SystemObjectInformation=0x0011,
    SystemPageFileInformation=0x0012,
    SystemVdmInstemulInformation=0x0013,
    SystemVdmBopInformation=0x0014,
    SystemFileCacheInformation=0x0015,
    SystemPoolTagInformation=0x0016,
    SystemInterruptInformation=0x0017,
    SystemDpcBehaviorInformation=0x0018,
    SystemFullMemoryInformation=0x0019,
    SystemLoadGdiDriverInformation=0x001A,
    SystemUnloadGdiDriverInformation=0x001B,
    SystemTimeAdjustmentInformation=0x001C,
    SystemSummaryMemoryInformation=0x001D,
    SystemMirrorMemoryInformation=0x001E,
    SystemPerformanceTraceInformation=0x001F,
    SystemCrashDumpInformation=0x0020,
    SystemExceptionInformation=0x0021,
    SystemCrashDumpStateInformation=0x0022,
    SystemKernelDebuggerInformation=0x0023,
    SystemContextSwitchInformation=0x0024,
    SystemRegistryQuotaInformation=0x0025,
    SystemExtendServiceTableInformation=0x0026,
    SystemPrioritySeperation=0x0027,
    SystemVerifierAddDriverInformation=0x0028,
    SystemVerifierRemoveDriverInformation=0x0029,
    SystemProcessorIdleInformation=0x002A,
    SystemLegacyDriverInformation=0x002B,
    SystemCurrentTimeZoneInformation=0x002C,
    SystemLookasideInformation=0x002D,
    SystemTimeSlipNotification=0x002E,
    SystemSessionCreate=0x002F,
    SystemSessionDetach=0x0030,
    SystemSessionInformation=0x0031,
    SystemRangeStartInformation=0x0032,
    SystemVerifierInformation=0x0033,
    SystemVerifierThunkExtend=0x0034,
    SystemSessionProcessInformation=0x0035,
    SystemLoadGdiDriverInSystemSpace=0x0036,
    SystemNumaProcessorMap=0x0037,
    SystemPrefetcherInformation=0x0038,
    SystemExtendedProcessInformation=0x0039,
    SystemRecommendedSharedDataAlignment=0x003A,
    SystemComPlusPackage=0x003B,
    SystemNumaAvailableMemory=0x003C,
    SystemProcessorPowerInformation=0x003D,
    SystemEmulationBasicInformation=0x003E,
    SystemEmulationProcessorInformation=0x003F,
    SystemExtendedHandleInformation=0x0040,
    SystemLostDelayedWriteInformation=0x0041,
    SystemBigPoolInformation=0x0042,
    SystemSessionPoolTagInformation=0x0043,
    SystemSessionMappedViewInformation=0x0044,
    SystemHotpatchInformation=0x0045,
    SystemObjectSecurityMode=0x0046,
    SystemWatchdogTimerHandler=0x0047,
    SystemWatchdogTimerInformation=0x0048,
    SystemLogicalProcessorInformation=0x0049,
    SystemWow64SharedInformationObsolete=0x004A,
    SystemRegisterFirmwareTableInformationHandler=0x004B,
    SystemFirmwareTableInformation=0x004C,
    SystemModuleInformationEx=0x004D,
    SystemVerifierTriageInformation=0x004E,
    SystemSuperfetchInformation=0x004F,
    SystemMemoryListInformation=0x0050,
    SystemFileCacheInformationEx=0x0051,
    SystemThreadPriorityClientIdInformation=0x0052,
    SystemProcessorIdleCycleTimeInformation=0x0053,
    SystemVerifierCancellationInformation=0x0054,
    SystemProcessorPowerInformationEx=0x0055,
    SystemRefTraceInformation=0x0056,
    SystemSpecialPoolInformation=0x0057,
    SystemProcessIdInformation=0x0058,
    SystemErrorPortInformation=0x0059,
    SystemBootEnvironmentInformation=0x005A,
    SystemHypervisorInformation=0x005B,
    SystemVerifierInformationEx=0x005C,
    SystemTimeZoneInformation=0x005D,
    SystemImageFileExecutionOptionsInformation=0x005E,
    SystemCoverageInformation=0x005F,
    SystemPrefetchPatchInformation=0x0060,
    SystemVerifierFaultsInformation=0x0061,
    SystemSystemPartitionInformation=0x0062,
    SystemSystemDiskInformation=0x0063,
    SystemProcessorPerformanceDistribution=0x0064,
    SystemNumaProximityNodeInformation=0x0065,
    SystemDynamicTimeZoneInformation=0x0066,
    SystemCodeIntegrityInformation=0x0067,
    SystemProcessorMicrocodeUpdateInformation=0x0068,
    SystemProcessorBrandString=0x0069,
    SystemVirtualAddressInformation=0x006A,
    SystemLogicalProcessorAndGroupInformation=0x006B,
    SystemProcessorCycleTimeInformation=0x006C,
    SystemStoreInformation=0x006D,
    SystemRegistryAppendString=0x006E,
    SystemAitSamplingValue=0x006F,
    SystemVhdBootInformation=0x0070,
    SystemCpuQuotaInformation=0x0071,
    SystemNativeBasicInformation=0x0072,
    SystemErrorPortTimeouts=0x0073,
    SystemLowPriorityIoInformation=0x0074,
    SystemBootEntropyInformation=0x0075,
    SystemVerifierCountersInformation=0x0076,
    SystemPagedPoolInformationEx=0x0077,
    SystemSystemPtesInformationEx=0x0078,
    SystemNodeDistanceInformation=0x0079,
    SystemAcpiAuditInformation=0x007A,
    SystemBasicPerformanceInformation=0x007B,
    SystemQueryPerformanceCounterInformation=0x007C,
    SystemSessionBigPoolInformation=0x007D,
    SystemBootGraphicsInformation=0x007E,
    SystemScrubPhysicalMemoryInformation=0x007F,
    SystemBadPageInformation=0x0080,
    SystemProcessorProfileControlArea=0x0081,
    SystemCombinePhysicalMemoryInformation=0x0082,
    SystemEntropyInterruptTimingInformation=0x0083,
    SystemConsoleInformation=0x0084,
    SystemPlatformBinaryInformation=0x0085,
    SystemThrottleNotificationInformation=0x0086,
    SystemHypervisorProcessorCountInformation=0x0087,
    SystemDeviceDataInformation=0x0088,
    SystemDeviceDataEnumerationInformation=0x0089,
    SystemMemoryTopologyInformation=0x008A,
    SystemMemoryChannelInformation=0x008B,
    SystemBootLogoInformation=0x008C,
    SystemProcessorPerformanceInformationEx=0x008D,
    SystemSpare0=0x008E,
    SystemSecureBootPolicyInformation=0x008F,
    SystemPageFileInformationEx=0x0090,
    SystemSecureBootInformation=0x0091,
    SystemEntropyInterruptTimingRawInformation=0x0092,
    SystemPortableWorkspaceEfiLauncherInformation=0x0093,
    SystemFullProcessInformation=0x0094,
    MaxSystemInfoClass=0x0095
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION
{
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

typedef struct _SYSTEM_PROCESS_INFORMATION
{
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

typedef struct _SYSTEM_PROCESSOR_INFORMATION {
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT MaximumProcessors;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

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


NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength);


/*
 * PROCESSES
 */

typedef struct _LDR_DATA_TABLE_ENTRY_NT513 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_NT513, *PLDR_DATA_TABLE_ENTRY_NT513;

typedef struct _PEB_LDR_DATA_NT513 {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA_NT513, *PPEB_LDR_DATA_NT513;

typedef struct _PEB_NT513 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr; /* PPEB_LDR_DATA */
    PVOID ProcessParameters; /* struct _RTL_USER_PROCESS_PARAMETERS * */
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID FreeList; /* PPEB_FREE_BLOCK */
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
} PEB_NT513, *PPEB_NT513;

typedef enum _PROCESS_INFORMATION_CLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
} PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

#define NtCurrentProcess() ((HANDLE)-1)

NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus);


/*
 * THREADS
 */

typedef struct _ACTIVATION_CONTEXT_STACK {
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    PVOID ActiveFrame;
    LIST_ENTRY FrameListCache;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PVOID FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME *Previous;
    TEB_ACTIVE_FRAME_CONTEXT *Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

/* Defined in winnt.h
typedef struct _NT_TIB {
    EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        ULONG Version;
    };
    PVOID ArbitraryUserPointer;
    _NT_TIB *Self;
} NT_TIB, *PNT_TIB;
*/

typedef struct __declspec(align(4)) _Wx86ThreadState {
    PUINT CallBx86Eip;
    PVOID DeallocationCpu;
    BOOLEAN UseKnownWx86Dll;
    BOOLEAN OleStubInvoked;
} Wx86ThreadState;

typedef struct _TEB_NT513 {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB_NT513 ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    ULONG CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    UINT ExceptionCode;
    ACTIVATION_CONTEXT_STACK ActivationContextStack;
    BYTE SpareBytes1[24];
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    PVOID GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    USHORT StaticUnicodeBuffer[261];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorsAreDisabled;
    PVOID Instrumentation[16];
    PVOID WinSockData;
    ULONG GdiBatchCount;
    BOOLEAN InDbgPrint;
    BOOLEAN FreeStackOnTermination;
    BOOLEAN HasFiberData;
    BYTE IdealProcessor;
    ULONG Spare3;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    Wx86ThreadState Wx86Thread;
    PVOID *TlsExpansionSlots;
    ULONG ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    PVOID CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    BOOLEAN SafeThunkCall;
    BOOLEAN BooleanSpare[3];
} TEB_NT513, *PTEB_NT513;

typedef struct _USER_STACK {
    PVOID FixedStackBase;
    PVOID FixedStackLimit;
    PVOID ExpandableStackBase;
    PVOID ExpandableStackLimit;
    PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _THREAD_INFORMATION_CLASS {          // num/query/set
    ThreadBasicInformation,                       //  0/Y/N
    ThreadTimes,                                  //  1/Y/N
    ThreadPriority,                               //  2/N/Y
    ThreadBasePriority,                           //  3/N/Y
    ThreadAffinityMask,                           //  4/N/Y
    ThreadImpersonationToken,                     //  5/N/Y
    ThreadDescriptorTableEntry,                   //  6/Y/N
    ThreadEnableAlignmentFaultFixup,              //  7/N/Y
    ThreadEventPair,                              //  8/N/Y
    ThreadQuerySetWin32StartAddress,              //  9/Y/Y
    ThreadZeroTlsCell,                            // 10/N/Y
    ThreadPerformanceCount,                       // 11/Y/N
    ThreadAmILastThread,                          // 12/Y/N
    ThreadIdealProcessor,                         // 13/N/Y
    ThreadPriorityBoost,                          // 14/Y/Y
    ThreadSetTlsArrayAddress,                     // 15/N/Y
    ThreadIsIoPending,                            // 16/Y/N
    ThreadHideFromDebugger                        // 17/N/Y
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

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

NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT pContext);

NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT pContext);

NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount);

NTSYSAPI NTSTATUS NTAPI NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount);

NTSYSAPI NTSTATUS NTAPI NtTerminateThread(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus);

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


/*
 * VIRTUAL MEMORY
 */

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetList,
    MemorySectionName,
    MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

/* Defined in winnt.h
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
*/

typedef struct _MEMORY_SECTION_NAME {
    UNICODE_STRING SectionFileName;
} MEMORY_SECTION_NAME, *PMEMORY_SECTION_NAME;

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

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff566460%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

/*
 * SECTIONS
 */

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

NTSYSAPI NTSTATUS NTAPI NtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

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


/*
 * FILES
 */

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileCopyOnWriteInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileObjectIdInformation,
    FileTrackingInformation,
    FileOleDirectoryInformation,
    FileContentIndexInformation,
    FileInheritContentIndexInformation,
    FileOleInformation,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

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

/* http://msdn.microsoft.com/en-us/library/windows/hardware/ff567011%28v=vs.85%29.aspx */
NTSYSAPI NTSTATUS NTAPI NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(
    HANDLE DeviceHandle,
    HANDLE Event,
    PIO_APC_ROUTINE UserApcRoutine,
    PVOID UserApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength);


/*
 * DEBUGGER
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


/*
 * LOCAL PROCEDURE CALLS
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

NTSYSAPI NTSTATUS NTAPI NtCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxDataSize,
    ULONG MaxMessageSize,
    ULONG Reserved);

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


/*
 * I/O
 */

NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(
    PHANDLE ReserveHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG ObjectType);

NTSYSAPI NTSTATUS NTAPI NtSetIoCompletion(
    HANDLE IoCompletionHandle,
    PVOID CompletionKey,
    PVOID CompletionContext,
    NTSTATUS CompletionStatus,
    ULONG CompletionInformation);

NTSYSAPI NTSTATUS NTAPI NtSetIoCompletionEx(
    HANDLE IoCompletionHandle,
    HANDLE ReserveHandle,
    PVOID CompletionKey,
    PVOID CompletionContext,
    NTSTATUS CompletionStatus,
    ULONG CompletionInformation);

/*
 * C runtime support
 */

int vsprintf(
   char *buffer,
   const char *format,
   va_list argptr);

#endif // __NTDLL_H_INCLUDED
