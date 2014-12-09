#ifndef __WINTERNALS_INCLUDED
#define __WINTERNALS_INCLUDED

//#include <winternl.h>

/* Stuff not defined for userland programs */

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_ALERTED
#define STATUS_ALERTED                   ((NTSTATUS)0x00000101L)
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


NTSYSAPI NTSTATUS NTAPI NtClose(
    HANDLE Handle);


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

#endif // __WINTERNALS_INCLUDED
