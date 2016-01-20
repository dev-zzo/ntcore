#ifndef __NTAPI_IO_H_INCLUDED
#define __NTAPI_IO_H_INCLUDED

/******************************************************************
 * File API
 *****************************************************************/

/*
 * Types
 */

/* CreateDisposition flags */

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

/* CreateOptions or OpenOptions flags */

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

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
#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
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
#endif
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef struct _FILE_PIPE_INFORMATION {
    ULONG ReadMode;
    ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION {
    ULONG NamedPipeType;
    ULONG NamedPipeConfiguration;
    ULONG MaximumInstances;
    ULONG CurrentInstances;
    ULONG InboundQuota;
    ULONG ReadDataAvailable;
    ULONG OutboundQuota;
    ULONG WriteQuotaAvailable;
    ULONG NamedPipeState;
    ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION {
    LARGE_INTEGER CollectDataTime;
    ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;

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
    ULONG FileInformationLength,
    FILE_INFORMATION_CLASS FileInformationClass);

NTSYSAPI NTSTATUS NTAPI NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG FileInformationLength,
    FILE_INFORMATION_CLASS FileInformationClass);


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
 * Input/Output Manager API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WIN7)

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtAllocateReserveObject(
    PHANDLE ReserveHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG ObjectType);

#endif

#endif
