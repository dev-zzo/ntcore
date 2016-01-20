#ifndef __NTAPI_MM_H_INCLUDED
#define __NTAPI_MM_H_INCLUDED

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

#endif
