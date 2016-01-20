#ifndef __NTAPI_OB_H_INCLUDED
#define __NTAPI_OB_H_INCLUDED

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
#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
    ObjectSessionInformation = 5,           // N/Y
#endif
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

NTSYSAPI NTSTATUS NTAPI NtSignalAndWaitForSingleObject(
    HANDLE ObjectToSignal,
    HANDLE WaitableObject,
    BOOLEAN Alertable,
    PLARGE_INTEGER Time OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtMakePermanentObject(
    HANDLE ObjectHandle);

NTSYSAPI NTSTATUS NTAPI NtMakeTemporaryObject(
    HANDLE ObjectHandle);

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

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WIN8)
NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObjectEx(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ShadowDirectoryHandle,
    ULONG Flags);
#endif

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
 * Namespace API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreatePrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID BoundaryDescriptor);

NTSYSAPI NTSTATUS NTAPI NtOpenPrivateNamespace(
    PHANDLE NamespaceHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID BoundaryDescriptor);

NTSYSAPI NTSTATUS NTAPI NtDeletePrivateNamespace(
    HANDLE NamespaceHandle);

#endif

#endif
