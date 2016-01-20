#ifndef __NTAPI_CM_H_INCLUDED
#define __NTAPI_CM_H_INCLUDED

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

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)
NTSYSAPI NTSTATUS NTAPI NtCreateKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class OPTIONAL,
    ULONG CreateOptions,
    HANDLE TransactionHandle,
    PULONG Disposition OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtOpenKeyTransacted(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE TransactionHandle);
#endif

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WIN7)
NTSYSAPI NTSTATUS NTAPI NtOpenKeyEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions);

NTSYSAPI NTSTATUS NTAPI NtOpenKeyTransactedEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions,
    HANDLE TransactionHandle);
#endif

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

#endif
