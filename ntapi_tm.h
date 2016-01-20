#ifndef __NTAPI_TM_H_INCLUDED
#define __NTAPI_TM_H_INCLUDED

/******************************************************************
 * Transaction manager API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

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

#endif


/******************************************************************
 * Transaction API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

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

#endif


/******************************************************************
 * Transaction enlistment API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

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

#endif


/******************************************************************
 * Resource manager API
 *****************************************************************/

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

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

#endif

#endif
