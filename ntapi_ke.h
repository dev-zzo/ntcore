#ifndef __NTAPI_KE_H_INCLUDED
#define __NTAPI_KE_H_INCLUDED

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

#endif
