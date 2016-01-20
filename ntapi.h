#ifndef __NTAPI_H_INCLUDED
#define __NTAPI_H_INCLUDED

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


typedef struct _KDPC KDPC, *PKDPC;

typedef VOID (NTAPI *PKDEFERRED_ROUTINE) (
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

#include "ntapi_ob.h"
#include "ntapi_ps.h"
#include "ntapi_io.h"
#include "ntapi_ke.h"
#include "ntapi_cm.h"
#include "ntapi_mm.h"
#include "ntapi_se.h"
#include "ntapi_sys.h"
#include "ntapi_lpc.h"
#include "ntapi_dbg.h"
#include "ntapi_tm.h"

/******************************************************************
 * Drivers API
 *****************************************************************/

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtLoadDriver(
    PUNICODE_STRING DriverServiceName);

NTSYSAPI NTSTATUS NTAPI NtUnloadDriver(
    PUNICODE_STRING DriverServiceName);


/******************************************************************
 * Power API
 *****************************************************************/

#if __INCLUDE_WINNT_DEFINES
typedef enum _POWER_INFORMATION_LEVEL {
    SystemPowerPolicyAc,
    SystemPowerPolicyDc,
    VerifySystemPolicyAc,
    VerifySystemPolicyDc,
    SystemPowerCapabilities,
    SystemBatteryState,
    SystemPowerStateHandler,
    ProcessorStateHandler,
    SystemPowerPolicyCurrent,
    AdministratorPowerPolicy,
    SystemReserveHiberFile,
    ProcessorInformation,
    SystemPowerInformation,
    ProcessorStateHandler2,
    LastWakeTime,
    LastSleepTime,
    SystemExecutionState,
    SystemPowerStateNotifyHandler,
    ProcessorPowerPolicyAc,
    ProcessorPowerPolicyDc,
    VerifyProcessorPowerPolicyAc,
    VerifyProcessorPowerPolicyDc,
    ProcessorPowerPolicyCurrent,
} POWER_INFORMATION_LEVEL;
#endif

typedef ULONG EXECUTION_STATE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtSetThreadExecutionState(
    EXECUTION_STATE esFlags,
    EXECUTION_STATE *PreviousFlags);
                       
NTSYSAPI NTSTATUS NTAPI NtPowerInformation(
    POWER_INFORMATION_LEVEL InformationLevel,
    PVOID InputBuffer OPTIONAL,
    ULONG InputBufferLength,
    PVOID OutputBuffer OPTIONAL,
    ULONG OutputBufferLength);


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
 * VDM API
 *****************************************************************/

NTSYSAPI NTSTATUS NTAPI NtVdmControl(
    ULONG ControlCode,
    PVOID ControlData);


/******************************************************************
 * C runtime API
 *****************************************************************/

int vsprintf(
   char *buffer,
   const char *format,
   va_list argptr);

#endif // __NTDLL_H_INCLUDED
