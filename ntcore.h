#ifndef __ntcore_included
#define __ntcore_included

#include <windows.h>
#include "ntdll.h"

typedef void (__fastcall *PTHREADPROC)(PVOID Arg1, PVOID Arg2);

NTSTATUS NtcCreateRemoteThread(
    PHANDLE ThreadHandle,
    HANDLE ProcessHandle,
    PTHREADPROC ThreadProc,
    PVOID Arg1,
    PVOID Arg2,
    SIZE_T StackSize);

#endif // __ntcore_included
