#include "ntcore.h"

static void InitializeContext(PCONTEXT Context, UINT_PTR InitialEsp, PVOID InitialEip, PVOID Arg1, PVOID Arg2)
{
    Context->SegCs = 0x0018;
    Context->SegDs = 0x0020;
    Context->SegSs = 0x0020;
    Context->SegEs = 0x0020;
    Context->SegFs = 0x0038;
    Context->SegGs = 0x0000;
    Context->Esp = InitialEsp - sizeof(UINT_PTR);
    Context->Eip = (UINT_PTR)InitialEip;
    Context->Ecx = (UINT_PTR)Arg1;
    Context->Edx = (UINT_PTR)Arg2;
    Context->ContextFlags = CONTEXT_ALL;
}

NTSTATUS NtcCreateRemoteThread(PHANDLE ThreadHandle, HANDLE ProcessHandle, PTHREADPROC ThreadProc, PVOID Arg1, PVOID Arg2, SIZE_T StackSize)
{
    NTSTATUS Status;
    USER_STACK Stack;
    PVOID StackBottom = NULL;
    CONTEXT Context;
    OBJECT_ATTRIBUTES ThreadAttributes;
    CLIENT_ID ThreadClientId;

    Status = NtAllocateVirtualMemory(
        ProcessHandle,
        &StackBottom,
        0,
        &StackSize,
        MEM_COMMIT,
        PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Stack.FixedStackBase = NULL;
    Stack.FixedStackLimit = NULL;
    Stack.ExpandableStackBase = (PVOID)((UINT_PTR)StackBottom + StackSize);
    Stack.ExpandableStackLimit = StackBottom;
    Stack.ExpandableStackBottom = StackBottom;

    InitializeContext(&Context, (UINT_PTR)Stack.ExpandableStackBase, ThreadProc, Arg1, Arg2);
    InitializeObjectAttributes(&ThreadAttributes, NULL, 0, NULL, NULL);

    Status = NtCreateThread(
        ThreadHandle,
        0x1F03FF,
        &ThreadAttributes,
        ProcessHandle,
        &ThreadClientId, 
        &Context,
        &Stack,
        FALSE);

    return Status;
}

