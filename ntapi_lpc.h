#ifndef __NTAPI_LPC_H_INCLUDED
#define __NTAPI_LPC_H_INCLUDED

/******************************************************************
 * Port API
 *****************************************************************/

/*
 * Types
 */

typedef struct _PORT_VIEW
{
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    ULONG ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
    ULONG Length;
    ULONG ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef struct _PORT_MESSAGE
{
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;       // Force quadword alignment
    };
    ULONG MessageId;
    union {
        ULONG ClientViewSize;               // Only valid on LPC_CONNECTION_REQUEST message
        ULONG CallbackId;                   // Only valid on LPC_REQUEST message
    };
    //  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreatePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxDataSize,
    ULONG MaxMessageSize,
    ULONG Reserved);

NTSYSAPI NTSTATUS NTAPI NtCreateWaitablePort(
    PHANDLE PortHandle,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG MaxConnectInfoLength,
    ULONG MaxDataLength,
    ULONG MaxPoolUsage);

NTSYSAPI NTSTATUS NTAPI NtAcceptConnectPort(
    PHANDLE PortHandle,
    PVOID PortContext,
    PPORT_MESSAGE ConnectionRequest,
    BOOLEAN AcceptConnection,
    PPORT_VIEW ServerView,
    PREMOTE_PORT_VIEW ClientView);

NTSYSAPI NTSTATUS NTAPI NtListenPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ConnectionRequest);

NTSYSAPI NTSTATUS NTAPI NtConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    PPORT_VIEW ClientView,
    PREMOTE_PORT_VIEW ServerView,
    PULONG MaxMessageLength,
    PVOID ConnectionInformation,
    PULONG ConnectionInformationLength);

NTSYSAPI NTSTATUS NTAPI NtSecureConnectPort(
    PHANDLE PortHandle,
    PUNICODE_STRING PortName,
    PSECURITY_QUALITY_OF_SERVICE Qos,
    PPORT_VIEW ClientView OPTIONAL,
    PSID ServerSid OPTIONAL,
    PREMOTE_PORT_VIEW ServerView OPTIONAL,
    PULONG MaxMessageLength OPTIONAL,
    PVOID ConnectionInformation OPTIONAL,
    PULONG ConnectionInformationLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtCompleteConnectPort(
    HANDLE PortHandle);

NTSYSAPI NTSTATUS NTAPI NtReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage);

NTSYSAPI NTSTATUS NTAPI NtReplyWaitReceivePortEx(
    HANDLE PortHandle,
    PVOID *PortContext OPTIONAL,
    PPORT_MESSAGE ReplyMessage OPTIONAL,
    PPORT_MESSAGE ReceiveMessage,
    DWORD ReceiveMessageLen);

NTSYSAPI NTSTATUS NTAPI NtReplyWaitReplyPort(
    HANDLE PortHandle,
    PPORT_MESSAGE ReplyMessage);

NTSYSAPI NTSTATUS NTAPI NtRequestPort(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage);

NTSYSAPI NTSTATUS NTAPI NtRequestWaitReplyPortEx(
    HANDLE PortHandle,
    PPORT_MESSAGE RequestMessage,
    PPORT_MESSAGE ReplyMessage,
    DWORD ReplyMessageLength);

NTSYSAPI NTSTATUS NTAPI NtClosePort(
    HANDLE PortHandle);

NTSYSAPI NTSTATUS NTAPI NtWriteRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten);

NTSYSAPI NTSTATUS NTAPI NtReadRequestData(
    HANDLE PortHandle,
    PPORT_MESSAGE Message,
    ULONG DataEntryIndex,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesRead);

NTSYSAPI NTSTATUS NTAPI NtImpersonateClientOfPort(
    HANDLE PortHandle,
    PPORT_MESSAGE Message);


/******************************************************************
 * Advanced LPC API
 *****************************************************************/

 #if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)

/*
 * Types
 */

typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    ULONG MaxMessageLength;
    ULONG MemoryBandwidth;
    ULONG MaxPoolUsage;
    ULONG MaxSectionSize;
    ULONG MaxViewSize;
    ULONG MaxTotalSectionSize;
    ULONG DupObjectTypes;
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtAlpcCreatePort(
    PHANDLE PortObject,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PALPC_PORT_ATTRIBUTES pPortInformation);

#endif

#endif
