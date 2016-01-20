#ifndef __NTAPI_SE_H_INCLUDED
#define __NTAPI_SE_H_INCLUDED

/******************************************************************
 * Security token API
 *****************************************************************/

/*
 * Types
 */

#if __INCLUDE_WINNT_DEFINES
typedef struct _ACL {
    CHAR AclRevision;
    CHAR Sbz1;
    USHORT AclSize;
    USHORT AceCount;
    USHORT Sbz2;
} ACL, *PACL;

typedef struct _SID_IDENTIFIER_AUTHORITY {
    CHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    CHAR Revision;
    CHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[1];
} SID, *PSID;

typedef struct _SID_AND_ATTRIBUTES {
    PVOID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    ULONG Attributes;
} LUID_AND_ATTRIBUTES;

typedef struct _TOKEN_OWNER {
    PVOID Owner;
} TOKEN_OWNER;

typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _TOKEN_PRIMARY_GROUP {
    PVOID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;

typedef struct _TOKEN_GROUPS {
    ULONG GroupCount;
    SID_AND_ATTRIBUTES Groups[1];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

typedef struct _TOKEN_DEFAULT_DACL {
    ACL *DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_SOURCE {
    CHAR SourceName[8];
    LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;
#endif /* __INCLUDE_WINNT_DEFINES */

/*
 * Functions
 */

NTSYSAPI NTSTATUS NTAPI NtCreateToken(
    PHANDLE TokenHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TOKEN_TYPE TokenType,
    PLUID AuthenticationId,
    PLARGE_INTEGER ExpirationTime,
    PTOKEN_USER TokenUser,
    PTOKEN_GROUPS TokenGroups,
    PTOKEN_PRIVILEGES TokenPrivileges,
    PTOKEN_OWNER TokenOwner,
    PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
    PTOKEN_DEFAULT_DACL TokenDefaultDacl,
    PTOKEN_SOURCE TokenSource);

NTSYSAPI NTSTATUS NTAPI NtDuplicateToken(
    HANDLE ExistingToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    TOKEN_TYPE TokenType,
    PHANDLE NewToken );

NTSYSAPI NTSTATUS NTAPI NtOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle);

NTSYSAPI NTSTATUS NTAPI NtOpenThreadToken(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_WINXP)
NTSYSAPI NTSTATUS NTAPI NtOpenProcessTokenEx(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    PHANDLE TokenHandle);

NTSYSAPI NTSTATUS NTAPI NtOpenThreadTokenEx(
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    BOOLEAN OpenAsSelf,
    ULONG HandleAttributes,
    PHANDLE TokenHandle);
#endif

NTSYSAPI NTSTATUS NTAPI NtAdjustGroupsToken(
    HANDLE TokenHandle,
    BOOLEAN ResetToDefault,
    PTOKEN_GROUPS TokenGroups,
    ULONG PreviousGroupsLength,
    PTOKEN_GROUPS PreviousGroups OPTIONAL,
    PULONG RequiredLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES TokenPrivileges,
    ULONG PreviousPrivilegesLength,
    PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
    PULONG RequiredLength OPTIONAL);

NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength);

NTSYSAPI NTSTATUS NTAPI NtQuerySecurityAttributesToken(
    HANDLE TokenHandle,
    PUNICODE_STRING Attributes,
    ULONG NumberOfAttributes,
    PVOID Buffer,
    ULONG Length,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI NtCompareTokens(
    HANDLE FirstTokenHandle,
    HANDLE SecondTokenHandle,
    PBOOLEAN Equal);

NTSYSAPI NTSTATUS NTAPI NtFilterToken(
    HANDLE ExistingTokenHandle,
    ULONG Flags,
    PTOKEN_GROUPS SidsToDisable OPTIONAL,
    PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    PTOKEN_GROUPS RestrictedSids OPTIONAL,
    PHANDLE NewTokenHandle);

NTSYSAPI NTSTATUS NTAPI NtAccessCheck(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtAccessCheckByType(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtAccessCheckByTypeResultList(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSID PrincipalSelfSid OPTIONAL,
    HANDLE ClientToken,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE_LIST ObjectTypeList,
    ULONG ObjectTypeListLength,
    PGENERIC_MAPPING GenericMapping,
    PPRIVILEGE_SET PrivilegeSet,
    PULONG PrivilegeSetLength,
    PACCESS_MASK GrantedAccess,
    PNTSTATUS AccessStatus);

NTSYSAPI NTSTATUS NTAPI NtPrivilegeCheck(
    HANDLE TokenHandle,
    PPRIVILEGE_SET RequiredPrivileges,
    PBOOLEAN Result);

NTSYSAPI NTSTATUS NTAPI NtAllocateLocallyUniqueId(
    PLUID LocallyUniqueId);

NTSYSAPI NTSTATUS NTAPI NtAllocateUuids(
    PLARGE_INTEGER Time,
    PULONG Range,
    PULONG Sequence);

#endif
