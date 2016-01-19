#ifndef __RTLAPI_H_INCLUDED
#define __RTLAPI_H_INCLUDED

/******************************************************************
 * Strings API
 *****************************************************************/

NTSYSAPI VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PWSTR SourceString OPTIONAL);

NTSYSAPI VOID NTAPI RtlInitUnicodeStringEx(
    PUNICODE_STRING DestinationString,
    PWSTR SourceString OPTIONAL);

NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeString(
    PUNICODE_STRING DestinationString,
    PWSTR SourceString);

NTSYSAPI BOOLEAN NTAPI RtlCreateUnicodeStringFromAsciiz(
    PUNICODE_STRING DestinationString,
    PSTR SourceString);

NTSYSAPI VOID NTAPI RtlFreeUnicodeString(
    PUNICODE_STRING UnicodeString);


#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE (0x00000001)
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING (0x00000002)

NTSYSAPI VOID NTAPI RtlDuplicateUnicodeString(
    ULONG Flags,
    PUNICODE_STRING StringIn,
    PUNICODE_STRING StringOut);

NTSYSAPI VOID NTAPI RtlCopyUnicodeString(
    PUNICODE_STRING DestinationString,
    PUNICODE_STRING SourceString OPTIONAL);

NTSYSAPI BOOLEAN NTAPI RtlPrefixUnicodeString(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive);

NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeStringToString(
    PUNICODE_STRING Destination,
    PUNICODE_STRING Source);

NTSYSAPI NTSTATUS NTAPI RtlAppendUnicodeToString(
    PUNICODE_STRING Destination,
    PWSTR Source OPTIONAL);

NTSYSAPI VOID NTAPI RtlEraseUnicodeString(
    PUNICODE_STRING String);


NTSYSAPI WCHAR NTAPI RtlUpcaseUnicodeChar(
    WCHAR SourceCharacter);

NTSYSAPI WCHAR NTAPI RtlDowncaseUnicodeChar(
    WCHAR SourceCharacter);

NTSYSAPI VOID NTAPI RtlUpcaseUnicodeString(
    _Inout_ PUNICODE_STRING DestinationString,
    PUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSYSAPI VOID NTAPI RtlDowncaseUnicodeString(
    _Inout_ PUNICODE_STRING DestinationString,
    PUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );


NTSYSAPI LONG NTAPI RtlCompareUnicodeString(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_VISTA)
NTSYSAPI LONG NTAPI RtlCompareUnicodeStrings(
    PWCH String1,
    SIZE_T String1Length,
    PWCH String2,
    SIZE_T String2Length,
    BOOLEAN CaseInSensitive);
#endif

NTSYSAPI BOOLEAN NTAPI RtlEqualUnicodeString(
    PUNICODE_STRING String1,
    PUNICODE_STRING String2,
    BOOLEAN CaseInSensitive);

#define HASH_STRING_ALGORITHM_DEFAULT 0
#define HASH_STRING_ALGORITHM_X65599 1
#define HASH_STRING_ALGORITHM_INVALID 0xffffffff

NTSYSAPI VOID NTAPI RtlHashUnicodeString(
    PUNICODE_STRING String,
    BOOLEAN CaseInSensitive,
    ULONG HashAlgorithm,
    PULONG HashValue);

NTSYSAPI VOID NTAPI RtlValidateUnicodeString(
    ULONG Flags,
    PUNICODE_STRING String);


#define RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END 0x00000001
#define RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET 0x00000002
#define RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE 0x00000004

NTSYSAPI VOID NTAPI RtlFindCharInUnicodeString(
    ULONG Flags,
    PUNICODE_STRING StringToSearch,
    PUNICODE_STRING CharSet,
    PUSHORT NonInclusivePrefixLength);

/******************************************************************
 * Path API
 *****************************************************************/

typedef struct _RTLP_CURDIR_REF *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(
    PWSTR DosFileName,
    PUNICODE_STRING NtFileName,
    PWSTR *FilePart OPTIONAL,
    PRTL_RELATIVE_NAME_U RelativeName OPTIONAL);

#if (NTAPI_LEVEL >= NTAPI_LEVEL_SERVER2K3)
NTSYSAPI NTSTATUS NTAPI RtlDosPathNameToNtPathName_U_WithStatus(
    PWSTR DosFileName,
    PUNICODE_STRING NtFileName,
    PWSTR *FilePart OPTIONAL,
    PRTL_RELATIVE_NAME_U RelativeName OPTIONAL);
#endif

/******************************************************************
 * OS Version API
 *****************************************************************/

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    PRTL_OSVERSIONINFOW lpVersionInformation);

#endif
