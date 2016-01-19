#ifndef __RTLAPI_H_INCLUDED
#define __RTLAPI_H_INCLUDED

/******************************************************************
 * Strings API
 *****************************************************************/

NTSYSAPI VOID NTAPI RtlInitUnicodeString(
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



#endif
