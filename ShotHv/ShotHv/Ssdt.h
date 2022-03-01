#pragma once

typedef struct _SSDT_ENTRY
{
	LONG* pServiceTable;
	PVOID pCounterTable;
	ULONGLONG NumberOfServices;
	PCHAR pArgumentTable;
}SSDT_ENTRY, * PSSDT_ENTRY;

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID
WINAPI
GetSsdtFunctionAddress(
	_In_ CHAR* ApiName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
WINAPI
GetSsdtFunctionIndex(
	_In_ PCHAR funName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG
WINAPI
GetIndexFromExportTable(
	_In_ PVOID pBaseAddress,
	_In_ PCHAR pszFunctionName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
SSDT_ENTRY*
WINAPI
GetSstdEntry();

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WINAPI
DllFileMap(
	_In_	UNICODE_STRING ustrDllFileName,
	_Inout_ HANDLE* phFile,
	_Inout_ HANDLE* phSection,
	_Inout_ PVOID* ppBaseAddress
);