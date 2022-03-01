#pragma once

PVOID
WINAPI
ShotHvMemoryAllocate(
	_In_ SIZE_T  Size,
	_In_ BOOLEAN isKernel
);

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID
WINAPI
AllocateR3Memory(
	_In_ HANDLE Pid,
	_In_ SIZE_T Size
);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
WINAPI
SetExecutePage(
	_In_ PVOID VirtualAddress,
	_In_ ULONG Size
);

_IRQL_requires_max_(DISPATCH_LEVEL)
PPAGE_ENTRY
WINAPI
MiGetPdeAddress(
	_In_ PVOID Va,
	_In_ PML Level
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WINAPI
FreeR3Memory(
	_In_ HANDLE Pid,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T Size
);