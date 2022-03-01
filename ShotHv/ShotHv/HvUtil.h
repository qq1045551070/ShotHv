#pragma once

/*
	APC等级以下的全逻辑内核调用分发
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
WINAPI
UtilForEachProcessor(
	_In_ NTSTATUS(*callback_routine)(void*),
	_In_opt_ void* context
);

/*
	DPC等级的全逻辑内核调用分发
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
UtilForEachProcessorDpc(
	_In_ PKDEFERRED_ROUTINE deferred_routine,
	_In_opt_ void* context
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WINAPI
UtilGetSelectorInfoBySelector(
	ULONG_PTR selector,
	ULONG_PTR* base,
	ULONG_PTR* limit,
	ULONG_PTR* attribute
);

/*
	注册关机回调
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WINAPI
RegisterShutdownCallBack(
	_In_ NTSTATUS (*ShutDownCallBack)(_In_ PDEVICE_OBJECT, _In_ PIRP)
);

/*
	卸载关机回调
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
WINAPI
UnRegisterShutdownCallBack();

BOOLEAN
WINAPI
BuildShellCode1(
	_Inout_ PHOOK_SHELLCODE1 pThunk,
	_In_	ULONG64 Pointer,
	_In_    BOOLEAN isX64
);

ULONG64
WINAPI
UtilPhysicalAddressToVirtualAddress(
	_In_ ULONG64 PhysicalAddress
);

ULONG64
WINAPI
UtilVirtualAddressToPhysicalAddress(
	_In_ ULONG64 VrtualAddress
);

/*
	R3 地址校验
*/
BOOLEAN
WINAPI
ProbeUserAddress(
	_In_ PVOID addr,
	_In_ SIZE_T size,
	_In_ ULONG alignment
);

/*
	R0 地址校验
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOL
WINAPI
ProbeKernelAddress(
	_In_ PVOID  addr,
	_In_ SIZE_T size,
	_In_ ULONG  alignment
);

/*
	安全拷贝数据
*/
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
WINAPI
SafeCopy(
	_In_ PVOID dest,
	_In_ PVOID src,
	_In_ SIZE_T size
);

/*
	设置先前模式
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
KPROCESSOR_MODE
WINAPI
KeSetPreviousMode(
	_In_ KPROCESSOR_MODE Mode
);

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG_PTR
WINAPI
QueryKernelModule(
	_In_	PUCHAR moduleName,
	_Inout_ ULONG_PTR* moduleSize
);

DWORD
WINAPI
GetUserCr3Offset();