#pragma once

/*
	检测系统对EPT的支持
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
CheckHvEptSupported();

/*
	初始化 EPT
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
InitlizetionHvEpt();

/*
	卸载 EPT
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
WINAPI
UnInitlizetionHvEpt();

/*
	获取MTRR相关信息
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
GetHvEptMtrrInFo();

/*
	构建EPT内存
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
BuildHvEptMemory();

/*
	设置EPT内存类型
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
SetEptMemoryByMttrInfo(
	_In_ HvContextEntry* ContextEntry,
	_In_ INT i,
	_In_ INT j
);

/*
	设置EPTP
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
SetEptp(
	_In_ HvContextEntry* ContextEntry
);

/*
	构建DynamicSplit
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
BuildHvEptDynamicSplit();

/*
	获取空闲的EPT_DYNAMIC_SPLIT内存
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
EPT_DYNAMIC_SPLIT*
WINAPI
GetHvEptDynamicSplit();

/*
	刷新EPT内存页表
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
EptUpdateTable(
	_In_ HvEptEntry* Table,
	_In_ EPT_ACCESS Access,
	_In_ ULONG64 PA,
	_In_ ULONG64 PFN
);

/*
	获取EPT对应项
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
PEPTE
WINAPI
EptGetEpteEntry(
	_In_ HvEptEntry* Table,
	_In_ ULONG64 PA
);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WINAPI
EptSplitLargePage(
	_In_ EPDE_2MB* LargeEptPde,
	_In_ EPT_DYNAMIC_SPLIT* PreAllocatedBuffer
);

/*
	获取EPTE
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
PEPTE
WINAPI
EptGetPml1Entry(
	_In_ HvEptEntry* EptPageTable,
	_In_ SIZE_T PhysicalAddress
);

/*
	获取EPDE
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
PEPDE_2MB
WINAPI
EptGetPml2Entry(
	_In_ HvEptEntry* EptPageTable,
	_In_ SIZE_T PhysicalAddress
);

/*
	处理EPT-VMX-EXIT
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WINAPI
EptViolationHandler(
	_In_ GuestReg* Registers
);

