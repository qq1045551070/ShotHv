#pragma once

/*
	PAGE HOOK初始化
*/
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS 
WINAPI
PHInitlizetion();

/*
	根据PFN获取HOOK CONTEXT
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
PPAGE_HOOK_CONTEXT
WINAPI
PHGetHookContextByPFN(
	_In_ ULONG64 PA,
	_In_ PAGE_TYPE Type
);

/*
	根据HookAddress VA获取HOOK CONTEXT
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
PPAGE_HOOK_CONTEXT
WINAPI
PHGetHookContextByVA(
	_In_ ULONG64 VA,
	_In_ PAGE_TYPE Type
);

/*
	跟据VA获取该页面被HOOK的次数
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WINAPI
PHPageHookCount(
	_In_ ULONG64 VA,
	_In_ PAGE_TYPE Type
);

/*
	EPT HOOK
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
PHHook(
	_In_	PVOID  pFunc, 
	_In_	PVOID  pHook,
	_Inout_ PVOID* pOriFun
);

/*
	EPT UNHOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
PHUnHook(
	_In_ PVOID pFunc
);

/*
	ALL EPT UNHOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
PHUnAllHook();

/*
	激活所有就绪状态的 EPT HOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
PHActivateHooks();

/*
	修改 EPT HOOK STATE
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
PHUpdateHookState(
	_In_ PVOID	 pFunc,
	_In_ ULONG64 State
);

/*
	隐藏内存CODE
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
PHHideMem(
	_In_ PVOID Address,
	_In_ PVOID Code, 
	_In_ ULONG Size
);

/*
	获取目标Cr3
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG64
WINAPI
PHGetHookCr3(
	_In_ PEPROCESS Process,
	_In_ BOOL IsKernel
);