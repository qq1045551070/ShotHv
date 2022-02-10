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
	R0 EPT HOOK
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
PHR0Hook(
	_In_	PVOID  pFunc, 
	_In_	PVOID  pHook,
	_Inout_ PVOID* pOriFun
);

/*
	R0 EPT UNHOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
PHR0UnHook(
	_In_ PVOID pFunc
);

/*
	ALL R0 EPT UNHOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
PHUnAllHook();

/*
	激活所有就绪状态的 R0 EPT HOOK
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WINAPI
PHActivateR0Hooks();