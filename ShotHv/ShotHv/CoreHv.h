#pragma once

/*
	启用 Intel VT
*/
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
EnableIntelVT();

_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
DisableIntelVT();

/*
	检测对VT环境的支持
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
CheckHvSupported();

/*
	检测硬件环境支持
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
CheckHvHardwareSupported();

/*
	检测系统环境支持
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
CheckHvOsSupported();

/*
	申请HV所需要的内存
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
InitlizetionIntelHvContext(
	_In_opt_ PVOID Args
);

/*
	初始化VMX所需要的内存结构
*/
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
InitiationVmxContext();

/*
	正式运行HV
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
RunIntelHyperV();

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
UnRunIntelHyperV();

/*
	初始化 VMCS
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
InitiationVmCsContext();

/*
	初始化 MSR
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
InitiationMsrContext();

/*
	初始化并激活 VMCS 区域
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
ExecuteVmxOn();

/*
	启动 Intel VT
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(DISPATCH_LEVEL)
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS
WINAPI
ExecuteVmlaunch();

/*
	清理 VMX
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS 
WINAPI
ClearVmxContext();

/*
	终止HV初始化
*/
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WINAPI
StopHvInitlizetion();

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WINAPI
VmxCsWrite(
	_In_ ULONG64 target_field, 
	_In_ ULONG64 value
);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG64
WINAPI
VmxCsRead(
	_In_ ULONG64 target_field
);

ULONG
WINAPI 
VmxAdjustControlValue(
	_In_ ULONG Msr, 
	_In_ ULONG Ctl
);

HvContextEntry*
WINAPI
GetHvContextEntry();

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WINAPI
HvRestoreRegisters();

BOOLEAN
WINAPI
HvVmCall(
	_In_ ULONG CallNumber,	/*序号*/
	_In_ ULONG64 arg1 = 0, 
	_In_ ULONG64 arg2 = 0, 
	_In_ ULONG64 arg3 = 0
);