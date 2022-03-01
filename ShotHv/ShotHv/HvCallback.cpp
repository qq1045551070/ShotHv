#include "HvPch.h"

_Use_decl_annotations_
VOID
WINAPI
DpcRunIntelHyperV(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ULONG CurrentCPU = KeGetCurrentProcessorNumber();
	DBG_PRINT("当前CPU-->%d\r\n", CurrentCPU);

	NTSTATUS ntStatus = RunIntelHyperV();

	if (NT_SUCCESS(ntStatus)) {
		DBG_PRINT("VT启动完毕! \r\n");
	}
	else {
		DBG_PRINT("VT启动失败! \r\n");
	}

	if (DeferredContext) {
		*(NTSTATUS*)DeferredContext = ntStatus;
	}
}

_Use_decl_annotations_
VOID
WINAPI
DpcUnRunIntelHyperV(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	
	NTSTATUS ntStatus = STATUS_SUCCESS;

	ntStatus = UnRunIntelHyperV();

	if (DeferredContext) {
		*(NTSTATUS*)DeferredContext = ntStatus;
	}
}

_Use_decl_annotations_
VOID
WINAPI
PHHookCallbackDPC(
	_In_ PRKDPC Dpc,
	_In_ PVOID Context,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PPAGE_HOOK_CONTEXT pHookEntry = (PPAGE_HOOK_CONTEXT)Context;

	if (pHookEntry)
	{
		if (Stop == pHookEntry->State)
		{
			HvVmCall(CallUnHookPage,
				pHookEntry->HookAddress,
				pHookEntry->DataPagePFN,
				pHookEntry->Cr3);
		}
		else
		{
			HvVmCall(pHookEntry->Hook ? CallHookPage : CallUnHookPage,
				pHookEntry->HookAddress,
				pHookEntry->Hook ? pHookEntry->CodePagePFN : pHookEntry->DataPagePFN,
				pHookEntry->Cr3);
		}	
	}
}