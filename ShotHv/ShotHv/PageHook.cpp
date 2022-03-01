#include "HvPch.h"

static KSPIN_LOCK g_PageLock = {};
static PAGE_HOOK_CONTEXT g_PageHookList  = { 0 };

_Use_decl_annotations_
NTSTATUS
WINAPI
PHInitlizetion()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	InitializeListHead(&g_PageHookList.List);

	return ntStatus;
}

_Use_decl_annotations_
PPAGE_HOOK_CONTEXT 
WINAPI
PHGetHookContextByPFN(
	_In_ ULONG64 PA, 
	_In_ PAGE_TYPE Type
)
{
#ifndef USE_HV_EPT
	return NULL;
#endif

	PPAGE_HOOK_CONTEXT pRet = NULL;

	ULONG64 tPFN = 0;

	KIRQL OldIrql;

	KeAcquireSpinLock(&g_PageLock, &OldIrql);

	if (!PA || IsListEmpty(&g_PageHookList.List)) {
		goto DONE;
	}

	tPFN = PFN( PA );

	for (PLIST_ENTRY pListEntry = g_PageHookList.List.Flink; pListEntry != &g_PageHookList.List; pListEntry = pListEntry->Flink)
	{
		PAGE_HOOK_CONTEXT* pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_CONTEXT, List);
		if (!MmIsAddressValid(pEntry) || FALSE == pEntry->Hook) continue;

		if ((Type == DATA_PAGE && pEntry->DataPagePFN == tPFN) || (Type == CODE_PAGE && pEntry->CodePagePFN == tPFN)) {
			pRet = pEntry;
			goto DONE;
		}
	}

DONE:
	KeReleaseSpinLock(&g_PageLock, OldIrql);

	return pRet;
}

_Use_decl_annotations_
PPAGE_HOOK_CONTEXT
WINAPI
PHGetHookContextByVA(
	_In_ ULONG64 VA,
	_In_ PAGE_TYPE Type
)
{
#ifndef USE_HV_EPT
	return NULL;
#endif

	UNREFERENCED_PARAMETER(Type);

	PPAGE_HOOK_CONTEXT pRet = NULL;

	KIRQL OldIrql;

	KeAcquireSpinLock(&g_PageLock, &OldIrql);

	if (!VA || IsListEmpty(&g_PageHookList.List)) {
		goto DONE;
	}

	for (PLIST_ENTRY pListEntry = g_PageHookList.List.Flink; pListEntry != &g_PageHookList.List; pListEntry = pListEntry->Flink)
	{
		PAGE_HOOK_CONTEXT* pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_CONTEXT, List);
		if (!MmIsAddressValid(pEntry) || FALSE == pEntry->Hook) continue;

		if (pEntry->Cr3 == __readcr3() && ((pEntry->HookAddress == VA || pEntry->DetourAddress == VA))) {
			pRet = pEntry;
			goto DONE;
		}
	}

DONE:
	KeReleaseSpinLock(&g_PageLock, OldIrql);

	return pRet;
}

_Use_decl_annotations_
ULONG
WINAPI
PHPageHookCount(
	_In_ ULONG64 VA,
	_In_ PAGE_TYPE Type
)
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	KIRQL OldIrql;

	ULONG Count = 0;

	ULONG64 PagePtr = (ULONG64)PAGE_ALIGN( VA );

	KeAcquireSpinLock(&g_PageLock, &OldIrql);

	if (!VA || IsListEmpty(&g_PageHookList.List)) {
		goto DONE;
	}

	for (PLIST_ENTRY pListEntry = g_PageHookList.List.Flink; pListEntry != &g_PageHookList.List; pListEntry = pListEntry->Flink)
	{
		PAGE_HOOK_CONTEXT* pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_CONTEXT, List);
		if (!MmIsAddressValid(pEntry) || FALSE == pEntry->Hook) continue;

		if ((Type == DATA_PAGE && pEntry->DataPageBase == PagePtr) || (Type == CODE_PAGE && pEntry->CodePageBase == PagePtr)) {
				Count++;	
		}		
	}

DONE:
	KeReleaseSpinLock(&g_PageLock, OldIrql);

	return Count;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
PHHook(
	_In_	PVOID  pFunc,
	_In_	PVOID  pHook,
	_Inout_ PVOID* pOriFun
)
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	if (!pFunc || !pHook || !pOriFun) {
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS ntStatus = STATUS_SUCCESS;
	PUCHAR   CodePage = NULL;
	BOOLEAN  NewPage  = TRUE;
	PHYSICAL_ADDRESS phys = { 0 }; phys.QuadPart = MAXULONG64;
	HOOK_SHELLCODE1 JmpCode = { 0 };
	HOOK_SHELLCODE1 RetCode = { 0 };
	ULONG_PTR HookSize = 0;
	PPAGE_HOOK_CONTEXT pHookContext = NULL, pNewEntry = NULL;
	KIRQL OldIrql = {};
	PVOID WowPeb = PsGetProcessWow64Process(IoGetCurrentProcess());
	BOOLEAN isX64 = WowPeb ? FALSE : TRUE;

	// 判断目标地址是否已经HOOK
	pHookContext = PHGetHookContextByVA( (ULONG64)pFunc, DATA_PAGE );
	if (NULL != pHookContext) {
		if (pOriFun){ *pOriFun = (PVOID)pHookContext->OriFunc; }
		return STATUS_GROUP_EXISTS;
	}

	// 检测目标页面是否已有HOOK点
	pHookContext = PHGetHookContextByPFN( MmGetPhysicalAddress(pFunc).QuadPart, DATA_PAGE );
	if (NULL != pHookContext) {
		CodePage = (PUCHAR)pHookContext->CodePageBase;
		NewPage = FALSE;
	}
	else {
		CodePage = (PUCHAR)MmAllocateContiguousMemory( PAGE_SIZE, phys );
	}

	if (NULL == CodePage) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 构建PAGE HOOK CONTEXT
	pNewEntry = (PPAGE_HOOK_CONTEXT)ExAllocatePool(NonPagedPoolNx, sizeof(PAGE_HOOK_CONTEXT));
	if (NULL == pNewEntry) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(pNewEntry, sizeof(PAGE_HOOK_CONTEXT));

	// 拷贝原页面
	if (NewPage) RtlCopyMemory( CodePage, PAGE_ALIGN(pFunc), PAGE_SIZE );

	// 构建JMP SHELL CODE
	BuildShellCode1(&JmpCode, (ULONG64)pHook, isX64);

	// 获取要HOOK目标页面的字节数
	HookSize = GetWriteCodeLen(pFunc, sizeof(HOOK_SHELLCODE1));
	if (!HookSize) {
		ExFreePool(pNewEntry);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 构建RET SHELL CODE
	BuildShellCode1(&RetCode, (ULONG64)pFunc + HookSize, isX64);
	
	// 构建ORI原函数流程
	pNewEntry->OriFunc = (ULONG64)ExAllocatePool(
		NonPagedPool,
		HookSize + sizeof(HOOK_SHELLCODE1)
		//(BOOLEAN)ProbeKernelAddress(pFunc, sizeof(ULONG64), sizeof(LONG))
	);

	if (!pNewEntry->OriFunc) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlFillMemory( (PVOID)pNewEntry->OriFunc, HookSize + sizeof(HOOK_SHELLCODE1), 0x90 );

	RtlCopyMemory( (PVOID)pNewEntry->OriFunc, pFunc, HookSize );
	RtlCopyMemory( (PVOID)(pNewEntry->OriFunc + HookSize), &RetCode, sizeof(HOOK_SHELLCODE1) );

	// HOOK
	ULONG_PTR PageOffset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN(pFunc);
	RtlCopyMemory( CodePage + PageOffset, &JmpCode, sizeof(HOOK_SHELLCODE1));

	pNewEntry->Hook = TRUE;
	pNewEntry->HookAddress = (ULONG64)pFunc;
	pNewEntry->HookSize = (ULONG32)HookSize;
	pNewEntry->DataPagePFN = PFN( MmGetPhysicalAddress(pFunc).QuadPart );
	pNewEntry->CodePagePFN = PFN( MmGetPhysicalAddress(CodePage).QuadPart );
	pNewEntry->DataPageBase = (ULONG64)PAGE_ALIGN( pFunc );
	pNewEntry->CodePageBase = (ULONG64)CodePage;
	pNewEntry->NewPage = NewPage;
	pNewEntry->State = Ready;
	pNewEntry->Cr3 = PHGetHookCr3(IoGetCurrentProcess(), ProbeKernelAddress(pFunc, sizeof(ULONG64), sizeof(LONG)));
	
	// 插入到空闲链表中
	KeAcquireSpinLock(&g_PageLock, &OldIrql);
	InsertTailList(&g_PageHookList.List, &pNewEntry->List);
	KeReleaseSpinLock(&g_PageLock, OldIrql);

	if (pOriFun)
	{
		*pOriFun = (PVOID)pNewEntry->OriFunc;
	}

	return ntStatus;
}

_Use_decl_annotations_
NTSTATUS 
WINAPI
PHUnHook(
	_In_ PVOID pFunc
)
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;

	KIRQL OldIrql = {};

	if (!pFunc) {
		return STATUS_INVALID_PARAMETER;
	}

	PPAGE_HOOK_CONTEXT HookContext = PHGetHookContextByVA( (ULONG64)pFunc , DATA_PAGE );
	if (NULL == HookContext) {
		return STATUS_NOT_FOUND;
	}
	
	if (HookContext->Hook) {

		HookContext->Hook = FALSE;

		// 获取函数页面Hook点次数
		if (PHPageHookCount((ULONG64)pFunc, DATA_PAGE) > 1) {
			KeAcquireSpinLock(&g_PageLock, &OldIrql);
			ULONG_PTR PageOffset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN(pFunc);
			memcpy((PUCHAR)HookContext->CodePageBase + PageOffset, (PVOID)HookContext->OriFunc, HookContext->HookSize);
		}
		else
		{
			KeAcquireSpinLock(&g_PageLock, &OldIrql);
			ntStatus = UtilForEachProcessorDpc(PHHookCallbackDPC, HookContext);
		}

		RemoveEntryList(&HookContext->List);
		ExFreePool((PVOID)HookContext->OriFunc);
		ExFreePool(HookContext);
	}

	KeReleaseSpinLock( &g_PageLock, OldIrql );

	return ntStatus;
}

_Use_decl_annotations_
NTSTATUS 
WINAPI
PHUnAllHook()
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (IsListEmpty(&g_PageHookList.List)) {		
		return ntStatus;
	}
	
	for (PLIST_ENTRY pListEntry = g_PageHookList.List.Flink; pListEntry != &g_PageHookList.List;)
	{
		PAGE_HOOK_CONTEXT* pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_CONTEXT, List);

		pListEntry = pListEntry->Flink;

		if (!MmIsAddressValid(pEntry) || FALSE == pEntry->Hook) continue;

		ntStatus = PHUnHook( (PVOID)pEntry->HookAddress );

		if (!NT_SUCCESS(ntStatus)) {
			DBG_PRINT( "PHR0UnHook: %#p\r\n", (PVOID)pEntry->HookAddress );
		}
	}

	return ntStatus;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
PHActivateHooks()
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (IsListEmpty(&g_PageHookList.List)) {
		return ntStatus;
	}

	// 遍历空闲链表
	for (PLIST_ENTRY pListEntry = g_PageHookList.List.Flink; pListEntry != &g_PageHookList.List;)
	{
		PAGE_HOOK_CONTEXT* pEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_CONTEXT, List);

		pListEntry = pListEntry->Flink;

		if (!MmIsAddressValid(pEntry) || FALSE == pEntry->Hook) continue;
		
		// 判断该项是否为就绪状态
		if (Ready == pEntry->State)
		{
			// 是的话则，激活
			_InterlockedCompareExchange8((CHAR*)&pEntry->State, Activiti, Ready);

			if (pEntry->NewPage) {
				ntStatus = UtilForEachProcessorDpc(PHHookCallbackDPC, pEntry);
				if (!NT_SUCCESS(ntStatus)) {
					DBG_PRINT("[R0]: %#p 激活失败!\r\n", (PVOID)pEntry->HookAddress);
				}
			}
		}
		// 如果为暂停状态
		else if (Stop == pEntry->State)
		{
			// 是的话则，激活
			_InterlockedCompareExchange8((CHAR*)&pEntry->State, Activiti, Stop);
		}
	}

	return ntStatus;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
PHUpdateHookState(
	_In_ PVOID pFunc,
	_In_ ULONG64 State
)
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (IsListEmpty(&g_PageHookList.List)) {
		return ntStatus;
	}

	if (!pFunc) {
		return STATUS_INVALID_PARAMETER;
	}

	PPAGE_HOOK_CONTEXT HookContext = PHGetHookContextByVA((ULONG64)pFunc, DATA_PAGE);
	if (NULL == HookContext) {
		return STATUS_NOT_FOUND;
	}

	if (HookContext->Hook) { // HOOK 是否还在

		if (!MmIsAddressValid(HookContext) || FALSE == HookContext->Hook) return STATUS_UNSUCCESSFUL;

		switch (State)
		{
		case Stop:
		{
			// 判断该项是否为激活状态
			if (Activiti == HookContext->State)
			{
				// 是的话则，暂停
				_InterlockedCompareExchange8((CHAR*)&HookContext->State, Stop, Activiti);
				ntStatus = UtilForEachProcessorDpc(PHHookCallbackDPC, HookContext);
				if (!NT_SUCCESS(ntStatus)) {
					DBG_PRINT("[R0]: %#p 激活失败!\r\n", (PVOID)HookContext->HookAddress);
				}
			}
		}
			break;
		case Activiti:
		{
			if (Stop == HookContext->State)
			{
				// 是的话则，激活
				_InterlockedCompareExchange8((CHAR*)&HookContext->State, Activiti, Stop);
				ntStatus = UtilForEachProcessorDpc(PHHookCallbackDPC, HookContext);
				if (!NT_SUCCESS(ntStatus)) {
					DBG_PRINT("[R0]: %#p 激活失败!\r\n", (PVOID)HookContext->HookAddress);
				}
			}
			else if (Ready == HookContext->State)
			{
				// 是的话则，激活
				_InterlockedCompareExchange8((CHAR*)&HookContext->State, Activiti, Ready);

				if (HookContext->NewPage) {
					ntStatus = UtilForEachProcessorDpc(PHHookCallbackDPC, HookContext);
					if (!NT_SUCCESS(ntStatus)) {
						DBG_PRINT("[R0]: %#p 激活失败!\r\n", (PVOID)HookContext->HookAddress);
					}
				}
			}
		}
			break;
		default:
			break;
		}	
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	return ntStatus;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
PHHideMem(
	_In_ PVOID Address,	// 目标地址
	_In_ PVOID Code,	// 要写入的字节
	_In_ ULONG Size		// 写入大小
)
{
#ifndef USE_HV_EPT
	return STATUS_UNSUCCESSFUL;
#endif

	if (!Address || !Code || !Size) {
		return STATUS_INVALID_PARAMETER;
	}

	PUCHAR  CodePage = NULL;
	BOOLEAN NewPage = TRUE;
	PHYSICAL_ADDRESS phys = { 0 }; phys.QuadPart = MAXULONG64;
	PPAGE_HOOK_CONTEXT pHookContext = NULL, pNewEntry = NULL;
	KIRQL OldIrql = {};

	// 判断目标地址是否已经HOOK
	pHookContext = PHGetHookContextByVA((ULONG64)Address, DATA_PAGE);
	if (NULL != pHookContext) {
		return STATUS_GROUP_EXISTS;
	}

	// 检测目标页面是否已有HOOK点
	pHookContext = PHGetHookContextByPFN(MmGetPhysicalAddress(Address).QuadPart, DATA_PAGE);
	if (NULL != pHookContext) {
		CodePage = (PUCHAR)pHookContext->CodePageBase;
		NewPage = FALSE;
	}
	else {
		CodePage = (PUCHAR)MmAllocateContiguousMemory(PAGE_SIZE, phys);
	}

	// 构建PAGE HOOK CONTEXT
	pNewEntry = (PPAGE_HOOK_CONTEXT)ExAllocatePool(NonPagedPoolNx, sizeof(PAGE_HOOK_CONTEXT));
	if (NULL == pNewEntry) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlSecureZeroMemory(pNewEntry, sizeof(PAGE_HOOK_CONTEXT));

	// 拷贝原页面
	if (NewPage) RtlCopyMemory(CodePage, PAGE_ALIGN(Address), PAGE_SIZE);

	// HOOK
	ULONG_PTR PageOffset = (ULONG_PTR)Address - (ULONG_PTR)PAGE_ALIGN(Address);
	RtlCopyMemory(CodePage + PageOffset, Code, Size);

	pNewEntry->Hook = TRUE;
	pNewEntry->HookAddress = (ULONG64)Address;
	pNewEntry->HookSize = (ULONG32)Size;
	pNewEntry->DataPagePFN = PFN(MmGetPhysicalAddress(Address).QuadPart);
	pNewEntry->CodePagePFN = PFN(MmGetPhysicalAddress(CodePage).QuadPart);
	pNewEntry->DataPageBase = (ULONG64)PAGE_ALIGN(Address);
	pNewEntry->CodePageBase = (ULONG64)CodePage;
	pNewEntry->NewPage = NewPage;
	pNewEntry->State = Ready;
	pNewEntry->Cr3 = PHGetHookCr3(IoGetCurrentProcess(), ProbeKernelAddress(Address, sizeof(ULONG64), sizeof(LONG)));

	// 插入到空闲链表中
	KeAcquireSpinLock(&g_PageLock, &OldIrql);
	InsertTailList(&g_PageHookList.List, &pNewEntry->List);
	KeReleaseSpinLock(&g_PageLock, OldIrql);

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
ULONG64
WINAPI
PHGetHookCr3(
	_In_ PEPROCESS Process,
	_In_ BOOL IsKernel
)
{
	if (!MmIsAddressValid(Process)) {
		__debugbreak();
	}

	ULONG64 KernelCr3 = *(PULONG64)((PUCHAR)Process + 0x28);	// dirbase x64, 32bit is 0x18
	ULONG64 UserCr3 = *(PULONG64)((PUCHAR)Process + GetUserCr3Offset());

	if (IsKernel)
	{
		// R0的话返回当前Cr3
		return  KernelCr3 ? KernelCr3 : UserCr3;
	}
	else
	{
		// R3返回用户Cr3
		return  UserCr3 ? UserCr3 : KernelCr3;
	}
}