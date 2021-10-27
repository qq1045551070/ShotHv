#include "HvPch.h"

// NULL的设备对象
static PDEVICE_OBJECT  g_NullDeviceObject = NULL;

_Use_decl_annotations_
NTSTATUS
WINAPI
UtilForEachProcessor(
	_In_ NTSTATUS(*callback_routine)(void*),
    _In_opt_  void* context
)
{
	const auto number_of_processors =
		KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (ULONG processor_index = 0; processor_index < number_of_processors;
        processor_index++) {
        PROCESSOR_NUMBER processor_number = {};
        auto status =
            KeGetProcessorNumberFromIndex(processor_index, &processor_number);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        // Switch the current processor
        GROUP_AFFINITY affinity = {};
        affinity.Group = processor_number.Group;
        affinity.Mask = 1ull << processor_number.Number;
        GROUP_AFFINITY previous_affinity = {};
        KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

        // Execute callback
        status = callback_routine(context);

        KeRevertToUserGroupAffinityThread(&previous_affinity);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
UtilForEachProcessorDpc(
    _In_ PKDEFERRED_ROUTINE deferred_routine,
    _In_opt_ void* context
)
{
    const auto number_of_processors =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (ULONG processor_index = 0; processor_index < number_of_processors;
        processor_index++) {
        PROCESSOR_NUMBER processor_number = {};
        auto status =
            KeGetProcessorNumberFromIndex(processor_index, &processor_number);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const auto dpc = static_cast<PRKDPC>(ExAllocatePool(
            NonPagedPool, sizeof(KDPC)));
        if (!dpc) {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }
        KeInitializeDpc(dpc, deferred_routine, context);
        KeSetImportanceDpc(dpc, HighImportance);
        status = KeSetTargetProcessorDpcEx(dpc, &processor_number);
        if (!NT_SUCCESS(status)) {
            ExFreePool(dpc);
            return status;
        }

        KeInsertQueueDpc(dpc, nullptr, nullptr);
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID 
WINAPI
UtilGetSelectorInfoBySelector(
    ULONG_PTR selector,
    ULONG_PTR* base,
    ULONG_PTR* limit,
    ULONG_PTR* attribute
)
{
    GDT gdtr = { 0 };
    kGdtEntry64* gdtEntry = NULL;

    if (!base || !limit || !attribute)
        return;

    //初始化为0
    *base = *limit = *attribute = 0;

    if (selector == 0 || (selector & SELECTOR_TABLE_INDEX) != 0) {
        *attribute = 0x10000;	// unusable
        return;
    }

    __sgdt(&gdtr);
    gdtEntry = (kGdtEntry64*)(gdtr.uBase + (selector & ~(0x3)));

    *limit = __segmentlimit((ULONG32)selector);
    *base = ((gdtEntry->u1.Bytes.BaseHigh << 24) | (gdtEntry->u1.Bytes.BaseMiddle << 16) | (gdtEntry->u1.BaseLow)) & 0xFFFFFFFF;
    *base |= ((gdtEntry->u1.Bits.Type & 0x10) == 0) ? ((uintptr_t)gdtEntry->u1.BaseUpper << 32) : 0;
    *attribute = (gdtEntry->u1.Bytes.Flags1) | (gdtEntry->u1.Bytes.Flags2 << 8);
    *attribute |= (gdtEntry->u1.Bits.Present) ? 0 : 0x10000;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
RegisterShutdownCallBack(
    _In_ NTSTATUS(*ShutDownCallBack)(_In_ PDEVICE_OBJECT, _In_ PIRP)
)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    PFILE_OBJECT FileObject = NULL;
    UNICODE_STRING  NullDeviceName = {};

    RtlInitUnicodeString(&NullDeviceName, L"\\Device\\Null");

    // 根据名称获取对应设备的设备指针
    ntStatus = IoGetDeviceObjectPointer(&NullDeviceName, GENERIC_ALL, &FileObject, &g_NullDeviceObject);
    if (!NT_SUCCESS(ntStatus)){
        goto DONE;
    }

    // 注册关机通知函数
    // 登记系统关机请求的驱动设备对象(就是激活关机请求对应的函数(IRP_MJ_SHUTDOWN))
    // 注册对应设备驱动的 lfShutDown 函数
    ntStatus = IoRegisterShutdownNotification(g_NullDeviceObject);
    if (!NT_SUCCESS(ntStatus)) {
        goto DONE;
    }

    // 将我们的 lfShutDown 函数赋值到目标的 IRP_MJ_SHUTDOWN 中
    g_NullDeviceObject->DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = ShutDownCallBack;

DONE:
    if (FileObject) {
        ObfDereferenceObject(FileObject);
    }

    return ntStatus;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
UnRegisterShutdownCallBack()
{
    if (g_NullDeviceObject) {
        IoUnregisterShutdownNotification(g_NullDeviceObject);
    }

    return STATUS_SUCCESS;
}

BOOLEAN
WINAPI
BuildShellCode1(
    _Inout_ PHOOK_SHELLCODE1 pThunk,
    _In_	ULONG64 Pointer
)
{
    if (pThunk)
    {
        PULARGE_INTEGER liTo = (PULARGE_INTEGER)&Pointer;

        __try {
            pThunk->PushOp = 0x68;
            pThunk->AddressLow = liTo->LowPart;
            pThunk->MovOp = 0x042444C7;
            pThunk->AddressHigh = liTo->HighPart;
            pThunk->RetOp = 0xC3;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }

        return TRUE;
    }

    return FALSE;
}

ULONG64 
WINAPI
UtilPhysicalAddressToVirtualAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = PhysicalAddress;

    return (UINT64)MmGetVirtualForPhysical(PhysicalAddr);
}

ULONG64 
WINAPI
UtilVirtualAddressToPhysicalAddress(
    _In_ ULONG64 VrtualAddress
)
{
    return MmGetPhysicalAddress((PVOID)VrtualAddress).QuadPart;
}

BOOLEAN 
WINAPI
ProbeUserAddress(
    _In_ PVOID addr, 
    _In_ SIZE_T size, 
    _In_ ULONG alignment 
)
{
    if (size == 0) {
        return TRUE;
    }

    /* 校验地址是否对齐 */
    ULONG_PTR current = (ULONG_PTR)addr;
    if (((ULONG_PTR)addr & (alignment - 1)) != 0) {
        return FALSE;
    }

    /* 判断是否为内核地址 */
    ULONG_PTR last = current + size - 1;
    if ((last < current) || (last >= (ULONG_PTR)MmHighestUserAddress/*MmUserProbeAddress*/)) {
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN
WINAPI
SafeCopy(
    _In_ PVOID dest, 
    _In_ PVOID src, 
    _In_ SIZE_T size
)
{
    SIZE_T returnSize = 0;
    if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
        return TRUE;
    }

    return FALSE;
}

