#include "HvPch.h"

// NULL的设备对象
static PDEVICE_OBJECT  g_NullDeviceObject = NULL;

ULONG GetThreadModeOffset()
{
    static ULONG offset = 0;
    if (offset)  return offset;
    UNICODE_STRING funcName = { 0 };
    RtlInitUnicodeString(&funcName, L"ExGetPreviousMode");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
    if (func == NULL) return 0;
    PUCHAR temp = func;

    for (int i = 10; i < 50; i++)
    {
        if (temp[i] == 0xC3)
        {
            if (temp[i + 1] == 0x90 || temp[i + 1] == 0x0 || temp[i + 1] == 0xcc)
            {
                temp += i;
                break;
            }
        }
    }

    if (temp != func)
    {
        temp -= 4;
        offset = *(PULONG)temp;
    }

    return offset;
}

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
    _In_	ULONG64 Pointer,
    _In_    BOOLEAN isX64
)
{
    if (pThunk)
    {
        PULARGE_INTEGER liTo = (PULARGE_INTEGER)&Pointer;

        __try {
            if (isX64)
            {
                pThunk->PushOp = 0x68;
                pThunk->AddressLow = liTo->LowPart;
                pThunk->MovOp = 0x042444C7;
                pThunk->AddressHigh = liTo->HighPart;
                pThunk->RetOp = 0xC3;
            }
            else
            {
                pThunk->PushOp = 0x68;
                pThunk->AddressLow = liTo->LowPart;
                pThunk->MovOp = 0x90909090;
                pThunk->AddressHigh = 0x90909090;
                pThunk->RetOp = 0xC3;
            }
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
        __debugbreak();
    }

    /* 判断是否为内核地址 */
    ULONG_PTR last = current + size - 1;
    if ((last < current) || (last >= (ULONG_PTR)MmHighestUserAddress/*MmUserProbeAddress*/)) {
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
BOOL
WINAPI
ProbeKernelAddress(
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
        __debugbreak();
    }

    /* 判断是否为用户地址 */
    ULONG_PTR last = current + size - 1;
    if ((last < current) || (last <= (ULONG_PTR)MmHighestUserAddress/*MmUserProbeAddress*/)) {
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

_Use_decl_annotations_
KPROCESSOR_MODE
WINAPI
KeSetPreviousMode(
    _In_ KPROCESSOR_MODE Mode
)
{
    ULONG offset = GetThreadModeOffset();
    KPROCESSOR_MODE old = ExGetPreviousMode();
    *(KPROCESSOR_MODE*)((PBYTE)KeGetCurrentThread() + offset) = Mode;
    return old;
}

/*
    See: 目标模块名称，获取指定模块信息
    RETURN: 返回目标模块BASE
*/
_Use_decl_annotations_
ULONG_PTR
WINAPI
QueryKernelModule(
    _In_	PUCHAR moduleName, 		   // 目标模块名称
    _Inout_ ULONG_PTR* moduleSize	   // 返回目标模块大小
)
{
    if (moduleName == NULL) return 0;

    RTL_PROCESS_MODULES rtlMoudles = { 0 };
    PRTL_PROCESS_MODULES SystemMoudles = &rtlMoudles;
    BOOLEAN isAllocate = FALSE;
    // 测量长度
    ULONG retLen = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, sizeof(RTL_PROCESS_MODULES), &retLen);

    // 分配实际长度内存
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        SystemMoudles = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, retLen + sizeof(RTL_PROCESS_MODULES));
        if (!SystemMoudles) return 0;

        memset(SystemMoudles, 0, retLen + sizeof(RTL_PROCESS_MODULES));

        status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, retLen + sizeof(RTL_PROCESS_MODULES), &retLen);

        if (!NT_SUCCESS(status))
        {
            ExFreePool(SystemMoudles);
            return 0;
        }

        isAllocate = TRUE;
    }

    PUCHAR kernelModuleName = NULL;
    ULONG_PTR moudleBase = 0;

    do
    {
        if (_stricmp((const char*)moduleName, "ntoskrnl.exe") == 0 || _stricmp((const char*)moduleName, "ntkrnlpa.exe") == 0)
        {
            PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[0];
            moudleBase = (ULONG_PTR)moudleInfo->ImageBase;
            if (moduleSize) *moduleSize = moudleInfo->ImageSize;

            break;
        }

        kernelModuleName = (PUCHAR)ExAllocatePool(PagedPool, strlen((const char*)moduleName) + 1);

        if (nullptr == kernelModuleName) {
            break;
        }

        memset(kernelModuleName, 0, strlen((const char*)moduleName) + 1);
        memcpy(kernelModuleName, moduleName, strlen((const char*)moduleName));
        _strlwr((char*)kernelModuleName); // 转小写比较

        for (ULONG i = 0; i < SystemMoudles->NumberOfModules; i++)
        {
            PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[i];

            PUCHAR pathName = (PUCHAR)_strlwr((char*)moudleInfo->FullPathName);

            // 包含关系判断
            if (strstr((const char*)pathName, (const char*)kernelModuleName))
            {
                moudleBase = (ULONG_PTR)moudleInfo->ImageBase;
                if (moduleSize) *moduleSize = moudleInfo->ImageSize;
                break;
            }
        }

    } while (false);

    if (kernelModuleName)
    {
        ExFreePool(kernelModuleName);
    }

    if (isAllocate)
    {
        ExFreePool(SystemMoudles);
    }

    return moudleBase;
}

DWORD 
WINAPI
GetUserCr3Offset()
{
    RTL_OSVERSIONINFOW Version = { 0 };
    RtlGetVersion(&Version);

    switch (Version.dwBuildNumber)
    {
    case WINDOWS_7:
        return 0x0;
    case WINDOWS_7_SP1:
        return 0x0;
    case WINDOWS_10_1803:
        return 0x0278;
    case WINDOWS_10_1809:
        return 0x0278;
    case WINDOWS_10_1903:
        return 0x0280;
    case WINDOWS_10_1909:
        return 0x0280;
    case WINDOWS_10_2004:
        return 0x0388;
    case WINDOWS_10_20H2:
        return 0x0388;
    case WINDOWS_10_21H1:
        return 0x0388;
    default:
        return 0x0388;
    }
}
