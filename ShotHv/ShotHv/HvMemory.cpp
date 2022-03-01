#include "HvPch.h"

static ULONG64 g_PTE_BASE = 0;
static ULONG64 g_PDE_BASE = 0;
static ULONG64 g_PPE_BASE = 0;
static ULONG64 g_PXE_BASE = 0;

NTSTATUS Pml4Init()
{
    if (g_PTE_BASE && g_PDE_BASE && g_PPE_BASE && g_PXE_BASE)
        return STATUS_SUCCESS;

    if (*NtBuildNumber <= SYSTEM_VERSION::WINDOWS_7_SP1) {

        // Win7 的页目录随机基址是固定的
        g_PTE_BASE = 0xFFFFF68000000000;
        g_PDE_BASE = 0xFFFFF6FB40000000;
        g_PPE_BASE = 0xFFFFF6FB7DA00000;
        g_PXE_BASE = 0xFFFFF6FB7DBED000;
    }
    else if (*NtBuildNumber >= SYSTEM_VERSION::WINDOWS_10_1803) {

        // Win10需要动态获取
        g_PTE_BASE = *(PULONG64)((ULONG64)MmGetVirtualForPhysical + 0x22);
        g_PDE_BASE = (g_PTE_BASE + ((g_PTE_BASE & 0xffffffffffff) >> 9));
        g_PPE_BASE = (g_PTE_BASE + ((g_PDE_BASE & 0xffffffffffff) >> 9));
        g_PXE_BASE = (g_PTE_BASE + ((g_PPE_BASE & 0xffffffffffff) >> 9));
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

PULONG64 GetPxeAddress(_In_ PVOID addr)
{
    // 1个 PXE 对应 512 GB
    return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 39) << 3) + g_PXE_BASE);
}

PULONG64 GetPpeAddress(_In_ PVOID addr)
{
    // 1个 PDPTE 对应 1 GB
    return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 30) << 3) + g_PPE_BASE);
}

PULONG64 GetPdeAddress(_In_ PVOID addr)
{
    // 1个 PDE 对应 2 MB
    return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 21) << 3) + g_PDE_BASE);
}

PULONG64 GetPteAddress(_In_ PVOID addr)
{
    // 1个 PTE 对应 4KB
    return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 12) << 3) + g_PTE_BASE);
}

static NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN ULONG* NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
)
{
    typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
        IN HANDLE ProcessHandle,
        IN PVOID* BaseAddress,
        IN ULONG* NumberOfBytesToProtect,
        IN ULONG NewAccessProtection,
        OUT PULONG OldAccessProtection);

    _NtProtectVirtualMemory NtProtectVirtualMemoryFunc = (_NtProtectVirtualMemory)GetSsdtFunctionAddress("NtProtectVirtualMemory");

    if (!NtProtectVirtualMemoryFunc) return STATUS_UNSUCCESSFUL;

    PVOID Address = *BaseAddress;

    KPROCESSOR_MODE PreviousMode = KeSetPreviousMode(KernelMode);
    NTSTATUS ntStatus = NtProtectVirtualMemoryFunc(
        ProcessHandle,
        &Address,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
    );
    KeSetPreviousMode(PreviousMode);
    return ntStatus;
}

PVOID
WINAPI
ShotHvMemoryAllocate(
    _In_ SIZE_T  Size,
    _In_ BOOLEAN isKernel
)
{
    UNREFERENCED_PARAMETER(isKernel);

    PVOID p = nullptr;
    UINT cout = 3;

    if (true) 
    {
        do
        {
            p = ExAllocatePool(NonPagedPool, Size);
            if (p) {
                memset(p, 0, Size);
                break;
            }
        } while (cout--);
    }
    else
    {
        p = AllocateR3Memory(PsGetCurrentProcessId(), Size);
        if (p) {
            memset(p, 0, Size);
        }
    }

    return p;
}

_Use_decl_annotations_
PVOID
WINAPI
AllocateR3Memory(
    _In_ HANDLE Pid,  // 进程PID
    _In_ SIZE_T Size  // 需要的大小
)
{
    PEPROCESS  Process = NULL;
    KAPC_STATE kApcState = { 0 };
    PVOID BaseAddress = 0;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &Process);
    ULONG Proc = NULL;

    if (!NT_SUCCESS(status))
    {
        return NULL;
    }

    if (STATUS_PENDING != PsGetProcessExitStatus(Process))
    {
        ObDereferenceObject(Process);
        return NULL;
    }

    KeStackAttachProcess(Process, &kApcState);

    status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (NT_SUCCESS(status)) {
        NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PULONG)&Size, PAGE_READWRITE, &Proc);
        RtlSecureZeroMemory(BaseAddress, Size);
        SetExecutePage(BaseAddress, (ULONG)Size);
    }

    KeUnstackDetachProcess(&kApcState);

    return BaseAddress;
}

/*
    See: 设置内存(PAGE_READWRITE | Nx位)，为可执行可写可读
    RETURN: 成功返回TRUE
*/
_Use_decl_annotations_
BOOLEAN
WINAPI
SetExecutePage(
    _In_ PVOID VirtualAddress,
    _In_ ULONG Size
)
{
    ULONG64 StartAddress = (ULONG64)VirtualAddress & (~0xFFF);
    ULONG64 EndAddress = ((ULONG64)VirtualAddress + Size) & (~0xFFF);

    PPAGE_ENTRY Pde = NULL;
    PPAGE_ENTRY Pte = NULL;

    // 循环设置PDE、PTE
    while (EndAddress >= StartAddress)
    {
        Pde = MiGetPdeAddress((PVOID)StartAddress, PML::PD);
        if (MmIsAddressValid(Pde) && Pde->Present)
        {
            Pde->Write = 1;
            Pde->ExecuteDisable = 0;
        }

        Pte = MiGetPdeAddress((PVOID)StartAddress, PML::PT);
        if (MmIsAddressValid(Pte) && Pte->Present)
        {
            Pte->Write = 1;
            Pte->ExecuteDisable = 0;
        }

        StartAddress += PAGE_SIZE;
    }

    return TRUE;
}

/*
    See: 获取目标地址对应页表项
    RETURN: 成功返回页表项 PPAGE_ENTRY
*/
_Use_decl_annotations_
PPAGE_ENTRY
WINAPI
MiGetPdeAddress(
    _In_ PVOID Va,	// 目标地址
    _In_ PML Level	// 页表项
)
{
    if (!NT_SUCCESS(Pml4Init())) {
        return nullptr;
    }

    PPAGE_ENTRY pxe = nullptr;

    switch (Level) {
    case PT: {
        pxe = (PPAGE_ENTRY)GetPteAddress(Va);
        if (pxe) return pxe;
    }
    case PD: {
        pxe = (PPAGE_ENTRY)GetPdeAddress(Va);
        if (pxe) return pxe;
    }
    case PDPT: {
        pxe = (PPAGE_ENTRY)GetPpeAddress(Va);
        if (pxe) return pxe;
    }
    case PML4: {
        pxe = (PPAGE_ENTRY)GetPxeAddress(Va);
        if (pxe) return pxe;
    }
    }

    return nullptr;
}

_Use_decl_annotations_
NTSTATUS
WINAPI
FreeR3Memory(
    _In_ HANDLE Pid,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T Size
)
{
    PEPROCESS Process = NULL;
    KAPC_STATE kApcState = { 0 };
    NTSTATUS ntStatus = PsLookupProcessByProcessId(Pid, &Process);

    if (!NT_SUCCESS(ntStatus))
    {
        return STATUS_NOT_FOUND;
    }

    if (STATUS_PENDING != PsGetProcessExitStatus(Process))
    {
        ObDereferenceObject(Process);
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess(Process, &kApcState);

    if (BaseAddress)
    {
        ntStatus = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &Size, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&kApcState);

    return ntStatus;
}