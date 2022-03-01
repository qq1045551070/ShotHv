#include "HvPch.h"

#define DEVICE_NAME         L"\\Device\\ShotHvDDK"
#define SYMBOLICLINK_NAME   L"\\??\\ShotHvDDK"

NTSTATUS
WINAPI
InitKernelComm(
	_In_ PDRIVER_OBJECT DriverObject
)
{
    // 创建设备对象
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING SysmolicLinkName = RTL_CONSTANT_STRING(SYMBOLICLINK_NAME);

    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    ntStatus = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(ntStatus)){
        return ntStatus;
    }

    // 创建符号链接
    ntStatus = IoCreateSymbolicLink(&SysmolicLinkName, &DeviceName);
    if (!NT_SUCCESS(ntStatus)){
        return ntStatus;
    }
    
    // 当3环执行 指定 操作时执行指定函数
    for (uintptr_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
    {
        // 遍历赋值IRP对应的函数指针
        DriverObject->MajorFunction[i] = ShotHvDispathRoutine;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ShotHvDeviceIoControl;
    
    // 设置交互模式，初始化设备对象
    DeviceObject->Flags |= DO_DIRECT_IO; // MDL
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

VOID 
WINAPI
UnInitKernelComm(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(SYMBOLICLINK_NAME);
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&SymbolicLink);
}

NTSTATUS 
WINAPI
ShotHvDispathRoutine(
    _In_ PDEVICE_OBJECT DeviceObject, 
    _In_ PIRP Irp
)
{
    // 得到当前IRP的 栈结构
    PIO_STACK_LOCATION sTack = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(sTack);

    // 设置IRP信息, 一定要处理
    // 返回给3环多少数据,没有填0
    Irp->IoStatus.Information = 0;
    // 设置IRP返回状态, 就是Getlasterror()函数获取的值
    Irp->IoStatus.Status = STATUS_SUCCESS;
    // 设置优先级，将IRP继续传递
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS 
WINAPI
ShotHvDeviceIoControl(
    _In_ PDEVICE_OBJECT DeviceObject, 
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PCHAR InputBuffer = NULL;
    ULONG InputLength = 0;
    PCHAR OutputBuffer = NULL;
    ULONG OutputLength = 0;
    ULONG Length = 0;
    PIO_STACK_LOCATION sTack = IoGetCurrentIrpStackLocation(Irp);
    // 获取 IO功能码
    ULONG IoCode = sTack->Parameters.DeviceIoControl.IoControlCode;
   
    switch (IoCode)
    {
    case CTL_SHOTHV: // 如果是0x800功能码, 缓冲区访问
    {
        // 获取输入缓冲区的地址
        InputBuffer  = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
        // 获取输入缓冲区的长度
        InputLength  = sTack->Parameters.DeviceIoControl.InputBufferLength;
        // 获取输出缓冲区的地址
        OutputBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
        // 获取输出缓冲区的长度
        OutputLength = sTack->Parameters.DeviceIoControl.OutputBufferLength;

        if (InputBuffer && SafeCopy(InputBuffer, InputBuffer, sizeof(COMM_ENTRY))) {
            ((COMM_ENTRY*)InputBuffer)->NtStatus = ShotHvCommHandler((COMM_ENTRY*)InputBuffer);
        }

        Length = 0;
        ntStatus = STATUS_SUCCESS;
    }break;
    default:
    {
        Length = 0;
        ntStatus = STATUS_SUCCESS;
    }break;
    }

    // 设置IRP必要属性
    Irp->IoStatus.Status = ntStatus;
    Irp->IoStatus.Information = Length;
    // 继续传递
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

NTSTATUS
WINAPI
ShotHvCommHandler(
    _In_ COMM_ENTRY* instructions
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

    if (UserMode != ExGetPreviousMode()) {
        return STATUS_NOT_SUPPORTED;
    }
   
    switch (instructions->CommCode)
    {
    case SHOTHV_HOOK_ADD:       // 添加HOOK
    {
        PHOOK_CONTEXT Context = (PHOOK_CONTEXT)instructions->inData;

        PEPROCESS TarProcess = NULL;

        KAPC_STATE kApc = { 0 };

        ntStatus = PsLookupProcessByProcessId((HANDLE)Context->TargetPid, &TarProcess);

        if (NT_SUCCESS(ntStatus)) {

            KeStackAttachProcess(TarProcess, &kApc);

            ntStatus = PHHook(Context->TargetAddress, Context->DetourAddress, Context->OriAddress);

            KeUnstackDetachProcess(&kApc);
        }     
    }
        break;
    case SHOTHV_HOOK_ENABLE:    // 启用HOOK
    {  
        ntStatus = PHActivateHooks();
    }
        break;
    case SHOTHV_HOOK_DISABLE:   // 关闭HOOK
    {
        PHOOK_CONTEXT Context = (PHOOK_CONTEXT)instructions->inData;

        PEPROCESS TarProcess = NULL;

        KAPC_STATE kApc = { 0 };

        ntStatus = PsLookupProcessByProcessId((HANDLE)Context->TargetPid, &TarProcess);

        if (NT_SUCCESS(ntStatus)) {

            KeStackAttachProcess(TarProcess, &kApc);

            ntStatus = PHUpdateHookState(Context->TargetAddress, Context->State);

            KeUnstackDetachProcess(&kApc);
        }
    }
        break;
    case SHOTHV_HOOK_DELETE:    // 删除HOOK
    {
        PHOOK_CONTEXT Context = (PHOOK_CONTEXT)instructions->inData;

        PEPROCESS TarProcess = NULL;

        KAPC_STATE kApc = { 0 };

        ntStatus = PsLookupProcessByProcessId((HANDLE)Context->TargetPid, &TarProcess);

        if (NT_SUCCESS(ntStatus)) {

            KeStackAttachProcess(TarProcess, &kApc);

            ntStatus = PHUnHook(Context->TargetAddress);

            KeUnstackDetachProcess(&kApc);
        }
    }
        break;
    case SHOTHV_HIDE_WRITE:
    {
        PHOOK_CONTEXT Context = (PHOOK_CONTEXT)instructions->inData;

        PEPROCESS TarProcess = NULL;

        KAPC_STATE kApc = { 0 };

        ntStatus = PsLookupProcessByProcessId((HANDLE)Context->TargetPid, &TarProcess);

        if (NT_SUCCESS(ntStatus)) {

            KeStackAttachProcess(TarProcess, &kApc);

            ntStatus = PHHideMem(Context->TargetAddress, Context->Code, (ULONG)Context->Size);

            KeUnstackDetachProcess(&kApc);
        }     
    }
        break;
    default:
        break;
    }

    return ntStatus;
}