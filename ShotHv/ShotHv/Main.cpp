#include "HvPch.h"

using NtCreateFileProc = NTSTATUS(NTAPI*)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
);

using NtOpenFileProc = NTSTATUS(NTAPI *)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG OpenOptions
);

PVOID OriNtCreateFile = NULL;
PVOID OriNtOpenFile = NULL;

NTSTATUS NTAPI xNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
)
{
	DBG_PRINT("xNtCreateFile!\r\n");

	if (OriNtCreateFile) {
		return ((NtCreateFileProc)OriNtCreateFile)(FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI xNtOpenFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG OpenOptions
)
{
	DBG_PRINT("xNtOpenFile!\r\n");

	if (OriNtOpenFile) {
		return ((NtOpenFileProc)OriNtOpenFile)(
			FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			ShareAccess,
			OpenOptions
			);
	}

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS
WINAPI
DetourHooks()
{
	// 测试同一物理页HOOK
	auto ntStatus = PHR0Hook(NtCreateFile, xNtCreateFile, &OriNtCreateFile);
		 ntStatus = PHR0Hook(NtOpenFile, xNtOpenFile, &OriNtOpenFile);

	if (NT_SUCCESS(ntStatus)) {
		// 激活所有HOOK
		PHActivateR0Hooks();
	}

	return STATUS_SUCCESS;
}

NTSTATUS 
WINAPI
ShotHvShutDown(
	_In_ PDEVICE_OBJECT DeviceObject, 
	_In_ PIRP Irp
){
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	DisableIntelVT();

	// IRP相关处理
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID 
WINAPI
DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
){
	UNREFERENCED_PARAMETER(DriverObject);
	
	DisableIntelVT();

	UnRegisterShutdownCallBack();
}

NTSTATUS 
WINAPI
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject, 
	_In_ PUNICODE_STRING RegisterPath
){
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegisterPath);
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	NTSTATUS ntStatus = STATUS_SUCCESS;

	DriverObject->DriverUnload = DriverUnload;

	// 注册关机回调
	ntStatus = RegisterShutdownCallBack(ShotHvShutDown);
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	// 开启 HV
	ntStatus = EnableIntelVT();
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	// HOOK
	ntStatus = DetourHooks();

	return ntStatus;
}