#include "HvPch.h"

PVOID OriPsLookupProcessByProcessId;

NTSTATUS
xPsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS* Process
)
{
	using _PsLookupProcessByProcessId = NTSTATUS(*)(
			_In_ HANDLE ProcessId,
			_Outptr_ PEPROCESS* Process
		);

	DBG_PRINT("xPsLookupProcessByProcessId!\r\n");

	if (OriPsLookupProcessByProcessId)
	{
		return ((_PsLookupProcessByProcessId)OriPsLookupProcessByProcessId)(ProcessId, Process);
	}

	return STATUS_UNSUCCESSFUL;
}

VOID 
WINAPI 
DetourHooks()
{
	PVOID Address = PsLookupProcessByProcessId;

	auto ntStatus = PHR0Hook(Address, xPsLookupProcessByProcessId, &OriPsLookupProcessByProcessId);

	if (NT_SUCCESS(ntStatus))
		PHActivateR0Hooks();

	return;
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
	
	DetourHooks();

	return ntStatus;
}