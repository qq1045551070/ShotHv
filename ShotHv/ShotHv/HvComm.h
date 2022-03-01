#pragma once

/*
	IOCTL 通信
*/
#define CTL_SHOTHV CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SHOTHV_HOOK_ADD     0x1	/* 添加Hook */
#define SHOTHV_HOOK_ENABLE  0x2	/* 激活Hook */
#define SHOTHV_HOOK_DISABLE 0x3 /* 关闭Hook */
#define SHOTHV_HOOK_DELETE  0x4 /* 删除Hook */
#define SHOTHV_HIDE_WRITE	0x5 /* R3隐写 */

typedef struct _HOOK_CONTEXT
{
	ULONG64	TargetPid;
	PVOID   TargetAddress;
	PVOID   DetourAddress;
	PVOID*  OriAddress;
	ULONG64 State;
	PVOID   Code;
	ULONG64 Size;
}HOOK_CONTEXT, * PHOOK_CONTEXT;

typedef struct _COMM_ENTRY
{
	ULONG64 CommCode;	// 通信码
	ULONG64 NtStatus;	// 返回值
	ULONG64 inData;		// 数据
}COMM_ENTRY, * PCOMM_ENTRY;


/*
	初始化内核通信
*/
NTSTATUS
WINAPI
InitKernelComm(
	_In_ PDRIVER_OBJECT DriverObject
);

/*
	卸载内核通信
*/
VOID
WINAPI
UnInitKernelComm(
	_In_ PDRIVER_OBJECT DriverObject
);

/* 
	默认填充IRP函数 
*/
NTSTATUS
WINAPI
ShotHvDispathRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

/*
	IRP_MJ_DEVICE_CONTROL
*/
NTSTATUS
WINAPI
ShotHvDeviceIoControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS
WINAPI
ShotHvCommHandler(
	_In_ COMM_ENTRY* instructions
);