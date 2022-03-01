#pragma once

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
    PVOID* OriAddress;
    ULONG64 State;
    PVOID   Code;
    ULONG64 Size;
}HOOK_CONTEXT, * PHOOK_CONTEXT;

typedef enum _PAGE_HOOK_STATE
{
    Ready = 0,		// 就绪
    Activiti = 1,	// 激活
    Stop = 2,		// 停止
} PAGE_HOOK_STATE;

typedef struct _COMM_ENTRY
{
    ULONG64 CommCode;	// 通信码
    ULONG64 NtStatus;	// 返回值
    ULONG64 inData;		// 数据
}COMM_ENTRY, * PCOMM_ENTRY;

namespace VtWb
{
    bool InitIoCtlComm();
    bool SendData(
        _In_ ULONG_PTR CommCode,
        _In_ PVOID InData
    );
    bool ShotHvAddHook(
        _In_ unsigned __int64 target_pid,
        _In_ void* target_address,
        _In_ void* detour_address
    );
    bool ShotHvHookEnable();
    bool ShotHvUpdateHookState(
        _In_ unsigned __int64 target_pid,
        _In_ void* target_address,
        _In_ unsigned __int64 state
    );
    bool ShotHvDelHook(
        _In_ unsigned __int64 target_pid,
        _In_ void* target_address
    );
    bool ShotHvHideWrite(
        _In_ unsigned __int64 target_pid,
        _In_ void* target_address,
        _In_ void* code,
        _In_ int size
    );
}

