#include "pch.h"

HANDLE g_hDevice;

// 初始化与内核的IOCTL通信
bool VtWb::InitIoCtlComm()
{
    // 在3环中访问符号链接是 \\.\ShotHvDDK
    g_hDevice = CreateFile(TEXT("\\\\.\\ShotHvDDK"),
        GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_ENCRYPTED,
        NULL
    );

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    return true;
}

// 发送通信包
bool VtWb::SendData(
    _In_ ULONG_PTR CommCode, 
    _In_ PVOID InData
)
{
    DWORD dwRet = 0;

    COMM_ENTRY Comm = { 0 };

    Comm.CommCode = CommCode;
    Comm.inData = (ULONG64)InData;

    bool Flag = DeviceIoControl(
        g_hDevice,          // 设备句柄Or文件句柄
        CTL_SHOTHV,         // Io控制码
        &Comm,              // 输入缓冲区
        sizeof(COMM_ENTRY), // 输入缓冲区长度
        NULL,               // 输出缓冲区
        NULL,               // 输出缓冲区长度
        &dwRet,             // 实际操作的数据长度
        NULL);

    return Comm.NtStatus == 0 ? true : false;
}

// 添加Ept Hook(支持R0\R3)
bool VtWb::ShotHvAddHook(
    _In_ unsigned __int64 target_pid, 
    _In_ void* target_address, 
    _In_ void* detour_address
)
{
    HOOK_CONTEXT Context = { 0 };

    PVOID ori_address = nullptr;

    Context.TargetPid = target_pid;
    Context.TargetAddress = target_address;
    Context.DetourAddress = detour_address;
    Context.OriAddress = &ori_address;

    return SendData(SHOTHV_HOOK_ADD, &Context);
}

// 激活所有Hook
bool VtWb::ShotHvHookEnable()
{
    HOOK_CONTEXT Context = { 0 };

    return SendData(SHOTHV_HOOK_ENABLE, &Context);
}

// 修改Hook状态
bool VtWb::ShotHvUpdateHookState(
    _In_ unsigned __int64 target_pid, 
    _In_ void* target_address, 
    _In_ unsigned __int64 state
)
{
    HOOK_CONTEXT Context = { 0 };

    Context.TargetPid = target_pid;
    Context.TargetAddress = target_address;
    Context.State = state;

    return SendData(SHOTHV_HOOK_DISABLE, &Context);
}

// 删除指定Ept Hook
bool VtWb::ShotHvDelHook(
    _In_ unsigned __int64 target_pid, 
    _In_ void* target_address
)
{
    HOOK_CONTEXT Context = { 0 };

    Context.TargetPid = target_pid;
    Context.TargetAddress = target_address;

    return SendData(SHOTHV_HOOK_DELETE, &Context);
}

// 隐写
bool VtWb::ShotHvHideWrite(
    _In_ unsigned __int64 target_pid, 
    _In_ void* target_address, 
    _In_ void* code, 
    _In_ int size
)
{
    HOOK_CONTEXT Context = { 0 };

    Context.TargetPid = target_pid;
    Context.TargetAddress = target_address;
    Context.Code = code;
    Context.Size = size;

    return SendData(SHOTHV_HIDE_WRITE, &Context);
}
