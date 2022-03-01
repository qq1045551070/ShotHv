#include "pch.h"

PVOID OriFun;

void Test1()
{
    printf("Test1!\r\n");
}

void Test2()
{
    printf("Test2!\r\n");
}

int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption,
    UINT uType) {

    VtWb::ShotHvUpdateHookState(GetCurrentProcessId(), &MessageBoxW, Stop);

    auto result = MessageBoxW(hWnd, L"Hooked!", lpCaption, uType);

    VtWb::ShotHvUpdateHookState(GetCurrentProcessId(), &MessageBoxW, Activiti);

    return result;
}

int main()
{
    if (VtWb::InitIoCtlComm())  // 需要先自行加载驱动
    {
        UCHAR Int3 = { 0xCC };

        VtWb::ShotHvHideWrite(GetCurrentProcessId(), &MessageBoxW, &Int3, 1); // 隐写
        VtWb::ShotHvHookEnable();                                             // 激活Hook
        system("pause");
        MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

        if (VtWb::ShotHvAddHook(GetCurrentProcessId(), &MessageBoxW, &DetourMessageBoxW)) // 添加Hook
        {
            printf("ShotHvAddHook Success!\r\n");
            system("pause");

            VtWb::ShotHvUpdateHookState(GetCurrentProcessId(), Test1, Stop);  // 更新Hook状态
            VtWb::ShotHvDelHook(GetCurrentProcessId(), &MessageBoxW);         // 删除Hook
        }
        else
        {
            printf("Error1:%x!\r\n", GetLastError());
        }
    }
    else
    {
        printf("Error2:%x!\r\n", GetLastError());
    }

    system("pause");

    MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);
    MessageBoxW(NULL, L"Not hooked...", L"MinHook Sample", MB_OK);

DONE:
    printf("结束!\r\n");
    CloseHandle(g_hDevice);
    system("pause");
    return 0;
}


