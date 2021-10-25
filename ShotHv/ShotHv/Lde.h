#pragma once

/*
	获取HOOK目标需要的字节数
*/
_IRQL_requires_max_(APC_LEVEL)
ULONG
WINAPI
GetWriteCodeLen(
	_In_ PVOID HookLinerAddress,
	_In_ ULONG_PTR ShellCodeLen
);