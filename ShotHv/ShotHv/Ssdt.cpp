#include "HvPch.h"

SSDT_ENTRY* SSDT;
SSDT_ENTRY* SSSDT;

/*
	See: 根据SSDT函数名称获取对应函数地址
	RETURN: 返回对应SSDT表函数地址
*/
_Use_decl_annotations_
PVOID
WINAPI
GetSsdtFunctionAddress(
	_In_ CHAR* ApiName	// 要获取的SSDT API名称
)
{
	if (!SSDT) {
		SSDT = GetSstdEntry();
		if (!SSDT) {
			DBG_PRINT("SSDT not found...\r\n");
			return NULL;
		}
	}

	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		DBG_PRINT("ServiceTable not found...\r\n");
		return 0;
	}

	/* 获取系统服务号 */
	ULONG Offset = GetSsdtFunctionIndex(ApiName);
	if (Offset == 0)
		return NULL;
	else if (Offset >= SSDT->NumberOfServices)
	{
		DBG_PRINT("Invalid Offset...\r\n");
		return 0;
	}

	return (PVOID)((SSDT->pServiceTable[Offset] >> 4) + SSDTbase);
}

/*
	See: 获取SSDT表函数下标
	RETURN: 返回对应SSDT表函数下标
*/
_Use_decl_annotations_
ULONG
WINAPI
GetSsdtFunctionIndex(
	_In_ PCHAR funName	// SSDT API名称
)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	WCHAR NtdllPath[MAX_PATH] = { 0 };
	UNICODE_STRING ustrDllFileName = { 0 };

	/* 获取 ntdll 路径 */
	wcscat(NtdllPath, L"\\??\\");
	wcscat(NtdllPath, ((KUSER_SHARED_DATA*)KI_USER_SHARED_DATA)->NtSystemRoot);
	wcscat(NtdllPath, L"\\System32\\ntdll.dll");

	RtlInitUnicodeString(&ustrDllFileName, NtdllPath);

	// 内存映射文件
	status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("DllFileMap Error!!!\n");
		return ulFunctionIndex;
	}

	// 根据导出表获取导出函数地址, 从而获取函数索引号
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, funName);

	// 释放
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	return ulFunctionIndex;
}

/*
	See: 根据NTDLL导出表获取导出函数地址, 从而获取函数索引号
	RETURN: 返回对应SSDT表函数索引号
*/
_Use_decl_annotations_
ULONG
WINAPI
GetIndexFromExportTable(
	_In_ PVOID pBaseAddress,	// BASE
	_In_ PCHAR pszFunctionName	// Export Api Name
)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// 有名称的导出函数个数
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// 导出函数名称地址表
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// 开始遍历导出表
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// 判断是否查找的函数
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// 获取导出函数地址
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// 获取 SSDT 函数 Index
#ifdef _WIN64 // 64bit
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 4);
#else		  // 32bits
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
#endif
			break;
		}
	}

	return ulFunctionIndex;
}

/*
	See: 获取SSDT表
	RETURN: 返回 SSDT_ENTRY*
*/
_Use_decl_annotations_
SSDT_ENTRY*
WINAPI
GetSstdEntry()
{
	if (!SSDT)
	{
		// x64 code
		ULONG_PTR kernelSize = 0;
		ULONG_PTR kernelBase = QueryKernelModule((PUCHAR)"ntoskrnl.exe", &kernelSize);
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;

		// Find KiSystemServiceStart
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		bool found = false;
		ULONG KiSSSOffset;
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = true;
				break;
			}
		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
		LONG relativeOffset = 0;
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			relativeOffset = *(LONG*)(address + 3);
		}
		if (relativeOffset == 0)
			return NULL;

		SSDT = (SSDT_ENTRY*)(address + relativeOffset + 7);
	}

	return SSDT;
}

/*
	See: 根据DLL名称，映射指定文件PE数据
	RETURN: 操作正确返回STATUS_SUCCESS
*/
_Use_decl_annotations_
NTSTATUS
WINAPI
DllFileMap(
	_In_	UNICODE_STRING ustrDllFileName,	// DLL名称
	_Inout_ HANDLE* phFile,					// 返回的文件句柄
	_Inout_ HANDLE* phSection,				// 返回的节区句柄
	_Inout_ PVOID* ppBaseAddress			// 返回映射的地址
)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;

	// 打开 DLL 文件, 并获取文件句柄
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		DBG_PRINT("ZwOpenFile Error! [error code: 0x%X]\r\n", status);
		return status;
	}
	// 创建一个节对象, 以 PE 结构中的 SectionALignment 大小对齐映射文件
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		DBG_PRINT("ZwCreateSection Error! [error code: 0x%X]\r\n", status);
		return status;
	}
	// 映射到内存
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		DBG_PRINT("ZwMapViewOfSection Error! [error code: 0x%X]\r\n", status);
		return status;
	}

	// 返回数据
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}