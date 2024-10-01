#ifndef UNICODE
#define UNICODE
#endif

#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 5 || argc > 5)
	{
		fwprintf(stderr, L"usage: %s exe dll func params", argv[0]);
		return 1;
	}

	wchar_t* exe = argv[1];
	wchar_t* dll = argv[2];
	wchar_t* func = argv[3];
	wchar_t* params = argv[4];

	HANDLE process = NULL;

	{
		HANDLE snap_process = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!snap_process)
			return 1;

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		Process32First(snap_process, &pe);
		do
		{
			if (!_wcsicmp(pe.szExeFile, exe))
			{
				process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
				if (!process)
					return 1;
				else
					break;
			}
		} while (Process32Next(snap_process, &pe));

		CloseHandle(snap_process);
	}

	if (!process)
		return 1;

	wchar_t full_path[MAX_PATH];
	GetFullPathName(dll, MAX_PATH, full_path, NULL);

	{
		void* alloc = VirtualAllocEx(process, NULL, sizeof(full_path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!alloc)
			return 1;

		WriteProcessMemory(process, alloc, full_path, sizeof(full_path), NULL);

		HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, alloc, 0, NULL);
		if (!thread)
			return 1;

		WaitForSingleObject(thread, INFINITE);

		CloseHandle(thread);
	}

	HMODULE module = NULL;

	{
		HANDLE snap_module = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process));
		if (!snap_module)
			return 1;

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);
		Module32First(snap_module, &me);
		do
		{
			if (!_wcsicmp(me.szExePath, full_path))
			{
				module = me.hModule;
				break;
			}
		} while(Module32Next(snap_module, &me));

		CloseHandle(snap_module);
	}

	if (!module)
		return 1;

	{
		char func_utf8[8192];
		WideCharToMultiByte(CP_UTF8, 0, func, -1, func_utf8, sizeof(func_utf8), NULL, NULL);
		HMODULE dll_module = LoadLibrary(dll);

		void* alloc = VirtualAllocEx(process, NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!alloc)
			return 1;

		WriteProcessMemory(process, alloc, params, 8192, NULL);

		void* remote_func_ptr = (void*)((UINT_PTR)module + (UINT_PTR)GetProcAddress(dll_module, func_utf8) - (UINT_PTR)dll_module);
		HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_func_ptr, alloc, 0, NULL);
		if (!thread)
			return 1;

		CloseHandle(thread);
	}

	return 0;
}