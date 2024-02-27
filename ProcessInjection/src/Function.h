#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <atlcore.h>
#include <iostream>



typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

extern WCHAR ProcessName[];

int DLLHollowing();
