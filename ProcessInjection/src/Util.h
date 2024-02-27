#pragma once
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <exception>

struct HookTrampolineBuffers{
    // (Input) Buffer containing bytes that should be restored while unhooking.
    BYTE* originalBytes;
    DWORD originalBytesSize;

    // (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    BYTE* previousBytes;
    DWORD previousBytesSize;
};

template<class... Args>
void log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);

    std::cout << oss.str() << std::endl;
    //printf(args...);  
}

template<class... Args>
class MyException :public std::exception {
public:
    MyException(Args... args) {
        log("[!] ", args...);
    }
};

void XORcrypt(char str2xor[], size_t len, char key = '\0');

void SWAPcrypt(char data[], const long long datasize);

bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers);

char* ReadFromFile(char* path);

DWORD GetPID(wchar_t* pProName);

BOOL EnableDebugPriv(void);
