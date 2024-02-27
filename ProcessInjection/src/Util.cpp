#include <Windows.h>
#include <atlstr.h>
#include <TlHelp32.h>
#include <iomanip>
#include "Util.h"

// 字符串异或
void XORcrypt(char str2xor[], size_t len, char key) {
    /*
            XORcrypt() is a simple XOR encoding/decoding function
    */
    int i;
    if (key == '\0')
        key = str2xor[len - 1];

    for (i = 0; i < len; i++) {
        //str2xor[i] = (BYTE)str2xor[i] ^ key;
        //Sleep(50);
        _InterlockedXor8(str2xor + i, key);
    }
}

// 字节交换
void SWAPcrypt(char data[], const long long datasize)
{
    char tmp;
    for (int i = 0; i < datasize-1; i+=2) {
        tmp = data[i];
        data[i] = data[i + 1];
        data[i + 1] = tmp;
    }
}

// 函数HOOK
bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers /*= NULL*/)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t addr = (uint64_t)(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t addr = (uint32_t)(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD dwSize = sizeof(trampoline);
    DWORD oldProt = 0;
    bool output = false;

    if (installHook)
    {
        if (buffers != NULL)
        {
            if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
                return false;

            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, trampoline, dwSize);
            output = true;
        }
    }
    else
    {
        if (buffers == NULL)
            return false;

        if (buffers->originalBytes == nullptr || buffers->originalBytesSize == 0)
            return false;

        dwSize = buffers->originalBytesSize;

        if (VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, buffers->originalBytes, dwSize);
            output = true;
        }
    }


    // We're flushing instructions cache just in case our hook didn't kick in immediately.
    //

    FlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);

    VirtualProtect(
        addressToHook,
        dwSize,
        oldProt,
        &oldProt
    );

    return output;
}

// 磁盘文件读取
char* ReadFromFile(char* path)
{
    DWORD fileReadSize;
    DWORD fileSize;
    LPVOID pFileBase;
    typedef std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> HandlePtr;
    // TODO：判断文件是否存在
    HandlePtr file(CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    ), &CloseHandle);

    fileSize = GetFileSize(file.get(), NULL);
    pFileBase = new char[fileSize];
    if (pFileBase == NULL)
        throw MyException("Out of memory.\n");

    BOOL ret = ReadFile(file.get(), pFileBase, fileSize, &fileReadSize, NULL);
    return (char *)pFileBase;
}

// 获取指定进程PID
DWORD GetPID(wchar_t* pProName)
{
    PROCESSENTRY32 pe32 = { 0 };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    BOOL bRet = FALSE;
    DWORD dwPID = 0;

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        log("CreateToolhelp32Snapshot process.");
        goto exit;
    }

    pe32.dwSize = sizeof(pe32);
    bRet = Process32First(hSnap, &pe32);
    while (bRet)
    {
        if (lstrcmp(pe32.szExeFile, pProName) == 0)
        {
            dwPID = pe32.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnap, &pe32);
    }

    CloseHandle(hSnap);
exit:
    return dwPID;
}

// 提升特权
BOOL EnableDebugPriv(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES sTP;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        sTP.PrivilegeCount = 1;
        sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
        {
            CloseHandle(hToken);
            return FALSE;
        }
        CloseHandle(hToken);
        return TRUE;
    }
    return FALSE;
}