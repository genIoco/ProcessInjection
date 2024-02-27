#include "ProcessInjection.h"
#include "Function.h"
#include "Util.h"


bool Init()
{
	// Initialization program
	// 1.Start injected process
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	USES_CONVERSION;
	if (!CreateProcessA(NULL, (LPSTR)W2A(ProcessName), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		throw MyException("Start injected process failed.");
	}
	return TRUE;
}

bool Close()
{
	// Close and clean program 
	// 1.Close injected process
	
	return TRUE;
}


int main(int argc, char* argv[])
{
	Init();
	DLLHollowing();
}