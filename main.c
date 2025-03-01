#include <windows.h>
#include <stdio.h>
#include <string.h>

void runSubProcess(const char *program, PROCESS_INFORMATION *pi) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(pi, sizeof(*pi));

    char commandLine[MAX_PATH];
    strcpy(commandLine, program);

    if (!CreateProcess(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, pi)) {
        printf("CreateProcess failed (%lu).\n", GetLastError());
    }
}

int main() {
    PROCESS_INFORMATION pi_a, pi_b;

    runSubProcess("a.exe", &pi_a);
    runSubProcess("b.exe", &pi_b);

    HANDLE handles[] = { pi_a.hProcess, pi_b.hProcess };

    while (1) {
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, 1000);
        
        if (result == WAIT_OBJECT_0) {
            printf("Process A has stopped. Restarting...\n");
            CloseHandle(pi_a.hProcess);
            CloseHandle(pi_a.hThread);
            runSubProcess("a.exe", &pi_a);
            handles[0] = pi_a.hProcess; 
        }
        
        if (result == WAIT_OBJECT_0 + 1) {
            printf("Process B has stopped. Restarting...\n");
            CloseHandle(pi_b.hProcess);
            CloseHandle(pi_b.hThread);
            runSubProcess("b.exe", &pi_b);
            handles[1] = pi_b.hProcess; 
        }
    }

    return 0;
}
