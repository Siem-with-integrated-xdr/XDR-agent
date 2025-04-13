#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#define NUM_PROCESSES 9
#define LOG_FILE "parent.log"

// List of process executables
const char *processes[NUM_PROCESSES] = {
    "compressor.exe",
    "encryptor.exe",
    "events_data_collector.exe",
    "processes_collector.exe",
    "network_collector.exe",
    "system_health.exe",
    "file_scanner.exe",
    "file_integrity.exe",
    "action.exe"
};

// Global variables for process information
PROCESS_INFORMATION pi[NUM_PROCESSES]; 
HANDLE handles[NUM_PROCESSES];  // Store only process handles
HANDLE jobObject;  // Job Object to manage all child processes

// Logging function to file
void log_message(const char *message) {
    FILE *log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[30];
        strftime(timestamp, 30, "%Y-%m-%d %H:%M:%S", tm_info);
        
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

// Function to create and run a subprocess using CreateProcess
void runSubProcess(const char *program, PROCESS_INFORMATION *pi, DWORD creationFlags) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(pi, sizeof(*pi));

    char commandLine[MAX_PATH];
    strcpy(commandLine, program);

    if (!CreateProcess(NULL, commandLine, NULL, NULL, FALSE, creationFlags, NULL, NULL, &si, pi)) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "CreateProcess failed for %s (%lu).", program, GetLastError());
        log_message(error_msg);
        printf("%s\n", error_msg);
    } else {
        char success_msg[256];
        snprintf(success_msg, sizeof(success_msg), "Started process: %s (PID: %lu)", program, pi->dwProcessId);
        log_message(success_msg);
        printf("%s\n", success_msg);

        // Assign the process to the job object for automatic cleanup.
        AssignProcessToJobObject(jobObject, pi->hProcess);
    }
}

int main() {
    // --- Enable Required Privileges in Parent Process ---
    // Enable SE_BACKUP_NAME so that child processes inherit this privilege.
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf("OpenProcessToken error: %lu\n", GetLastError());
        return 1;
    }
    
    if (!LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid)) {
        printf("LookupPrivilegeValue error: %lu\n", GetLastError());
        CloseHandle(token);
        return 1;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges error: %lu\n", GetLastError());
        CloseHandle(token);
        return 1;
    }
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege.\n");
        CloseHandle(token);
        return 1;
    }
    
    CloseHandle(token);

    // --- Create a Job Object with automatic child process cleanup ---
    jobObject = CreateJobObject(NULL, NULL);
    if (jobObject == NULL) {
        log_message("Failed to create Job Object.");
        printf("Failed to create Job Object (%lu).\n", GetLastError());
        return 1;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo;
    ZeroMemory(&jobInfo, sizeof(jobInfo));
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (!SetInformationJobObject(jobObject, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo))) {
        log_message("Failed to set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.");
        printf("Failed to set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (%lu).\n", GetLastError());
        return 1;
    }

    // --- Start all child processes ---
    for (int i = 0; i < NUM_PROCESSES; i++) {
        // Use CREATE_NO_WINDOW flag for all processes except "encryptor.exe"
        DWORD flags = (strcmp(processes[i], "encryptor.exe") == 0) ? 0 : CREATE_NO_WINDOW;
        runSubProcess(processes[i], &pi[i], flags);
        handles[i] = pi[i].hProcess;  // Store only the process HANDLE
    }

    // --- Monitor and restart crashed processes ---
    while (1) {
        // Check for any process exit (timeout 1000 ms)
        DWORD result = WaitForMultipleObjects(NUM_PROCESSES, handles, FALSE, 1000);

        if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + NUM_PROCESSES) {
            int index = result - WAIT_OBJECT_0;  // Identify the crashed process

            char crash_msg[256];
            snprintf(crash_msg, sizeof(crash_msg), "Process %s has crashed. Restarting...", processes[index]);
            log_message(crash_msg);
            printf("%s\n", crash_msg);

            CloseHandle(pi[index].hProcess);
            CloseHandle(pi[index].hThread);

            Sleep(2000); // Prevent infinite restart loops

            DWORD flags = (strcmp(processes[index], "encryptor.exe") == 0) ? 0 : CREATE_NO_WINDOW;
            runSubProcess(processes[index], &pi[index], flags);
            handles[index] = pi[index].hProcess;  // Update with new process handle
        }
    }

    return 0;
}
