#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <tchar.h>
#include <cJSON.h>
#include <initguid.h>
#include <Wbemidl.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

//------------------------------------------------------------------------------
// Logging helper: Writes timestamped error messages to process_log.log.
void log_error(const char *format, ...) {
    FILE *f = fopen("process_log.log", "a");
    if (!f)
        return;
    
    // Get current local time.
    time_t t = time(NULL);
    struct tm tm_info;
    localtime_s(&tm_info, &t);
    char time_buffer[64];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    
    // Write timestamp.
    fprintf(f, "[%s] ", time_buffer);
    
    // Write the formatted message.
    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);
    
    fprintf(f, "\n");
    fclose(f);
}

// Forward declaration of getProcessPath
void getProcessPath(DWORD pid, char *szProcessPath, size_t size);

//------------------------------------------------------------------------------
// Helper: Format FILETIME in ISO 8601 (UTC) format.
void FormatFileTimeISO(FILETIME ft, char *buffer, size_t bufferSize) {
    SYSTEMTIME stUTC;
    FileTimeToSystemTime(&ft, &stUTC);
    snprintf(buffer, bufferSize, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             stUTC.wYear, stUTC.wMonth, stUTC.wDay,
             stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
}

//------------------------------------------------------------------------------
// Helper: Format memory usage (working set) as a string.
void FormatMemory(DWORD_PTR mem, char *buffer, size_t bufferSize) {
    snprintf(buffer, bufferSize, "%lu", (unsigned long)mem);
}

//------------------------------------------------------------------------------
// Helper: Convert FILETIME to seconds (as double).
double getTimeInSeconds(FILETIME ft) {
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    // FILETIME is in 100-nanosecond units; convert to seconds.
    return (double)li.QuadPart / 10000000.0;
}

//------------------------------------------------------------------------------
// Helper: Get the process owner (domain\username) as a string.
BOOL getProcessOwner(HANDLE hProcess, char *owner, DWORD ownerSize) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        log_error("getProcessOwner: OpenProcessToken failed.");
        return FALSE;
    }
    
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0) {
        log_error("getProcessOwner: GetTokenInformation size retrieval failed.");
        CloseHandle(hToken);
        return FALSE;
    }
    
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) {
        log_error("getProcessOwner: malloc failed to allocate %lu bytes.", dwSize);
        CloseHandle(hToken);
        return FALSE;
    }
    
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        log_error("getProcessOwner: GetTokenInformation failed.");
        free(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }
    
    char name[256] = {0};
    char domain[256] = {0};
    DWORD nameSize = sizeof(name);
    DWORD domainSize = sizeof(domain);
    SID_NAME_USE sidType;
    if (!LookupAccountSidA(NULL, pTokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType)) {
        log_error("getProcessOwner: LookupAccountSidA failed.");
        free(pTokenUser);
       	CloseHandle(hToken);
        return FALSE;
    }
    
    snprintf(owner, ownerSize, "%s\\%s", domain, name);
    free(pTokenUser);
    CloseHandle(hToken);
    return TRUE;
}

//------------------------------------------------------------------------------
// Helper: Get module count for a process.
DWORD getModuleCount(DWORD pid) {
    DWORD count = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            count = cbNeeded / sizeof(HMODULE);
        }
        CloseHandle(hProcess);
    }
    return count;
}

//------------------------------------------------------------------------------
// Helper: Get the process executable path for a given process ID.
void getProcessPath(DWORD pid, char *szProcessPath, size_t size) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL) {
        if (GetModuleFileNameExA(hProcess, NULL, szProcessPath, (DWORD)size) == 0) {
            snprintf(szProcessPath, size, "Access Denied or Unavailable");
            log_error("getProcessPath: GetModuleFileNameExA failed for PID %lu.", (unsigned long)pid);
        }
        CloseHandle(hProcess);
    } else {
        snprintf(szProcessPath, size, "Access Denied or Unavailable");
        log_error("getProcessPath: OpenProcess failed for PID %lu.", (unsigned long)pid);
    }
}

//------------------------------------------------------------------------------
// Create a JSON object with detailed process information.
cJSON* createProcessJsonDetailed(DWORD pid, DWORD ppid, const char* name, const char* path,
                                   const char* timestamp, const char* command_line,
                                   const char* working_set, unsigned long thread_count,
                                   const char* owner, double kernel_time, double user_time, DWORD module_count) {
    cJSON* jsonProcessObj = cJSON_CreateObject();
    if (!jsonProcessObj) {
        log_error("createProcessJsonDetailed: Failed to create JSON object.");
        return NULL;
    }
    
    cJSON_AddStringToObject(jsonProcessObj, "timestamp", timestamp);
    cJSON_AddStringToObject(jsonProcessObj, "category", "process");

    cJSON *procDetails = cJSON_CreateObject();
    if (!procDetails) {
        log_error("createProcessJsonDetailed: Failed to create process details object.");
        cJSON_Delete(jsonProcessObj);
        return NULL;
    }
    cJSON_AddNumberToObject(procDetails, "pid", (double)pid);
    cJSON_AddNumberToObject(procDetails, "ppid", (double)ppid);
    cJSON_AddStringToObject(procDetails, "name", name);
    cJSON_AddStringToObject(procDetails, "path", path);
    cJSON_AddStringToObject(procDetails, "command_line", command_line);
    cJSON_AddStringToObject(procDetails, "working_set", working_set);
    cJSON_AddNumberToObject(procDetails, "thread_count", (double)thread_count);
    
    // Additional details:
    cJSON_AddStringToObject(procDetails, "owner", owner);
    cJSON_AddNumberToObject(procDetails, "kernel_time", kernel_time);
    cJSON_AddNumberToObject(procDetails, "user_time", user_time);
    cJSON_AddNumberToObject(procDetails, "module_count", (double)module_count);

    cJSON_AddItemToObject(jsonProcessObj, "process", procDetails);
    return jsonProcessObj;
}

//------------------------------------------------------------------------------
// Takes an initial snapshot of current processes and prints a JSON array.
void initialSnapshot() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Unable to create process snapshot.\n");
        log_error("initialSnapshot: Unable to create process snapshot.");
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        fprintf(stderr, "Error: Unable to retrieve first process.\n");
        log_error("initialSnapshot: Unable to retrieve first process from snapshot.");
        CloseHandle(hSnapshot);
        return;
    }
    
    cJSON *jsonArray = cJSON_CreateArray();
    if (!jsonArray) {
        log_error("initialSnapshot: Failed to create JSON array.");
        CloseHandle(hSnapshot);
        return;
    }
    
    do {
        char szProcessPath[MAX_PATH] = {0};
        char creationTime[64] = {0};
        char memoryUsage[64] = {0};
        char owner[256] = "N/A";
        // For the initial snapshot, command_line is not available.
        const char *cmdLine = "N/A";
        double kernelTime = 0.0, userTime = 0.0;
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (hProcess != NULL) {
            if (GetModuleFileNameExA(hProcess, NULL, szProcessPath, MAX_PATH) == 0) {
                snprintf(szProcessPath, MAX_PATH, "Access Denied or Unavailable");
                log_error("initialSnapshot: GetModuleFileNameExA failed for PID %lu.", (unsigned long)pe.th32ProcessID);
            }
            FILETIME ftCreation, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                FormatFileTimeISO(ftCreation, creationTime, sizeof(creationTime));
                kernelTime = getTimeInSeconds(ftKernel);
                userTime = getTimeInSeconds(ftUser);
            } else {
                snprintf(creationTime, sizeof(creationTime), "unknown");
                log_error("initialSnapshot: GetProcessTimes failed for PID %lu.", (unsigned long)pe.th32ProcessID);
            }
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                FormatMemory(pmc.WorkingSetSize, memoryUsage, sizeof(memoryUsage));
            } else {
                snprintf(memoryUsage, sizeof(memoryUsage), "N/A");
                log_error("initialSnapshot: GetProcessMemoryInfo failed for PID %lu.", (unsigned long)pe.th32ProcessID);
            }
            getProcessOwner(hProcess, owner, sizeof(owner));
            CloseHandle(hProcess);
        } else {
            snprintf(szProcessPath, MAX_PATH, "Access Denied or Unavailable");
            snprintf(creationTime, sizeof(creationTime), "unknown");
            snprintf(memoryUsage, sizeof(memoryUsage), "N/A");
            log_error("initialSnapshot: OpenProcess failed for PID %lu.", (unsigned long)pe.th32ProcessID);
        }
        
        // Use the thread count from PROCESSENTRY32.
        unsigned long threadCount = pe.cntThreads;
        DWORD moduleCount = getModuleCount(pe.th32ProcessID);
        
        cJSON *jsonProcess = createProcessJsonDetailed(pe.th32ProcessID, pe.th32ParentProcessID,
                                                         pe.szExeFile, szProcessPath,
                                                         creationTime, cmdLine,
                                                         memoryUsage, threadCount,
                                                         owner, kernelTime, userTime, moduleCount);
        if (jsonProcess) {
            cJSON_AddItemToArray(jsonArray, jsonProcess);
        }
        
    } while (Process32Next(hSnapshot, &pe));
    
    char *jsonString = cJSON_Print(jsonArray);
    if (jsonString) {
        printf("Initial Process Snapshot:\n%s\n", jsonString);
        free(jsonString);
    } else {
        log_error("initialSnapshot: cJSON_Print failed.");
    }
    
    cJSON_Delete(jsonArray);
    CloseHandle(hSnapshot);
}

//------------------------------------------------------------------------------
// Monitors process creation events using WMI and prints each new process as JSON.
void monitorProcessCreationEvents() {
    HRESULT hr;
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("Failed to initialize COM library. Error code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: Failed to initialize COM library. Error code = 0x%lX", hr);
        return;
    }
    
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hr)) {
        printf("Failed to initialize security. Error code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: Failed to initialize security. Error code = 0x%lX", hr);
        CoUninitialize();
        return;
    }
    
    IWbemLocator *pLocator = NULL;
    hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator, (void **)&pLocator);
    if (FAILED(hr)) {
        printf("Failed to create IWbemLocator object. Err code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: Failed to create IWbemLocator object. Err code = 0x%lX", hr);
        CoUninitialize();
        return;
    }
    
    IWbemServices *pService = NULL;
    hr = pLocator->lpVtbl->ConnectServer(
        pLocator,
        L"ROOT\\CIMV2",   // WMI namespace
        NULL,
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        &pService
    );
    if (FAILED(hr)) {
        printf("Could not connect to WMI. Error code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: Could not connect to WMI. Error code = 0x%lX", hr);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }
    
    hr = CoSetProxyBlanket(
       (IUnknown *)pService,
       RPC_C_AUTHN_WINNT,
       RPC_C_AUTHZ_NONE,
       NULL,
       RPC_C_AUTHN_LEVEL_CALL,
       RPC_C_IMP_LEVEL_IMPERSONATE,
       NULL,
       EOAC_NONE
    );
    if (FAILED(hr)) {
        printf("Could not set proxy blanket. Error code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: Could not set proxy blanket. Error code = 0x%lX", hr);
        pService->lpVtbl->Release(pService);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }
    
    IEnumWbemClassObject *pEnumerator = NULL;
    hr = pService->lpVtbl->ExecNotificationQuery(
        pService,
        L"WQL",
        // WMI query retrieves ProcessId, ParentProcessId, Name, CommandLine, and ThreadCount.
        L"SELECT TargetInstance.ProcessId, TargetInstance.ParentProcessId, TargetInstance.Name, TargetInstance.CommandLine, TargetInstance.ThreadCount FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    if (FAILED(hr)) {
        printf("ExecNotificationQuery failed. Error code = 0x%lX\n", hr);
        log_error("monitorProcessCreationEvents: ExecNotificationQuery failed. Error code = 0x%lX", hr);
        pService->lpVtbl->Release(pService);
        pLocator->lpVtbl->Release(pLocator);
        CoUninitialize();
        return;
    }
    
    printf("Waiting for process creation events...\n");
    
    while (1) {
        IWbemClassObject *pEvent = NULL;
        ULONG uReturn = 0;
        hr = pEnumerator->lpVtbl->Next(pEnumerator, 5000, 1, &pEvent, &uReturn);
        if (FAILED(hr)) {
            printf("Failed to get next event. Error code = 0x%lX\n", hr);
            log_error("monitorProcessCreationEvents: Failed to get next event. Error code = 0x%lX", hr);
            break;
        }
        if (uReturn == 0) {
            continue; // Timeout; no event received.
        }
        
        VARIANT vtProp;
        hr = pEvent->lpVtbl->Get(pEvent, L"TargetInstance", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_UNKNOWN && vtProp.punkVal != NULL) {
            IWbemClassObject *pTargetInstance = NULL;
            hr = vtProp.punkVal->lpVtbl->QueryInterface(vtProp.punkVal, &IID_IWbemClassObject, (void **)&pTargetInstance);
            if (SUCCEEDED(hr)) {
                VARIANT vtPid, vtPPid, vtName, vtCmd, vtThreadCount;
                hr = pTargetInstance->lpVtbl->Get(pTargetInstance, L"ProcessId", 0, &vtPid, 0, 0);
                hr = pTargetInstance->lpVtbl->Get(pTargetInstance, L"ParentProcessId", 0, &vtPPid, 0, 0);
                hr = pTargetInstance->lpVtbl->Get(pTargetInstance, L"Name", 0, &vtName, 0, 0);
                hr = pTargetInstance->lpVtbl->Get(pTargetInstance, L"CommandLine", 0, &vtCmd, 0, 0);
                hr = pTargetInstance->lpVtbl->Get(pTargetInstance, L"ThreadCount", 0, &vtThreadCount, 0, 0);
                
                // Prepare a timestamp.
                SYSTEMTIME st;
                GetSystemTime(&st);
                char timestamp[64];
                snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                         st.wYear, st.wMonth, st.wDay,
                         st.wHour, st.wMinute, st.wSecond);
                
                // Safely extract PID and PPID.
                DWORD pid = 0, ppid = 0;
                if (vtPid.vt == VT_UINT || vtPid.vt == VT_UI4)
                    pid = vtPid.uintVal;
                else
                    log_error("monitorProcessCreationEvents: Unexpected vtPid type for event.");
                
                if (vtPPid.vt == VT_UINT || vtPPid.vt == VT_UI4)
                    ppid = vtPPid.uintVal;
                else
                    log_error("monitorProcessCreationEvents: Unexpected vtPPid type for event.");
                
                char processName[256] = {0};
                char szProcessPath[256] = {0};
                char commandLine[1024] = {0};
                char owner[256] = "N/A";
                // Check that vtName is a valid BSTR.
                if (vtName.vt == VT_BSTR && vtName.bstrVal != NULL) {
                    wcstombs(processName, vtName.bstrVal, sizeof(processName));
                } else {
                    snprintf(processName, sizeof(processName), "N/A");
                    log_error("monitorProcessCreationEvents: vtName is not a valid BSTR for PID %lu.", (unsigned long)pid);
                }
                // Check CommandLine variant.
                if (vtCmd.vt == VT_BSTR && vtCmd.bstrVal != NULL) {
                    wcstombs(commandLine, vtCmd.bstrVal, sizeof(commandLine));
                } else {
                    snprintf(commandLine, sizeof(commandLine), "N/A");
                }
                // Retrieve the executable path.
                getProcessPath(pid, szProcessPath, sizeof(szProcessPath));
                
                PROCESS_MEMORY_COUNTERS pmc;
                char memoryUsage[64] = {0};
                double kernelTime = 0.0, userTime = 0.0;
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProc != NULL) {
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                        FormatMemory(pmc.WorkingSetSize, memoryUsage, sizeof(memoryUsage));
                    } else {
                        snprintf(memoryUsage, sizeof(memoryUsage), "N/A");
                        log_error("monitorProcessCreationEvents: GetProcessMemoryInfo failed for PID %lu.", (unsigned long)pid);
                    }
                    // Get owner.
                    getProcessOwner(hProc, owner, sizeof(owner));
                    // Get CPU times.
                    FILETIME ftCreation, ftExit, ftKernel, ftUser;
                    if (GetProcessTimes(hProc, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                        kernelTime = getTimeInSeconds(ftKernel);
                        userTime = getTimeInSeconds(ftUser);
                    } else {
                        log_error("monitorProcessCreationEvents: GetProcessTimes failed for PID %lu.", (unsigned long)pid);
                    }
                    CloseHandle(hProc);
                } else {
                    snprintf(memoryUsage, sizeof(memoryUsage), "Access Denied");
                    log_error("monitorProcessCreationEvents: OpenProcess failed for PID %lu.", (unsigned long)pid);
                }
                
                unsigned long threadCount = 0;
                if (vtThreadCount.vt == VT_I4) {
                    threadCount = (unsigned long)vtThreadCount.intVal;
                } else {
                    log_error("monitorProcessCreationEvents: Unexpected vtThreadCount type for PID %lu.", (unsigned long)pid);
                }
                
                DWORD moduleCount = getModuleCount(pid);
                
                cJSON *jsonEvent = createProcessJsonDetailed(pid, ppid, processName, szProcessPath,
                                                              timestamp, commandLine,
                                                              memoryUsage, threadCount,
                                                              owner, kernelTime, userTime, moduleCount);
                if (jsonEvent) {
                    char *jsonString = cJSON_Print(jsonEvent);
                    if (jsonString) {
                        printf("%s\n", jsonString);
                        free(jsonString);
                    } else {
                        log_error("monitorProcessCreationEvents: cJSON_Print failed for event PID %lu.", (unsigned long)pid);
                    }
                    cJSON_Delete(jsonEvent);
                }
                
                VariantClear(&vtPid);
                VariantClear(&vtPPid);
                VariantClear(&vtName);
                VariantClear(&vtCmd);
                VariantClear(&vtThreadCount);
                pTargetInstance->lpVtbl->Release(pTargetInstance);
            }
        }
        VariantClear(&vtProp);
        pEvent->lpVtbl->Release(pEvent);
    }
    
    pEnumerator->lpVtbl->Release(pEnumerator);
    pService->lpVtbl->Release(pService);
    pLocator->lpVtbl->Release(pLocator);
    CoUninitialize();
}

int main(void) {
    // Take an initial snapshot of processes.
    initialSnapshot();
    
    // Monitor for new process creation events.
    monitorProcessCreationEvents();
    
    return 0;
}
