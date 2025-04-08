#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "cJSON.h"  // Include the cJSON header

#pragma comment(lib, "wevtapi.lib")

// Global log file pointer
FILE *logFile = NULL;

// Unhandled exception filter to catch unexpected crashes
LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo) {
    if (logFile) {
        fwprintf(logFile, L"Unhandled exception occurred: Exception code: 0x%08X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
        fflush(logFile);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// Helper function to log errors to the events.log file
void logError(const wchar_t *format, ...) {
    if (!logFile) return;
    va_list args;
    va_start(args, format);
    vfwprintf(logFile, format, args);
    fwprintf(logFile, L"\n");
    fflush(logFile);
    va_end(args);
}

// Helper function to convert a wide-character string to a UTF-8 encoded char string.
// The caller is responsible for freeing the returned buffer.
char *wchar_to_utf8(const wchar_t *wstr) {
    if (!wstr)
        return NULL;
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char *str = (char *)malloc(size_needed);
    if (str) {
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, size_needed, NULL, NULL);
    }
    return str;
}

int main(void) {
    // Open the log file in append mode
    logFile = _wfopen(L"events.log", L"a");
    if (!logFile) {
        wprintf(L"Failed to open log file events.log\n");
        return 1;
    }
    
    // Set up the unhandled exception filter
    SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

    // Query the "Security" log; adjust the channel as needed
    EVT_HANDLE hQuery = EvtQuery(NULL, L"Security", L"*", EvtQueryReverseDirection);
    if (!hQuery) {
        logError(L"EvtQuery failed with error %lu", GetLastError());
        wprintf(L"EvtQuery failed with error %lu\n", GetLastError());
        fclose(logFile);
        return 1;
    }

    EVT_HANDLE hEvent = NULL;
    DWORD dwReturned = 0;

    // Create a cJSON array to hold all event objects
    cJSON *jsonArray = cJSON_CreateArray();
    if (!jsonArray) {
        logError(L"Failed to create JSON array");
        wprintf(L"Failed to create JSON array\n");
        EvtClose(hQuery);
        fclose(logFile);
        return 1;
    }

    // Loop through events
    while (EvtNext(hQuery, 1, &hEvent, 1000, 0, &dwReturned)) {
        DWORD dwBufferSize = 0, dwBufferUsed = 0;

        // First call to determine the buffer size needed for the event XML
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &dwBufferUsed, &dwBufferSize)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                logError(L"EvtRender (size query) failed with error %lu", GetLastError());
                wprintf(L"EvtRender (size query) failed with error %lu\n", GetLastError());
                EvtClose(hEvent);
                continue;
            }
        }

        // Allocate buffer for the event XML
        wchar_t *buffer = (wchar_t *)malloc(dwBufferUsed);
        if (!buffer) {
            logError(L"Memory allocation failed for buffer of size %lu", dwBufferUsed);
            wprintf(L"Memory allocation failed.\n");
            EvtClose(hEvent);
            break;
        }

        // Retrieve the event as XML
        if (EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferUsed, buffer, &dwBufferUsed, &dwBufferSize)) {
            // Convert the wide XML string to UTF-8
            char *utf8Str = wchar_to_utf8(buffer);
            if (utf8Str) {
                // Create a JSON object for the event
                cJSON *jsonEvent = cJSON_CreateObject();
                if (jsonEvent) {
                    cJSON_AddStringToObject(jsonEvent, "event", utf8Str);
                    cJSON_AddItemToArray(jsonArray, jsonEvent);
                }
                free(utf8Str);
            } else {
                logError(L"Failed to convert wide string to UTF-8");
            }
        } else {
            logError(L"EvtRender failed with error %lu", GetLastError());
            wprintf(L"EvtRender failed with error %lu\n", GetLastError());
        }

        free(buffer);
        EvtClose(hEvent);
    }

    // Convert the JSON array to a string and output it
    char *jsonString = cJSON_Print(jsonArray);
    if (jsonString) {
        printf("%s\n", jsonString);
        free(jsonString);
    } else {
        wprintf(L"Failed to print JSON string\n");
    }

    cJSON_Delete(jsonArray);
    EvtClose(hQuery);
    fclose(logFile);
    return 0;
}
