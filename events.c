#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

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

// Helper function to escape a wide string for JSON output
void printEscapedJson(const wchar_t *str) {
    while (*str) {
        switch (*str) {
            case L'\"':
                wprintf(L"\\\"");
                break;
            case L'\\':
                wprintf(L"\\\\");
                break;
            case L'\b':
                wprintf(L"\\b");
                break;
            case L'\f':
                wprintf(L"\\f");
                break;
            case L'\n':
                wprintf(L"\\n");
                break;
            case L'\r':
                wprintf(L"\\r");
                break;
            case L'\t':
                wprintf(L"\\t");
                break;
            default:
                wprintf(L"%c", *str);
        }
        str++;
    }
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

    // Begin JSON array output
    wprintf(L"[\n");
    BOOL first = TRUE;

    // Loop through events
    while (EvtNext(hQuery, 1, &hEvent, 1000, 0, &dwReturned)) {
        DWORD dwBufferSize = 0, dwBufferUsed = 0;

        // First call to determine the buffer size needed
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
            if (!first) {
                wprintf(L",\n");
            } else {
                first = FALSE;
            }
            // Wrap the XML in a JSON object with proper escaping
            wprintf(L"  {\"event\": \"");
            printEscapedJson(buffer);
            wprintf(L"\"}");
        } else {
            logError(L"EvtRender failed with error %lu", GetLastError());
            wprintf(L"EvtRender failed with error %lu\n", GetLastError());
        }

        free(buffer);
        EvtClose(hEvent);
    }

    // End JSON array
    wprintf(L"\n]\n");
    EvtClose(hQuery);

    // Close the log file
    fclose(logFile);
    return 0;
}