#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <cJSON.h>
#include <zmq.h>

FILE *logFile = NULL;

LONG WINAPI MyUnhandledExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo) {
    if (logFile) {
        fwprintf(logFile, L"Unhandled exception: 0x%08X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
        fflush(logFile);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void logError(const wchar_t *format, ...) {
    if (!logFile) return;
    va_list args;
    va_start(args, format);
    vfwprintf(logFile, format, args);
    fwprintf(logFile, L"\n");
    fflush(logFile);
    va_end(args);
}

// Get the current time in microseconds since Unix epoch.
uint64_t get_precise_time_microseconds() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    const uint64_t EPOCH_DIFF = 11644473600ULL * 10000000ULL;
    uint64_t time100ns = uli.QuadPart - EPOCH_DIFF;
    return time100ns / 10;
}

char *wchar_to_utf8(const wchar_t *wstr) {
    if (!wstr) return NULL;
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char *str = (char *)malloc(size);
    if (str) {
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, size, NULL, NULL);
    }
    return str;
}

// Helper function to extract the EventID value from the event's XML.
char *extract_event_id(const char *xml) {
    const char *startTag = "<EventID>";
    const char *endTag = "</EventID>";
    char *start = strstr(xml, startTag);
    if (!start) return NULL;
    start += strlen(startTag);
    char *end = strstr(start, endTag);
    if (!end) return NULL;
    size_t len = end - start;
    char *eventId = (char *)malloc(len + 1);
    if (eventId) {
        strncpy(eventId, start, len);
        eventId[len] = '\0';
    }
    return eventId;
}

int send_json_via_zmq(const char *jsonStr, const char *endpoint) {
    void *context = zmq_ctx_new();
    if (!context) return -1;
    void *socket = zmq_socket(context, ZMQ_PUSH);
    if (!socket) {
        zmq_ctx_destroy(context);
        return -1;
    }
    if (zmq_connect(socket, endpoint) != 0) {
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return -1;
    }
    zmq_msg_t message;
    size_t msg_size = strlen(jsonStr);
    if (zmq_msg_init_size(&message, msg_size) != 0) {
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return -1;
    }
    memcpy(zmq_msg_data(&message), jsonStr, msg_size);
    int rc = zmq_msg_send(&message, socket, 0);
    zmq_msg_close(&message);
    zmq_close(socket);
    zmq_ctx_destroy(context);
    return (rc == -1) ? -1 : 0;
}

// Callback for real-time event subscription.
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action == EvtSubscribeActionError) {
        logError(L"Subscription error: %lu", GetLastError());
        return ERROR_SUCCESS;
    } 
    else if (action == EvtSubscribeActionDeliver) {
        // pContext is the channel name (as wide string) passed during subscription.
        const wchar_t *channelNameW = (const wchar_t *)pContext;
        
        // Render the event as XML.
        DWORD bufferUsed = 0, bufferSize = 0;
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &bufferSize)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                logError(L"EvtRender size query failed: %lu", GetLastError());
                EvtClose(hEvent);
                return ERROR_SUCCESS;
            }
        }
        wchar_t *buffer = (wchar_t *)malloc(bufferUsed);
        if (!buffer) {
            logError(L"Memory allocation failed for %lu bytes", bufferUsed);
            EvtClose(hEvent);
            return ERROR_SUCCESS;
        }
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, buffer, &bufferUsed, &bufferSize)) {
            logError(L"EvtRender failed: %lu", GetLastError());
            free(buffer);
            EvtClose(hEvent);
            return ERROR_SUCCESS;
        }
        
        // Convert event XML to UTF-8 string.
        char *eventContent = wchar_to_utf8(buffer);
        free(buffer);
        if (!eventContent) {
            logError(L"UTF-8 conversion failed");
            EvtClose(hEvent);
            return ERROR_SUCCESS;
        }
        
        // Get the current UTC timestamp in ISO8601 format.
        char timestamp[64];
        uint64_t preciseTimeMicro = get_precise_time_microseconds();
        time_t sec = (time_t)(preciseTimeMicro / 1000000);
        long usec = (long)(preciseTimeMicro % 1000000);
        struct tm *tm_info = localtime(&sec);
        if (tm_info != NULL) {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(timestamp, "N/A", sizeof(timestamp));
            timestamp[sizeof(timestamp) - 1] = '\0';
        }
        char usec_str[16];
        sprintf(usec_str, ".%06ld", usec);
        strncat(timestamp, usec_str, sizeof(timestamp) - strlen(timestamp) - 1);
        
        // Convert the channel name to UTF-8.
        char *channel_utf8 = wchar_to_utf8(channelNameW);
        
        // Build JSON with timestamp, event (extracted event type), channel, and content.
        cJSON *jsonEvent = cJSON_CreateObject();
        if (jsonEvent) {
            cJSON_AddStringToObject(jsonEvent, "timestamp", timestamp);
            cJSON_AddStringToObject(jsonEvent, "category", "event");
            cJSON_AddStringToObject(jsonEvent, "channel", channel_utf8 ? channel_utf8 : "unknown");
            cJSON_AddStringToObject(jsonEvent, "content", eventContent);
            
            char *jsonString = cJSON_Print(jsonEvent);
            if (jsonString) {
                // Send the JSON message via ZeroMQ to the specified endpoint.
                if (send_json_via_zmq(jsonString, "tcp://localhost:5555") != 0) {
                    fwprintf(logFile, L"Failed to send JSON via ZeroMQ\n");
                }
                free(jsonString);
            }
            cJSON_Delete(jsonEvent);
        }
        
        if (channel_utf8) free(channel_utf8);
        free(eventContent);
        EvtClose(hEvent);
    }
    return ERROR_SUCCESS;
}

int main(void) {
    logFile = _wfopen(L"events.log", L"a");
    if (!logFile) {
        wprintf(L"Failed to open log file\n");
        return 1;
    }
    
    SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

    // List of Windows event channels to subscribe to for security analysis.
    const wchar_t *channels[] = {
        L"Security",
        L"System",
        L"Application",
        L"Microsoft-Windows-Sysmon/Operational",
        L"Microsoft-Windows-Windows Defender/Operational",
        L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        L"Windows PowerShell",
        L"Microsoft-Windows-WMI-Activity/Operational"
    };
    const int numChannels = sizeof(channels) / sizeof(channels[0]);
    EVT_HANDLE subscriptions[10] = {0};

    // Subscribe to each channel for future events only.
    for (int i = 0; i < numChannels; i++) {
        EVT_HANDLE hSubscription = EvtSubscribe(
            NULL,                        // local session
            NULL,                        // no callback window
            channels[i],                 // channel name
            L"*",                        // query: all events
            NULL,                        // no bookmark (start from now)
            (PVOID)channels[i],          // context: pass the channel name
            (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback,
            EvtSubscribeToFutureEvents   // subscribe to new events only
        );
        if (hSubscription == NULL) {
            fwprintf(logFile, L"EvtSubscribe failed for channel %s: %lu\n", channels[i], GetLastError());
        } else {
            subscriptions[i] = hSubscription;
        }
    }

    // Infinite loop to keep the process running so that subscription callbacks continue to be invoked.
    while (1) {
        Sleep(1000);
    }

    // (Cleanup code below is unreachable in this infinite loop.)
    for (int i = 0; i < numChannels; i++) {
        if (subscriptions[i]) {
            EvtClose(subscriptions[i]);
        }
    }
    fclose(logFile);
    return 0;
}
