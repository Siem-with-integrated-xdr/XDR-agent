#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <zmq.h>
#include <cJSON.h>

#define BUFFER_SIZE 65536
#define MAX_RETRY 5
#define ZMQ_ENDPOINT "tcp://localhost:5555"

// Global resources used by the whole program.
static void *g_context = NULL;  // Global ZeroMQ context (shared among threads)
static FILE *g_log_file = NULL; // Global log file pointer

// Structure for each drive-monitoring thread.
typedef struct {
    WCHAR drivePath[MAX_PATH]; // e.g. "C:\\"
} MONITOR_ENTRY;

// ===========================================================================
// Logging, Cleanup, and Signal Handling
// ===========================================================================

// Log a message to the log file.
void log_message(const char *format, ...) {
    if (!g_log_file) return;
    va_list args;
    va_start(args, format);
    vfprintf(g_log_file, format, args);
    fprintf(g_log_file, "\n");
    fflush(g_log_file);
    va_end(args);
}

// Cleanup resources before exiting.
void cleanup() {
    if (g_context) {
        zmq_ctx_term(g_context);
        g_context = NULL;
    }
    if (g_log_file) {
        log_message("Exiting program cleanly.");
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

// Console control handler (CTRL+C, CTRL+BREAK, etc.).
BOOL WINAPI consoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        log_message("Received signal %d, terminating...", signal);
        cleanup();
        exit(EXIT_SUCCESS);
    }
    return TRUE;
}

// ===========================================================================
// Utility Functions
// ===========================================================================

// Provided function to get precise time in microseconds.
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

// A simple Base64 encoding function.
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char pad = '=';
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = (char*)malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | (octet_c);
        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = (i - 1) > input_length ? pad : encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = i > input_length ? pad : encoding_table[triple & 0x3F];
    }
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// ===========================================================================
// File Event Handling and JSON Message Construction
// ===========================================================================

// This function reads the file, builds a JSON object with file details, and sends it via ZeroMQ.
int send_file_event_json(const wchar_t* filePath, const wchar_t* fileName, int action, void* zmq_socket) {
    // Open the file (with multiple retries if needed).
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int attempts = 0;
    while (attempts < MAX_RETRY) {
        hFile = CreateFileW(
            filePath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if (hFile != INVALID_HANDLE_VALUE)
            break;
        Sleep(500);
        attempts++;
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        log_message("Failed to open file: %ls", filePath);
        return -1;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        log_message("Failed to get file size for: %ls", filePath);
        CloseHandle(hFile);
        return -1;
    }
    
    char *fileBuffer = (char*)malloc(fileSize);
    if (!fileBuffer) {
        log_message("Memory allocation failed for file: %ls", filePath);
        CloseHandle(hFile);
        return -1;
    }
    
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        log_message("Failed to read file: %ls", filePath);
        free(fileBuffer);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile);
    
    // Base64 encode the file data.
    size_t b64_len = 0;
    char *b64_data = base64_encode((unsigned char*)fileBuffer, fileSize, &b64_len);
    free(fileBuffer);
    if (!b64_data) {
        log_message("Base64 encoding failed for file: %ls", filePath);
        return -1;
    }
    
    // Generate a human-readable timestamp with microsecond precision.
    char timestamp[64];
    uint64_t preciseTimeMicro = get_precise_time_microseconds();
    time_t sec = (time_t)(preciseTimeMicro / 1000000);
    long usec = (long)(preciseTimeMicro % 1000000);
    struct tm *tm_info = localtime(&sec);
    if (tm_info) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(timestamp, "N/A", sizeof(timestamp));
        timestamp[sizeof(timestamp)-1] = '\0';
    }
    char usec_str[16];
    sprintf(usec_str, ".%06ld", usec);
    strncat(timestamp, usec_str, sizeof(timestamp) - strlen(timestamp) - 1);
    
    // Build the JSON message using cJSON.
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        log_message("Failed to create JSON root object.");
        free(b64_data);
        return -1;
    }
    cJSON_AddStringToObject(root, "timestamp", timestamp);
    cJSON_AddStringToObject(root, "category", "file_scan");
    
    cJSON *content = cJSON_CreateObject();
    if (!content) {
        log_message("Failed to create JSON content object.");
        cJSON_Delete(root);
        free(b64_data);
        return -1;
    }
    
    // Convert wide-character file path to a multibyte string.
    char filePathA[MAX_PATH] = {0};
    size_t converted = 0;
    wcstombs_s(&converted, filePathA, sizeof(filePathA), filePath, _TRUNCATE);
    cJSON_AddStringToObject(content, "file_path", filePathA);
    
    // Extract only the base file name rather than the entire relative path.
    WCHAR *baseFileName = wcsrchr(fileName, L'\\');
    if (baseFileName != NULL)
        baseFileName++; // Move past the backslash.
    else
        baseFileName = (wchar_t*)fileName;
    
    char fileNameA[MAX_PATH] = {0};
    wcstombs_s(&converted, fileNameA, sizeof(fileNameA), baseFileName, _TRUNCATE);
    cJSON_AddStringToObject(content, "file_name", fileNameA);
    
    cJSON_AddNumberToObject(content, "file_size", (double)fileSize);
    
    // Convert the numeric action code to a human-readable string.
    const char *action_str = "UNKNOWN";
    switch (action) {
        case FILE_ACTION_ADDED:            action_str = "ADDED"; break;
        case FILE_ACTION_REMOVED:          action_str = "REMOVED"; break;
        case FILE_ACTION_MODIFIED:         action_str = "MODIFIED"; break;
        case FILE_ACTION_RENAMED_OLD_NAME: action_str = "RENAMED_OLD"; break;
        case FILE_ACTION_RENAMED_NEW_NAME: action_str = "RENAMED_NEW"; break;
    }
    cJSON_AddStringToObject(content, "action", action_str);
    
    cJSON_AddStringToObject(content, "file_data", b64_data);
    cJSON_AddItemToObject(root, "content", content);
    
    char *jsonString = cJSON_Print(root);
    cJSON_Delete(root);
    free(b64_data);
    if (!jsonString) {
        log_message("Failed to print JSON string for file: %ls", filePath);
        return -1;
    }
    
    // Send the JSON string via ZeroMQ.
    if (zmq_send(zmq_socket, jsonString, strlen(jsonString), 0) == -1) {
        log_message("Failed to send JSON message via ZeroMQ: %s", zmq_strerror(errno));
        free(jsonString);
        return -1;
    }
    free(jsonString);
    log_message("Successfully sent JSON event for file: %ls", filePath);
    return 0;
}

// ===========================================================================
// Drive-Monitoring Thread Routine
// ===========================================================================

// Each monitoring thread opens its assigned drive's root directory (once) and continuously monitors
// for file events. When an event is detected, a JSON message is built and sent via ZeroMQ.
DWORD WINAPI MonitorDrive(LPVOID lpParam) {
    MONITOR_ENTRY *entry = (MONITOR_ENTRY*)lpParam;
    
    // Open the drive's root directory.
    HANDLE hDir = CreateFileW(
        entry->drivePath,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );
    if (hDir == INVALID_HANDLE_VALUE) {
        log_message("Failed to open directory for drive: %ls", entry->drivePath);
        return 1;
    }
    
    // Create a dedicated ZeroMQ PUSH socket for this thread.
    void *socket = zmq_socket(g_context, ZMQ_PUSH);
    if (!socket) {
        log_message("Failed to create ZeroMQ socket for drive: %ls", entry->drivePath);
        CloseHandle(hDir);
        return 1;
    }
    if (zmq_connect(socket, ZMQ_ENDPOINT) != 0) {
        log_message("zmq_connect error for drive %ls: %s", entry->drivePath, zmq_strerror(errno));
        zmq_close(socket);
        CloseHandle(hDir);
        return 1;
    }
    
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesReturned;
    FILE_NOTIFY_INFORMATION *fni;
    while (1) {
        if (!ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE, // Monitor subdirectories.
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                NULL,
                NULL
            ))
        {
            log_message("ReadDirectoryChangesW failed on drive: %ls, error: %ld", entry->drivePath, GetLastError());
            break;
        }
        DWORD offset = 0;
        do {
            fni = (FILE_NOTIFY_INFORMATION*)((char*)buffer + offset);
            int fileNameLength = fni->FileNameLength / sizeof(WCHAR);
            WCHAR fileName[MAX_PATH] = {0};
            if (fileNameLength >= MAX_PATH) {
                log_message("File name too long on drive %ls, skipping.", entry->drivePath);
                goto next_notification;
            }
            wcsncpy_s(fileName, MAX_PATH, fni->FileName, fileNameLength);
            fileName[fileNameLength] = L'\0';
            
            // Build the full file path: drive root + file name.
            WCHAR filePath[MAX_PATH] = {0};
            swprintf_s(filePath, MAX_PATH, L"%s%s", entry->drivePath, fileName);
            
            log_message("Detected event %d on file: %ls", fni->Action, filePath);
            switch (fni->Action) {
                case FILE_ACTION_ADDED:
                case FILE_ACTION_MODIFIED:
                case FILE_ACTION_RENAMED_NEW_NAME:
                    if (send_file_event_json(filePath, fileName, fni->Action, socket) != 0) {
                        log_message("Error sending file event for: %ls", filePath);
                    }
                    break;
                default:
                    log_message("Unhandled action %d for file: %ls", fni->Action, filePath);
            }
next_notification:
            if (fni->NextEntryOffset == 0)
                break;
            offset += fni->NextEntryOffset;
        } while (offset < bytesReturned);
    }
    zmq_close(socket);
    CloseHandle(hDir);
    return 0;
}

// ===========================================================================
// Main Routine: Single-Time Drive Enumeration then Continuous Monitoring
// ===========================================================================

int main(void) {
    // Open the log file in append mode.
    g_log_file = fopen("file_scanner.log", "a");
    if (!g_log_file) {
        fprintf(stderr, "Failed to open log file.\n");
        exit(EXIT_FAILURE);
    }
    log_message("Program started.");
    
    // Set the console control handler.
    if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
        log_message("Failed to set control handler.");
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Create a global ZeroMQ context.
    g_context = zmq_ctx_new();
    if (!g_context) {
        log_message("Failed to create ZeroMQ context: %s", zmq_strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    // *******************************************************
    // Enumerate drives exactly once at startup.
    // This loop determines which drives to monitor.
    // *******************************************************
    DWORD drives = GetLogicalDrives();
    MONITOR_ENTRY monitorEntries[26];
    HANDLE threadHandles[26] = {0};
    int driveCount = 0;
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            WCHAR drivePath[MAX_PATH] = {0};
            swprintf_s(drivePath, MAX_PATH, L"%c:\\", 'A' + i);
            UINT driveType = GetDriveTypeW(drivePath);
            // Monitor only fixed and removable drives.
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                wcsncpy_s(monitorEntries[driveCount].drivePath, MAX_PATH, drivePath, _TRUNCATE);
                threadHandles[driveCount] = CreateThread(NULL, 0, MonitorDrive, &monitorEntries[driveCount], 0, NULL);
                if (threadHandles[driveCount] == NULL) {
                    log_message("Failed to create thread for drive: %ls", drivePath);
                } else {
                    log_message("Monitoring drive: %ls", drivePath);
                    driveCount++;
                }
            }
        }
    }
    
    if (driveCount == 0) {
        log_message("No drives found to monitor.");
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Wait indefinitely for all monitoring threads.
    WaitForMultipleObjects(driveCount, threadHandles, TRUE, INFINITE);
    
    cleanup();
    return 0;
}
