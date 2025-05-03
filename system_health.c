#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <signal.h>
#include <cJSON.h>
#include <zmq.h>

// Global resources for cleanup.
static void *g_context = NULL;
static void *g_socket = NULL;
static FILE *g_log_file = NULL;

// Log messages to the log file.
void log_message(const char *format, ...) {
    if (g_log_file == NULL)
        return;
    
    va_list args;
    va_start(args, format);
    vfprintf(g_log_file, format, args);
    fprintf(g_log_file, "\n");
    fflush(g_log_file);
    va_end(args);
}

// Cleanup resources before exiting.
void cleanup() {
    if (g_socket) {
        zmq_close(g_socket);
        g_socket = NULL;
    }
    if (g_context) {
        zmq_ctx_destroy(g_context);
        g_context = NULL;
    }
    if (g_log_file) {
        log_message("Exiting program cleanly.");
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

// Signal handler to catch termination signals.
void signal_handler(int signum) {
    log_message("Received signal %d, terminating...", signum);
    cleanup();
    exit(EXIT_FAILURE);
}

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

// Function to calculate CPU usage over an interval using GetSystemTimes.
double getCpuUsage() {
    static int firstTime = 1;
    static ULONGLONG prevIdle = 0, prevKernel = 0, prevUser = 0;
    FILETIME idleTime, kernelTime, userTime;
    
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        log_message("GetSystemTimes failed.");
        return -1.0;
    }
    
    ULONGLONG idle = (((ULONGLONG)idleTime.dwHighDateTime << 32) | idleTime.dwLowDateTime);
    ULONGLONG kernel = (((ULONGLONG)kernelTime.dwHighDateTime << 32) | kernelTime.dwLowDateTime);
    ULONGLONG user = (((ULONGLONG)userTime.dwHighDateTime << 32) | userTime.dwLowDateTime);
    
    if (firstTime) {
        firstTime = 0;
        prevIdle = idle;
        prevKernel = kernel;
        prevUser = user;
        return 0.0;
    }
    
    ULONGLONG idleDiff = idle - prevIdle;
    ULONGLONG kernelDiff = kernel - prevKernel;
    ULONGLONG userDiff = user - prevUser;
    ULONGLONG totalDiff = kernelDiff + userDiff;
    
    double cpuUsage = 0.0;
    if (totalDiff > 0) {
        cpuUsage = (double)(totalDiff - idleDiff) * 100.0 / totalDiff;
    }
    
    prevIdle = idle;
    prevKernel = kernel;
    prevUser = user;
    
    return cpuUsage;
}

// Function to get disk usage percentage for a given path (e.g., "C:\").
int getDiskUsagePercent(const char *path, double *usagePercent) {
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (!GetDiskFreeSpaceExA(path, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        log_message("GetDiskFreeSpaceExA failed for path: %s", path);
        return -1;
    }
    ULONGLONG usedBytes = totalNumberOfBytes.QuadPart - totalNumberOfFreeBytes.QuadPart;
    *usagePercent = (double)usedBytes * 100.0 / totalNumberOfBytes.QuadPart;
    return 0;
}

int main(void) {
    // Open the log file in append mode.
    g_log_file = fopen("system_health.log", "a");
    if (!g_log_file) {
        fprintf(stderr, "Failed to open log file.\n");
        exit(EXIT_FAILURE);
    }
    log_message("Program started.");

    // Register signal handlers.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize ZeroMQ context.
    g_context = zmq_ctx_new();
    if (!g_context) {
        log_message("Failed to create ZeroMQ context: %s", zmq_strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Create a PUSH socket.
    g_socket = zmq_socket(g_context, ZMQ_PUSH);
    if (!g_socket) {
        log_message("Failed to create ZeroMQ socket: %s", zmq_strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    // Connect to the endpoint.
    if (zmq_connect(g_socket, "tcp://localhost:5555") != 0) {
        log_message("zmq_connect error: %s", zmq_strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }
    
    while (1) {
        // Gather system health data.
        double cpu = getCpuUsage();
        if (cpu < 0) {
            log_message("Error getting CPU usage.");
            cleanup();
            exit(EXIT_FAILURE);
        }
        
        // Get memory usage.
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (!GlobalMemoryStatusEx(&memInfo)) {
            log_message("GlobalMemoryStatusEx failed.");
            cleanup();
            exit(EXIT_FAILURE);
        }
        ULONGLONG totalPhys = memInfo.ullTotalPhys;
        ULONGLONG availPhys = memInfo.ullAvailPhys;
        double usedMemory = (double)(totalPhys - availPhys);
        double memUsagePercent = usedMemory * 100.0 / totalPhys;
        
        // Get disk usage for drive C:\.
        double diskUsagePercent = 0.0;
        if (getDiskUsagePercent("C:\\", &diskUsagePercent) != 0) {
            diskUsagePercent = -1.0; // error indicator
        }
        
        // Get system uptime in seconds.
        ULONGLONG uptimeMillis = GetTickCount64();
        double uptimeSeconds = uptimeMillis / 1000.0;
        
        // Create JSON object using cJSON.
        cJSON *root = cJSON_CreateObject();
        if (!root) {
            log_message("Failed to create JSON root object.");
            cleanup();
            exit(EXIT_FAILURE);
        }
        
        // Create a human-readable timestamp with microsecond precision.
        char global_ts[64];
        uint64_t preciseTimeMicro = get_precise_time_microseconds();
        time_t sec = (time_t)(preciseTimeMicro / 1000000);
        long usec = (long)(preciseTimeMicro % 1000000);
        struct tm *tm_info = localtime(&sec);
        if (tm_info != NULL) {
            strftime(global_ts, sizeof(global_ts), "%Y-%m-%d %H:%M:%S", tm_info);
        } else {
            strncpy(global_ts, "N/A", sizeof(global_ts));
            global_ts[sizeof(global_ts) - 1] = '\0';
        }
        char usec_str[16];
        sprintf(usec_str, ".%06ld", usec);
        strncat(global_ts, usec_str, sizeof(global_ts) - strlen(global_ts) - 1);
        // Add the formatted timestamp to the JSON object.
        cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(global_ts));
        
        cJSON_AddStringToObject(root, "category", "system_health");
        
        // Create content object with health metrics.
        cJSON *content = cJSON_CreateObject();
        if (!content) {
            log_message("Failed to create JSON content object.");
            cJSON_Delete(root);
            cleanup();
            exit(EXIT_FAILURE);
        }
        cJSON_AddNumberToObject(content, "cpu_usage", cpu);
        cJSON_AddNumberToObject(content, "memory_usage", memUsagePercent);
        cJSON_AddNumberToObject(content, "disk_usage", diskUsagePercent);
        cJSON_AddNumberToObject(content, "uptime_seconds", uptimeSeconds);
        cJSON_AddItemToObject(root, "content", content);
        
        // Convert JSON object to string.
        char *jsonString = cJSON_Print(root);
        if (!jsonString) {
            log_message("Failed to print JSON string.");
            cJSON_Delete(root);
            cleanup();
            exit(EXIT_FAILURE);
        }
        
        // Send the JSON string via ZeroMQ.
        zmq_msg_t message;
        if (zmq_msg_init_size(&message, strlen(jsonString)) != 0) {
            log_message("zmq_msg_init_size error: %s", zmq_strerror(errno));
            free(jsonString);
            cJSON_Delete(root);
            cleanup();
            exit(EXIT_FAILURE);
        }
        memcpy(zmq_msg_data(&message), jsonString, strlen(jsonString));
        if (zmq_msg_send(&message, g_socket, 0) == -1) {
            log_message("zmq_msg_send error: %s", zmq_strerror(errno));
            zmq_msg_close(&message);
            free(jsonString);
            cJSON_Delete(root);
            cleanup();
            exit(EXIT_FAILURE);
        }
        zmq_msg_close(&message);
        
        // Clean up JSON objects and allocated memory.
        cJSON_Delete(root);
        free(jsonString);
        
        // Wait for 5 seconds before gathering data again.
        Sleep(5000);
    }
    
    cleanup();
    return 0;
}
