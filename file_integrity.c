#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <windows.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <zmq.h>
#include "cJSON.h"  // Ensure cJSON.h is in your include path

#define BUFFER_SIZE 8192

// Log error messages to file_integrity.log
void log_error(const char *msg) {
    FILE *logfile = fopen("file_integrity.log", "a");
    if (logfile) {
        fprintf(logfile, "%s\n", msg);
        fclose(logfile);
    }
}

// Signal handler to catch fatal signals and exit safely.
void handle_signal(int sig) {
    char msg[128];
    snprintf(msg, sizeof(msg), "Received signal %d. Exiting safely.", sig);
    log_error(msg);
    exit(EXIT_FAILURE);
}

// Compute the SHA-256 hash of a file specified by filename.
// The computed digest is written as a hexadecimal string into outputBuffer,
// which must be at least (EVP_MAX_MD_SIZE*2)+1 bytes in length.
// Returns 0 on success, -1 on error.
int compute_file_hash(const char *filename, char *outputBuffer) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        char err[256];
        snprintf(err, sizeof(err), "Failed to open file: %s (errno=%d)", filename, errno);
        log_error(err);
        return -1;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fclose(file);
        log_error("EVP_MD_CTX_new failed");
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        log_error("EVP_DigestInit_ex failed");
        return -1;
    }

    unsigned char buf[BUFFER_SIZE];
    size_t bytesRead = 0;
    while ((bytesRead = fread(buf, 1, BUFFER_SIZE, file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, bytesRead) != 1) {
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            log_error("EVP_DigestUpdate failed");
            return -1;
        }
    }
    if (ferror(file)) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        log_error("Error while reading file");
        return -1;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        log_error("EVP_DigestFinal_ex failed");
        return -1;
    }
    
    fclose(file);
    EVP_MD_CTX_free(mdctx);
    
    // Convert binary hash to a hexadecimal string.
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[hash_len * 2] = '\0';
    
    return 0;
}

// Helper: Extract file name from a given file path.
const char* extract_file_name(const char *filepath) {
    const char *name = strrchr(filepath, '\\');
    if (name) {
        return name + 1;  // Skip the backslash.
    }
    return filepath;
}

int main(void) {
    // Register signal handlers for safe exit on errors.
    signal(SIGSEGV, handle_signal);
    signal(SIGABRT, handle_signal);
    signal(SIGFPE,  handle_signal);
    
    // List of critical files (full paths) to monitor.
    const char *files[] = {
        "C:\\Windows\\System32\\wininit.exe",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\csrss.exe",
        "C:\\Windows\\System32\\services.exe",
        "C:\\Windows\\System32\\userinit.exe",
        "C:\\Windows\\System32\\rundll32.exe",
        "C:\\Windows\\System32\\taskhostw.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\ntoskrnl.exe",
        "C:\\Windows\\System32\\winload.exe",
        "C:\\Windows\\System32\\winresume.exe",
        "C:\\Windows\\System32\\hal.dll",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\drivers\\disk.sys",
        "C:\\Windows\\System32\\drivers\\ntfs.sys",
        "C:\\Windows\\System32\\drivers\\tcpip.sys",
        "C:\\Windows\\System32\\drivers\\afd.sys",
        "C:\\Windows\\System32\\drivers\\fwpkclnt.sys",
        "C:\\Windows\\System32\\crypt32.dll",
        "C:\\Windows\\System32\\cryptdll.dll",
        "C:\\Windows\\System32\\secur32.dll",
        "C:\\Windows\\System32\\schannel.dll"
    };
    int num_files = sizeof(files) / sizeof(files[0]);

    // Initialize ZeroMQ context and create a PUSH socket.
    void *context = zmq_ctx_new();
    if (!context) {
        log_error("Failed to create ZeroMQ context");
        return EXIT_FAILURE;
    }

    void *socket = zmq_socket(context, ZMQ_PUSH);
    if (!socket) {
        log_error("Failed to create ZeroMQ socket");
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    // Connect to a ZeroMQ endpoint (adjust the address as needed).
    if (zmq_connect(socket, "tcp://localhost:5555") != 0) {
        log_error("Failed to connect to ZeroMQ endpoint (tcp://localhost:5555)");
        zmq_close(socket);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    // Main monitoring loop: runs continuously every 1 minute.
    while (1) {
        // Create a cJSON root object.
        cJSON *root = cJSON_CreateObject();
        if (!root) {
            log_error("Failed to create root JSON object");
            Sleep(60000);
            continue;
        }
        
        // --- Create a high-resolution timestamp ---
        // Use Windows functions to obtain time in format: YYYY-MM-DD HH:MM:SS.ffffff
        FILETIME ft, local_ft;
        SYSTEMTIME st;
        GetSystemTimePreciseAsFileTime(&ft);
        FileTimeToLocalFileTime(&ft, &local_ft);
        FileTimeToSystemTime(&local_ft, &st);
        
        // Convert FILETIME (100-nanosecond intervals) to microseconds.
        ULONGLONG ft64 = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        unsigned int microsec = (unsigned int)((ft64 % 10000000ULL) / 10ULL);
        
        char timestamp_str[64];
        // Format: YYYY-MM-DD HH:MM:SS.ffffff
        snprintf(timestamp_str, sizeof(timestamp_str), "%04d-%02d-%02d %02d:%02d:%02d.%06d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, microsec);
        cJSON_AddStringToObject(root, "timestamp", timestamp_str);
        
        // Add the fixed category.
        cJSON_AddStringToObject(root, "category", "file_integrity");
        
        // Create an array for file integrity content.
        cJSON *contentArray = cJSON_CreateArray();
        if (!contentArray) {
            log_error("Failed to create content JSON array");
            cJSON_Delete(root);
            Sleep(60000);
            continue;
        }
        cJSON_AddItemToObject(root, "content", contentArray);
        
        // Process each file.
        char hashOutput[EVP_MAX_MD_SIZE * 2 + 1];
        for (int i = 0; i < num_files; i++) {
            // Check if the file exists and is not a directory.
            struct _stat st_file;
            if (_stat(files[i], &st_file) != 0) {
                char err[256];
                snprintf(err, sizeof(err), "Cannot stat file: %s (errno=%d)", files[i], errno);
                log_error(err);
                continue;
            }
            // Skip directories.
            if (st_file.st_mode & _S_IFDIR) {
                continue;
            }
            
            if (compute_file_hash(files[i], hashOutput) == 0) {
                // Create a JSON object for this file.
                cJSON *file_obj = cJSON_CreateObject();
                if (!file_obj) {
                    log_error("Failed to create JSON object for file");
                    continue;
                }
                // Add file path.
                cJSON_AddStringToObject(file_obj, "file_path", files[i]);
                // Extract and add file name.
                const char *file_name = extract_file_name(files[i]);
                cJSON_AddStringToObject(file_obj, "file_name", file_name);
                // Add file hash.
                cJSON_AddStringToObject(file_obj, "file_hash", hashOutput);
                // Append this file object to the content array.
                cJSON_AddItemToArray(contentArray, file_obj);
            }
        }
        
        // Convert JSON object to a string.
        char *json_string = cJSON_Print(root);
        if (!json_string) {
            log_error("Failed to print JSON string");
            cJSON_Delete(root);
            Sleep(60000);
            continue;
        }
        
        // Send the JSON message via ZeroMQ.
        int send_result = zmq_send(socket, json_string, (int)strlen(json_string), 0);
        if (send_result < 0) {
            log_error("Failed to send ZeroMQ message");
        }
        
        // Clean up dynamically allocated memory.
        free(json_string);
        cJSON_Delete(root);
        
        // Sleep for 1 minute (60000 milliseconds)
        Sleep(60000);
    }

    // Clean up ZeroMQ resources before exiting.
    zmq_close(socket);
    zmq_ctx_destroy(context);
    return EXIT_SUCCESS;
}
