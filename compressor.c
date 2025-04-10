#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>
#include <zstd.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>

// Logging function that writes timestamped messages to compresso.log
void log_error(const char *format, ...) {
    FILE *logFile = fopen("compressor.log", "a");
    if (!logFile) {
        fprintf(stderr, "Unable to open log file for writing\n");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    if (tm_info != NULL) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(time_buf, "N/A", sizeof(time_buf));
        time_buf[sizeof(time_buf) - 1] = '\0';
    }
    fprintf(logFile, "[%s] ", time_buf);
    va_list args;
    va_start(args, format);
    vfprintf(logFile, format, args);
    va_end(args);
    fprintf(logFile, "\n");
    fclose(logFile);
}

// Signal handler to catch fatal signals and log them
void signal_handler(int signum) {
    log_error("Program terminated by signal: %d", signum);
    exit(EXIT_FAILURE);
}

int main(void) {
    // Register signal handlers for common fatal signals.
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE, signal_handler);
    signal(SIGILL, signal_handler);


    // Create a ZeroMQ context.
    void *context = zmq_ctx_new();
    if (!context) {
        log_error("Error creating ZeroMQ context: %s", zmq_strerror(zmq_errno()));
        return EXIT_FAILURE;
    }
    
    // Create a PULL socket for receiving messages.
    void *receiver = zmq_socket(context, ZMQ_PULL);
    if (!receiver) {
        log_error("Error creating ZeroMQ receiver socket: %s", zmq_strerror(zmq_errno()));
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }
    if (zmq_bind(receiver, "tcp://*:5555") != 0) {
        log_error("Error binding receiver socket to endpoint: %s", zmq_strerror(zmq_errno()));
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }
    
    // Create a PUSH socket for sending compressed data.
    void *sender = zmq_socket(context, ZMQ_PUSH);
    if (!sender) {
        log_error("Error creating ZeroMQ sender socket: %s", zmq_strerror(zmq_errno()));
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }
    // Use zmq_connect() for the sender socket.
    if (zmq_connect(sender, "tcp://localhost:5556") != 0) {
        log_error("Error connecting sender socket to endpoint: %s", zmq_strerror(zmq_errno()));
        zmq_close(sender);
        zmq_close(receiver);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    // Continuously receive, compress, and send messages.
    while (1) {
        zmq_msg_t msg;
        if (zmq_msg_init(&msg) != 0) {
            log_error("Error initializing message: %s", zmq_strerror(zmq_errno()));
            break;
        }

        // Receive a message from a PUSH sender.
        int rc = zmq_msg_recv(&msg, receiver, 0);
        if (rc == -1) {
            log_error("Error receiving message: %s", zmq_strerror(zmq_errno()));
            zmq_msg_close(&msg);
            break;
        }

        // Retrieve the data and its size from the zmq_msg.
        char *data = (char *)zmq_msg_data(&msg);
        size_t data_len = zmq_msg_size(&msg);

        // Allocate memory for the compressed data.
        size_t bound = ZSTD_compressBound(data_len);
        void *compressed_data = malloc(bound);
        if (!compressed_data) {
            log_error("Memory allocation failed for compression buffer");
            zmq_msg_close(&msg);
            break;
        }

        // Compress the data using Zstd.
        int compressionLevel = 3;
        size_t compressed_size = ZSTD_compress(compressed_data, bound, data, data_len, compressionLevel);
        if (ZSTD_isError(compressed_size)) {
            log_error("Compression error: %s", ZSTD_getErrorName(compressed_size));
            free(compressed_data);
            zmq_msg_close(&msg);
            continue;  // Skip this message and wait for the next one.
        }

        // Initialize a new message for the compressed data.
        zmq_msg_t out_msg;
        if (zmq_msg_init_size(&out_msg, compressed_size) != 0) {
            log_error("Error initializing outgoing message: %s", zmq_strerror(zmq_errno()));
            free(compressed_data);
            zmq_msg_close(&msg);
            continue;
        }
        memcpy(zmq_msg_data(&out_msg), compressed_data, compressed_size);

        // Send the compressed data.
        if (zmq_msg_send(&out_msg, sender, 0) == -1) {
            log_error("Error sending compressed message: %s", zmq_strerror(zmq_errno()));
            zmq_msg_close(&out_msg);
            free(compressed_data);
            zmq_msg_close(&msg);
            continue;
        }
        zmq_msg_close(&out_msg);

        // Clean up for this message.
        free(compressed_data);
        zmq_msg_close(&msg);
    }

    // Cleanup resources on exit.
    zmq_close(sender);
    zmq_close(receiver);
    zmq_ctx_destroy(context);
    log_error("Program terminated normally");
    return EXIT_SUCCESS;
}
