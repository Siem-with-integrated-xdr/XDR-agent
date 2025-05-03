#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <zmq.h>
#include <cJSON.h>

// Function prototypes
void log_error(const char *message);
void signal_handler(int signum);

int main(void) {
    // Set up signal handlers for unexpected termination.
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Fixed ZeroMQ endpoint.
    const char *endpoint = "tcp://*:5557";

    // Create ZeroMQ context.
    void *zmq_context = zmq_ctx_new();
    if (!zmq_context) {
        log_error("Failed to create ZeroMQ context.");
        exit(EXIT_FAILURE);
    }

    // Create a PULL socket.
    void *puller = zmq_socket(zmq_context, ZMQ_PULL);
    if (!puller) {
        log_error("Failed to create ZeroMQ PULL socket.");
        zmq_ctx_destroy(zmq_context);
        exit(EXIT_FAILURE);
    }

    // Bind the PULL socket to the fixed endpoint to listen for incoming messages.
    if (zmq_bind(puller, endpoint) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "Failed to bind to ZeroMQ endpoint %s", endpoint);
        log_error(err_msg);
        zmq_close(puller);
        zmq_ctx_destroy(zmq_context);
        exit(EXIT_FAILURE);
    }

    // Main loop: wait for messages.
    while (1) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        int rc = zmq_msg_recv(&msg, puller, 0);  // Blocking receive
        if (rc == -1) {
            log_error("Error receiving ZeroMQ message.");
            zmq_msg_close(&msg);
            continue;
        }

        size_t msg_size = zmq_msg_size(&msg);
        // Allocate memory for the message payload plus a null terminator.
        char *payload = malloc(msg_size + 1);
        if (!payload) {
            log_error("Memory allocation error for ZeroMQ message payload.");
            zmq_msg_close(&msg);
            continue;
        }
        memcpy(payload, zmq_msg_data(&msg), msg_size);
        payload[msg_size] = '\0';

        // Parse the JSON payload using cJSON.
        cJSON *json = cJSON_Parse(payload);
        free(payload); // Release allocated memory after copying.
        if (!json) {
            log_error("JSON parse error from ZeroMQ message.");
            zmq_msg_close(&msg);
            continue;
        }

        // Extract "number_of_commands" and "commands" array from the JSON.
        cJSON *num_cmds = cJSON_GetObjectItemCaseSensitive(json, "number_of_commands");
        cJSON *commands = cJSON_GetObjectItemCaseSensitive(json, "commands");

        if (!cJSON_IsNumber(num_cmds) || !cJSON_IsArray(commands)) {
            log_error("Invalid JSON format: missing number_of_commands or commands array.");
            cJSON_Delete(json);
            zmq_msg_close(&msg);
            continue;
        }

        if (cJSON_GetArraySize(commands) != num_cmds->valueint) {
            log_error("Mismatch between number_of_commands and actual commands count.");
            cJSON_Delete(json);
            zmq_msg_close(&msg);
            continue;
        }

        // Loop through the commands, printing and executing each one.
        for (int i = 0; i < num_cmds->valueint; i++) {
            cJSON *cmd_item = cJSON_GetArrayItem(commands, i);
            if (!cJSON_IsString(cmd_item)) {
                log_error("Invalid command in JSON: not a string.");
                continue;
            }

            // Execute the commands.
            int ret = system(cmd_item->valuestring);
            if (ret != 0) {
                char logbuf[256];
                snprintf(logbuf, sizeof(logbuf), "Command execution failed: %s", cmd_item->valuestring);
                log_error(logbuf);
            }
        }

        // Clean up: delete the cJSON object and close the ZeroMQ message.
        cJSON_Delete(json);
        zmq_msg_close(&msg);
    }

    // Unreachable cleanup code.
    zmq_close(puller);
    zmq_ctx_destroy(zmq_context);
    return EXIT_SUCCESS;
}

// log_error() appends an error message with a timestamp to "action.log".
void log_error(const char *message) {
    FILE *fp = fopen("action.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
        fprintf(fp, "[%s] %s\n", timebuf, message);
        fclose(fp);
    }
}

// signal_handler() logs the received signal and exits safely.
void signal_handler(int signum) {
    char errbuf[128];
    snprintf(errbuf, sizeof(errbuf), "Program encountered signal: %d. Exiting safely.", signum);
    log_error(errbuf);
    exit(EXIT_FAILURE);
}
