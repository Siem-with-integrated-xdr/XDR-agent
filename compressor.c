#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <zmq.h>
#include <zstd.h>
#include <cjson/cJSON.h>
#include <pcap.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>

// simple filter for which interfaces to ignore
int is_valid_interface(const char *desc) {
    if (!desc) return 0;
    if (strstr(desc, "WAN Miniport") ||
        strstr(desc, "Virtual")      ||
        strstr(desc, "Loopback")     ||
        strstr(desc, "Bluetooth"))
        return 0;
    return 1;
}

// Logging helper
void log_error(const char *format, ...) {
    FILE *logFile = fopen("compressor.log", "a");
    if (!logFile) {
        fprintf(stderr, "Unable to open log file for writing\n");
        return;
    }
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[64];
    if (tm_info) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(time_buf, "N/A", sizeof(time_buf));
        time_buf[sizeof(time_buf)-1] = '\0';
    }
    fprintf(logFile, "[%s] ", time_buf);
    va_list args;
    va_start(args, format);
    vfprintf(logFile, format, args);
    va_end(args);
    fprintf(logFile, "\n");
    fclose(logFile);
}

// catch fatal signals
void signal_handler(int signum) {
    log_error("Program terminated by signal: %d", signum);
    exit(EXIT_FAILURE);
}

// retrieve hostname + first non-loopback IPv4 via pcap
void get_host_info(char *name_buf, size_t name_len, char *ip_buf, size_t ip_len) {
    // 1) hostname
    if (gethostname(name_buf, (int)name_len) != 0) {
        strncpy(name_buf, "unknown", name_len);
        name_buf[name_len-1] = '\0';
    }

    // 2) find via pcap
    pcap_if_t *alldevs = NULL, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        log_error("pcap_findalldevs failed: %s", errbuf);
        goto fallback;
    }
    for (d = alldevs; d; d = d->next) {
        if (!is_valid_interface(d->description)) continue;
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)a->addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, ip_buf, ip_len)) {
                    pcap_freealldevs(alldevs);
                    return;
                }
            }
        }
    }
    pcap_freealldevs(alldevs);

fallback:
    // fallback if nothing found
    strncpy(ip_buf, "127.0.0.1", ip_len);
    ip_buf[ip_len-1] = '\0';
}

int main(void) {
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGFPE,  signal_handler);
    signal(SIGILL,  signal_handler);
    log_error("Program started");

    // ZeroMQ setup
    void *ctx = zmq_ctx_new();
    if (!ctx) { log_error("zmq_ctx_new: %s", zmq_strerror(zmq_errno())); return EXIT_FAILURE; }

    void *pull = zmq_socket(ctx, ZMQ_PULL);
    if (!pull) { log_error("zmq_socket(PULL): %s", zmq_strerror(zmq_errno())); zmq_ctx_destroy(ctx); return EXIT_FAILURE; }
    if (zmq_bind(pull, "tcp://localhost:5555") != 0) {
        log_error("zmq_bind(PULL): %s", zmq_strerror(zmq_errno()));
        zmq_close(pull); zmq_ctx_destroy(ctx); return EXIT_FAILURE;
    }

    void *push = zmq_socket(ctx, ZMQ_PUSH);
    if (!push) { log_error("zmq_socket(PUSH): %s", zmq_strerror(zmq_errno())); zmq_close(pull); zmq_ctx_destroy(ctx); return EXIT_FAILURE; }
    if (zmq_connect(push, "tcp://localhost:5556") != 0) {
        log_error("zmq_connect(PUSH): %s", zmq_strerror(zmq_errno()));
        zmq_close(push); zmq_close(pull); zmq_ctx_destroy(ctx); return EXIT_FAILURE;
    }

    while (1) {
        zmq_msg_t in;
        if (zmq_msg_init(&in) != 0) { log_error("zmq_msg_init: %s", zmq_strerror(zmq_errno())); break; }
        if (zmq_msg_recv(&in, pull, 0) == -1) {
            log_error("zmq_msg_recv: %s", zmq_strerror(zmq_errno()));
            zmq_msg_close(&in);
            break;
        }

        size_t in_sz = zmq_msg_size(&in);
        char *in_buf = malloc(in_sz+1);
        if (!in_buf) { log_error("malloc(in_buf) failed"); zmq_msg_close(&in); break; }
        memcpy(in_buf, zmq_msg_data(&in), in_sz);
        in_buf[in_sz] = '\0';

        // wrap JSON
        char host[256], ip[64];
        get_host_info(host, sizeof(host), ip, sizeof(ip));
        cJSON *arr  = cJSON_CreateArray();
        cJSON *info = cJSON_CreateObject();
        cJSON_AddStringToObject(info, "computer_name", host);
        cJSON_AddStringToObject(info, "computer_ip",   ip);
        cJSON_AddItemToArray(arr, info);

        cJSON *orig = cJSON_Parse(in_buf);
        if (!orig) {
            log_error("cJSON_Parse failed, wrapping raw");
            orig = cJSON_CreateString(in_buf);
        }
        cJSON_AddItemToArray(arr, orig);
        free(in_buf);

        char *wrapped = cJSON_Print(arr);
        cJSON_Delete(arr);
        if (!wrapped) { log_error("cJSON_Print failed"); break; }

        // compress
        size_t bound = ZSTD_compressBound(strlen(wrapped));
        void *cmp = malloc(bound);
        if (!cmp) { log_error("malloc(cmp) failed"); free(wrapped); break; }
        size_t cmp_sz = ZSTD_compress(cmp, bound, wrapped, strlen(wrapped), 3);
        free(wrapped);
        if (ZSTD_isError(cmp_sz)) {
            log_error("ZSTD_compress: %s", ZSTD_getErrorName(cmp_sz));
            free(cmp);
            zmq_msg_close(&in);
            continue;
        }

        // send
        zmq_msg_t out;
        if (zmq_msg_init_size(&out, cmp_sz) != 0) {
            log_error("zmq_msg_init_size: %s", zmq_strerror(zmq_errno()));
            free(cmp); zmq_msg_close(&in);
            continue;
        }
        memcpy(zmq_msg_data(&out), cmp, cmp_sz);
        free(cmp);

        if (zmq_msg_send(&out, push, 0) == -1) {
            log_error("zmq_msg_send: %s", zmq_strerror(zmq_errno()));
        }
        zmq_msg_close(&out);
        zmq_msg_close(&in);
    }

    zmq_close(push);
    zmq_close(pull);
    zmq_ctx_destroy(ctx);
    log_error("Program terminated normally");
    return EXIT_SUCCESS;
}
