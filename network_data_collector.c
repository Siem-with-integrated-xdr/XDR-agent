#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <time.h>
#include <cJSON.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <zmq.h>   // ZeroMQ header

#define MAX_PACKET_SIZE 65536
#define MAX_BUFFER_SIZE 10   // Number of packets to buffer before sending to the analysis engine
#define FLUSH_INTERVAL 5     // Time interval (in seconds) to flush the buffer if not full

// ---------------------- Packet Structures ----------------------

// Captured packet structure.
struct captured_packet {
    struct pcap_pkthdr header;
    u_char *packet;  // Dynamically allocated copy of the packet data
};

// Ethernet Header
struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

// IPv4 Header
struct ip_header {
    uint8_t ihl_version;     // 4 bits version, 4 bits header length
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t offset;         // Contains fragmentation flags & offset
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

// IPv6 Header (fixed 40 bytes)
struct ipv6_header {
    uint32_t version_tc_flow;  // 4 bits version, 8 bits traffic class, 20 bits flow label
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    unsigned char src_addr[16];
    unsigned char dest_addr[16];
};

// TCP Header
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;   // Upper 4 bits represent header length in 32-bit words
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// UDP Header
struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// ICMP Header for IPv4
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

// ICMPv6 Header for IPv6
struct icmp6_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};

// Packet buffer structure to hold captured packets.
struct packet_buffer {
    struct captured_packet *packets[MAX_BUFFER_SIZE];
    int packet_count;
    int total_size;
    time_t last_flush_time;
};

// ---------------------- Global Resources & Cleanup ----------------------

struct resources {
    pcap_t *handle;
    pcap_if_t *alldevs;
#ifdef _WIN32
    int winsock_initialized;
#endif
    struct packet_buffer *buffer;  // Dynamically allocated packet buffer
};
static struct resources g_resources = {0};

// Global ZeroMQ context and sender socket.
static void *zmq_context = NULL;
static void *zmq_sender = NULL;

void cleanup_resources() {
    // Free any captured packets in the buffer.
    if (g_resources.buffer) {
        for (int i = 0; i < g_resources.buffer->packet_count; i++) {
            if (g_resources.buffer->packets[i]) {
                free(g_resources.buffer->packets[i]->packet);
                free(g_resources.buffer->packets[i]);
                g_resources.buffer->packets[i] = NULL;
            }
        }
        free(g_resources.buffer);
        g_resources.buffer = NULL;
    }
    if (g_resources.alldevs) {
        pcap_freealldevs(g_resources.alldevs);
        g_resources.alldevs = NULL;
    }
    if (g_resources.handle) {
        pcap_close(g_resources.handle);
        g_resources.handle = NULL;
    }
#ifdef _WIN32
    if (g_resources.winsock_initialized) {
        WSACleanup();
        g_resources.winsock_initialized = 0;
    }
#endif
    // Cleanup ZeroMQ resources.
    if (zmq_sender) {
        zmq_close(zmq_sender);
        zmq_sender = NULL;
    }
    if (zmq_context) {
        zmq_ctx_destroy(zmq_context);
        zmq_context = NULL;
    }
}

// Log error messages to "network_log.log" with a timestamp.
void log_error(const char *format, ...) {
    FILE *logFile = fopen("network_log.log", "a");
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

// Crash handler: logs the error, calls cleanup, and exits.
void crash_handler(int sig) {
    log_error("Crash detected: signal %d", sig);
    cleanup_resources();
    exit(EXIT_FAILURE);
}

// ---------------------- Utility Functions ----------------------

// Format IPv4 address into a string.
void format_ipv4(uint32_t ip, char *buffer, size_t buflen) {
    sprintf(buffer, "%d.%d.%d.%d", ip & 0xFF, (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

// Format MAC address into a string.
void format_mac(const uint8_t *mac, char *buffer, size_t buflen) {
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Format IPv6 address into a string (simple non-compressed format).
void format_ipv6(const unsigned char *addr, char *buffer, size_t buflen) {
    sprintf(buffer,
            "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            addr[0], addr[1], addr[2], addr[3],
            addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11],
            addr[12], addr[13], addr[14], addr[15]);
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

// Format pcap timestamp into a string.
void format_timestamp(const struct pcap_pkthdr *header, char *buffer, size_t buflen) {
    time_t t = (time_t) header->ts.tv_sec;
    struct tm *tm_info = localtime(&t);
    if (tm_info != NULL) {
        strftime(buffer, buflen, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "N/A", buflen);
        buffer[buflen - 1] = '\0';
    }
    long micro = header->ts.tv_usec;
    if (micro < 0)
        micro = 0;
    if (micro > 1000000)
        micro /= 1000;
    char usec[10];
    sprintf(usec, ".%06ld", micro);
    strncat(buffer, usec, buflen - strlen(buffer) - 1);
}

// Get protocol name for IPv4.
const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Other";
    }
}

// Get next header name for IPv6.
const char* get_ipv6_next_header(uint8_t next_header) {
    switch (next_header) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 58: return "ICMPv6";
        default: return "Other";
    }
}

// ---------------------- Packet Processing ----------------------

// Process the buffered packets and return a JSON string.
char* process_buffer(struct packet_buffer *buffer) {
    cJSON *root = cJSON_CreateObject();
    cJSON *packet_array = cJSON_CreateArray();
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
    cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(global_ts));
    cJSON_AddItemToObject(root, "category", cJSON_CreateString("Network Packet"));
    cJSON_AddItemToObject(root, "number_of_packets", cJSON_CreateNumber(buffer->packet_count));
    cJSON_AddItemToObject(root, "packets", packet_array);

    for (int i = 0; i < buffer->packet_count; i++) {
        struct captured_packet *cp = buffer->packets[i];
        const struct pcap_pkthdr *header = &cp->header;
        const u_char *packet = cp->packet;
        cJSON *packet_obj = cJSON_CreateObject();

        // 1. Packet timestamp.
        char pkt_ts[64];
        format_timestamp(header, pkt_ts, sizeof(pkt_ts));
        cJSON_AddItemToObject(packet_obj, "packet_timestamp", cJSON_CreateString(pkt_ts));

        // 2. Ether type.
        if (header->len < sizeof(struct ethernet_header)) {
            cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for Ethernet header"));
            cJSON_AddItemToArray(packet_array, packet_obj);
            continue;
        }
        struct ethernet_header *eth = (struct ethernet_header *)packet;
        uint16_t eth_type = ntohs(eth->eth_type);
        cJSON_AddItemToObject(packet_obj, "ether_type", cJSON_CreateNumber(eth_type));

        // 3. MAC addresses.
        char mac_buf[18];
        format_mac(eth->src_mac, mac_buf, sizeof(mac_buf));
        cJSON_AddItemToObject(packet_obj, "source_mac", cJSON_CreateString(mac_buf));
        format_mac(eth->dest_mac, mac_buf, sizeof(mac_buf));
        cJSON_AddItemToObject(packet_obj, "destination_mac", cJSON_CreateString(mac_buf));

        // 4. Packet size.
        cJSON_AddItemToObject(packet_obj, "packet_size", cJSON_CreateNumber(header->len));

        // 5. Determine protocol (default "N/A")
        char protocol_str[16] = "N/A";
        if (eth_type == 0x0800) { // IPv4
            if (header->len >= sizeof(struct ethernet_header) + sizeof(struct ip_header)) {
                struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
                switch (ip->protocol) {
                    case 6:  strcpy(protocol_str, "TCP"); break;
                    case 17: strcpy(protocol_str, "UDP"); break;
                    case 1:  strcpy(protocol_str, "ICMP"); break;
                    default: strcpy(protocol_str, "Other"); break;
                }
            }
        } else if (eth_type == 0x86DD) { // IPv6
            if (header->len >= sizeof(struct ethernet_header) + sizeof(struct ipv6_header)) {
                struct ipv6_header *ip6 = (struct ipv6_header *)(packet + sizeof(struct ethernet_header));
                switch (ip6->next_header) {
                    case 6:  strcpy(protocol_str, "TCP"); break;
                    case 17: strcpy(protocol_str, "UDP"); break;
                    case 58: strcpy(protocol_str, "ICMPv6"); break;
                    default: strcpy(protocol_str, "Other"); break;
                }
            }
        }
        cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString(protocol_str));

        // 6. Process protocol-specific fields.
        if (eth_type == 0x0800) { // IPv4
            if (header->len < sizeof(struct ethernet_header) + sizeof(struct ip_header)) {
                cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv4 header"));
                cJSON_AddItemToArray(packet_array, packet_obj);
                continue;
            }
            struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
            int ip_header_len = (ip->ihl_version & 0x0F) * 4;
            if (header->len < sizeof(struct ethernet_header) + ip_header_len) {
                cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv4 header with options"));
                cJSON_AddItemToArray(packet_array, packet_obj);
                continue;
            }
            char ip_buf[16];
            format_ipv4(ip->src_ip, ip_buf, sizeof(ip_buf));
            cJSON_AddItemToObject(packet_obj, "source_ip", cJSON_CreateString(ip_buf));
            format_ipv4(ip->dest_ip, ip_buf, sizeof(ip_buf));
            cJSON_AddItemToObject(packet_obj, "destination_ip", cJSON_CreateString(ip_buf));
            cJSON_AddItemToObject(packet_obj, "ttl", cJSON_CreateNumber(ip->ttl));
            cJSON_AddItemToObject(packet_obj, "tos", cJSON_CreateNumber(ip->tos));
            cJSON_AddItemToObject(packet_obj, "ip_total_length", cJSON_CreateNumber(ntohs(ip->total_length)));
            cJSON_AddItemToObject(packet_obj, "ip_id", cJSON_CreateNumber(ntohs(ip->id)));
            cJSON_AddItemToObject(packet_obj, "ip_offset", cJSON_CreateNumber(ntohs(ip->offset)));

            if (ip->protocol == 6) {  // TCP
                if (header->len < sizeof(struct ethernet_header) + ip_header_len + sizeof(struct tcp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for TCP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
                int tcp_header_len = ((tcp->data_offset >> 4) * 4);
                if (header->len < sizeof(struct ethernet_header) + ip_header_len + tcp_header_len) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for TCP header with options"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                cJSON_AddItemToObject(packet_obj, "source_port", cJSON_CreateNumber(ntohs(tcp->src_port)));
                cJSON_AddItemToObject(packet_obj, "destination_port", cJSON_CreateNumber(ntohs(tcp->dest_port)));
                cJSON_AddItemToObject(packet_obj, "sequence_number", cJSON_CreateNumber(ntohl(tcp->seq_num)));
                cJSON_AddItemToObject(packet_obj, "acknowledgment_number", cJSON_CreateNumber(ntohl(tcp->ack_num)));
                cJSON_AddItemToObject(packet_obj, "tcp_flags", cJSON_CreateNumber(tcp->flags));
                cJSON_AddItemToObject(packet_obj, "window_size", cJSON_CreateNumber(ntohs(tcp->window)));

                int payload_offset = sizeof(struct ethernet_header) + ip_header_len + tcp_header_len;
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            } else if (ip->protocol == 17) {  // UDP
                if (header->len < sizeof(struct ethernet_header) + ip_header_len + sizeof(struct udp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for UDP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
                cJSON_AddItemToObject(packet_obj, "source_port", cJSON_CreateNumber(ntohs(udp->src_port)));
                cJSON_AddItemToObject(packet_obj, "destination_port", cJSON_CreateNumber(ntohs(udp->dest_port)));
                cJSON_AddItemToObject(packet_obj, "udp_length", cJSON_CreateNumber(ntohs(udp->length)));

                int payload_offset = sizeof(struct ethernet_header) + ip_header_len + sizeof(struct udp_header);
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            } else if (ip->protocol == 1) {  // ICMP
                if (header->len < sizeof(struct ethernet_header) + ip_header_len + sizeof(struct icmp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for ICMP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct icmp_header *icmp = (struct icmp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
                cJSON_AddItemToObject(packet_obj, "icmp_type", cJSON_CreateNumber(icmp->type));
                cJSON_AddItemToObject(packet_obj, "icmp_code", cJSON_CreateNumber(icmp->code));

                int payload_offset = sizeof(struct ethernet_header) + ip_header_len + sizeof(struct icmp_header);
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            }
        }
        else if (eth_type == 0x86DD) { // IPv6
            if (header->len < sizeof(struct ethernet_header) + sizeof(struct ipv6_header)) {
                cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 header"));
                cJSON_AddItemToArray(packet_array, packet_obj);
                continue;
            }
            struct ipv6_header *ip6 = (struct ipv6_header *)(packet + sizeof(struct ethernet_header));
            char ip6_buf[48];
            format_ipv6(ip6->src_addr, ip6_buf, sizeof(ip6_buf));
            cJSON_AddItemToObject(packet_obj, "source_ip", cJSON_CreateString(ip6_buf));
            format_ipv6(ip6->dest_addr, ip6_buf, sizeof(ip6_buf));
            cJSON_AddItemToObject(packet_obj, "destination_ip", cJSON_CreateString(ip6_buf));
            cJSON_AddItemToObject(packet_obj, "ttl", cJSON_CreateNumber(ip6->hop_limit));
            cJSON_AddItemToObject(packet_obj, "payload_length", cJSON_CreateNumber(ntohs(ip6->payload_length)));
            if (ip6->next_header == 6) {  // TCP
                if (header->len < sizeof(struct ethernet_header) + 40 + sizeof(struct tcp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 TCP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + 40);
                int tcp_header_len = ((tcp->data_offset >> 4) * 4);
                if (header->len < sizeof(struct ethernet_header) + 40 + tcp_header_len) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 TCP header with options"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                cJSON_AddItemToObject(packet_obj, "source_port", cJSON_CreateNumber(ntohs(tcp->src_port)));
                cJSON_AddItemToObject(packet_obj, "destination_port", cJSON_CreateNumber(ntohs(tcp->dest_port)));
                cJSON_AddItemToObject(packet_obj, "tcp_flags", cJSON_CreateNumber(tcp->flags));
                int payload_offset = sizeof(struct ethernet_header) + 40 + tcp_header_len;
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            }
            else if (ip6->next_header == 17) {  // UDP
                if (header->len < sizeof(struct ethernet_header) + 40 + sizeof(struct udp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 UDP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ethernet_header) + 40);
                cJSON_AddItemToObject(packet_obj, "source_port", cJSON_CreateNumber(ntohs(udp->src_port)));
                cJSON_AddItemToObject(packet_obj, "destination_port", cJSON_CreateNumber(ntohs(udp->dest_port)));
                int payload_offset = sizeof(struct ethernet_header) + 40 + sizeof(struct udp_header);
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            }
            else if (ip6->next_header == 58) {  // ICMPv6
                if (header->len < sizeof(struct ethernet_header) + 40 + sizeof(struct icmp6_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 ICMP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct icmp6_header *icmp6 = (struct icmp6_header *)(packet + sizeof(struct ethernet_header) + 40);
                cJSON_AddItemToObject(packet_obj, "icmp_type", cJSON_CreateNumber(icmp6->type));
                cJSON_AddItemToObject(packet_obj, "icmp_code", cJSON_CreateNumber(icmp6->code));
                int payload_offset = sizeof(struct ethernet_header) + 40 + sizeof(struct icmp6_header);
                int payload_size = header->len - payload_offset;
                if (payload_size > 0) {
                    int payload_len = (payload_size < 16) ? payload_size : 16;
                    char payload[33] = {0};
                    for (int j = 0; j < payload_len; j++) {
                        snprintf(payload + j * 2, 3, "%02X", packet[payload_offset + j]);
                    }
                    cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString(payload));
                }
            }
        }
        // Ensure payload field exists; if not, set it to "N/A".
        if (!cJSON_GetObjectItem(packet_obj, "payload")) {
            cJSON_AddItemToObject(packet_obj, "payload", cJSON_CreateString("N/A"));
        }
        cJSON_AddItemToArray(packet_array, packet_obj);
    }

    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    return json_string;
}


// ---------------------- Packet Handler ----------------------

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct packet_buffer *buffer = (struct packet_buffer *)args;
    struct captured_packet *cp = malloc(sizeof(struct captured_packet));
    if (!cp) {
        log_error("Memory allocation error for captured_packet");
        fprintf(stderr, "Memory allocation error for captured_packet\n");
        return;
    }
    cp->packet = malloc(header->caplen);
    if (!cp->packet) {
        log_error("Memory allocation error for packet data");
        fprintf(stderr, "Memory allocation error for packet data\n");
        free(cp);
        return;
    }
    memcpy(cp->packet, packet, header->caplen);
    cp->header = *header;

    uint64_t preciseTimeMicro = get_precise_time_microseconds();
    cp->header.ts.tv_sec = (long)(preciseTimeMicro / 1000000);
    cp->header.ts.tv_usec = (long)(preciseTimeMicro % 1000000);

    if (buffer->packet_count < MAX_BUFFER_SIZE) {
        buffer->packets[buffer->packet_count] = cp;
        buffer->packet_count++;
        buffer->total_size += header->len;
    } else {
        // Buffer full: process and send JSON via ZeroMQ using zmq_msg_t.
        char *json_output = process_buffer(buffer);
        if (zmq_sender) {
            zmq_msg_t msg;
            size_t msg_size = strlen(json_output);
            zmq_msg_init_size(&msg, msg_size);
            memcpy(zmq_msg_data(&msg), json_output, msg_size);
            zmq_msg_send(&msg, zmq_sender, 0);
            zmq_msg_close(&msg);
        }
        free(json_output);
        for (int i = 0; i < buffer->packet_count; i++) {
            free(buffer->packets[i]->packet);
            free(buffer->packets[i]);
        }
        buffer->packet_count = 0;
        buffer->total_size = 0;
        buffer->last_flush_time = time(NULL);
        buffer->packets[buffer->packet_count] = cp;
        buffer->packet_count++;
        buffer->total_size += header->len;
    }

    time_t current_time = time(NULL);
    if (difftime(current_time, buffer->last_flush_time) >= FLUSH_INTERVAL) {
        // Time-based flush: process and send JSON via ZeroMQ using zmq_msg_t.
        char *json_output = process_buffer(buffer);
        if (zmq_sender) {
            zmq_msg_t msg;
            size_t msg_size = strlen(json_output);
            zmq_msg_init_size(&msg, msg_size);
            memcpy(zmq_msg_data(&msg), json_output, msg_size);
            zmq_msg_send(&msg, zmq_sender, 0);
            zmq_msg_close(&msg);
        }
        free(json_output);
        for (int i = 0; i < buffer->packet_count; i++) {
            free(buffer->packets[i]->packet);
            free(buffer->packets[i]);
        }
        buffer->packet_count = 0;
        buffer->total_size = 0;
        buffer->last_flush_time = current_time;
    }
}

// ---------------------- Interface Validation ----------------------

int is_valid_interface(const char *desc) {
    if (!desc) return 0;
    if (strstr(desc, "WAN Miniport") || strstr(desc, "Virtual") ||
        strstr(desc, "Loopback") || strstr(desc, "Bluetooth"))
        return 0;
    return 1;
}

// ---------------------- Main Function ----------------------

int main() {
    // Setup crash handlers.
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGFPE, crash_handler);
    signal(SIGILL, crash_handler);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        log_error("WSAStartup failed.");
        fprintf(stderr, "WSAStartup failed.\n");
        cleanup_resources();
        return 1;
    }
    g_resources.winsock_initialized = 1;
#endif

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&g_resources.alldevs, errbuf) == -1) {
        log_error("Error finding devices: %s", errbuf);
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        cleanup_resources();
        return 1;
    }

    pcap_if_t *dev, *best_dev = NULL;
    for (dev = g_resources.alldevs; dev; dev = dev->next) {
        if (is_valid_interface(dev->description)) {
            best_dev = dev;
            break;
        }
    }

    if (!best_dev) {
        log_error("No suitable network interface found.");
        fprintf(stderr, "No suitable network interface found.\n");
        cleanup_resources();
        return 1;
    }

    g_resources.handle = pcap_open_live(best_dev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!g_resources.handle) {
        log_error("Error opening device: %s", errbuf);
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        cleanup_resources();
        return 1;
    }

    // Allocate and initialize the packet buffer.
    g_resources.buffer = malloc(sizeof(struct packet_buffer));
    if (!g_resources.buffer) {
        log_error("Failed to allocate memory for packet buffer.");
        fprintf(stderr, "Failed to allocate memory for packet buffer.\n");
        cleanup_resources();
        return 1;
    }
    g_resources.buffer->packet_count = 0;
    g_resources.buffer->total_size = 0;
    g_resources.buffer->last_flush_time = time(NULL);

    // Initialize ZeroMQ context and PUSH socket for sending JSON output.
    zmq_context = zmq_ctx_new();
    if (!zmq_context) {
        log_error("Failed to create ZeroMQ context.");
        fprintf(stderr, "Failed to create ZeroMQ context.\n");
        cleanup_resources();
        return 1;
    }
    zmq_sender = zmq_socket(zmq_context, ZMQ_PUSH);
    if (!zmq_sender) {
        log_error("Failed to create ZeroMQ sender socket.");
        fprintf(stderr, "Failed to create ZeroMQ sender socket.\n");
        cleanup_resources();
        return 1;
    }
    // Connect to the next stage endpoint (adjust as needed).
    if (zmq_connect(zmq_sender, "tcp://localhost:5555") != 0) {
        log_error("Failed to connect ZeroMQ sender socket.");
        fprintf(stderr, "Failed to connect ZeroMQ sender socket.\n");
        cleanup_resources();
        return 1;
    }

    if (pcap_loop(g_resources.handle, 0, packet_handler, (u_char *)g_resources.buffer) < 0) {
        log_error("Error capturing packets: %s", pcap_geterr(g_resources.handle));
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(g_resources.handle));
        cleanup_resources();
        return 1;
    }

    // Final flush for any remaining packets.
    if (g_resources.buffer->packet_count > 0) {
        char *json_output = process_buffer(g_resources.buffer);
        if (zmq_sender) {
            zmq_msg_t msg;
            size_t msg_size = strlen(json_output);
            zmq_msg_init_size(&msg, msg_size);
            memcpy(zmq_msg_data(&msg), json_output, msg_size);
            zmq_msg_send(&msg, zmq_sender, 0);
            zmq_msg_close(&msg);
        }
        free(json_output);
        for (int i = 0; i < g_resources.buffer->packet_count; i++) {
            free(g_resources.buffer->packets[i]->packet);
            free(g_resources.buffer->packets[i]);
        }
    }

    cleanup_resources();
    return 0;
}
