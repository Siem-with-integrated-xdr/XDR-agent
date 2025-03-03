#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <time.h>
#include <cJSON.h>

#define MAX_PACKET_SIZE 65536
#define MAX_BUFFER_SIZE 10   // Number of packets to buffer before sending to the analysis engine
#define FLUSH_INTERVAL 5     // Time interval (in seconds) to flush the buffer if not full

// ----- Define Captured Packet Structure Globally -----
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

// ----- Update packet_buffer to store captured_packet pointers -----
struct packet_buffer {
    struct captured_packet *packets[MAX_BUFFER_SIZE];
    int packet_count;
    int total_size;
    time_t last_flush_time;
};

// Format IPv4 address into a string (keeping original formatting)
void format_ipv4(uint32_t ip, char *buffer, size_t buflen) {
    sprintf(buffer, "%d.%d.%d.%d", ip & 0xFF, (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

// Format MAC address into a string
void format_mac(const uint8_t *mac, char *buffer, size_t buflen) {
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Format IPv6 address into a string (simple non-compressed format)
void format_ipv6(const unsigned char *addr, char *buffer, size_t buflen) {
    sprintf(buffer,
            "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            addr[0], addr[1], addr[2], addr[3],
            addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11],
            addr[12], addr[13], addr[14], addr[15]);
}

// Get the current time in microseconds since Unix epoch (January 1, 1970)
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

// Format pcap timestamp into a string using strftime/localtime.
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
    char usec[8];
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
        global_ts[sizeof(global_ts)-1] = '\0';
    }
    char usec_str[16];
    sprintf(usec_str, ".%06ld", usec);
    strncat(global_ts, usec_str, sizeof(global_ts) - strlen(global_ts) - 1);
    cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(global_ts));
    cJSON_AddItemToObject(root, "category", cJSON_CreateString("Network Packet"));
    cJSON_AddItemToObject(root, "number_of_packets", cJSON_CreateNumber(buffer->packet_count));
    cJSON_AddItemToObject(root, "packets", packet_array);

    // Process each captured packet
    for (int i = 0; i < buffer->packet_count; i++) {
        struct captured_packet *cp = buffer->packets[i];
        const struct pcap_pkthdr *header = &cp->header;
        const u_char *packet = cp->packet;
        cJSON *packet_obj = cJSON_CreateObject();

        // Add per-packet timestamp.
        char pkt_ts[64];
        format_timestamp(header, pkt_ts, sizeof(pkt_ts));
        cJSON_AddItemToObject(packet_obj, "packet_timestamp", cJSON_CreateString(pkt_ts));

        // Ensure packet is long enough for Ethernet header
        if (header->len < sizeof(struct ethernet_header)) {
            cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for Ethernet header"));
            cJSON_AddItemToArray(packet_array, packet_obj);
            continue;
        }

        // Ethernet header.
        struct ethernet_header *eth = (struct ethernet_header *)packet;
        uint16_t eth_type = ntohs(eth->eth_type);
        char mac_buf[18];
        format_mac(eth->src_mac, mac_buf, sizeof(mac_buf));
        cJSON_AddItemToObject(packet_obj, "source_mac", cJSON_CreateString(mac_buf));
        format_mac(eth->dest_mac, mac_buf, sizeof(mac_buf));
        cJSON_AddItemToObject(packet_obj, "destination_mac", cJSON_CreateString(mac_buf));
        cJSON_AddItemToObject(packet_obj, "ether_type", cJSON_CreateNumber(eth_type));
        cJSON_AddItemToObject(packet_obj, "packet_size", cJSON_CreateNumber(header->len));

        // IPv4 processing.
        if (eth_type == 0x0800) {
            // Ensure packet is long enough for minimal IPv4 header
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
                // Check for minimal TCP header
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
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("TCP"));
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
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("UDP"));
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
            } else if (ip->protocol == 1) {  // ICMP (IPv4)
                if (header->len < sizeof(struct ethernet_header) + ip_header_len + sizeof(struct icmp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for ICMP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct icmp_header *icmp = (struct icmp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("ICMP"));
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
        // Process IPv6 packets.
        else if (eth_type == 0x86DD) {
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
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("TCP"));
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
            } else if (ip6->next_header == 17) {  // UDP
                if (header->len < sizeof(struct ethernet_header) + 40 + sizeof(struct udp_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 UDP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ethernet_header) + 40);
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("UDP"));
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
            } else if (ip6->next_header == 58) {  // ICMPv6
                if (header->len < sizeof(struct ethernet_header) + 40 + sizeof(struct icmp6_header)) {
                    cJSON_AddItemToObject(packet_obj, "error", cJSON_CreateString("Packet too short for IPv6 ICMP header"));
                    cJSON_AddItemToArray(packet_array, packet_obj);
                    continue;
                }
                struct icmp6_header *icmp6 = (struct icmp6_header *)(packet + sizeof(struct ethernet_header) + 40);
                cJSON_AddItemToObject(packet_obj, "protocol", cJSON_CreateString("ICMPv6"));
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
        cJSON_AddItemToArray(packet_array, packet_obj);
    }

    char *json_string = cJSON_Print(root);
    cJSON_Delete(root);
    return json_string;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct packet_buffer *buffer = (struct packet_buffer *)args;

    // Allocate a captured_packet structure
    struct captured_packet *cp = malloc(sizeof(struct captured_packet));
    if (!cp) {
        fprintf(stderr, "Memory allocation error\n");
        return;
    }

    // Allocate memory and copy packet data (fix: copy packet data to ensure it's valid later)
    cp->packet = malloc(header->caplen);
    if (!cp->packet) {
        fprintf(stderr, "Memory allocation error for packet data\n");
        free(cp);
        return;
    }
    memcpy(cp->packet, packet, header->caplen);
    cp->header = *header; // Copy the header

    // Use precise timestamp
    uint64_t preciseTimeMicro = get_precise_time_microseconds();
    cp->header.ts.tv_sec = (long)(preciseTimeMicro / 1000000);
    cp->header.ts.tv_usec = (long)(preciseTimeMicro % 1000000);

    if (buffer->packet_count < MAX_BUFFER_SIZE) {
        buffer->packets[buffer->packet_count] = cp;
        buffer->packet_count++;
        buffer->total_size += header->len;
    } else {
        printf("Buffer full, processing packets...\n");
        char *json_output = process_buffer(buffer);
        printf("JSON Output: \n%s\n", json_output);
        free(json_output);
        // Free previously stored packets (fix: free both the packet data and the captured_packet struct)
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
        printf("Flushing buffer...\n");
        char *json_output = process_buffer(buffer);
        printf("JSON Output: \n%s\n", json_output);
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

int is_valid_interface(const char *desc) {
    if (!desc) return 0;
    if (strstr(desc, "WAN Miniport") || strstr(desc, "Virtual") ||
        strstr(desc, "Loopback") || strstr(desc, "Bluetooth"))
        return 0;
    return 1;
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_if_t *best_dev = NULL;
    struct packet_buffer buffer = { .packet_count = 0, .total_size = 0, .last_flush_time = time(NULL) };

#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
#endif

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    for (dev = alldevs; dev; dev = dev->next) {
        if (is_valid_interface(dev->description)) {
            best_dev = dev;
            break;
        }
    }

    if (!best_dev) {
        printf("No suitable network interface found.\n");
        pcap_freealldevs(alldevs);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    handle = pcap_open_live(best_dev->name, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!handle) {
        printf("Error opening device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("Capturing packets...\n");
    if (pcap_loop(handle, 0, packet_handler, (u_char *)&buffer) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    // Final flush for any remaining packets in the buffer.
    if (buffer.packet_count > 0) {
        printf("Final flush of buffer...\n");
        char *json_output = process_buffer(&buffer);
        printf("JSON Output: \n%s\n", json_output);
        free(json_output);
        for (int i = 0; i < buffer.packet_count; i++) {
            free(buffer.packets[i]->packet);
            free(buffer.packets[i]);
        }
    }

    pcap_freealldevs(alldevs);
    pcap_close(handle);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}
