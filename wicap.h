#pragma once

#define MAX_PACKET_SIZE 65535

#pragma pack(push, 1)
#define GLOBAL_HEADER_SIZE sizeof(pcap_hdr_t)
typedef struct pcap_hdr_s {
	unsigned int magic_number;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;
    unsigned int sigfigs;
    unsigned int snaplen;
    unsigned int network;
} pcap_hdr_t;

#define PACKET_HEADER_SIZE sizeof(pcaprec_hdr_t)
typedef struct pcaprec_hdr_s {
    unsigned int ts_sec;
    unsigned int ts_usec;
    unsigned int incl_len;
    unsigned int orig_len;
} pcaprec_hdr_t;
#pragma pack(pop)

typedef void (*capture_callback)(void* packet, int total_size,
	int captured_size);

int start_server(unsigned short port);
void send_data(void* buffer, int size);
int is_tuple_client(unsigned int addr, unsigned short port);

void generate_global_header(void* buffer);
void generate_packet_header(int total_size, int captured_size, void* buffer);

int run_cap(capture_callback callback);
