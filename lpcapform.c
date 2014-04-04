#include <stdio.h>
#include <stdlib.h>

#include <sys/time.h>

#include "wicap.h"

#define LIBPCAP_MAGIC 0xa1b2c3d4
#define LIBPCAP_MAJOR 2
#define LIBPCAP_MINOR 4

#define NETWORK_TYPE_ETHERNET 1

void generate_global_header(void* buffer) {
	pcap_hdr_t *hdr;	

	hdr = (pcap_hdr_t*)buffer;
	hdr->magic_number = LIBPCAP_MAGIC;
	hdr->version_major = LIBPCAP_MAJOR;
	hdr->version_minor = LIBPCAP_MINOR;
	hdr->thiszone = 0; // Times are in GMT
	hdr->sigfigs = 0; // Always set to 0
	hdr->snaplen = MAX_PACKET_SIZE;
	hdr->network = NETWORK_TYPE_ETHERNET;
}

void generate_packet_header(int total_size, int captured_size, void* buffer) {
	pcaprec_hdr_t *hdr;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	hdr = (pcaprec_hdr_t*)buffer;
	hdr->ts_sec = tv.tv_sec;
	hdr->ts_usec = tv.tv_usec;
	hdr->incl_len = captured_size;
	hdr->orig_len = total_size;
}
