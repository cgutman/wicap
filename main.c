#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <stdlib.h>

#include <stdio.h>
#include <execinfo.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "wicap.h"

#define SERVER_PORT 40000

int is_from_wicap(void* packet, int captured_size) {
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;

	if (captured_size < sizeof(*ethhdr)) {
		// Too small to be Ethernet
		return 0;
	}

	ethhdr = (struct ethhdr*)packet;
	if (ethhdr->h_proto != htons(ETH_P_IP)) {
		// Not IP
 		return 0;
	}

	if (captured_size < sizeof(*ethhdr) + sizeof(*iphdr)) {
		// Too small to be IP
		return 0;
	}

	iphdr = (struct iphdr*)(ethhdr + 1);
	if (iphdr->version != 0x04) {
		// Not IPv4
		return 0;
	}

	if (iphdr->protocol != IPPROTO_TCP) {
		// Not TCP
		return 0;
	}

	if (captured_size < sizeof(*ethhdr) + (iphdr->ihl * 4) + sizeof(*tcphdr)) {
		// Too small to be TCP
		return 0;
	}

	tcphdr = (struct tcphdr*)(((char*)iphdr) + (iphdr->ihl * 4));
	if (tcphdr->source != htons(SERVER_PORT) && tcphdr->dest != htons(SERVER_PORT)) {
		// Not to our port
		return 0;
	}

	// TODO: Check interface and specific client addresses too

	// Looks like Wicap traffic
	return 1;
}

void
packet_callback(void* packet, int total_size, int captured_size) {
	char packet_header[PACKET_HEADER_SIZE];

	// Skip our own traffic
	if (is_from_wicap(packet, captured_size)) {
		return;
	}

	// Send the PCAP packet header first
	generate_packet_header(total_size, captured_size, packet_header);
	send_data(packet_header, PACKET_HEADER_SIZE);

	// Now send the packet data
	send_data(packet, captured_size);
}

int main(int argc, char* argv[]) {
	int err;

	err = start_server(SERVER_PORT);
	if (err < 0) {
		return err;
	}

	return run_cap(packet_callback);
}
