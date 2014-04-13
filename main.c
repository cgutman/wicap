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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "wicap.h"

#define DEFAULT_SERVER_PORT 40000

static unsigned short port;
static int write_to_stdout;
static int exclude_wicap_traffic;

static
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
	if (tcphdr->dest == htons(port)) {
		// The packet is directed at our port; check if it's from one of our clients
		if (is_tuple_client(iphdr->saddr, tcphdr->source)) {
			// Yes, it's Wicap traffic
			return 1;
		}
	}
	else if (tcphdr->source == htons(port)) {
		// The packet is send from our port; check if it's to one of our clients
		if (is_tuple_client(iphdr->daddr, tcphdr->dest)) {
			// Yes, it's Wicap traffic
			return 1;
		}
	} 

	// Not Wicap traffic
	return 0;
}

void
packet_callback(void* packet, int total_size, int captured_size) {
	char packet_header[PACKET_HEADER_SIZE];

	// Skip our own traffic unless explicitly disabled by user
	if (exclude_wicap_traffic && is_from_wicap(packet, captured_size)) {
		return;
	}

	// Send the PCAP packet header first
	generate_packet_header(total_size, captured_size, packet_header);
	send_data(packet_header, PACKET_HEADER_SIZE);

	// Now send the packet data
	send_data(packet, captured_size);

	// Write the header and data to stdout if requested
	if (write_to_stdout) {
		fwrite(packet_header, PACKET_HEADER_SIZE, 1, stdout);
		fwrite(packet, captured_size, 1, stdout);
	}
}

static
void print_usage(void) {
	printf("Usage: wicap [options] <listening port>\n");
	printf("Options:\n");
	printf("  -o\t\tWrite captured output to stdout\n");
	printf("  -a\t\tDon't exclude Wicap traffic (use with caution)\n");
	printf("  -?\t\tPrint this usage information\n");
}

static
int parse_args(int argc, char* argv[]) {
	int i;

	// Default vals
	port = DEFAULT_SERVER_PORT;
	write_to_stdout = 0;
	exclude_wicap_traffic = 1;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (strlen(argv[i]) > 2) {
				fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
				print_usage();
				return -1;
			}

			switch (argv[i][1]) {
				case 'o':
					write_to_stdout = 1;
					break;
				case 'a':
					exclude_wicap_traffic = 0;
					break;
				default:
					fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
				case '?':
					print_usage();
					return -1;
			}
		}
		else {
			port = atoi(argv[i]);
			if (port == 0) {
				fprintf(stderr, "Invalid port number: %s\n", argv[i]);
				print_usage();
				return -1;
			}
		}
	}

	return 0;
}

int main(int argc, char* argv[]) {
	int err;

	err = parse_args(argc, argv);
	if (err != 0) {
		return err;
	}

	err = start_server(port);
	if (err != 0) {
		return err;
	}

	// Write the global header to stdout before any packets
	if (write_to_stdout) {
		char global_header[GLOBAL_HEADER_SIZE];

		generate_global_header(global_header);
		fwrite(global_header, GLOBAL_HEADER_SIZE, 1, stdout);
	}

	fprintf(stderr, "Listening on port %d\n", port);

	return run_cap(packet_callback);
}
