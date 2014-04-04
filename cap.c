#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "wicap.h"

int run_cap(capture_callback callback) {
	int sock;
	int recv_bytes;
	void *packet;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock == -1) {
		printf("socket() failed: %d\n", errno);
		return errno;
	}

	packet = malloc(MAX_PACKET_SIZE);
	if (packet == NULL) {
		printf("malloc() failed\n");
		close(sock);
		return -1;
	}

	for (;;) {
		struct sockaddr_ll from;
		socklen_t from_len;

		from_len = sizeof(from);
		recv_bytes = recvfrom(sock, packet, MAX_PACKET_SIZE,
			MSG_TRUNC, (struct sockaddr*)&from, &from_len);
		if (recv_bytes <= 0) {
			printf("recvfrom() failed: %d\n", errno);
			free(packet);
			close(sock);
			return errno;
		}

		callback(packet, recv_bytes,
			recv_bytes > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : recv_bytes);
	}
}

