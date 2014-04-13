#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <pthread.h>

#include "wicap.h"

struct client_entry {
	struct client_entry *next;
	int sock;
	struct sockaddr_in peeraddr;
};

static int server_sock;
static pthread_t server_thread;

static struct client_entry *client_head;
static pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;

void send_data(void* buffer, int size) {
	struct client_entry *current_client, *last_client;
	int err;

	pthread_mutex_lock(&client_lock);
	last_client = NULL;
	current_client = client_head;
	while (current_client != NULL) {
		err = send(current_client->sock, buffer, size, 0);
		if (err <= 0) {
			fprintf(stderr, "Client disconnected (%s:%d)\n",
				inet_ntoa(current_client->peeraddr.sin_addr),
				htons(current_client->peeraddr.sin_port));
			if (last_client == NULL) {
				client_head = current_client->next;
				free(current_client);
				current_client = client_head;
			} else {
				last_client->next = current_client->next;
				free(current_client);
				current_client = last_client->next;
			}
		} else {
			last_client = current_client;
			current_client = current_client->next;
		}
	}
	pthread_mutex_unlock(&client_lock);
}

void* server_thread_func(void* context) {
	struct client_entry *new_entry;
	char global_header[GLOBAL_HEADER_SIZE];
	int err;
	socklen_t addr_len;

	// We only need to generate a global header once
	generate_global_header(global_header);

	for (;;) {
		new_entry = malloc(sizeof(*new_entry));
		if (new_entry == NULL) {
			fprintf(stderr, "malloc() failed\n");
			return NULL;
		}

		addr_len = sizeof(new_entry->peeraddr);
		new_entry->sock = accept(server_sock,
			(struct sockaddr*)&new_entry->peeraddr, &addr_len);
		if (new_entry->sock == -1) {
			fprintf(stderr, "accept() failed: %d\n", errno);
			free(new_entry);
			return NULL;
		}

		// Send the global header first on every new connection
		err = send(new_entry->sock, global_header, GLOBAL_HEADER_SIZE, 0);
		if (err <= 0) {
			fprintf(stderr, "send() failed: %d\n", errno);
			close(new_entry->sock);
			free(new_entry);
			continue;
		}

		fprintf(stderr, "Client connected (%s:%d)\n",
			inet_ntoa(new_entry->peeraddr.sin_addr),
			htons(new_entry->peeraddr.sin_port));

		pthread_mutex_lock(&client_lock);
		new_entry->next = client_head;
		client_head = new_entry;
		pthread_mutex_unlock(&client_lock);
	}

	return NULL;
}

int is_tuple_client(unsigned int addr, unsigned short port) {
	struct client_entry *current_client;
	int ret = 0;
	
	pthread_mutex_lock(&client_lock);
	current_client = client_head;
	while (current_client != NULL) {
		if (current_client->peeraddr.sin_port == port &&
			current_client->peeraddr.sin_addr.s_addr == addr) {
			ret = 1;
			break;
		}
		current_client = current_client->next;
	}
	pthread_mutex_unlock(&client_lock);

	return ret;
}

int start_server(unsigned short port) {
	int err;
	struct sockaddr_in addrin;
	struct sigaction sa;

	// We have to ignore SIGPIPEs because they'll
	// kill the whole program
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigaction(SIGPIPE, &sa, 0) == -1) {
		fprintf(stderr, "sigaction() failed: %d\n", errno);
		return errno;
	}

	server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_sock == -1) {
		fprintf(stderr, "socket() failed: %d\n", errno);
		return errno;
	}

	memset(&addrin, 0, sizeof(addrin));
	addrin.sin_family = AF_INET;
	addrin.sin_port = htons(port);
	err = bind(server_sock, (struct sockaddr*)&addrin, sizeof(addrin));
	if (err < 0) {
		fprintf(stderr, "bind() failed: %d\n", errno);
		close(server_sock);
		return errno;
	}

	err = listen(server_sock, SOMAXCONN);
	if (err < 0) {
		fprintf(stderr, "listen() failed: %d\n", errno);
		close(server_sock);
		return errno;
	}

	err = pthread_create(&server_thread, NULL, server_thread_func, NULL);
	if (err < 0) {
		fprintf(stderr, "pthread_create() failed: %d\n", err);
		close(server_sock);
		return err;
	}

	return 0;
}
