#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
			printf("Client disconnected (Error %d)\n", errno);
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

	// We only need to generate a global header once
	generate_global_header(global_header);

	for (;;) {
		new_entry = malloc(sizeof(*new_entry));
		if (new_entry == NULL) {
			printf("malloc() failed\n");
			return NULL;
		}

		new_entry->sock = accept(server_sock, NULL, NULL);
		if (new_entry->sock == -1) {
			printf("accept() failed: %d\n", errno);
			free(new_entry);
			return NULL;
		}

		// Send the global header first on every new connection
		err = send(new_entry->sock, global_header, GLOBAL_HEADER_SIZE, 0);
		if (err <= 0) {
			printf("send() failed: %d\n", errno);
			close(new_entry->sock);
			free(new_entry);
			continue;
		}

		pthread_mutex_lock(&client_lock);
		new_entry->next = client_head;
		client_head = new_entry;
		pthread_mutex_unlock(&client_lock);
	}

	return NULL;
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
		printf("sigaction() failed: %d\n", errno);
		return errno;
	}

	server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_sock == -1) {
		printf("socket() failed: %d\n", errno);
		return errno;
	}

	memset(&addrin, 0, sizeof(addrin));
	addrin.sin_family = AF_INET;
	addrin.sin_port = htons(port);
	err = bind(server_sock, (struct sockaddr*)&addrin, sizeof(addrin));
	if (err < 0) {
		printf("bind() failed: %d\n", errno);
		close(server_sock);
		return errno;
	}

	err = listen(server_sock, SOMAXCONN);
	if (err < 0) {
		printf("listen() failed: %d\n", errno);
		close(server_sock);
		return errno;
	}

	err = pthread_create(&server_thread, NULL, server_thread_func, NULL);
	if (err < 0) {
		printf("pthread_create() failed: %d\n", err);
		close(server_sock);
		return err;
	}

	return 0;
}
