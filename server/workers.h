/*
 * server_loop.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef SERVER_LOOP_H_
#define SERVER_LOOP_H_

#include "config.h"
#include "packets.h"
#include <assert.h>
#include <netinet/in.h>
#include "ssl_wrap.h"

#define MAX_CLIENTS 1000

typedef struct CLIENT_CONNDATA
{
	struct sockaddr_in cl_addr;
	//TODO: add local network data here too
} CLIENT_CONNDATA;

enum CLIENT_COMMAND {
	CLIENT_NOCMD = 0,
	CLIENT_SEND_CONTACTS
};

typedef struct CLIENT
{
	long user_id; // from database
	char username[MAX_USERNAME_L];
	time_t time;
	int socket;
	CLIENT_CONNDATA conndata;
	ssl_context ssl;
	int signal_shutdown;
	pthread_mutex_t mutex;
	unsigned long last_stored_event;
} CLIENT;


/* functions for workers (clients) data access */
CLIENT **get_clients();
void *server_client_thread(void *client);
int clients_free();
int client_find_free();
int client_alloc(int nr);
int client_free(int nr);
int client_signal_exit(int nr);
int client_status(long user_id);
int check_username_registered(char *username);
CLIENT* find_client_by_username(char *username);
void server_loop(int server_fd);
CLIENT* find_client_by_id(long id);
int client_is_authenticated(CLIENT *client);
int calculate_clients_free();
int packet_send_client(CLIENT* client, const VCRYPT_PACKET *packet);

ssl_prerequisites *server_get_ssl_req();

#endif /* SERVER_LOOP_H_ */
