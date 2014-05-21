/*
 * server_loop.c

 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include "workers.h"
#include "packets.h"
#include "contacts.h"
#include <mysql/mysql.h>
#include "ssl_wrap.h"
#include "public_keys.h"
#include "auth.h"
#include "offline_events.h"
#include "version.h"

static CLIENT *clients[MAX_CLIENTS];
static ssl_prerequisites ssl_req;

/* this mutex is mainly to ensure that no client is free'd while others are checking its data */
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

int packet_send_client(CLIENT* client, const VCRYPT_PACKET *packet)
{
	pthread_mutex_lock(&client->mutex);
	int ret = packet_send(&client->ssl, packet);
	pthread_mutex_unlock(&client->mutex);
	return ret;
}

CLIENT **get_clients()
{
	return clients;
}

ssl_prerequisites *server_get_ssl_req()
{
	return &ssl_req;
}

/* returns: 0 - offline, 1 - online */
int client_status(long user_id)
{
	pthread_mutex_lock(&clients_mutex);

	int i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i] != NULL && clients[i]->user_id == user_id) {
			pthread_mutex_unlock(&clients_mutex);
			return 1;
		}
	}

	pthread_mutex_unlock(&clients_mutex);
	return 0;
}

int calculate_clients_free()
{
	pthread_mutex_lock(&clients_mutex);

	int i, total = 0;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i] != NULL )
			total++;
	}

	pthread_mutex_unlock(&clients_mutex);

	return MAX_CLIENTS - total;
}

/* returns 1 on success */
int client_alloc(int nr)
{
	if (nr < 0 || nr >= MAX_CLIENTS)
		return 0;

	pthread_mutex_lock(&clients_mutex);

	clients[nr] = calloc(1, sizeof(CLIENT));
	pthread_mutex_init(&clients[nr]->mutex, NULL );

	pthread_mutex_unlock(&clients_mutex);
	return clients[nr] != NULL ;
}

/* handles correctly null clients */
int client_signal_exit(int nr)
{
	pthread_mutex_lock(&clients_mutex);

	if (clients[nr])
		clients[nr]->signal_shutdown = 1;

	pthread_mutex_unlock(&clients_mutex);
	return 0;
}

int client_free(int nr)
{
	if (nr < 0 || nr >= MAX_CLIENTS)
		return 0;

	pthread_mutex_lock(&clients_mutex);

	assert(clients[nr] != NULL);

	pthread_mutex_destroy(&clients[nr]->mutex);

	free(clients[nr]);
	clients[nr] = NULL;

	pthread_mutex_unlock(&clients_mutex);

	printf("free clients: %d\n", calculate_clients_free());
	return 1;
}

void update_client_activity_time(CLIENT *client)
{
	// no need for mutex here as the only thread which updates this is the client's own thread
	time(&client->time);
}

int client_find_free()
{
	int ret = -1;
	pthread_mutex_lock(&clients_mutex);

	int i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i] == NULL ) {
			ret = i;
			break;
		}
	}

	pthread_mutex_unlock(&clients_mutex);
	return ret;
}

CLIENT* find_client_by_id(long id)
{
	if (id == 0)
		return (NULL );

	pthread_mutex_lock(&clients_mutex);

	int i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i] == NULL )
			continue;

		if (clients[i]->user_id == id) {
			pthread_mutex_unlock(&clients_mutex);
			return clients[i];
		}
	}

	pthread_mutex_unlock(&clients_mutex);
	return NULL ;
}

CLIENT* find_client_by_username(char *username)
{
	pthread_mutex_lock(&clients_mutex);

	if (strlen(username) == 0)
		return NULL ;

	int i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i] == NULL )
			continue;

		if (strncmp(username, clients[i]->username, MAX_USERNAME_L) == 0) {
			pthread_mutex_unlock(&clients_mutex);
			return clients[i];
		}
	}

	pthread_mutex_unlock(&clients_mutex);

	return NULL ;
}

int client_is_authenticated(CLIENT *client)
{
	pthread_mutex_lock(&clients_mutex);

	int ret = client->user_id > 0;

	pthread_mutex_unlock(&clients_mutex);
	return ret;
}

int process_authentication(CLIENT *client, const VCRYPT_PACKET *packet)
{
	PAYLOAD_AUTH *data = (PAYLOAD_AUTH*) packet->payload;

	if (data->version < VCRYPT_PROTOCOL_VERSION
			|| packet->payload_len != sizeof(PAYLOAD_AUTH)) {
		fprintf(stderr, "got version: %d have ver: %d\n", data->version,
				VCRYPT_PROTOCOL_VERSION);

		VCRYPT_PACKET* ret_packet = packet_clone_header(packet);
		ret_packet->type = RESP_REGISTER_UNSUPPORTED_VERSION;
		int retval = packet_send_client(client, ret_packet);
		packet_free(ret_packet);
		return retval;
	}

	uint64_t pk_fp = 0;
	long user_id = auth_user(data->username, data->password, &pk_fp);

	if (user_id <= 0) {
		VCRYPT_PACKET* ret_packet = packet_clone_header(packet);
		ret_packet->type =
				user_id == 0 ? RESP_REGISTER_AUTH_FAILURE : RESP_ERR_TEMPORARY;
		int retval = packet_send_client(client, ret_packet);
		packet_free(ret_packet);
		return retval;
	}

	if (find_client_by_id(user_id)) {
		VCRYPT_PACKET* ret_packet = packet_clone_header(packet);
		ret_packet->type = RESP_REGISTER_ALREADY_LOGGED_IN;
		int retval = packet_send_client(client, ret_packet);
		packet_free(ret_packet);
		return retval;
	}

	strncpy(client->username, data->username, MAX_USERNAME_L);
	client->user_id = user_id;

	fprintf(stderr, "INFO: User %ld (%s) logged in\n", user_id, data->username);

	VCRYPT_PACKET* contacts_packet = contacts_make_packet(client, user_id,
			pk_fp);
	assert(contacts_packet);

	int retval = packet_send_client(client, contacts_packet);
	free(contacts_packet);

	if (retval)
		return retval;

	// announce all users that this user came online
	return contacts_send_status_notify(user_id, client->username, STATUS_ONLINE);
}

int process_ping_server(CLIENT *client, const VCRYPT_PACKET *packet)
{
	VCRYPT_PACKET* clone = packet_clone_header(packet);
	clone->type = RESP_OK;
	int retval = packet_send_client(client, clone);
	packet_free(clone);
	return retval;
}

int process_contact_add_del(CLIENT *client, const VCRYPT_PACKET *packet)
{
	VCRYPT_PACKET* clone = packet_clone(packet);

	if (packet->type == REQ_CONTACT_ADD) {
		clone->type = contact_add(client->user_id, clone->payload);
	} else if (packet->type == REQ_CONTACT_DEL) {
		clone->type = contact_del(client->user_id, clone->payload);
	} else {
		return -1;
	}

	int retval = packet_send_client(client, clone);
	packet_free(clone);
	return retval;
}

/* the packet will be forwarded to the another client */
int process_msg_forward(CLIENT *sender, VCRYPT_PACKET *packet)
{
	printf("'%s' forwards message to '%s'\n", sender->username,
			packet->username);

	switch (packet->type)
	{
	case REQ_MESSAGE_STORED_READ:
		offline_message_delete(sender->user_id, packet->queue_id);
		break;
	}

	CLIENT *receiver = find_client_by_username(packet->username);
	if (receiver == NULL ) {
		packet->dest = DEST_SERVER;

		long contact_id = contact_get_id(packet->username);
		switch (contact_id)
		{
		case -1:
			packet->type = RESP_ERR_TEMPORARY;
			break;
		case -2:
			packet->type = RESP_ERR_NOSUCHUSER;
			break;
		default:
			if (packet->type == REQ_MESSAGE_SEND) {
				if (offline_message_store(sender->user_id, contact_id,
						packet->queue_id, packet->payload, packet->payload_len))
					packet->type = RESP_ERR_TEMPORARY;
				else
					packet->type = RESP_MESSAGE_STORED;
			} else {
				packet->type = RESP_ERR_USEROFFLINE;
			}
			break;
		}

		packet->payload_len = 0;
	} else if (receiver == sender) {
		packet->dest = DEST_SERVER;
		packet->type = RESP_ERR_MYSELF;
		packet->payload_len = 0;
	} else {
		// switch username, so the receiver knows from who it received the message
		strcpy(packet->username, sender->username);
		packet->dest = DEST_CLIENT;
		int dontforward = 0;

		// here we inject needed payload for some of the commands
		switch (packet->type)
		{
		case REQ_CALL:
		case RESP_CALL_OK:
			if (packet->payload_len >= sizeof(PAYLOAD_P2PINFO) + 1) {
				// TODO: use proper conversion here, so its the same on all platforms (endiannes, etc)
				((PAYLOAD_P2PINFO*) (packet->payload + 1))->p2p_addr =
						sender->conndata.cl_addr.sin_addr.s_addr;
			} else {
				dontforward = 1;
			}
			break;
		default:
			break;
		}

		// TODO: optimized this as some operations are unused here
		printf(" <<-- wrote (client fwd): %s\n", packet_dump(packet));

		if (packet_send_client(receiver, packet) != 0 || dontforward) {
			packet->type = RESP_ERR_PACKET_FORWARD;
			packet->dest = DEST_SERVER;
			packet->payload_len = 0;
		} else {
			packet->type = RESP_PACKET_FORWARDED;
			packet->dest = DEST_SERVER;
			packet->payload_len = 0;
		}
	}

	if (packet->no_srv_ack == 0) {
		printf(" <<-- wrote srv: %s\n", packet_dump(packet));
		return packet_send_client(sender, packet);
	}

	return 0;
}

/* returning negative will trigger user disconnect */
int server_process_server_message(CLIENT *client, const VCRYPT_PACKET *packet)
{
	if (!client_is_authenticated(client)) {
		// messages for NON-authenticated clients
		switch (packet->type)
		{
		case REQ_AUTHENTICATE:
			return process_authentication(client, packet);
		default: // wrong message!
			// we simply return an error to break the connection
			return -3;
		}

		return 0; // all non-authenticated commands end here
	}

	// messages for authenticated clients
	switch (packet->type)
	{
	case REQ_PASSWORD_CHANGE:
		if (auth_change_pass(client, packet) < 0)
			return -2;
		break;
	case REQ_PING_SERVER:
		if (process_ping_server(client, packet) < 0)
			return -2;
		break;
	case REQ_CONTACT_ADD:
	case REQ_CONTACT_DEL:
		if (process_contact_add_del(client, packet) < 0) {
			return -25;
		}
		break;
	case REQ_PUBKEY_UPLOAD:
		if (process_public_key_update(client, packet) < 0)
			return -2;
		break;
	case REQ_GET_PUBLIC_KEY:
		if (process_get_public_key(client, packet) < 0)
			return -2;
		break;
	default: // wrong message!
		// we simply return an error to break the connection
		return -3;
	}

	return 0;
}

/* negative return value will cause connection drop
 * 0 - means success
 * */
int server_process_packet(CLIENT *client, VCRYPT_PACKET* packet)
{
	update_client_activity_time(client);
	printf(" -->> received packet: %s\n", packet_dump(packet));

	if (packet->dest == DEST_SERVER) {
		return server_process_server_message(client, packet);
	} else if (packet->dest == DEST_CLIENT) {
		return process_msg_forward(client, packet);
	} else {
		return -1; // broken, message, disconnect
	}

	return 0;
}

#define BUFFER_SIZE 1024*4

void *server_client_thread(void *_cl_idx)
{
	assert(_cl_idx);

	int cl_idx = *(int*) _cl_idx;
	free(_cl_idx);

	CLIENT *client = clients[cl_idx];
	assert(client);

	mysql_thread_init();

	char buffer[BUFFER_SIZE];
	VCRYPT_PACKET *packet = (VCRYPT_PACKET*) buffer;

	if (net_set_nonblock(client->socket) != 0) {
		fprintf(stderr, "ERROR: can't set fd to blocking\n");
		exit(1); // fatal error
	}

	update_client_activity_time(client);

	int ret;
	if ((ret = ssl_init(&client->ssl)) != 0) {
		printf(" failed\n  ! ssl_init returned %d\n\n", ret);
		goto thread_exit;
	}

	ssl_set_dbg(&client->ssl, my_ssl_debug, stdout);
	ssl_set_endpoint(&client->ssl, SSL_IS_SERVER);
	ssl_set_authmode(&client->ssl, SSL_VERIFY_NONE);
	ssl_set_rng(&client->ssl, ctr_drbg_random, &ssl_req.ctr_drbg);
	ssl_set_own_cert(&client->ssl, &ssl_req.srvcert, &ssl_req.rsa);

	ssl_set_bio(&client->ssl, net_recv, &client->socket, net_send,
			&client->socket);

	// TODO: do this properly via POLLIN otherwise it will block the tread
	while ((ret = ssl_handshake(&client->ssl)) != 0) {
		if (ret != POLARSSL_ERR_NET_WANT_READ
				&& ret != POLARSSL_ERR_NET_WANT_WRITE) {
			char strerr[100];
			error_strerror(ret, strerr, sizeof strerr);
			printf(" failed\n  ! ssl_handshake returned %d (%s)\n\n", ret,
					strerr);
			goto thread_exit;
		}
	}

	int reading_header = 1; // we are reading header now
	int already_read = 0;
	int packet_ready = 0;

	fd_set sock_fd;

	struct timeval timeout;
	int offline_messages = 1; // we suppose there are some

	while (client->signal_shutdown == 0) {
		int n;
		size_t to_read;
		char *dest;

		if (reading_header) {
			to_read = PACKET_HEAD_SIZE;
			dest = buffer;
		} else {
			to_read = packet->payload_len;
			dest = buffer + PACKET_HEAD_SIZE;
		}

		assert(to_read + already_read <= BUFFER_SIZE);

		n = ssl_read(&client->ssl, (unsigned char*) dest + already_read,
				to_read - already_read);

		if (n == POLARSSL_ERR_NET_WANT_READ) {
			/*
			 * place to do other write jobs
			 */

			if (client->user_id && offline_messages) {
				offline_messages = offline_messages_send(client);

				if (offline_messages < 0)
					goto thread_exit;
			}

			FD_ZERO(&sock_fd);
			FD_SET(client->socket, &sock_fd);
			timeout.tv_sec = 0;
			timeout.tv_usec = 10000;
			select(client->socket + 1, &sock_fd, NULL, NULL, &timeout);
			continue;
		}

		if (n > 0) {
			already_read += n;

			if (reading_header) {
				assert(already_read <= PACKET_HEAD_SIZE);

				// check if client wants to send a packet too big
				if (packet->payload_len > BUFFER_SIZE - PACKET_HEAD_SIZE ) {
					fprintf(stderr,
							"ERROR: client wants to sent too big packet\n");

					VCRYPT_PACKET *p = packet_new(DEST_SERVER, "",
							RESP_ERR_PACKET_TOO_BIG, 0);
					packet_send(&client->ssl, p); // try to tell client about the error

					goto thread_exit;
				}

				// check if we read enough data for the header
				if (already_read == PACKET_HEAD_SIZE ) {
					reading_header = 0;
					already_read = 0;
				}

				if (packet->payload_len == 0)
					packet_ready = 1;

			} else {
				// we read packet payload here
				assert(already_read <= PACKET_HEAD_SIZE + packet->payload_len);

				if (already_read == packet->payload_len) {
					packet_ready = 1;
				}
			}
		} else {
			// receiving zero bytes with POLLIN means disconnect
			fprintf(stderr, "ERROR: client disconnected\n");
			goto thread_exit;
		}

		if (packet_ready) {
			int res = server_process_packet(client, packet);
			if (res < 0) {
				printf("process_received_packet returned negative: %d\n", res);
				goto thread_exit;
			}

			// prepare for a new packet
			reading_header = 1;
			already_read = 0;
			packet_ready = 0;
		}
	}

	thread_exit: //

	ssl_close_notify(&client->ssl);

	if (client->signal_shutdown == 0) {
		// sent to others a command that this guy disconnected
		if (client->user_id > 0) // only if it was authenticated
			contacts_send_status_notify(client->user_id, client->username,
					STATUS_OFFLINE);
	}

	shutdown(client->socket, SHUT_RDWR);
	close(client->socket);
	ssl_free(&client->ssl);
	client_free(cl_idx);

	mysql_thread_end();
	printf("client thread exit\n");

	return NULL ;
}

