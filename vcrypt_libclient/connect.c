/*
 * connect.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include "client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <unistd.h>
#include <inttypes.h>

#if HAS_NETDB_H
#include <netdb.h>
#endif

#include "client_p2p.h"
#include "packets.h"
#include "connect.h"
#include <assert.h>
#include "version.h"

int server_connect(VCRYPT_CTX *ctx, char *address, int port)
{
	assert(get_thread_status(ctx) == THREAD_RUNNING);
	assert(address);

	if (ctx->socket_server > 0)
		return -ERR_SERVER_ALREADY_CONNECTED;

	int ret;
	if ((ret = net_connect(&ctx->socket_server, address, port)) != 0) {
		return -ERR_CONNECTION_FAILURE;
	}

	if ((ret = ssl_init(&ctx->ssl)) != 0)
		return -ERR_CONNECTION_SSL_INIT_FAILURE;

	ssl_set_endpoint(&ctx->ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ctx->ssl, SSL_VERIFY_NONE);
	ssl_set_rng(&ctx->ssl, ctr_drbg_random, &ctx->ssl_req.ctr_drbg);
	ssl_set_dbg(&ctx->ssl, my_ssl_debug, stdout);

	ssl_set_bio(&ctx->ssl, net_recv, &ctx->socket_server, net_send,
			&ctx->socket_server);

	if (net_set_nonblock(ctx->socket_server) != 0) {
		dolog(0, "ERROR: can't set fd to blocking\n");
		exit(1);
	}

	// TODO: do this properly via POLLIN otherwise it will block the tread
	while ((ret = ssl_handshake(&ctx->ssl)) != 0) {
		if (ret != POLARSSL_ERR_NET_WANT_READ
				&& ret != POLARSSL_ERR_NET_WANT_WRITE) {
			return -ERR_CONNECTION_SSL_HANDSHAKE_FAILURE;
		}

		usleep(1000);
	}

	return 0;
}

int server_disconnect(VCRYPT_CTX *ctx)
{
	if (ctx->socket_server > 0) {
		net_close(ctx->socket_server);
		ctx->socket_server = -1;
	}

	return 0;
}

int server_auth(VCRYPT_CTX *ctx, char *username, char *password)
{
	if (ctx->socket_server < 0)
		return -ERR_UNKNOWN(401);

	// check if the tread is already running
	assert(get_thread_status(ctx) == THREAD_RUNNING);

	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, "", REQ_AUTHENTICATE,
			sizeof(PAYLOAD_AUTH));

	if (packet == NULL ) {
		return -ERR_MALLOC;
	}

	PAYLOAD_AUTH *data = (PAYLOAD_AUTH*) packet->payload;

	strncpy(data->username, username, MAX_USERNAME_L);
	strncpy(data->password, password, MAX_USERNAME_L);
	data->username[MAX_USERNAME_L - 1] = 0;
	data->password[MAX_USERNAME_L - 1] = 0;
	data->version = VCRYPT_PROTOCOL_VERSION;

	if (packet_send(&ctx->ssl, packet) < 0) {
		packet_free(packet);
		return -ERR_PACKET_WRITE;
	}

	// first read the header only, to get the payload size
	int n = ssl_read_tm(&ctx->ssl, (unsigned char*) packet, PACKET_HEAD_SIZE,
			5000);
	dolog(0, "server_read_nb returned %d\n", n);

	if (n <= 0) {
		free(packet);
		return -ERR_SERVER_TIMEOUT;
	} else if (n < (int) PACKET_HEAD_SIZE ) {
		free(packet);
		return -ERR_BAD_PACKET;
	}

	int result = 0;

	dolog(0, " --- got packet type %d, %s", packet->type, packet_dump(packet));

	switch (packet->type)
	{
	case RESP_REGISTER_OK_CONTACTS:
		/* this will also return the public key finger print stored on server */
		if (packet->payload_len >= 8) {

			uint64_t serv_pkfp = 0;
			int n = ssl_read_tm(&ctx->ssl, (unsigned char*) &serv_pkfp, 8,
					5000);
			if (n != 8) {
				free(packet);
				dolog(0, "err: could not read finger print: %d\n", n);
				return -ERR_SERVER_TIMEOUT;
			}

			if (ctx->public_key_fp_local != serv_pkfp) {
				dolog(0, "warn: public key FP mismatch, will upload %" PRIx64
				"%" PRIx64 "\n", ctx->public_key_fp_local, serv_pkfp);
				if (upload_public_key(ctx) < 0) {
					return -ERR_RSA_NO_KEYS;
				}
			}
		} else {
			free(packet);
			return -ERR_BAD_PACKET;
		}

		if (packet->payload_len > 8) {
			char *contacts = alloca(packet->payload_len - 8);
			n = ssl_read_tm(&ctx->ssl, (unsigned char*) contacts,
					packet->payload_len - 8, 5000);

			if (n <= 0) {
				free(packet);
				dolog(0, "err: could not read contacts: %d\n", n);
				return -ERR_SERVER_TIMEOUT;
			}

			// this function will free the contacts
			ctx->callback_load_contacts(contacts);
		}

		result = ERR_SUCCESS;
		break;
	case RESP_REGISTER_AUTH_FAILURE:
		result = -ERR_REGISTER_AUTH_FAILURE;
		break;
	case RESP_ERR_TEMPORARY:
		result = -ERR_TEMPORARY_ERROR;
		break;
	case RESP_REGISTER_ALREADY_LOGGED_IN:
		result = -ERR_REGISTER_ALREADY_LOGGED;
		break;
	case RESP_REGISTER_UNSUPPORTED_VERSION:
		result = -ERR_REGISTER_UNSUPPORTED_VERSION;
		break;
	default:
		result = -ERR_UNKNOWN(207);
		break;
	}

	free(packet);
	return result;
}

void vcrypt_close_sockets(VCRYPT_CTX* ctx)
{
	server_disconnect(ctx);
	p2p_close(ctx);
	ctx->connection_in_progress = 0;
}

