/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "client.h"

#include <errno.h>

#include "client_p2p.h"
#include "packets.h"
#include "common.h"
#include "queue.h"
#include "connect.h"
#include "worker.h"
#include "fifo.h"
#include <opus/opus.h>
#include "profiler.h"
#include "dummycallbacks.h"
#include "dh_sessions.h"
#include "commands.h"

VCRYPT_CTX* vcrypt_create(const char *keys_fname)
{
	assert(keys_fname);

	VCRYPT_CTX *ctx = (VCRYPT_CTX *) calloc(1, sizeof(VCRYPT_CTX));
	if (ctx == NULL)
		return NULL;

	ctx->socket_server = -1;
	ctx->socket_p2p = -1;

	ctx->public_keys = NULL;
	ctx->dh_keys = NULL;

	setup_dummy_callbacks(ctx);

	ctx->packet_queue.open = 0; // mark as closed

	if (ssl_requisites_init(&ctx->ssl_req) != 0) {
		free(ctx);
		return NULL;
	}

	ctx->login_details.hostname = NULL;
	ctx->login_details.username = NULL;
	ctx->login_details.password = NULL;

	/*
	 * 0 -  keys are invalid, must generate new,
	 * 1 - keys are OK
	 */
	ctx->has_valid_keys_locally = 0;

	pthread_mutex_init(&ctx->mutex, NULL);
	set_thread_status(ctx, THREAD_NONE);

	ctx->thread_handle = 0;
	ctx->thread_keys_handle = 0;

	// try to load keys
	_vcrypt_load_keys(ctx, keys_fname, NULL);

#if WIN32
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		printf("WSAStartup() failed. Error Code : %d",WSAGetLastError());
		exit(EXIT_FAILURE);
	}
#endif

	return ctx;
}

void vcrypt_destroy(VCRYPT_CTX *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->socket_server)
		server_disconnect(ctx);

	if (ctx->socket_p2p)
		p2p_close(ctx);

	ssl_requisites_free(&ctx->ssl_req);

	free_null((void*) &ctx->login_details.hostname);
	free_null((void*) &ctx->login_details.username);
	free_null((void*) &ctx->login_details.password);

	public_key_list_free(&ctx->public_keys);
	dh_key_list_free(&ctx->dh_keys);

	// and so on
	free(ctx);
}

int get_thread_status(VCRYPT_CTX *ctx)
{
	int val;
	pthread_mutex_lock(&ctx->mutex);
	val = ctx->flag_thread_status;
	pthread_mutex_unlock(&ctx->mutex);

	return val;
}

void set_thread_status(VCRYPT_CTX *ctx, int val)
{
	pthread_mutex_lock(&ctx->mutex);
	ctx->flag_thread_status = val;
	pthread_mutex_unlock(&ctx->mutex);
}

// wait can be 1 or 0
int vcrypt_close(VCRYPT_CTX *ctx, int wait)
{
	if (get_thread_status(ctx) == THREAD_NONE) {
		return 0;
	}

	dolog(D_FUNC, "entered vcrypt close\n");

	pthread_mutex_lock(&ctx->mutex);
	if (ctx->flag_thread_status == THREAD_RUNNING) {
		ctx->flag_thread_status = THREAD_SIGNAL_STOP;
	}
	pthread_mutex_unlock(&ctx->mutex);

	// TODO: use conditional vars here, also research is needed about doing join on detached threads
	// wait until it changes this flag
	while (wait && get_thread_status(ctx) != THREAD_NONE) {
		usleep(10000);
	}

	return 0;
}

int vcrypt_is_connected(VCRYPT_CTX *ctx)
{
	return ctx->connection_in_progress;
}

int vcrypt_call_inprogress(VCRYPT_CTX *ctx)
{
	return ctx->call_ctx.status != CALL_STATUS_NONE;
}

/* address can contain the port like domain:port or ip:port */
void vcrypt_connect_auth(VCRYPT_CTX *ctx, const char *hostname,
        const char *username, const char *password)
{
	assert(ctx);
	assert(hostname);
	assert(username);

	if (get_thread_status(ctx) != THREAD_NONE) {
		ctx->callback_server_disconnect(-ERR_SERVER_ALREADY_CONNECTED);
		return;
	}

	if (!ctx->has_valid_keys_locally) {
		ctx->callback_server_disconnect(-ERR_RSA_NO_KEYS);
		return;
	}

	ctx->connection_in_progress = 1;

	free_null((void*) &ctx->login_details.hostname);
	free_null((void*) &ctx->login_details.username);
	free_null((void*) &ctx->login_details.password);

	char *port_str = strrchr(hostname, ':');
	if (port_str && strlen(port_str) > 1) {
		ctx->login_details.port = atoi(port_str + 1) & 0xFFFF;

		ctx->login_details.hostname = malloc(port_str - hostname + 1);
		memcpy(ctx->login_details.hostname, hostname, port_str - hostname);
		ctx->login_details.hostname[port_str - hostname] = 0;
	} else {
		ctx->login_details.port = VCRYPT_SERVER_DEFAULT_PORT;
		ctx->login_details.hostname = strdup(hostname);
	}

	ctx->login_details.username = strdup(username);
	ctx->login_details.password = strdup(password);

	int res = vcrypt_start_thread(ctx);
	if (res < 0) {
		vcrypt_close_sockets(ctx);
		ctx->callback_server_disconnect(res);
		return;
	}

	return;
}

void vcrypt_ping_server(VCRYPT_CTX *ctx)
{
	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, NULL, REQ_PING_SERVER, 0);
	int ret = vqueue_add_packet(&ctx->packet_queue, packet,
	VCRYPT_TIMEOUT_SERVER, 1);

	if (ret < 0)
		ctx->callback_ping_response(NULL, ret);
}

void vcrypt_ping_client(VCRYPT_CTX *ctx, char *username)
{
	VCRYPT_PACKET *packet = packet_new(DEST_CLIENT, username, REQ_PING_CLIENT,
	        0);
	int ret = vqueue_add_packet(&ctx->packet_queue, packet,
	VCRYPT_TIMEOUT_CLIENT, 1);

	if (ret < 0)
		ctx->callback_ping_response(strdup(username), ret);
}

void vcrypt_password_change(VCRYPT_CTX *ctx, const char *oldpwd,
        const char *newpwd, const char *newpwd_r)
{
	if (strlen(oldpwd) == 0 || strlen(newpwd) == 0) {
		ctx->callback_password_change_response(-ERR_PASSWORD_EMPTY);
		return;
	}

	if (strcmp(oldpwd, newpwd) == 0) {
		ctx->callback_password_change_response(-ERR_PASSWORD_SAMEASOLD);
		return;
	}

	if (strcmp(newpwd, newpwd_r) != 0) {
		ctx->callback_password_change_response(-ERR_PASSWORD_NOMATCH);
		return;
	}

	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, oldpwd, REQ_PASSWORD_CHANGE,
	        strlen(newpwd) + 1);

	strncpy_ex(packet->payload, newpwd, packet->payload_len);

	int ret = vqueue_add_packet(&ctx->packet_queue, packet,
	VCRYPT_TIMEOUT_SERVER, 1);

	if (ret < 0)
		ctx->callback_password_change_response(ret);
}

/* returns 0 on success */
int vcrypt_queue_audio(VCRYPT_CTX *ctx, const char *data, int size)
{
	if (ctx->socket_p2p == -1)
		return 0;

	// theoretically there should be no need for more bytes than raw bytes before encoding
	int max_encoded_size = ctx->call_ctx.audio_ctx.packet_frames_opus
	        * VCRYPT_AUDIO_CHANNELS * sizeof(int16_t);

	// reserve space for header, IV, last block info, and eventual padding for last block
	P2P_PACKET *packet = alloca(P2P_HEAD + max_encoded_size + 16 + 1 + 15);

	packet->type = P2P_CALL_AUDIO;
	packet->packet_nr = ++ctx->call_ctx.packet_nr_sent;

	int enc_size = audio_encode(&ctx->call_ctx.audio_ctx, (int16_t*) data,
	        size / (VCRYPT_AUDIO_CHANNELS * sizeof(int16_t)),
	        (uint8_t*) packet->payload + 16 + 1, max_encoded_size);

	if (enc_size <= 0)
		return enc_size;

	int last_block = enc_size & 0xF; // TODO: port this method to messaging too

	assert(ctx->call_ctx.key);

	packet->payload[0] = 0; // indicates how much space is NOT used in the last block
	memcpy(packet->payload + 1, ctx->call_ctx.key->iv, 16);

	if (last_block) {
		// TODO: add propper padding to last block
		packet->payload[0] = 16 - last_block;
		enc_size += packet->payload[0];
	}

	assert((enc_size & 0xF) == 0);

	int ret = aes_crypt_cbc(&ctx->call_ctx.key->aes_enc, AES_ENCRYPT, enc_size,
	        ctx->call_ctx.key->iv, packet->payload + 17, packet->payload + 17);
	if (ret) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_ENCRYPTION_ERROR;
	}

	int total_size = P2P_HEAD + 1 + 16 + enc_size;
	int sendto_ret = sendto(ctx->socket_p2p, (char*) packet, total_size, 0,
	        (struct sockaddr*) &ctx->call_ctx.p2p_info,
	        sizeof(struct sockaddr_in));

//	if (sendto_ret < 0) {
//		dolog(0, "sendto said %d errno: %d, %s (sock: %d)", sendto_ret, errno,
//		        strerror(errno), ctx->socket_p2p);
//	}

	return sendto_ret == total_size ? 0 : -ERR_UNKNOWN_ERROR;
}

void vcrypt_contact_add(VCRYPT_CTX *ctx, const char *username)
{
	if (!username) {
		ctx->callback_contact_add_del_response(REQ_CONTACT_ADD,
		        -ERR_PARAM_ISNULL, strdup(""));
		return;
	}

	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, "", REQ_CONTACT_ADD,
	        strlen(username) + 1);
	strncpy_ex(packet->payload, username, packet->payload_len);

	int ret = vqueue_add_packet(&ctx->packet_queue, packet,
	VCRYPT_TIMEOUT_SERVER, 1);
	if (ret < 0) {
		ctx->callback_contact_add_del_response(REQ_CONTACT_ADD, ret,
		        strdup(username));
	}
}

void vcrypt_contact_del(VCRYPT_CTX *ctx, const char *username)
{
	if (!username) {
		ctx->callback_contact_add_del_response(REQ_CONTACT_DEL,
		        -ERR_PARAM_ISNULL, strdup(""));
		return;
	}

	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, "", REQ_CONTACT_DEL,
	        strlen(username) + 1);
	strncpy_ex(packet->payload, username, packet->payload_len);

	int ret = vqueue_add_packet(&ctx->packet_queue, packet,
	VCRYPT_TIMEOUT_SERVER, 1);
	if (ret < 0)
		ctx->callback_contact_add_del_response(REQ_CONTACT_ADD, ret,
		        strdup(username));
}

/* */
int vcrypt_message_send_prepare(VCRYPT_CTX *ctx, const char *username)
{
	return 0;
}

// returns queue_id which is used as message id, or a negative error code
// returns also zero if a command was processed (should be ignored)
int32_t vcrypt_message_send(VCRYPT_CTX *ctx, const char *username,
        const char *message)
{
	if (commands_process(ctx, username, message))
		return 0;

	VCRYPT_PACKET *packet = NULL;
	int ret;

	DH_KEY *key = dh_key_list_get(ctx->dh_keys, username, DHKEY_MESSAGING);
	if (dh_is_useable(key)) {
		// use DH method
		ret = dh_message_encrypt(ctx, key, username, message, &packet);
		if (ret)
			return ret;
	} else {
		// try RSA method
		rsa_context *rsa = public_key_list_get(ctx->public_keys, username);
		if (rsa == NULL) {
			ctx->callback_message_received(username,
			        strdup("No public key for this user, "
					        "download with /pkget command"), 3);
			return -ERR_NO_PUBKEY;
		}

		int ret = message_rsa_encrypt(ctx, rsa, username, message, &packet);
		if (ret)
			return ret;
	}

	return vqueue_add_packet(&ctx->packet_queue, packet, VCRYPT_TIMEOUT_CLIENT,
	        1);
}

