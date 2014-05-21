/*
 * worker.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>

#if HAVE_WINDOWS_H
#include <windows.h>
#include <ws2tcpip.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "client.h"
#include "client_p2p.h"
#include "queue.h"
#include "packets.h"
#include "connect.h"
#include "dh_sessions.h"
#include "call.h"

#define BUFFER_SIZE 4096 // we have big public keys
#define BUFFER_P2P_SIZE 4096

int response_to_error(int resp_code)
{
	int errcode;
	switch (resp_code)
	{
	case RESP_OK:
		errcode = -ERR_SUCCESS;
		break;
	case RESP_CALL_OK:
		errcode = -ERR_SUCCESS;
		break;
	case RESP_ERR_TEMPORARY:
		errcode = -ERR_TEMPORARY_ERROR;
		break;
	case RESP_ERR_NOSUCHUSER:
		errcode = -ERR_NOSUCHUSER;
		break;
	case RESP_ERR_USEROFFLINE:
		errcode = -ERR_USER_OFFLINE;
		break;
	case RESP_ERR_MYSELF:
		errcode = -ERR_MSG_CALLINGITSELF;
		break;
	case RESP_PACKET_FORWARDED:
		errcode = -ERR_INPROGRESS_SERVER;
		break;
	case RESP_ERR_PACKET_FORWARD:
		errcode = -ERR_UNKNOWN(601);
		break;
	case RESP_CLIENT_BUSY:
		errcode = -ERR_CLIENT_CALLBUSY;
		break;
	case RESP_PUBLIC_KEY_NONE:
		errcode = -ERR_NO_PUBKEY;
		break;
	case RESP_MESSAGE_STORED:
		errcode = -ERR_MESSAGE_STORED;
		break;
	case RESP_MESSAGE_ERR_DECRYPT:
		errcode = -ERR_DECRYPTION_ERROR;
		break;
	case RESP_PASSWORD_CHANGE_BAD_PASSWORD:
		errcode = -ERR_PASSWORD_BAD;
		break;
	case RESP_REGISTER_AUTH_FAILURE:
		errcode = -ERR_REGISTER_AUTH_FAILURE;
		break;
	case RESP_REGISTER_UNSUPPORTED_VERSION:
		errcode = ERR_REGISTER_UNSUPPORTED_VERSION;
		break;
	case RESP_ERR_NOT_IMPLEMENTED:
		errcode = -ERR_NOT_IMPLEMENTED;
		break;
	case RESP_CALL_REJECTED:
		errcode = -ERR_CALL_REJECTED;
		break;
	case RESP_UNKNOWN_CLIENT_ERROR:
	case RESP_MSG_UNKNOWN_CLIENT_ERROR:
		errcode = -ERR_UNKNOWN_ERROR;
		break;
	default:
		dolog(0, "missing response code: %d (%s)\n", resp_code,
				packet_type_str(resp_code));
		errcode = -ERR_UNKNOWN(603);
		break;
	}

	return errcode;
}

/* processes packet that match a command in queue */
int process_queue_response(VCRYPT_CTX *ctx, VQ_ENTRY *qentry_matched,
		VCRYPT_PACKET *packet)
{
	int retval = 0;
	int err = response_to_error(packet->type);

	switch (qentry_matched->packet->type)
	{
	case REQ_CONTACT_ADD:
	case REQ_CONTACT_DEL:
		ctx->callback_contact_add_del_response(qentry_matched->packet->type,
				err, packet->payload);
		break;

	case REQ_PING_SERVER:
		ctx->callback_ping_response(NULL, err);
		break;

	case REQ_CALL:
		if (err) {
			vcrypt_call_end(ctx, qentry_matched->packet->username, err);
		} else {
			vcrypt_setup_answered_call(ctx, qentry_matched->packet->username,
					packet);
		}

		break;

	case REQ_PUBKEY_UPLOAD:
		dolog(0, "error: %s\n", vcrypt_get_error(err));
		retval = err;
		break;

	case REQ_GET_PUBLIC_KEY:
		if (err == 0) {
			err = cache_public_key(ctx, qentry_matched->packet->username,
					packet);
		}

		if (err == 0) {
			ctx->callback_message_received(qentry_matched->packet->username,
					strdup("Public key downloaded"), 1);
		} else {
			ctx->callback_message_received(qentry_matched->packet->username,
					strdup(vcrypt_get_error(err)), 1);
		}

		break;

	case REQ_DH_SENDPARAMS:
		if (err == 0) {
			err = dh_receive_public(ctx, DHKEY_MESSAGING, packet);
		} else {
			dh_mark_error(ctx, DHKEY_MESSAGING, packet->username);
		}

		if (err == 0) {
			ctx->callback_message_received(qentry_matched->packet->username,
					strdup("DH session started"), 1);
		} else {
			ctx->callback_message_received(qentry_matched->packet->username,
					strdup(vcrypt_get_error(err)), 1);
		}
		break;
	case REQ_PING_CLIENT:
		ctx->callback_ping_response(packet->username, err);
		break;

	case REQ_MESSAGE_SEND_DH:
		// cancel the DH session here if there is error
	case REQ_MESSAGE_SEND:
		ctx->callback_message_sent_status_update(
				qentry_matched->packet->username, packet->queue_id, err);
		break;
	case REQ_PASSWORD_CHANGE:
		ctx->callback_password_change_response(err);
		break;
	default:
		retval = -ERR_UNEXPECTED_PACKET;
		break;
	}

	vqueue_entry_free(&ctx->packet_queue, qentry_matched);

	return retval;
}

/* this alters the packet, prepares it as a response */
int receive_message_rsa(VCRYPT_CTX* ctx, VCRYPT_PACKET* packet, int offline)
{
	int ret = 0;
	char* plaintext;

	rsa_context* public_rsa = public_key_list_get(ctx->public_keys,
			packet->username);

	int err = message_rsa_decrypt(ctx, public_rsa, (uint8_t*) packet->payload,
			packet->payload_len, &plaintext);

	if (err >= 0 || err == -ERR_SIGN_VERIFY_ERROR) {
		ctx->callback_message_received(packet->username, plaintext, offline);
		packet->type = RESP_OK;
	} else {
		packet->type = RESP_MESSAGE_ERR_DECRYPT;
	}

	if (err < 0) {
		ctx->callback_message_received(packet->username,
				strdup(vcrypt_get_error(err)), 1);
	}

	packet->payload_len = 0;

	return ret;
}

/* this alters the packet, prepares it as a response */
int receive_message_dh(VCRYPT_CTX* ctx, VCRYPT_PACKET* packet)
{
	int ret = 0;
	int err;

	char* plaintext;

	DH_KEY* dh_key = dh_key_list_get(ctx->dh_keys, packet->username,
			DHKEY_MESSAGING);

	if (dh_is_useable(dh_key)) {
		err = dh_message_decrypt(ctx, dh_key, (uint8_t*) packet->payload,
				packet->payload_len, &plaintext);

		if (err >= 0 || err == -ERR_SIGN_VERIFY_ERROR) {
			ctx->callback_message_received(packet->username, plaintext, 0);
			packet->type = RESP_OK;
		} else {
			packet->type = RESP_MESSAGE_ERR_DECRYPT;
		}
	} else {
		packet->type = RESP_MESSAGE_ERR_DECRYPT;
		err = -ERR_DECRYPTION_ERROR;
	}

	if (err < 0) {
		ctx->callback_message_received(packet->username,
				strdup(vcrypt_get_error(err)), 1);
	}

	packet->payload_len = 0;

	return ret;
}

/* processes packet that come from server, and have no match in queue */
int process_new_packet_server(VCRYPT_CTX *ctx, VCRYPT_PACKET *packet)
{
	dolog(D_FUNC, "func %s called\n", __func__);

	switch (packet->type)
	{
	case REQ_CONTACT_STATUS_CHANGE: {
		char *data = packet->payload + 1;
		char *tmp;
		if ((tmp = strchr(data, '\n')))
			*tmp = 0;

		ctx->callback_contact_status_notify(data, *packet->payload);
		return -ERR_SUCCESS;
	}
	case REQ_MESSAGE_OFFLINE: {
		int ret = receive_message_rsa(ctx, packet, 3);
		if (ret == 0) {
			// TODO: check if user is online here
			// notify user that we got the message
			packet->type = REQ_MESSAGE_STORED_READ;
			packet->dest = DEST_CLIENT;
			packet->no_srv_ack = 1;
			packet->payload_len = 0;
			ret = packet_send(&ctx->ssl, packet);

			dolog(D_PACKET, " <<-- wrote: %s\n", packet_dump(packet));
		}
		return ret;
	}
		break;

	case RESP_PACKET_FORWARDED:
		return 0;

	default:
		return -ERR_UNEXPECTED_PACKET;
	}
}

/* processes packet that come from clients, and have no match in queue */
int process_new_packet_client(VCRYPT_CTX *ctx, VCRYPT_PACKET *packet)
{
	dolog(D_FUNC, "func %s called\n", __func__);
	int respond = 1;
	int ret = 0;

	switch (packet->type)
	{
	case REQ_PING_CLIENT:
		packet->type = RESP_OK;
		break;
	case REQ_MESSAGE_SEND:
		if ((ret = receive_message_rsa(ctx, packet, 0)) < 0) {
			respond = 0;
		}
		break;
	case REQ_MESSAGE_SEND_DH:
		if ((ret = receive_message_dh(ctx, packet)) < 0) {
			respond = 0;
		}
		break;
	case REQ_MESSAGE_STORED_READ:
		respond = 0;
		ctx->callback_message_sent_status_update(packet->username,
				packet->queue_id, 0);
		break;
	case REQ_DH_SENDPARAMS:
		// we ignore the error here, it will be catched by timeout
		respond = 0;
		dh_receive_send_public_params(ctx, DHKEY_MESSAGING, packet);
		break;

	case RESP_OK:
		ret = 0;
		respond = 0;
		break;

	case REQ_CALL:
		ret = vcrypt_setup_received_call(ctx, packet->username, packet);

		if (ret == -ERR_CALL_INPROGRESS) {
			packet->type = RESP_CLIENT_BUSY;
		} else if (ret) {
			packet->type = RESP_UNKNOWN_CLIENT_ERROR;
			packet->payload_len = 0;
		} else {
			// user will answer with accept or reject packet
			respond = 0;
		}

		break;

	case REQ_CALL_HANGUP:
		vcrypt_call_end(ctx, packet->username, -ERR_CALL_OTHER_HANGUP);
		respond = 0;
		break;
	case RESP_CALL_REJECTED:
	case RESP_CALL_OK:
		dolog(0, "WORKER: Client tries to answer/reject a timed out call\n");
		return 0;
	default:
		ret = -ERR_UNEXPECTED_PACKET;
		respond = 0;
		break;
	}

	if (respond) {
		packet->no_srv_ack = 1; // we don't need server response for these
		dolog(D_PACKET, " <<-- wrote: %s\n", packet_dump(packet));
		return packet_send(&ctx->ssl, packet);
	}

	return ret;
}

/* all received packets end here first, this function dispatches them */
int process_packet(VCRYPT_CTX *ctx, VCRYPT_PACKET* packet)
{
	if (packet->type == RESP_ERR_PACKET_TOO_BIG) {
		return -ERR_PACKET_TOO_BIG;
	}

	// check if received packet is a response for one of the queued packets
	VQ_ENTRY *qmatched = vqueue_packet_matches(&ctx->packet_queue, packet);

	if (qmatched) {
		dolog(D_PACKET, " -->> received response for %s: %s\n",
				packet_type_str(qmatched->packet->type), packet_dump(packet));

		if (packet->type == RESP_PACKET_FORWARDED) {
			vqueue_update_server_response_time(qmatched);
			return 0;
		}

		return process_queue_response(ctx, qmatched, packet);
	} else {
		dolog(D_PACKET, " -->> received: %s\n", packet_dump(packet));

		if (packet->dest == DEST_SERVER) {
			return process_new_packet_server(ctx, packet);
		} else if (packet->dest == DEST_CLIENT) {
			return process_new_packet_client(ctx, packet);
		}
	}

	return 0;
}

int process_queued_commands(VCRYPT_CTX *ctx)
{
	pthread_mutex_lock(&ctx->packet_queue.mutex);
	int i;

	if (ctx->packet_queue.packets_enqueued > 0) {
		// check for timed out packets
		for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
			if (!ctx->packet_queue.entries[i].queued)
				continue;

			int ptimeout = vqueue_check_timeout(ctx->packet_queue.entries + i);

			if (ptimeout) {
				switch (ctx->packet_queue.entries[i].packet->type)
				{
				case REQ_PING_SERVER:
					ctx->callback_ping_response(NULL, ptimeout);
					break;
				case REQ_PING_CLIENT:
					ctx->callback_ping_response(
							ctx->packet_queue.entries[i].packet->username,
							ptimeout);
					break;
				case REQ_MESSAGE_SEND:
					ctx->callback_message_sent_status_update(
							ctx->packet_queue.entries[i].packet->username,
							ctx->packet_queue.entries[i].packet->queue_id,
							ptimeout);
					break;
				case REQ_GET_PUBLIC_KEY:
					ctx->callback_message_received(
							ctx->packet_queue.entries[i].packet->username,
							strdup(vcrypt_get_error(ptimeout)), 1);
					break;
				case REQ_PUBKEY_UPLOAD:
					return -ERR_PUBKEY_SYNC;
				case REQ_PASSWORD_CHANGE:
					ctx->callback_password_change_response(ptimeout);
					break;
				case REQ_DH_SENDPARAMS:
					dh_mark_error(ctx, DHKEY_MESSAGING,
							ctx->packet_queue.entries[i].packet->username);
					ctx->callback_message_received(
							ctx->packet_queue.entries[i].packet->username,
							strdup(vcrypt_get_error(ptimeout)), 1);
					break;
				case REQ_CALL:
					vcrypt_call_end(ctx,
							ctx->packet_queue.entries[i].packet->username,
							ptimeout);
					break;
				default:
					assert(1 == 0 && "Timeout for packet type not processed"); // exit...
					break;
				}

				vqueue_entry_free(&ctx->packet_queue,
						ctx->packet_queue.entries + i);
			}
		}
	}

	if (ctx->packet_queue.packets_enqueued > 0) {
		// check for packets not yet sent, at this point all timed out packets are deleted
		for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
			if (!ctx->packet_queue.entries[i].queued)
				continue;

			// these are already sent
			if (ctx->packet_queue.entries[i].time_sent_ms)
				continue;

			assert(ctx->packet_queue.entries[i].packet != NULL);

			ctx->packet_queue.entries[i].time_sent_ms = time_get_ms();

			if (packet_send(&ctx->ssl, ctx->packet_queue.entries[i].packet)
					< 0) {
				vqueue_entry_free(&ctx->packet_queue,
						ctx->packet_queue.entries + i);

				// this is severe error, we should disconnect here
				dolog(0, "ERROR: Could not write packet, disconnecting\n");

				//ctx->flag_thread_status = THREAD_EXIT_ERROR; // exit the thread
				pthread_mutex_unlock(&ctx->packet_queue.mutex);
				return -ERR_PACKET_WRITE;
			}

			dolog(D_PACKET, " <<-- sent %s\n",
					packet_dump(ctx->packet_queue.entries[i].packet));

			if (!ctx->packet_queue.entries[i].wait_match) {
				// free sent packet
				vqueue_entry_free(&ctx->packet_queue,
						ctx->packet_queue.entries + i);
			}
		}
	}

	pthread_mutex_unlock(&ctx->packet_queue.mutex);
	return 0;
}

int process_postponed_packets(VCRYPT_CTX *ctx, VQUEUE *queue)
{
	int i;

	if (queue->packets_enqueued > 0) {
		// check for timed out packets
		for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
			if (!queue->entries[i].queued)
				continue;

			int ptimeout = vqueue_check_timeout(queue->entries + i);

			if (ptimeout) {
				switch (queue->entries[i].packet->type)
				{
				case REQ_MESSAGE_SEND:
				case REQ_MESSAGE_OFFLINE:
					if (ptimeout == -ERR_SERVER_TIMEOUT) {
						ctx->callback_message_received(
								queue->entries[i].packet->username,
								strdup(vcrypt_get_error(-ERR_NO_PUBKEY)), 1);
					}
					break;
				default:
					assert(2 == 0); // exit...
					break;
				}

				vqueue_entry_free(queue, queue->entries + i);
			}
		}
	}

	// check for packets not yet processed
	if (queue->packets_enqueued > 0) {
		for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
			if (!queue->entries[i].queued)
				continue;

			assert(queue->entries[i].packet != NULL);

			int ret = process_packet(ctx, queue->entries[i].packet);
			if (ret != -ERR_POSTPONE_PACKET) {
				vqueue_entry_free(queue, queue->entries + i);
				return ret;
			}
		}
	}

	return 0;
}

enum thread_state {
	thread_none, thread_connected, thread_logged_in, thread_contacts_received
};

/* TODO: move all read/write here */
void *vcrypt_client_thread(void *vctx)
{
	VCRYPT_CTX *ctx = (VCRYPT_CTX *) vctx;
#ifdef __ANDROID__
	ctx->callback_jni_setup(1);
#endif

	enum thread_state state = thread_none;

	vqueue_init(&ctx->packet_queue);
	VQUEUE postponed_packets;
	vqueue_init(&postponed_packets);

	dolog(D_FUNC, "thread started\n");

// deal with login/connect stuff
	int connecting = 1;
	while (get_thread_status(ctx) == THREAD_RUNNING && connecting) {
		int res;
		switch (state)
		{
		case thread_none:
			res = server_connect(ctx, ctx->login_details.hostname,
					ctx->login_details.port);
			if (res != 0) {
				set_thread_status(ctx, res);
				continue;
			} else {
				state = thread_connected;
			}
			break;
		case thread_connected:
			res = server_auth(ctx, ctx->login_details.username,
					ctx->login_details.password);
			if (res < 0) {
				// signal disconnect
				set_thread_status(ctx, res);
				continue;
			} else {
				state = thread_logged_in;
				ctx->callback_server_disconnect(0);
			}
			break;
		default:
			connecting = 0;
			break;
		}
	}

	int reading_header = 1; // we are reading header now
	int already_read = 0;
	int packet_ready = 0;

	char buffer[BUFFER_SIZE];
	VCRYPT_PACKET *packet = (VCRYPT_PACKET*) buffer;

	while (get_thread_status(ctx) == THREAD_RUNNING) {
		int n;
		size_t to_read;
		char *dest;

		// queued commands must be processed before, otherwise we may end up with a full queue
		int pqc_res = process_queued_commands(ctx);
		if (pqc_res != 0) {
			// disconnect
			set_thread_status(ctx, pqc_res);
			continue;
		}

		if (reading_header) {
			to_read = PACKET_HEAD_SIZE;
			dest = buffer;
		} else {
			to_read = packet->payload_len;
			dest = buffer + PACKET_HEAD_SIZE;
		}

		assert(to_read + already_read <= BUFFER_SIZE);

		// this doesn't block
		n = ssl_read(&ctx->ssl, (unsigned char*) dest + already_read,
				to_read - already_read);

		if (n == POLARSSL_ERR_NET_WANT_READ) {
			/*
			 * place to do other writing jobs
			 */

			// check local queue for commands to re-process
			if (postponed_packets.packets_enqueued) {
				int ppp = process_postponed_packets(ctx, &postponed_packets);
				if (ppp != 0) {
					dolog(D_PACKET, "process postponed returned: %d %s\n", ppp,
							vcrypt_get_error(ppp));
					// disconnect
					set_thread_status(ctx, ppp);
					continue;
				}
			}

			// if ssl_read() produced no data, wait for data to come so we don't use too much CPU
			fd_set sock_fd;
			FD_ZERO(&sock_fd);
			FD_SET(ctx->socket_server, &sock_fd);

			if (ctx->socket_p2p != -1)
				FD_SET(ctx->socket_p2p, &sock_fd);

			struct timeval timeout;
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000; // 10 times per sec, saving CPU
			select(MAX(ctx->socket_server,ctx->socket_p2p) + 1, &sock_fd, NULL,
					NULL, &timeout);

			vcrypt_call_process(ctx,
					(ctx->socket_p2p != -1)
							&& FD_ISSET(ctx->socket_p2p, &sock_fd));
			continue;
		}

		if (n > 0) {
			already_read += n;

			if (reading_header) {
				assert(already_read <= PACKET_HEAD_SIZE);

				// check if client wants to send a packet too big
				if (packet->payload_len > BUFFER_SIZE - PACKET_HEAD_SIZE ) {
					dolog(0, "ERROR: server wants to sent too big packet\n");
					set_thread_status(ctx, -ERR_PACKET_TOO_BIG);
					continue;
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
			dolog(0, "ERROR: server disconnected\n");
			set_thread_status(ctx, -ERR_SERVER_DISCONNECT);
			continue;
		}

		if (packet_ready) {
			int res = process_packet(ctx, packet);

			if (res < 0) {
				if (res == -ERR_POSTPONE_PACKET) {
					VCRYPT_PACKET *postponed = packet_clone(packet);

					if (!postponed) {
						set_thread_status(ctx, -ERR_MALLOC);
						continue;
					}

					// postpone the packet for latter processing when the preconditions are met
					res = vqueue_add_packet_noid(&postponed_packets, postponed,
							5000);
					if (res < 0) {
						dolog(0, "ERROR: can't postpone packet, err: %d\n",
								res);
						set_thread_status(ctx, res);
					}
				} else {
					dolog(0, "ERROR: client_process_packet error: %d ('%s' ?),"
							"\n    packet: %s\n", res, vcrypt_get_error(res),
							packet_dump((VCRYPT_PACKET*) buffer));

					//if (res != -ERR_UNEXPECTED_PACKET)
					set_thread_status(ctx, res);
				}
			}

			// prepare for a new packet
			reading_header = 1;
			already_read = 0;
			packet_ready = 0;
		}
	}

// finish the existing call if any
	if (ctx->call_ctx.status != CALL_STATUS_NONE) {
		//client_send_p2p_command(ctx, P2P_CALL_HANGUP);
		client_close_call(ctx);
	}

	ssl_close_notify(&ctx->ssl);
	ssl_free(&ctx->ssl);
	vcrypt_close_sockets(ctx);
	vqueue_close(&ctx->packet_queue);
	vqueue_close(&postponed_packets);

// TODO: review this, may be its better to call these callbacks right after the error happened
	switch (get_thread_status(ctx))
	{
	case THREAD_SIGNAL_STOP:
		set_thread_status(ctx, THREAD_EXIT_NORMAL);
		ctx->callback_server_disconnect(-ERR_DISCONNECT_SUCCESS);
		break;
	default:
		ctx->callback_server_disconnect(ctx->flag_thread_status);
		break;
	}

	dolog(D_FUNC, "Exiting thread (from thread func)\n");

	set_thread_status(ctx, THREAD_NONE);

#ifdef __ANDROID__
	ctx->callback_jni_setup(0);
#endif

	return NULL ;
}

int vcrypt_start_thread(VCRYPT_CTX *ctx)
{
	if (get_thread_status(ctx) != THREAD_NONE)
		return -ERR_UNKNOWN(201);

	set_thread_status(ctx, THREAD_RUNNING);
	pthread_create(&ctx->thread_handle, NULL, vcrypt_client_thread,
			(void*) ctx);
	pthread_detach(ctx->thread_handle);

	return ERR_SUCCESS;
}

