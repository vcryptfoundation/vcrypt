/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "config.h"
#include <unistd.h>

#if HAVE_WINDOWS_H
#include <windows.h>
#include <ws2tcpip.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "client.h"
#include "dh_sessions.h"
#include "version.h"
#include "call.h"
#include <assert.h>
#include "client_p2p.h"
#include <arpa/inet.h>
#include <stdlib.h>

void init_call_context(VCRYPT_CTX* ctx, int is_caller)
{
	// this will init the audio ctx too
	memset(&ctx->call_ctx, 0, sizeof(struct CALL_CTX));

	ctx->call_ctx.status = CALL_STATUS_RINGING;
	ctx->call_ctx.start_time_ms = time_get_ms();
	ctx->call_ctx.is_caller = is_caller;
}

/* this initiates new call */
void vcrypt_call(VCRYPT_CTX *ctx, const char *username)
{
	int ret = -ERR_UNKNOWN_ERROR;

	// TODO: add semaphore
	if (ctx->call_ctx.status != CALL_STATUS_NONE) {
		ctx->callback_call_status_change(username, -ERR_CALL_MAINTAINSTATUS,
				-ERR_CALL_INPROGRESS); //TODO: this is a bug, it hangs up the call while it shouldn't
		dolog(0, "call status is: %d\n", ctx->call_ctx.status);
		return;
	}

	int local_p2p_port = 0;
	ret = p2p_socket_setup(ctx, &local_p2p_port);
	if (ret < 0)
		goto update_status;

	dolog(0, "Local p2p port is: %d\n", local_p2p_port);

	init_call_context(ctx, 1);
	strncpy_ex(ctx->call_ctx.username, username, MAX_USERNAME_L);

	ret = dh_key_add_or_reuse(&ctx->dh_keys, username, DHKEY_VOICE,
			&ctx->call_ctx.key);
	if (ret)
		goto update_status;

	unsigned char buff[2048];
	ret = dh_step_1(ctx, ctx->call_ctx.key, buff, sizeof buff);
	if (ret <= 0)
		goto update_status;

	/*
	 * 1 byte - protocol version
	 * p2p info - which will have the IP address filled by server (because only server knows that)
	 * DH first step
	 * */
	VCRYPT_PACKET *packet = packet_new(DEST_CLIENT, username, REQ_CALL,
			1 + sizeof(PAYLOAD_P2PINFO) + ret);

	if (!packet) {
		ret = -ERR_MALLOC;
		goto update_status;
	}

	packet->payload[0] = VCRYPT_PROTOCOL_VERSION;
	memcpy(packet->payload + 1 + sizeof(PAYLOAD_P2PINFO), buff, ret);

	((PAYLOAD_P2PINFO*) (packet->payload + 1))->p2p_port = local_p2p_port;

	ret = vqueue_add_packet(&ctx->packet_queue, packet,
			VCRYPT_TIMEOUT_CALLANSWER, 1);

	update_status: //
	if (ret > 0) {
		ctx->callback_call_status_change(username, -ERR_CALL_SENT, 0);
		ctx->call_ctx.packet_id = ret;
	} else {
		vcrypt_call_end(ctx, username, ret);
	}
}

int vcrypt_setup_received_call(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet)
{
	if (ctx->call_ctx.status != CALL_STATUS_NONE) {
		ctx->callback_call_status_change(username, -ERR_CALL_RECEIVED,
				-ERR_CALL_INPROGRESS);

		return -ERR_CALL_INPROGRESS;
	}

	init_call_context(ctx, 0);
	ctx->call_ctx.packet_id = packet->queue_id;

	strncpy_ex(ctx->call_ctx.username, username, MAX_USERNAME_L);

	int ret;

	if (packet->payload[0] != VCRYPT_PROTOCOL_VERSION) {
		ret = -ERR_REGISTER_UNSUPPORTED_VERSION;
		goto reterr;
	}

	ret = dh_key_add_or_reuse(&ctx->dh_keys, username, DHKEY_VOICE,
			&ctx->call_ctx.key);
	if (ret) {
		ctx->call_ctx.key = NULL;
		goto reterr;
	}

	ret = dh_step_2a(ctx, ctx->call_ctx.key,
			(uint8_t*) packet->payload + 1 + sizeof(PAYLOAD_P2PINFO),
			packet->payload_len - 1 - sizeof(PAYLOAD_P2PINFO));
	if (ret < 0)
		goto reterr;

	ret = client_setup_p2p_info(ctx, (PAYLOAD_P2PINFO*) (packet->payload + 1));
	if (ret)
		goto reterr;

	client_print_p2p_info(ctx);

	// this means to start ringing
	ctx->callback_call_status_change(username, -ERR_CALL_RECEIVED, 0);

	return 0;

	reterr: //
	vcrypt_call_end(ctx, username, ret);
	return ret;
}

int vcrypt_setup_answered_call(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet)
{
	if (ctx->call_ctx.status != CALL_STATUS_RINGING
			|| !ctx->call_ctx.is_caller) {
		ctx->callback_call_status_change(username, -ERR_CALL_HANGUP,
				-ERR_UNKNOWN_ERROR);

		return -ERR_UNKNOWN_ERROR;
	}

	ctx->call_ctx.status = CALL_STATUS_AUDIO;
	ctx->call_ctx.time_audio_start = time_get_ms();
	ctx->call_ctx.time_packet_sent = ctx->call_ctx.time_audio_start;
	ctx->call_ctx.time_packet_rcvd = ctx->call_ctx.time_audio_start;

	int ret;

	if (packet->payload[0] != VCRYPT_PROTOCOL_VERSION) {
		ret = -ERR_REGISTER_UNSUPPORTED_VERSION;
		goto reterr;
	}

	if (ctx->call_ctx.key == NULL ) {
		ret = -ERR_NO_DHKEY;
		goto reterr;
	}

	ret = dh_step_3(ctx, ctx->call_ctx.key,
			(uint8_t*) packet->payload + 1 + sizeof(PAYLOAD_P2PINFO),
			packet->payload_len - 1 - sizeof(PAYLOAD_P2PINFO));
	if (ret < 0)
		goto reterr;

	ret = client_setup_p2p_info(ctx, (PAYLOAD_P2PINFO*) (packet->payload + 1));
	if (ret)
		goto reterr;

	client_print_p2p_info(ctx);

	// we start audio sending after all DH routines are done
	if ((ret = ctx->callback_start_audio_sending()))
		goto reterr;

	// this means to start sending audio
	ctx->callback_call_status_change(username, -ERR_CALL_ANSWERED, 0);

	return 0;

	reterr: //
	vcrypt_call_end(ctx, username, ret);
	return ret;
}

// the worker will call this after some error happens
int vcrypt_call_end(VCRYPT_CTX *ctx, const char *username, int reason)
{
	p2p_close(ctx);

	if (ctx->call_ctx.status == CALL_STATUS_NONE) {
		dolog(0, "--- nothing to end here\n");
		return -ERR_CALL_NO_ACTIVE_CALL;
	}

	ctx->callback_call_status_change(username, -ERR_CALL_HANGUP, reason);

	// do some call cleanup dh session, etc

	if (ctx->call_ctx.key) {
		ctx->call_ctx.key->status = DHKEY_STATUS_ADDED;
	}

	ctx->call_ctx.status = CALL_STATUS_NONE;
	return 0;
}

/* this should be called during a call, it doesn't reject an incoming call */
int vcrypt_call_hangup(VCRYPT_CTX *ctx, const char *username)
{
	// check if we can hang up now: caller can hang up anytime, calee only after he answered the call
	if (ctx->call_ctx.status == CALL_STATUS_NONE
			|| (!ctx->call_ctx.is_caller
					&& ctx->call_ctx.status == CALL_STATUS_RINGING)) {
		ctx->callback_call_status_change(username, -ERR_CALL_MAINTAINSTATUS,
				-ERR_CALL_NO_ACTIVE_CALL);
		return -ERR_CALL_NO_ACTIVE_CALL;
	}

	vcrypt_call_end(ctx, username, 0);

	// send hangup packet
	VCRYPT_PACKET *packet = packet_new(DEST_CLIENT, username, REQ_CALL_HANGUP,
			0);
	if (!packet)
		return -ERR_MALLOC;

	packet->no_srv_ack = 1;

	return vqueue_add_packet(&ctx->packet_queue, packet, VCRYPT_TIMEOUT_CLIENT,
			0);
}

/* use thsi to accept or reject a call */
int vcrypt_call_accept(VCRYPT_CTX *ctx, const char *username, int reject)
{
	// this function should work only on callee
	if (ctx->call_ctx.is_caller
			|| ctx->call_ctx.status != CALL_STATUS_RINGING) {
		ctx->callback_call_status_change(username, -ERR_CALL_MAINTAINSTATUS,
				-ERR_CALL_NOT_RINGING);
		return -ERR_CALL_NOT_RINGING;
	}

	VCRYPT_PACKET *packet;
	int ret;

	if (reject) {
		packet = packet_new(DEST_CLIENT, username, RESP_CALL_REJECTED, 0);
		packet->queue_id = ctx->call_ctx.packet_id;
		vcrypt_call_end(ctx, username, -ERR_CALL_REJECTED);
	} else {
		int local_p2p_port = 0;
		ret = p2p_socket_setup(ctx, &local_p2p_port);
		if (ret < 0)
			goto err;

		dolog(0, "Local p2p port is: %d\n", local_p2p_port);

		unsigned char buff[2048];
		ret = dh_step_2b(ctx, ctx->call_ctx.key, buff, sizeof buff);
		if (ret > 0) {
			packet = packet_new(DEST_CLIENT, username, RESP_CALL_OK,
					1 + sizeof(PAYLOAD_P2PINFO) + ret);
			if (!packet) {
				ret = -ERR_MALLOC;
				goto err;
			}

			packet->queue_id = ctx->call_ctx.packet_id;
			packet->payload[0] = VCRYPT_PROTOCOL_VERSION;
			memcpy(packet->payload + 1 + sizeof(PAYLOAD_P2PINFO), buff, ret);

			((PAYLOAD_P2PINFO*) (packet->payload + 1))->p2p_port =
					local_p2p_port;

			if ((ret = ctx->callback_start_audio_sending()))
				goto err;

			ctx->call_ctx.status = CALL_STATUS_AUDIO;
			ctx->call_ctx.time_audio_start = time_get_ms();
			ctx->call_ctx.time_packet_sent = ctx->call_ctx.time_audio_start;
			ctx->call_ctx.time_packet_rcvd = ctx->call_ctx.time_audio_start;
			ctx->callback_call_status_change(username, -ERR_CALL_ANSWERED, 0);
		} else {
			packet = packet_new(DEST_CLIENT, username,
					RESP_UNKNOWN_CLIENT_ERROR, ret);
			if (!packet) {
				ret = -ERR_MALLOC;
				goto err;
			}

			packet->queue_id = ctx->call_ctx.packet_id;
			vcrypt_call_end(ctx, username, ret);
		}
	}

	ret = vqueue_add_packet(&ctx->packet_queue, packet, VCRYPT_TIMEOUT_CLIENT,
			0);

	if (ret >= 0) {
		return 0;
	}

	err: //
	vcrypt_call_end(ctx, username, ret);
	return ret;
}

int receive_encoded_audio(VCRYPT_CTX *ctx, PACKET_NR packet_nr, uint8_t *data,
		int data_size)
{
	int16_t *decoded = alloca(ctx->call_ctx.audio_ctx.packet_frames_play
			* VCRYPT_AUDIO_CHANNELS * sizeof(int16_t));

	if (packet_nr != ctx->call_ctx.packet_nr_recv + 1) {
		dolog(0, "packet loss: %d packets\n",
				packet_nr - ctx->call_ctx.packet_nr_recv);
	}
	ctx->call_ctx.packet_nr_recv = packet_nr;

	int ret = aes_crypt_cbc(&ctx->call_ctx.key->aes_dec, AES_DECRYPT,
			data_size - 17, data + 1, data + 17, data + 17);

	if (ret != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_DECRYPTION_ERROR;
	}

	data_size = data_size - 17 - (data[0] & 0x0F);

	int dec_frames = audio_decode(&ctx->call_ctx.audio_ctx, data + 17,
			data_size, decoded, ctx->call_ctx.audio_ctx.packet_frames_play, 0);

	if (dec_frames != ctx->call_ctx.audio_ctx.packet_frames_play) {
		dolog(0, "DECODER frames mismatch: %d %d, data_size=%d\n",
				ctx->call_ctx.audio_ctx.packet_frames_play, dec_frames,
				data_size);
	}

	if (dec_frames > 0) {
		ctx->callback_audio((char*) decoded,
				dec_frames * VCRYPT_AUDIO_CHANNELS * sizeof(int16_t));
	}

	return 0;
}

unsigned char buff_p2p[1024 * 10];

int vcrypt_call_process(VCRYPT_CTX *ctx, int have_data)
{
	if (have_data) {
		buff_p2p[0] = 0;
		P2P_PACKET *packet = (P2P_PACKET*) buff_p2p;

		struct sockaddr_in from_addr;
		socklen_t slen = sizeof(struct sockaddr);
		int n = recvfrom(ctx->socket_p2p, buff_p2p, sizeof(buff_p2p), 0,
				(struct sockaddr*) &from_addr, &slen);

		if (ctx->call_ctx.status != CALL_STATUS_AUDIO)
			return 0;

		int matches = packet_matches_callctx(ctx, &from_addr);

		if (matches) {
			if (packet->type == P2P_CALL_AUDIO) {
				receive_encoded_audio(ctx, packet->packet_nr, packet->payload,
						n - P2P_HEAD );
			} else {
				dolog(0, "unknown packet type received: %d (%d bytes)\n",
						packet->type, n);
			}

			ctx->call_ctx.time_packet_rcvd = time_get_ms();
		} else {
			dolog(0, " * Received P2P %d bytes from %s (%s): %d\n", n,
					inet_ntoa(from_addr.sin_addr),
					matches ? "matches" : "doesn't match", packet->packet_nr);
		}
	}

	// check for timeout on callee (on caller the packet_queue will time out)
	if ((ctx->call_ctx.status == CALL_STATUS_RINGING)
			&& !ctx->call_ctx.is_caller
			&& (time_passed_ms(ctx->call_ctx.start_time_ms)
					> VCRYPT_TIMEOUT_CALLANSWER)) {
		vcrypt_call_end(ctx, ctx->call_ctx.username, -ERR_CALLANSWER_TIMEOUT);
	} else if (ctx->call_ctx.status == CALL_STATUS_AUDIO) {
		if (time_passed_ms(ctx->call_ctx.time_packet_rcvd) > VCRYPT_TIMEOUT_CALL) {
			vcrypt_call_end(ctx, ctx->call_ctx.username,
					-ERR_CALL_AUDIO_TIMEOUT);
			return 0;
		}

//		if (time_passed_ms(ctx->call_ctx.time_packet_sent) > 500) {
//			ctx->call_ctx.packet_nr_sent++;
//			int res = sendto(ctx->socket_p2p, &ctx->call_ctx.packet_nr_sent, 4,
//					0, (struct sockaddr*) &ctx->call_ctx.p2p_info,
//					sizeof(struct sockaddr_in));
//
//			ctx->call_ctx.time_packet_sent = time_get_ms();
//
//			if (res != 4) {
//				vcrypt_call_end(ctx, ctx->call_ctx.username,
//						-ERR_UDP_HOLE_PUNCHING_TIMEOUT);
//			}
//		}
	}

	return 0;
}
