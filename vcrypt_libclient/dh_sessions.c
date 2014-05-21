/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#include "client.h"
#include "version.h"
#include "dh_sessions.h"

int dh_step_1(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *buff,
		size_t buff_size)
{
	if (key->status == DHKEY_STATUS_PARAMS_QUEUED) {
		return -ERR_INPROGRESS;
	}

	key->initiator = 1;
	key->status = DHKEY_STATUS_ERROR;

	dhm_free(&key->dhm);

	int ret;
	if ((ret = mpi_read_string(&key->dhm.P, 16,
			POLARSSL_DHM_RFC5114_MODP_2048_P)) != 0
			|| mpi_read_string(&key->dhm.G, 16,
					POLARSSL_DHM_RFC5114_MODP_2048_G) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_UNKNOWN(35);
	}

	size_t olen = 0;

	if ((ret = dhm_make_params(&key->dhm, mpi_size(&key->dhm.P), buff, &olen,
			ctr_drbg_random, &ctx->ssl_req.ctr_drbg)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_UNKNOWN(36);
	}

	assert(olen <= buff_size);
	key->status = DHKEY_STATUS_PARAMS_QUEUED;

	return olen;
}

int dh_step_2a(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *in, size_t inlen)
{
	int ret;

	key->status = DHKEY_STATUS_ERROR;
	key->fingerprint = 0;
	key->initiator = 0;
	dhm_free(&key->dhm);

	if ((ret = dhm_read_params(&key->dhm, &in, in + inlen + 2)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	key->fingerprint = 0;
	key->status = DHKEY_STATUS_PARAMS_RECVD;

	return 0;
}

int dh_step_2b(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *out, size_t outlen)
{
	int ret = 0;

	if (key->status != DHKEY_STATUS_PARAMS_RECVD) {
		ret = -ERR_NO_DHKEY;
		goto errkey;
	}

	if (key->dhm.len > outlen) {
		ret = -ERR_UNKNOWN(56);
		goto errkey;
	}

	if ((ret = dhm_make_public(&key->dhm, key->dhm.len, out, key->dhm.len,
			ctr_drbg_random, &ctx->ssl_req.ctr_drbg)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		ret = -ERR_NO_DHKEY;
		goto errkey;
	}

	unsigned char *secret_buff = alloca(key->dhm.len);
	size_t n = key->dhm.len;
	if ((ret = dhm_calc_secret(&key->dhm, secret_buff, &n)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		goto errkey;
	}

	// TODO: hmac the DH key
	ret = aes_setkey_enc(&key->aes_enc, secret_buff, 256);
	if (ret) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		goto errkey;
	}

	// TODO: hmac this and make it different
	ret = aes_setkey_dec(&key->aes_dec, secret_buff, 256);
	if (ret) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		goto errkey;
	}

	ret = entropy_func(&ctx->ssl_req.entropy, key->iv, sizeof(key->iv));
	if (ret != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		goto errkey;
	}

	key->fingerprint = fletcher64(secret_buff, key->dhm.len);
	key->status = DHKEY_STATUS_READY;
	return n;

	errkey: //
	key->status = DHKEY_STATUS_ERROR;
	return ret;
}

int dh_step_3(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *in, size_t inlen)
{
	int ret;
	unsigned char buff[2048];
	key->status = DHKEY_STATUS_ERROR;
	key->fingerprint = 0;

	if ((ret = dhm_read_public(&key->dhm, in, inlen)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	size_t n = key->dhm.len;
	if ((ret = dhm_calc_secret(&key->dhm, buff, &n)) != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	// TODO: hmac the DH key, probably the best is to use
	// salt = initiator username + other username
	ret = aes_setkey_enc(&key->aes_enc, buff, 256);
	if (ret) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	// TODO: make this key different
	ret = aes_setkey_dec(&key->aes_dec, buff, 256);
	if (ret) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	ret = entropy_func(&ctx->ssl_req.entropy, key->iv, sizeof(key->iv));
	if (ret != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		return -ERR_NO_DHKEY;
	}

	// TODO: improve this, use hmac, then fletcher64
	key->fingerprint = fletcher64(buff, n);
	key->status = DHKEY_STATUS_READY;

	return 0;
}

/* third DH step, initiator runs this */
int dh_receive_public(VCRYPT_CTX *ctx, const int purpose, VCRYPT_PACKET *packet)
{
	DH_KEY *key = dh_key_list_get(ctx->dh_keys, packet->username, purpose);
	if (!key)
		return -ERR_NO_DHKEY;

	return dh_step_3(ctx, key, (uint8_t*) packet->payload, packet->payload_len);
}

/* second DH step, destination runs this (client) */
int dh_receive_send_public_params(VCRYPT_CTX *ctx, const int purpose,
		VCRYPT_PACKET *packet)
{
	int ret;
	DH_KEY *key;

	ret = dh_key_add_or_reuse(&ctx->dh_keys, packet->username, purpose, &key);
	if (ret)
		return ret;

	unsigned char buff_pub[2048];
	unsigned char *payload_ptr = (unsigned char*) packet->payload;

	ret = dh_step_2a(ctx, key, payload_ptr, packet->payload_len);
	if (ret < 0)
		return ret; // no need th mark the key as error as it was done by step_2

	ret = dh_step_2b(ctx, key, buff_pub, sizeof buff_pub);
	if (ret <= 0)
		return ret;

	VCRYPT_PACKET *packet_out = packet_new(DEST_CLIENT, packet->username,
			RESP_OK, ret);

	if (!packet_out) {
		ret = -ERR_MALLOC;
		goto errkey;
	}

	packet_out->queue_id = packet->queue_id;

	memcpy(packet_out->payload, buff_pub, packet_out->payload_len);

	// this is run from worker so we can use send
	ret = packet_send(&ctx->ssl, packet_out);
	packet_free(packet_out);

	if (ret) {
		dolog(0, "could not send packet!! %d\n", ret);
		goto errkey;
	}

	// TODO:del
	ctx->callback_message_received(packet->username,
			strdup("Establised DH session"), 1);

	return 0;

	errkey: //
	key->status = DHKEY_STATUS_ERROR;
	return ret;
}

/* first DH step, initiator sends this (server) */
int dh_start_exchange(VCRYPT_CTX *ctx, const char *username, const int purpose)
{
	int ret;
	DH_KEY *key;

	ret = dh_key_add_or_reuse(&ctx->dh_keys, username, purpose, &key);
	if (ret)
		return ret;

	unsigned char buff[2048];
	ssize_t olen = dh_step_1(ctx, key, buff, sizeof buff);
	if (olen < 0)
		return olen;

	VCRYPT_PACKET *packet = packet_new(DEST_CLIENT, username, REQ_DH_SENDPARAMS,
			olen);

	if (!packet) {
		ret = -ERR_MALLOC;
		goto errkey;
	}

	memcpy(packet->payload, buff, packet->payload_len);

	ret = vqueue_add_packet(&ctx->packet_queue, packet, VCRYPT_TIMEOUT_CLIENT,
			1);
	if (ret < 0)
		goto errkey;

	// success
	return -ERR_DHKEY_NEGOTIATING;

	errkey: //
	key->status = DHKEY_STATUS_ERROR;
	return ret;
}

void dh_mark_error(VCRYPT_CTX *ctx, const int purpose, const char *username)
{
	DH_KEY *key = dh_key_list_get(ctx->dh_keys, username, purpose);

	if (key)
		key->status = DHKEY_STATUS_ERROR;
}

int dh_is_useable(DH_KEY *key)
{
	if (key == NULL )
		return 0;

	if (key->status == DHKEY_STATUS_READY)
		return 1;

	return 0;
}

int dh_message_decrypt(VCRYPT_CTX *ctx, DH_KEY *dh_context, uint8_t *ciphertext,
		size_t len, char **decrypted)
{
	int plain_padded_len = len - offsetof(DH_MESSAGE_FORMAT, ciphertext);

	if (plain_padded_len < 16)
		return -ERR_DECRYPTION_ERROR;

	if (plain_padded_len % 16)
		return -ERR_DECRYPTION_ERROR;

	DH_MESSAGE_FORMAT *msg = (DH_MESSAGE_FORMAT*) ciphertext;

	if (msg->proto_ver != VCRYPT_PROTOCOL_VERSION)
		return -ERR_DECRYPTION_ERROR;

	if (msg->last_block_bytes > 15)
		return -ERR_DECRYPTION_ERROR;

	*decrypted = malloc(plain_padded_len + 1); // for the NULL terminating byte
	if (!*decrypted)
		return -ERR_MALLOC;

	// IV debugging
//	char ivstr[FLETCHER_SIZE_STR * 2];
//	fletcher64_to_str(ivstr, (uint64_t*) msg->iv);
//	strcat(ivstr, " ");
//	fletcher64_to_str(ivstr + FLETCHER_SIZE_STR, (uint64_t*) (msg->iv + 8));
//	dolog(0, "decrypting with IV: %s\n", ivstr);

	int ret = aes_crypt_cbc(&dh_context->aes_dec, AES_DECRYPT, plain_padded_len,
			msg->iv, msg->ciphertext, (uint8_t*) *decrypted);

	if (ret != 0) {
		log_polarssl_err(ret, __FUNCTION__, __LINE__);
		free(*decrypted);
		return -ERR_DECRYPTION_ERROR;
	}

	int msg_len = plain_padded_len;
	if (msg->last_block_bytes) {
		msg_len = plain_padded_len - 16 + msg->last_block_bytes;
	}

	uint64_t flsm = fletcher64(*decrypted, msg_len);
	if (flsm != msg->fletcher_sum) {
		dolog(0, "fletcher sum mismatch\n");
		free(*decrypted);
		return -ERR_DECRYPTION_ERROR;
	}

	(*decrypted)[msg_len] = 0;

	return msg_len + 1;
}

int dh_message_encrypt(VCRYPT_CTX *ctx, DH_KEY *dh_context,
		const char *username, const char *message, VCRYPT_PACKET **packet)
{
	ssize_t msg_len = strlen(message);
	ssize_t encr_len = msg_len;
	int last_block_bytes = 0;

	if (msg_len == 0) {
		return -ERR_ENCRYPTION_ERROR;
	}

	if (msg_len % 16) {
		encr_len = (msg_len / 16) * 16 + 16;
		last_block_bytes = msg_len + 16 - encr_len;
	}

	//uint8_t iv[16];
	*packet = packet_new(DEST_CLIENT, username, REQ_MESSAGE_SEND_DH,
			encr_len + offsetof(DH_MESSAGE_FORMAT, ciphertext) );
	if (!*packet)
		return -ERR_MALLOC;

	DH_MESSAGE_FORMAT *msg = (DH_MESSAGE_FORMAT *) (*packet)->payload;

	msg->proto_ver = VCRYPT_PROTOCOL_VERSION;
	msg->last_block_bytes = last_block_bytes;
	msg->fletcher_sum = fletcher64(message, msg_len);
	memcpy(msg->iv, dh_context->iv, sizeof(dh_context->iv));

	ssize_t no_last_block_len = encr_len;
	if (last_block_bytes) {
		no_last_block_len -= 16; // we will encrypt last block differently
		if (no_last_block_len < 0)
			no_last_block_len = 0;
	}

	int ret = 0;
	if (no_last_block_len) {
		ret = aes_crypt_cbc(&dh_context->aes_enc, AES_ENCRYPT,
				no_last_block_len, dh_context->iv, (uint8_t*) message,
				msg->ciphertext);
		if (ret != 0) {
			log_polarssl_err(ret, __FUNCTION__, __LINE__);
			packet_free(*packet);
			return -ERR_ENCRYPTION_ERROR;
		}
	}

	if (last_block_bytes) {
		uint8_t last_block[16];

		memcpy(last_block, message + no_last_block_len, last_block_bytes);

		ret = entropy_func(&ctx->ssl_req.entropy, last_block + last_block_bytes,
				sizeof(last_block) - last_block_bytes);
		if (ret != 0) {
			log_polarssl_err(ret, __FUNCTION__, __LINE__);
			return -ERR_UNKNOWN_ERROR;
		}

		ret = aes_crypt_cbc(&dh_context->aes_enc, AES_ENCRYPT, 16,
				dh_context->iv, last_block,
				msg->ciphertext + no_last_block_len);

		if (ret != 0) {
			log_polarssl_err(ret, __FUNCTION__, __LINE__);
			packet_free(*packet);
			return -ERR_ENCRYPTION_ERROR;
		}
	}

	return 0;
}
