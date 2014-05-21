/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "client.h"
#include "ssl_wrap.h"
#include <assert.h>
#include "polarssl/asn1.h"
#include <math.h>
#include "version.h"

int rsa_get_public_key_fingerprint(rsa_context *rsa, uint64_t *fingerprint,
		char fingerprint_ascii[FLETCHER_SIZE_STR])
{
	int ret;
	if ((ret = rsa_check_pubkey(rsa)) != 0) {
		char err[128];
		error_strerror(ret, err, sizeof err);
		dolog(D_ENC, "ERROR verifying public key: %s\n", err);
		return -ERR_NO_PUBKEY;
	}

	uint8_t pk[2048]; // public key is not bigger than this
	int pk_len = asn1_encode_public_key_der(pk, sizeof pk, rsa);

	if (pk_len <= 0) {
		return -ERR_UNKNOWN(901);
	}

	uint64_t fp;
	if (fingerprint == NULL ) {
		fingerprint = &fp;
	}

	*fingerprint = fletcher64(pk, pk_len);

	if (fingerprint_ascii)
		fletcher64_to_str(fingerprint_ascii, fingerprint);

	return 0;
}

int vcrypt_get_key_fingerprint_ctx(VCRYPT_CTX *ctx,
		char checksum[FLETCHER_SIZE_STR])
{
	return rsa_get_public_key_fingerprint(&ctx->ssl_req.rsa,
			&ctx->public_key_fp_local, checksum);
}

/* this updates/creates only the key file, to use the key a reconnect is needed */
int vcrypt_generate_keys_sync(VCRYPT_CTX *ctx, const char* filename,
		char pub_checksum[FLETCHER_SIZE_STR])
{
	int ret;

	// TODO: this deletes the old key
	FILE *f = fopen(filename, "wb");
	if (f == NULL ) {
		return -ERR_FILE_WRITE;
	}

	// we use temporary rsa storage
	rsa_context rsa;
	rsa_init(&rsa, ctx->ssl_req.rsa.padding, ctx->ssl_req.rsa.hash_id);

	if ((ret = rsa_gen_key(&rsa, ctr_drbg_random, &ctx->ssl_req.ctr_drbg,
			2048 /*4096*/, 65537)) != 0) {
		return -ERR_RSA_ERROR_GENERATING_KEYS;
	}

	uint8_t keys[4096];
	int pk_len = asn1_encode_private_key_der(keys, sizeof keys, &rsa);

	if (pk_len <= 0) {
		fclose(f);
		rsa_free(&rsa);
		return -ERR_UNKNOWN(900);
	}

	if (fwrite(keys, 1, pk_len, f) != pk_len) {
		fclose(f);
		rsa_free(&rsa);
		return -ERR_FILE_WRITE;
	}

	rsa_get_public_key_fingerprint(&rsa, NULL, pub_checksum);

	rsa_free(&rsa);
	fclose(f);
	return pk_len > 0 ? 0 : pk_len;
}

struct GENKEY_PARMS {
	VCRYPT_CTX *ctx;
	char *filename;
} GENKEY_PARMS;

void *genkey_thread(void *p)
{
	struct GENKEY_PARMS *parms = p;
#ifdef __ANDROID__
	parms->ctx->callback_jni_setup(1);
#endif

	char *pub_checksum = calloc(1, FLETCHER_SIZE_STR);
	if (!pub_checksum) {
		parms->ctx->callback_key_generate_response(-ERR_MALLOC, NULL );
		goto cleanup;
	}

	int result = vcrypt_generate_keys_sync(parms->ctx, parms->filename,
			pub_checksum);

	if (result < 0) {
		free(pub_checksum);
		pub_checksum = NULL;
	}

	parms->ctx->callback_key_generate_response(result, pub_checksum);
	parms->ctx->thread_keys_handle = 0;

	cleanup: //
#ifdef __ANDROID__
	parms->ctx->callback_jni_setup(0);
#endif

	free(parms->filename);
	free(parms);

	return NULL ;
}

void vcrypt_generate_keys(VCRYPT_CTX *ctx, const char* filename)
{
	// TODO: use mutex here
	if (ctx->thread_keys_handle) {
		ctx->callback_key_generate_response(-ERR_INPROGRESS, NULL );
		return;
	}

	ctx->thread_keys_handle = 1; // temporarily

	struct GENKEY_PARMS *params = malloc(sizeof GENKEY_PARMS);

	if (params == NULL ) {
		ctx->callback_key_generate_response(-ERR_MALLOC, NULL );
		ctx->thread_keys_handle = 0;
		return;
	}

	params->ctx = ctx;
	params->filename = strdup(filename);

	pthread_create(&ctx->thread_keys_handle, NULL, genkey_thread,
			(void*) params);
	pthread_detach(ctx->thread_keys_handle);

	// todo check thread outcome...
}

int vcrypt_is_keys_in_progress(VCRYPT_CTX *ctx)
{
	return ctx->thread_keys_handle;
}

int _vcrypt_load_keys(VCRYPT_CTX *ctx, const char *file, char *checksum)
{
	FILE *f = fopen(file, "rb");
	if (f == NULL ) {
		ctx->has_valid_keys_locally = 0;
		return -ERR_FILE_READ;
	}

	uint8_t keydata[4096];
	int keylen = fread(keydata, 1, sizeof keydata, f);
	if (keylen <= 0) {
		fclose(f);
		return -ERR_FILE_READ;
	}

	fclose(f);

	ctx->has_valid_keys_locally = 0; // the next will invalidate them
	rsa_free(&ctx->ssl_req.rsa);

	int ret = x509parse_key(&ctx->ssl_req.rsa, keydata, keylen, NULL, 0);

	if (ret == 0)
		vcrypt_get_key_fingerprint_ctx(ctx, checksum);

	ctx->has_valid_keys_locally = 1;

	return ret == 0 ? 0 : -ERR_RSA_ERROR_LOADING_KEYS;
}

int vcrypt_load_keys(VCRYPT_CTX *ctx, const char *file, char *checksum)
{
	int ret = _vcrypt_load_keys(ctx, file, checksum);
	if (ret)
		return ret;

	if (vcrypt_is_connected(ctx))
		return upload_public_key(ctx);
	else
		return 0;
}

int vcrypt_has_keys(VCRYPT_CTX *ctx)
{
	return ctx->has_valid_keys_locally;
}

int upload_public_key(VCRYPT_CTX *ctx)
{
	// checking the public key first
	int ret;
	if ((ret = rsa_check_pubkey(&ctx->ssl_req.rsa)) != 0) {
		return -ERR_RSA_NO_KEYS;
	}

	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, NULL, REQ_PUBKEY_UPLOAD,
			1024);
	if (packet == NULL )
		goto err;

	int pk_len = asn1_encode_public_key_der((uint8_t*) packet->payload + 8,
			packet->payload_len - 8, &ctx->ssl_req.rsa);

	if (pk_len <= 0)
		goto err;

	uint64_t fp = fletcher64(packet->payload + 8, pk_len);

	// consistency check
	assert(ctx->public_key_fp_local == fp);

	memcpy(packet->payload, &fp, 8);

	packet->payload_len = pk_len + 8;

	return vqueue_add_packet(&ctx->packet_queue, packet, VCRYPT_TIMEOUT_SERVER,
			1);

	err: //
	if (packet)
		packet_free(packet);

	return -ERR_UNKNOWN(908);
}

int cache_public_key(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet)
{
	int ret;

	// add dummy entry
	if (!packet) {
		rsa_context *pk = public_key_list_get(ctx->public_keys, username);
		if (pk) {
			ret = public_key_node_update(pk, NULL, NULL );
		} else {
			ret = public_key_list_add(&ctx->public_keys, username, NULL, NULL );
		}

		return ret ? ret : -ERR_NO_PUBKEY;
	}

	unsigned char *p = (unsigned char*) packet->payload;
	unsigned char *end = p + packet->payload_len;
	size_t len = 0;
	mpi N, E;

	if ((ret = asn1_get_tag(&p, end, &len, ASN1_CONSTRUCTED | ASN1_SEQUENCE))
			!= 0)
		return -ERR_NO_PUBKEY;

	if (p + len != end)
		return -ERR_NO_PUBKEY;

	mpi_init(&N);
	mpi_init(&E);

	if ((ret = asn1_get_mpi(&p, end, &N)) != 0
			|| (ret = asn1_get_mpi(&p, end, &E)) != 0) {
		mpi_free(&N);
		mpi_free(&E);
		return -ERR_NO_PUBKEY;
	}

	if (p != end) {
		mpi_free(&N);
		mpi_free(&E);
		return -ERR_NO_PUBKEY;
	}

	rsa_context *pk = public_key_list_get(ctx->public_keys, username);
	if (pk) {
		ret = public_key_node_update(pk, &E, &N);
	} else {
		ret = public_key_list_add(&ctx->public_keys, username, &E, &N);
	}

	mpi_free(&N);
	mpi_free(&E);

	return ret;
}

int message_rsa_encrypt(VCRYPT_CTX *ctx, rsa_context *public_rsa,
		const char *username, const char *message, VCRYPT_PACKET **packet)
{
	int ret;
	/*
	 * format:
	 * 1 byte protocol version
	 * 2 bytes encryption key size in bytes
	 * 2 bytes signature key size in bytes
	 * ciphertext
	 * signature
	 *
	 */

	if (!public_rsa->len)
		return -ERR_NO_PUBKEY;

	// we dont encrypt null terminating char, as this creates a vector of attack
	int plain_len = strlen(message);
	if (plain_len == 0)
		return -ERR_ENCRYPTION_ERROR;

	size_t plain_chunk_len = public_rsa->len - 11;
	// get packet size
	int plain_chunks = ceil(plain_len / (float) plain_chunk_len);
	int ciphertext_len = plain_chunks * public_rsa->len;

	// space for signature
	ciphertext_len += ctx->ssl_req.rsa.len;

	*packet = packet_new(DEST_CLIENT, username, REQ_MESSAGE_SEND,
			ciphertext_len + 5);
	if (!*packet)
		return -ERR_MALLOC;

	// TODO: add ciphertext stealing (form signature) to save bandwidth (i.e. use signature as padding)

	int chunk;
	int chunk_len;
	uint8_t *in = (uint8_t*) message, *out = (uint8_t*) (*packet)->payload;

	*out++ = VCRYPT_PROTOCOL_VERSION;
	*((uint16_t*) out) = public_rsa->len;
	out += 2;
	*((uint16_t*) out) = ctx->ssl_req.rsa.len;
	out += 2;

	for (chunk = 0; chunk < plain_chunks; chunk++, in += plain_chunk_len, out +=
			public_rsa->len) {

		// last usually has different length
		chunk_len =
				chunk == plain_chunks - 1 ?
						plain_len % plain_chunk_len : plain_chunk_len;

		if ((ret = rsa_pkcs1_encrypt(public_rsa, ctr_drbg_random,
				&ctx->ssl_req.ctr_drbg, RSA_PUBLIC, chunk_len, in, out) != 0)) {
			free(packet);
			return -ERR_ENCRYPTION_ERROR;
		}
	}

	unsigned char hash[64];
	sha4_context sha_ctx;
	sha4_starts(&sha_ctx, 1);
	sha4_update(&sha_ctx, (uint8_t*) message, plain_len);
	sha4_finish(&sha_ctx, hash);

	if ((ret = rsa_pkcs1_sign(&ctx->ssl_req.rsa, NULL, NULL, RSA_PRIVATE,
			ctx->ssl_req.rsa.hash_id, sizeof hash, hash, out) != 0)) {
		free(packet);
		return -ERR_SIGN_ERROR;
	}

	return 0;
}

int message_rsa_decrypt(VCRYPT_CTX *ctx, rsa_context *public_rsa,
		uint8_t *ciphertext, size_t len, char **decrypted)
{
	int ret = 0;
	int ret_len = 0;

	if (len < 5)
		return -ERR_DECRYPTION_ERROR;

	if (*ciphertext++ != VCRYPT_PROTOCOL_VERSION)
		return -ERR_DECRYPTION_ERROR;

	uint16_t encr_key_len = *((uint16_t*) ciphertext);
	ciphertext += 2;
	uint16_t sig_key_len = *((uint16_t*) ciphertext);
	ciphertext += 2;

	if (encr_key_len != ctx->ssl_req.rsa.len)
		return -ERR_DECRYPTION_ERROR;

	if ((len - 5 - sig_key_len) % encr_key_len)
		return -ERR_DECRYPTION_ERROR;

	int ciphertext_chunks = (len - 5 - sig_key_len) / encr_key_len;

	// maximum possible plaintext length
	int plain_len = ciphertext_chunks * ctx->ssl_req.rsa.len;

	if (ciphertext_chunks < 1)
		return -ERR_DECRYPTION_ERROR; // we need the signature too

	*decrypted = malloc(plain_len + 1); // 1 char for the null terminator
	if (!*decrypted)
		return -ERR_MALLOC;

	int chunk;
	size_t decrypted_len = 0;
	uint8_t *in = ciphertext, *out = (uint8_t*) *decrypted;

	for (chunk = 0; chunk < ciphertext_chunks;
			chunk++, out += decrypted_len, in += ctx->ssl_req.rsa.len) {
		if ((ret = rsa_pkcs1_decrypt(&ctx->ssl_req.rsa, RSA_PRIVATE,
				&decrypted_len, in, out, ctx->ssl_req.rsa.len)) != 0) {

			char err[256];
			error_strerror(ret, err, sizeof err);
			dolog(0,
					" failed\n  ! rsa_pkcs1_decrypt returned %d: %s (chunk: %d)\n",
					ret, err, chunk);

			free(*decrypted);
			return -ERR_DECRYPTION_ERROR;
		}

		ret_len += decrypted_len;
	}

	*out = 0;

	if (!public_rsa || !public_rsa->len) {
		return -ERR_SIGN_VERIFY_ERROR;
	}

	unsigned char hash[64];
	sha4_context sha_ctx;
	sha4_starts(&sha_ctx, 1);
	sha4_update(&sha_ctx, (uint8_t*) *decrypted, ret_len);
	sha4_finish(&sha_ctx, hash);

	if ((ret = rsa_pkcs1_verify(public_rsa, RSA_PUBLIC, public_rsa->hash_id,
			sizeof hash, hash, in)) != 0) {

		char err[256];
		error_strerror(ret, err, sizeof err);
		dolog(0,
				" failed\n  ! rsa_pkcs1_verify returned %d: %s\nmessage was: %s\n",
				ret, err, *decrypted);

		return -ERR_SIGN_VERIFY_ERROR;
	}

	return ret_len;
}

