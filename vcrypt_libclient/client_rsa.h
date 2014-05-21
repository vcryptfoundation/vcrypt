/*
 * client_rsa.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CLIENT_RSA_H_
#define CLIENT_RSA_H_

#include "common.h"

void vcrypt_generate_keys(VCRYPT_CTX *ctx, const char* filename);
int vcrypt_get_key_fingerprint_ctx(VCRYPT_CTX *ctx,
		char checksum[FLETCHER_SIZE_STR]);
int upload_public_key(VCRYPT_CTX *ctx);
int _vcrypt_load_keys(VCRYPT_CTX *ctx, const char *file, char *checksum);
int vcrypt_load_keys(VCRYPT_CTX *ctx, const char *file, char *checksum);
int cache_public_key(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet);
int message_rsa_encrypt(VCRYPT_CTX *ctx, rsa_context *public_rsa,
		const char *username, const char *message, VCRYPT_PACKET **packet);
int message_rsa_decrypt(VCRYPT_CTX *ctx, rsa_context *public_rsa,
		uint8_t *ciphertext, size_t len, char **decrypted);
int vcrypt_is_keys_in_progress(VCRYPT_CTX *ctx);
int rsa_get_public_key_fingerprint(rsa_context *rsa, uint64_t *fingerprint,
		char fingerprint_ascii[FLETCHER_SIZE_STR]);

#endif /* CLIENT_RSA_H_ */
