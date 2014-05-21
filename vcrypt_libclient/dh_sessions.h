/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#ifndef DH_SESSIONS_H_
#define DH_SESSIONS_H_

#pragma pack(push)
#pragma pack(1)

typedef struct DH_MESSAGE_FORMAT {
	uint8_t proto_ver;
	uint8_t last_block_bytes;
	uint8_t iv[16];
	uint64_t fletcher_sum;
	uint8_t ciphertext[1];
} DH_MESSAGE_FORMAT;

#pragma pack(pop)

int dh_step_1(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *buff,
		size_t buff_size);
int dh_step_2a(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *in, size_t inlen);
int dh_step_2b(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *out, size_t outlen);
int dh_step_3(VCRYPT_CTX *ctx, DH_KEY *key, unsigned char *in, size_t inlen);

int dh_start_exchange(VCRYPT_CTX *ctx, const char *username, const int purpose);
int dh_receive_send_public_params(VCRYPT_CTX *ctx, const int purpose,
		VCRYPT_PACKET *packet);
int dh_receive_public(VCRYPT_CTX *ctx, const int purpose, VCRYPT_PACKET *packet);
void dh_mark_error(VCRYPT_CTX *ctx, const int purpose, const char *username);
int dh_is_useable(DH_KEY *key);

int dh_message_encrypt(VCRYPT_CTX *ctx, DH_KEY *dh_context,
		const char *username, const char *message, VCRYPT_PACKET **packet);
int dh_message_decrypt(VCRYPT_CTX *ctx, DH_KEY *dh_context, uint8_t *ciphertext,
		size_t len, char **decrypted);
#endif /* DH_SESSIONS_H_ */
