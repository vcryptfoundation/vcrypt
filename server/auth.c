/*
 * auth.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <string.h>
#include <stdlib.h>
#include <polarssl/pkcs5.h>
#include "database.h"
#include "auth.h"

int password_hash(const char* salt, const char *pass, uint8_t *out,
		size_t out_size, uint32_t iterations)
{
	int ret;
	md_context_t sha4_ctx;
	const md_info_t* info_sha4;
	info_sha4 = md_info_from_type(POLARSSL_MD_SHA512);
	if (info_sha4 == NULL )
		return (-1);

	if ((ret = md_init_ctx(&sha4_ctx, info_sha4)) != 0)
		return (-1);

	int hmacres = pkcs5_pbkdf2_hmac(&sha4_ctx, (uint8_t*) pass, strlen(pass),
			(uint8_t*) salt, strlen(salt), iterations, out_size, out);

	md_free_ctx(&sha4_ctx);

	return hmacres;
}

/* hash must be size of HMAC_SIZE + 4 */
int password_generate_hash(const char *password, const char *username,
		uint8_t *hash, int hashlen)
{
	uint32_t iterations = 3768; // may be make this random as an extra salt
	int ret = password_hash(username, password, hash + 4, hashlen - 4,
			iterations);
	if (ret == 0) {
		memcpy(hash, &iterations, 4);
		return 0;
	}

	return -1;
}

/* to be extended.. */
int password_validate_strength(const char *password)
{
	return (strlen(password) >= 8);
}

int password_verify(const char *password, const char *username,
		const char *hash, int hashlen)
{
	uint32_t iterations = 0;
	if (hashlen != sizeof(iterations) + HMAC_SIZE) {
		printf("pass size mismatch %d\n", hashlen);
		return -2;
	}

	memcpy(&iterations, hash, 4);

	// dos attack protection
	if (iterations > 50000)
		return -2;

	uint8_t hmac[HMAC_SIZE];
	if (password_hash(username, password, hmac, HMAC_SIZE, iterations) != 0)
		return -2;

	if (memcmp(hmac, hash + 4, HMAC_SIZE))
		return 0;

	return 1;
}

/* returns user_id>0 on success, 0 on invalid user/pass, and -1 on DB errors */
int64_t auth_user(char *username, const char *password, uint64_t *public_key_fp)
{
	MYSQL_RES* res = db_select(
			"select user_id, password, public_key_fp from users "
					"where username=%s", username);

	if (res == NULL ) {
		db_print_error();
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	unsigned long *lengths = mysql_fetch_lengths(res);

	long result = 0;

	if (row == NULL )
		goto cleanup;

	int retpass = password_verify(password, username, row[1], lengths[1]);
	if (retpass < 0) {
		result = -1;
		goto cleanup;
	}

	if (retpass == 0) {
		result = 0;
		goto cleanup;
	}

	// copy the user id
	result = atol(row[0]);

	if (public_key_fp) {
		*public_key_fp = atoll(row[2]);
	}

	cleanup: //
	mysql_free_result(res);
	return result;
}

int auth_change_pass(CLIENT *client, const VCRYPT_PACKET *packet)
{
	int retval;
	VCRYPT_PACKET *clone = packet_clone_header(packet);
	if (!clone)
		return -1;

	clone->type = RESP_UNKNOWN_SERVER_ERROR;

	if (!password_validate_strength(packet->payload)) {
		clone->type = RESP_PASSWORD_CHANGE_BAD_PASSWORD;
		goto sendresp;
	}

	if (auth_user(client->username, packet->username, NULL ) <= 0) {
		clone->type = RESP_REGISTER_AUTH_FAILURE;
		goto sendresp;
	}

	uint8_t out[PASSWORD_HASH_SIZE]; // space for the iteration count
	if (password_generate_hash(packet->payload, client->username, out,
			PASSWORD_HASH_SIZE) != 0) {
		clone->type = RESP_ERR_TEMPORARY;
		goto sendresp;
	}

	if (db_insert("update users set password=%b where username=%s", out,
			PASSWORD_HASH_SIZE, client->username) != 0) {
		clone->type = RESP_ERR_TEMPORARY;
		goto sendresp;
	}

	clone->type = RESP_OK;

	sendresp: //
	retval = packet_send_client(client, clone);
	packet_free(clone);
	return retval;
}
