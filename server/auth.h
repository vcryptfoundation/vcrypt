/*
 * auth.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef AUTH_H_
#define AUTH_H_

#include <stdint.h>
#include "workers.h"

#define HMAC_SIZE 64
#define PASSWORD_HASH_SIZE (HMAC_SIZE + 4)

int64_t auth_user(char *username, const char *password, uint64_t *public_key_fp);
int password_generate_hash(const char *password, const char *username,
		uint8_t *hash, int hashlen);
int auth_change_pass(CLIENT *client, const VCRYPT_PACKET *packet);
int password_validate_strength(const char *password);

#endif /* AUTH_H_ */
