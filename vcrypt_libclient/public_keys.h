/*
 * public_keys.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef PUBLIC_KEYS_H_
#define PUBLIC_KEYS_H_

/* chained list of public key of users */
typedef struct PUBLIC_KEY {
	char *username;
	rsa_context rsa;
	struct PUBLIC_KEY *prev;
	struct PUBLIC_KEY *next;
} PUBLIC_KEY;

int public_key_list_test();
int public_key_list_add(PUBLIC_KEY **root, const char *username, mpi *E, mpi *N);
int public_key_node_update(rsa_context *rsa, mpi *E, mpi *N);
rsa_context *public_key_list_get(PUBLIC_KEY *list, const char *username);
int public_key_list_free(PUBLIC_KEY **root);

#endif /* PUBLIC_KEYS_H_ */
