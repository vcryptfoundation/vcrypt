/*
 * public_keys.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <malloc.h>
#include "ssl_wrap.h"
#include "public_keys.h"
#include "error_enum.h"
#include "common.h"

int public_key_node_update(rsa_context *rsa, mpi *E, mpi *N)
{
	dolog(D_FUNC, "updating public key\n");

	if (rsa->E.p) {
		dolog(0, "freeing RSA pubkey\n");
		rsa_free(rsa);
	}

	if (E && N) {
		if (mpi_copy(&rsa->E, E) || mpi_copy(&rsa->N, N))
			return -ERR_MALLOC;

		rsa->len = mpi_size(&rsa->N);
	} else {
		rsa->len = 0;
	}

	return 0;
}

int public_key_list_add(PUBLIC_KEY **root, const char *username, mpi *E, mpi *N)
{
	PUBLIC_KEY *last;

	dolog(D_FUNC, "adding  public key for user: %s\n", username);
	if (*root == NULL ) {
		*root = calloc(1, sizeof(PUBLIC_KEY));
		if (!root)
			return -ERR_MALLOC;

		last = *root;
	} else {
		last = *root;
		while (last->next)
			last = last->next;

		last->next = calloc(1, sizeof(PUBLIC_KEY));
		if (!last->next)
			return -ERR_MALLOC; //TODO: add proper freeing

		last->next->prev = last;
		last = last->next;
	}

	last->username = strdup(username);
	if (!last->username)
		return -ERR_MALLOC;

	rsa_init(&last->rsa, RSA_PKCS_V15, SIG_RSA_SHA384);

	return public_key_node_update(&last->rsa, E, N);
}

rsa_context *public_key_list_get(PUBLIC_KEY *list, const char *username)
{
	PUBLIC_KEY *item = list;

	while (item) {
		if (strcmp(username, item->username) == 0)
			return &item->rsa;

		item = item->next;
	}

	return NULL ;
}

int public_key_list_free(PUBLIC_KEY **root)
{
	PUBLIC_KEY *item = *root;
	PUBLIC_KEY *temp;

	// find last element
	while (item && item->next) {
		item = item->next;
	}

	while (item) {
		free(item->username);
		rsa_free(&item->rsa);

		temp = item->prev;
		free(item);

		item = temp;
	}

	*root = 0;
	return 0;
}

