/*
 * dh_keys.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <malloc.h>
#include "client.h"
#include "ssl_wrap.h"
#include "dh_keys.h"
#include "common.h"
#include "vcrypt_errors.h"
#include "packets.h"


int dh_key_node_update(rsa_context *rsa, mpi *E, mpi *N)
{
	dolog(D_FUNC, "updating dh key\n");

	if (rsa->E.p) {
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

int dh_key_list_add(DH_KEY **root, const char *username, int purpose,
		DH_KEY **item)
{
	DH_KEY *last;

	dolog(D_FUNC, "adding  dh key for user: %s\n", username);

	if (*root == NULL ) {
		*root = calloc(1, sizeof(DH_KEY));
		if (!root)
			return -ERR_MALLOC;

		last = *root;
	} else {
		last = *root;
		while (last->next)
			last = last->next;

		last->next = calloc(1, sizeof(DH_KEY));
		if (!last->next)
			return -ERR_MALLOC; //TODO: add proper freeing

		last->next->prev = last;
		last = last->next;
	}

	last->username = strdup(username);
	if (!last->username) {
		// TODO: elaborate free() here
		return -ERR_MALLOC;
	}

	memset(&last->dhm, 0, sizeof(last->dhm));
	last->purpose = purpose;
	last->status = DHKEY_STATUS_ADDED;

	*item = last;

	return 0;
}

DH_KEY *dh_key_list_get(DH_KEY *list, const char *username, int purpose)
{
	DH_KEY *item = list;

	while (item) {
		if (strcmp(username, item->username) == 0 && purpose == item->purpose)
			return item;

		item = item->next;
	}

	return NULL ;
}

int dh_key_list_free(DH_KEY **root)
{
	DH_KEY *item = *root;
	DH_KEY *temp;

	// find last element
	while (item && item->next) {
		item = item->next;
	}

	while (item) {
		free(item->username);
		dhm_free(&item->dhm);

		temp = item->prev;
		free(item);

		item = temp;
	}

	*root = 0;
	return 0;
}

int dh_key_matches(DH_KEY *key, const char *username, const int purpose)
{
	if (key == NULL )
		return 0;

	if (strcmp(key->username, username))
		return 0;

	if (purpose != key->purpose)
		return 0;

	return 0;
}

int dh_key_add_or_reuse(DH_KEY **root, const char *username, const int purpose,
		DH_KEY **key)
{
	int ret = 0;

	*key = dh_key_list_get(*root, username, purpose);
	if (*key == NULL ) {
		ret = dh_key_list_add(root, username, purpose, key);
	}

	return ret;
}
