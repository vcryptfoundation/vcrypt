/*
 * dh_keys.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef DH_KEYS_H_
#define DH_KEYS_H_

#define DHKEY_MESSAGING 1
#define DHKEY_VOICE 2
#define DHKEY_SIZE 32

typedef enum DHKEY_STATUS {
	DHKEY_STATUS_ADDED, 		//
	DHKEY_STATUS_PARAMS_RECVD,	//
	DHKEY_STATUS_PARAMS_QUEUED,	//
	DHKEY_STATUS_READY,			//
	DHKEY_STATUS_ERROR			// ended with error
} DHKEY_STATUS;

/* chained list of Diffie-Hellmann keys for different purposes */
typedef struct DH_KEY {
	char *username;
	int purpose;
	int initiator; // who initiated the dh key exchange
	DHKEY_STATUS status;
	dhm_context dhm;
	aes_context aes_enc;
	aes_context aes_dec;
	struct DH_KEY *prev;
	struct DH_KEY *next;
	uint64_t fingerprint;
	uint8_t iv[16]; // for IV reusing
} DH_KEY;


int dh_key_matches(DH_KEY *key, const char *username, const int purpose);
DH_KEY *dh_key_list_get(DH_KEY *list, const char *username, int purpose);
int dh_key_list_add(DH_KEY **root, const char *username, int purpose,
		DH_KEY **item);
int dh_key_add_or_reuse(DH_KEY **root, const char *username, const int purpose,
		DH_KEY **key);
int dh_key_list_free(DH_KEY **root);

#endif /* DH_KEYS_H_ */
