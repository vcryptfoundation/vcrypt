/*
 * public_keys.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef PUBLIC_KEYS_H_
#define PUBLIC_KEYS_H_

int process_public_key_update(CLIENT *client, const VCRYPT_PACKET *packet);
int process_get_public_key(CLIENT *client, const VCRYPT_PACKET *packet);

#endif /* PUBLIC_KEYS_H_ */
