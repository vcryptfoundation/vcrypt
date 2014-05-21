/*
 * contacts.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CONTACTS_H_
#define CONTACTS_H_


#include <stdint.h>
#include "workers.h"

typedef enum CLIENT_STATUS {
	STATUS_OFFLINE,
	STATUS_ONLINE
} CLIENT_STATUS;

int contact_add(long user_id, char *username);
int contact_del(long user_id, char *username);
long contact_get_id(char* username);
int contacts_send_status_notify(long user_id, char *username, CLIENT_STATUS status);
VCRYPT_PACKET* contacts_make_packet(CLIENT* client, long user_id, uint64_t pk_fp);


#endif /* CONTACTS_H_ */
