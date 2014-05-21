/*
 * offline_events.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef OFFLINE_EVENTS_H_
#define OFFLINE_EVENTS_H_
#include "workers.h"

int offline_message_store(long src_contact_id, long dst_contact_id,
		long message_id, char *data, int size);
int offline_messages_send(CLIENT *client);
int offline_message_delete(long dst_contact_id, long message_id);
#endif /* OFFLINE_EVENTS_H_ */
