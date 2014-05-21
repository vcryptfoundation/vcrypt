/*
 * offline_events.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include "offline_events.h"
#include "database.h"
#include "workers.h"
#include <stdlib.h>

int offline_message_store(long src_contact_id, long dst_contact_id,
		long message_id, char *data, int size)
{
	return db_insert(
			"insert into stored_events (src_contact_id, dst_contact_id, type, data, data_id)"
					"VALUES(%l, %l, 'message', %b, %l)", &src_contact_id,
			&dst_contact_id, data, size, &message_id);
}

int offline_message_delete(long dst_contact_id, long message_id)
{
	return db_insert(
			"delete from  stored_events where dst_contact_id=%l and data_id=%l",
			&dst_contact_id, &message_id);
}

int offline_messages_send(CLIENT *client)
{
	MYSQL_RES *res =
			db_select(
					"select username, data, data_id, event_id from stored_events "
							"join users on (users.user_id=stored_events.src_contact_id) "
							"where dst_contact_id=%l and event_id > %l ORDER BY event_id ASC LIMIT 2",
					&client->user_id, &client->last_stored_event);

	if (!res)
		return -1;

	MYSQL_ROW row;
	VCRYPT_PACKET *packet;

	int sent = 0;
	while ((row = mysql_fetch_row(res))) {
		unsigned long *lengths = mysql_fetch_lengths(res);

		packet = packet_new(DEST_SERVER, row[0], REQ_MESSAGE_OFFLINE,
				lengths[1]);
		assert(packet);

		memcpy(packet->payload, row[1], lengths[1]);
		packet->queue_id = atol(row[2]);

		int ret = packet_send_client(client, packet);
		packet_free(packet);

		if (ret) {
			mysql_free_result(res);
			return -2;
		}

		client->last_stored_event = atol(row[3]);
		sent++;
	}

	mysql_free_result(res);

	return sent;
}

