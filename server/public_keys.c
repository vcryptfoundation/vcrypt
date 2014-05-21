/*
 * public_keys.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include "workers.h"
#include "packets.h"
#include "database.h"
#include <assert.h>
#include <unistd.h>

int process_public_key_update(CLIENT *client, const VCRYPT_PACKET *packet)
{
	assert(packet->payload_len > 8 + 128);

	int res = db_insert("update users set public_key_fp=%l, public_key=%b "
			"where user_id=%d", //
			packet->payload, //
			packet->payload + 8, packet->payload_len - 8, //
			&client->user_id);

	VCRYPT_PACKET* clone = packet_clone_header(packet);
	clone->type = res ? RESP_ERR_TEMPORARY : RESP_OK;
	clone->payload_len = 0;
	int retval = packet_send_client(client, clone);
	packet_free(clone);
	return retval;
}

int process_get_public_key(CLIENT *client, const VCRYPT_PACKET *packet)
{
	MYSQL_RES *res = db_select("select public_key from users where username=%s",
			packet->username);

	VCRYPT_PACKET *ret_packet;

	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		unsigned long *lengths = mysql_fetch_lengths(res);

		if (row) {
			if (row[0]) {
				ret_packet = packet_new(DEST_SERVER, NULL, RESP_OK, lengths[0]);
				memcpy(ret_packet->payload, row[0], lengths[0]);
			} else {
				ret_packet = packet_new(DEST_SERVER, NULL, RESP_PUBLIC_KEY_NONE,
						0);
			}
		} else {
			ret_packet = packet_new(DEST_SERVER, NULL, RESP_ERR_NOSUCHUSER, 0);
		}
	} else {
		ret_packet = packet_new(DEST_SERVER, NULL, RESP_ERR_TEMPORARY, 0);
	}

	ret_packet->queue_id = packet->queue_id;
	int retval = packet_send_client(client, ret_packet);
	packet_free(ret_packet);
	return retval;
}

