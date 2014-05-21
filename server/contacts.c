/*
 * contacts.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "packets.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "workers.h"
#include "contacts.h"
#include "database.h"

/* returns -1 for db errors, -2 for no such user, or the user id */
long contact_get_id(char* username)
{
	MYSQL_RES* res = db_select("select user_id from users where username=%s",
			username);

	if (res == NULL ) {
		db_print_error();
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	if (row == NULL ) {
		mysql_free_result(res);
		return -2;
	}

	long contact_id = atol(row[0]);
	mysql_free_result(res);

	return contact_id;
}

int contact_add(long user_id, char *username)
{
	long contact_id = contact_get_id(username);
	if (contact_id == -1)
		return RESP_ERR_TEMPORARY;

	if (contact_id == -2)
		return RESP_ERR_NOSUCHUSER;

	if (user_id == contact_id)
		return RESP_ERR_MYSELF;

	if (db_insert("insert into contacts (user_id, contact_id) VALUES(%d, %d)",
			&user_id, &contact_id)) {
		if (db_get_errorno() == 1062)
			return RESP_ERR_DUPLICATE;
		else
			return RESP_ERR_TEMPORARY;
	}

	return RESP_OK;
}

int contact_del(long user_id, char *username)
{
	long contact_id = contact_get_id(username);

	if (contact_id == -1)
		return RESP_ERR_TEMPORARY;

	if (db_insert("delete from contacts where user_id=%d and contact_id=%d",
			&user_id, &contact_id))
		return RESP_ERR_TEMPORARY;

	return RESP_OK;
}

int make_contact_entry(char *dest, int dest_size, char* contact,
		CLIENT_STATUS status)
{
	assert(strlen(contact) + 2 <= dest_size - strlen(dest));

	strcat(dest, status ? "1" : "0");
	strcat(dest, contact);
	strcat(dest, "\n");

	return 0;
}

/* this also returns public key fingerprint */
VCRYPT_PACKET* contacts_make_packet(CLIENT* client, long user_id,
		uint64_t pk_fp)
{
	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, "",
			RESP_REGISTER_OK_CONTACTS, 1 + 8);

	packet->payload_len = 9;
	packet->payload[0] = 0;
	packet->type = RESP_REGISTER_OK_CONTACTS;

	memcpy(packet->payload, &pk_fp, 8);

	MYSQL_RES* res = db_select("select contact_id, username from contacts "
			"join users on (contacts.contact_id=users.user_id) "
			"where contacts.user_id=%d", &user_id);

	if (res == NULL ) {
		db_print_error();
		return NULL ;
	}

	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		char *contact = row[1];
		long row_user_id = atol(row[0]);

		packet->payload_len += (strlen(contact) + 2); // 2 - status byte and delimiter byte

		packet = packet_resize(packet, packet->payload_len);

		make_contact_entry(packet->payload + 8, packet->payload_len, contact,
				client_status(row_user_id));
	}

	if (packet->payload_len == 1)
		packet->payload_len = 0;

	mysql_free_result(res);

	return packet;
}

int contacts_send_status_notify(long user_id, char *username,
		CLIENT_STATUS status)
{

	// find all user ID's that have this contact in their contact list
	MYSQL_RES* res = db_select(
			"select user_id from contacts where contact_id=%d", &user_id);

	if (res == NULL ) {
		db_print_error();
		return -1;
	}

	// prepare the packet
	int plen = strlen(username) + 3; // status, username, delimiter, null
	VCRYPT_PACKET *packet = packet_new(DEST_SERVER, "",
			REQ_CONTACT_STATUS_CHANGE, plen);
	assert(packet);

	make_contact_entry(packet->payload, plen, username, status);

	MYSQL_ROW row;
	while ((row = mysql_fetch_row(res))) {
		long row_user_id = atol(row[0]);

		CLIENT* client = find_client_by_id(row_user_id);

		if (client == NULL )
			continue;

		if (!client_is_authenticated(client))
			continue;

		printf("announcing user %ld that %ld (%s) logged in\n", row_user_id,
				user_id, username);

		packet_send_client(client, packet);
	}

	packet_free(packet);

	mysql_free_result(res);
	return 0;
}

