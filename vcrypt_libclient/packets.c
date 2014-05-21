/*
 * packets.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <malloc.h>

#if WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "packets.h"
#include "enum_defs.h"

#undef ENUM_BEGIN
#undef ENUM
#undef ENUM_END
#define ENUM_BEGIN(typ) const char * typ ## _name_table [] = {
#define ENUM(nam) #nam
#define ENUM_END(typ) };
#include "packet_types.h"
#include <assert.h>
#include <pthread.h>
#include "polarssl/net.h"
#include "common.h"

/* this returns a new packet with the specified params */
VCRYPT_PACKET * packet_new(uint8_t dest, const char *callee_username,
		uint8_t type, size_t payload_size)
{
	VCRYPT_PACKET *packet = calloc(1, PACKET_HEAD_SIZE + payload_size);

	if (packet == NULL ) {
		return NULL ;
	}

	packet->type = type;
	packet->dest = dest;
	packet->queue_id = 0;
	packet->payload_len = (uint32_t) payload_size;

	packet->username[0] = 0;
	if (callee_username) {
		strncpy_ex(packet->username, callee_username, MAX_USERNAME_L);
	}

	return packet;
}

VCRYPT_PACKET* packet_resize(VCRYPT_PACKET *packet, size_t payload_size)
{
	return realloc(packet, PACKET_HEAD_SIZE + payload_size);
}

VCRYPT_PACKET* packet_clone_header(const VCRYPT_PACKET *packet)
{
	VCRYPT_PACKET *clone = malloc(PACKET_HEAD_SIZE );
	if (clone == NULL ) {
		return NULL ;
	}

	memcpy(clone, packet, PACKET_HEAD_SIZE );
	clone->payload_len = 0;
	return clone;
}

VCRYPT_PACKET* packet_clone(const VCRYPT_PACKET *packet)
{
	VCRYPT_PACKET *clone = malloc(PACKET_HEAD_SIZE + packet->payload_len);
	if (clone == NULL ) {
		return NULL ;
	}

	memcpy(clone, packet, PACKET_HEAD_SIZE + packet->payload_len);
	return clone;
}

int packet_send(ssl_context *ssl, const VCRYPT_PACKET *packet)
{
	size_t dataLength = PACKET_HEAD_SIZE + packet->payload_len;

	int n;
	while (1) {
		n = ssl_write(ssl, (unsigned char*) packet, dataLength);

		if (n == POLARSSL_ERR_NET_WANT_WRITE)
			continue;

		break;
	}

	return (n == (int) dataLength) ? 0 : -1;
}

void packet_free(VCRYPT_PACKET *packet)
{
	free(packet);
}

const char* packet_type_str(int type)
{
	return PacketTypes_name_table[type];
}

// TODO: may be optimize this
int packet_is_response(int type)
{
	return PacketTypes_name_table[type][2] == 'S';
}

const char* packet_dump(const VCRYPT_PACKET *packet)
{
	static char buffer[200];

	if (packet == NULL ) {
		return "empty packet (null)";
	}

	snprintf(buffer, 200,
			"type:%d(%s) dest: %s (%d), length:%d, queue_id:%d, username: '%s'",
			packet->type, PacketTypes_name_table[packet->type],
			packet->dest == DEST_SERVER ? "SERVER" : "CLIENT", packet->dest,
			packet->payload_len, packet->queue_id, packet->username);

	buffer[199] = 0;
	return buffer;
}
