/*
 * packets.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef PACKETS_H_
#define PACKETS_H_

#include <stdint.h>
#include <malloc.h> // needed for ofsetof macros
#define MAX_USERNAME_L	64

#include "enum_defs.h"
#include "polarssl/ssl.h"

enum PACKET_DEST {
	DEST_SERVER, DEST_CLIENT
};

enum VCRYPT_PACKET_DIRECTION {
	DIR_INBOUND, DIR_OUTBOUND
};

typedef uint32_t PACKET_NR;

#pragma pack(push)
#pragma pack(1)

/* structures which are sent over network */

// this is for communicating with the server
typedef struct VCRYPT_PACKET {
	uint8_t type;
	uint8_t dest; // this serves as a source too
	uint8_t no_srv_ack;
	uint32_t payload_len;
	int32_t queue_id;
	/* this username filed will contain, either sender or receiver username
	 * when the sender sends the message this field contains the receiving username,
	 * when server forwards the message - it replaces this with the sender username
	 * this is done for protection from impersonation
	 *
	 * username field usually carries the receiver of the message, but may also be used for retrieveing
	 * info from server about a specific username (like retrieving the public key)
	 * */
	char username[MAX_USERNAME_L];
	char payload[1];
} VCRYPT_PACKET;

#define PACKET_HEAD_SIZE offsetof(VCRYPT_PACKET, payload)

typedef struct PAYLOAD_AUTH {
	uint32_t version;
	char username[MAX_USERNAME_L];
	char password[MAX_USERNAME_L];
/* p2p address is taken from the connection */
} PAYLOAD_AUTH;

typedef struct PAYLOAD_P2PINFO {
	uint32_t p2p_addr;
	uint16_t p2p_port;
} PAYLOAD_P2PINFO;

#pragma pack(pop)


#ifdef __cplusplus
extern "C" {
#endif

VCRYPT_PACKET * packet_new(uint8_t dest, const char *callee_username, uint8_t type,
		size_t payload_size);
int packet_send(ssl_context *ssl, const VCRYPT_PACKET *packet);

void packet_free(VCRYPT_PACKET *packet);
const char* packet_dump(const VCRYPT_PACKET *packet);
const char* packet_type_str(int type);
int packet_is_response(int type);
VCRYPT_PACKET* packet_resize(VCRYPT_PACKET *packet, size_t payload_size);
VCRYPT_PACKET* packet_clone(const VCRYPT_PACKET *packet);
VCRYPT_PACKET* packet_clone_header(const VCRYPT_PACKET *packet);

#ifdef __cplusplus
}
#endif

#endif /* PACKETS_H_ */
