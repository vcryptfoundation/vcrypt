/*
 * client_p2p.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CLIENT_P2P_H_
#define CLIENT_P2P_H_

#include "client.h"
#if HAS_WINDOWS_H
#include <windows.h>
#include <stddef.h>
//#include <malloc.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum P2P_PACKET_TYPE
{
	P2P_CALL_AUDIO
};

#pragma pack(push)
#pragma pack(1)

typedef struct P2P_PACKET
{
	uint8_t type;
	PACKET_NR packet_nr;
	uint8_t payload[1];
} P2P_PACKET;

#define P2P_HEAD offsetof(P2P_PACKET, payload)

#pragma pack(pop)

int p2p_socket_setup(VCRYPT_CTX *ctx, int *p2p_listen_port);
int p2p_close(VCRYPT_CTX *ctx);
void client_close_call(VCRYPT_CTX* ctx);
int packet_matches_callctx(VCRYPT_CTX *ctx, struct sockaddr_in *addr);
int client_setup_p2p_info(VCRYPT_CTX *ctx, PAYLOAD_P2PINFO *info);
int client_send_p2p_command(VCRYPT_CTX* ctx, enum P2P_PACKET_TYPE type);
int client_send_audio_to_socket(VCRYPT_CTX* ctx);
int client_receive_audio_from_socket(VCRYPT_CTX *ctx, char *buffer, int size);
void client_print_p2p_info(VCRYPT_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_P2P_H_ */
