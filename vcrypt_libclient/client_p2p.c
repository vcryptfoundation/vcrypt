/*
 * client_p2p.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "config.h"

#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_WINDOWS_H
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#endif

#include "client.h"
#include "client_p2p.h"
#include "profiler.h"

int p2p_socket_setup(VCRYPT_CTX *ctx, int *p2p_listen_port)
{
	struct sockaddr_in si_me;
	int temp_socket;

	if (ctx->socket_p2p != -1)
		return -ERR_P2P_SOCKET_EXISTS;

	if ((temp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		//dolog(0, " no socket\n");
		return -ERR_P2P_SOCKET;
	}

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = 0;
	si_me.sin_addr.s_addr = htonl(INADDR_ANY );
	if (bind(temp_socket, (struct sockaddr *) &si_me, sizeof(si_me)) == -1) {
		//dolog(0, " no bind\n");
		return -ERR_P2P_SOCKET;
	}

	socklen_t len = sizeof(si_me);
	getsockname(temp_socket, (struct sockaddr *) &si_me, &len);

	*p2p_listen_port = ntohs(si_me.sin_port);
	ctx->socket_p2p = temp_socket;

	return -ERR_SUCCESS;
}

int p2p_close(VCRYPT_CTX *ctx)
{
	if (ctx->socket_p2p != -1) {
		net_close(ctx->socket_p2p);
		ctx->socket_p2p = -1;
	}

	return 0;
}

int packet_matches_callctx(VCRYPT_CTX *ctx, struct sockaddr_in *addr)
{
	if (ctx->call_ctx.p2p_info.sin_addr.s_addr != addr->sin_addr.s_addr)
		return 0;

	if (ctx->call_ctx.p2p_info.sin_port != addr->sin_port)
		return 0;

	return 1;
}

void client_close_call(VCRYPT_CTX* ctx)
{
	ctx->call_ctx.status = CALL_STATUS_NONE;
}

int client_setup_p2p_info(VCRYPT_CTX *ctx, PAYLOAD_P2PINFO *info)
{
	memset(&ctx->call_ctx.p2p_info, 0, sizeof(ctx->call_ctx.p2p_info));

	ctx->call_ctx.p2p_info.sin_family = AF_INET;
	ctx->call_ctx.p2p_info.sin_addr.s_addr = info->p2p_addr;
	ctx->call_ctx.p2p_info.sin_port = htons(info->p2p_port);

	return 0;
}

void client_print_p2p_info(VCRYPT_CTX *ctx)
{
	dolog(0, "call p2p info: %s:%d\n",
			inet_ntoa(ctx->call_ctx.p2p_info.sin_addr),
			ntohs(ctx->call_ctx.p2p_info.sin_port));
}
