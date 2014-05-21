/*
 * connect.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CONNECT_H_
#define CONNECT_H_

int server_connect(VCRYPT_CTX *ctx, char *address, int port);
int server_auth(VCRYPT_CTX *ctx, char *username, char *password);
int server_disconnect(VCRYPT_CTX *ctx);

#endif /* CONNECT_H_ */
