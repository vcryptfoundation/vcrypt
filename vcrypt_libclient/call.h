/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#ifndef CALL_H_
#define CALL_H_

int vcrypt_call_process(VCRYPT_CTX *ctx, int have_data);
int vcrypt_setup_received_call(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet);
int vcrypt_setup_answered_call(VCRYPT_CTX *ctx, const char *username,
		VCRYPT_PACKET *packet);
int vcrypt_call_end(VCRYPT_CTX *ctx, const char *username, int reason);

#ifdef __cplusplus
extern "C" {
#endif

void vcrypt_call(VCRYPT_CTX *ctx, const char *callee_username);
int vcrypt_call_hangup(VCRYPT_CTX *ctx, const char *username);
int vcrypt_call_accept(VCRYPT_CTX *ctx, const char *username, int reject);

#ifdef __cplusplus
}
#endif


#endif /* CALL_H_ */
