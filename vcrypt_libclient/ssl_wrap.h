/*
 * ssl_wrap.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef SSL_WRAP_H_
#define SSL_WRAP_H_

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"
#include "polarssl/ssl.h"
#include "polarssl/rsa.h"
#include "polarssl/net.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"
#include "config.h"

typedef struct ssl_prerequisites {
	rsa_context rsa;
	x509_cert srvcert;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
} ssl_prerequisites;

int ssl_requisites_init(ssl_prerequisites* req);
void ssl_requisites_free(ssl_prerequisites *req);
int ssl_load_keys(ssl_prerequisites *req, char *priv_key_fname, char *pass);
void my_ssl_debug(void *ctx, int level, const char *str);
void log_polarssl_err(int ret, const char *func, int line);

#endif /* SSL_WRAP_H_ */
