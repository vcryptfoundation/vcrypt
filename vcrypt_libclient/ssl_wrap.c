/*
 * ssl_wrap.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include "ssl_wrap.h"
#include "common.h"

void log_polarssl_err(int ret, const char *func, int line)
{
	char err[100];
	error_strerror(ret, err, sizeof err);
	dolog(0, "ERROR: in %s at line %d returned %d (%s)\n", func, line, ret,
			err);
}

void ssl_requisites_free(ssl_prerequisites *req)
{
	rsa_free(&req->rsa);
	x509_free(&req->srvcert);
}

int ssl_requisites_init(ssl_prerequisites* req)
{
	int ret;
	memset(req, 0, sizeof *req);
	memset(&req->srvcert, 0, sizeof req->srvcert); // this is mandatory!

	rsa_init(&req->rsa, RSA_PKCS_V15, SIG_RSA_SHA384);
	entropy_init(&req->entropy);

	char* pers = "ssl_server";
	if ((ret = ctr_drbg_init(&req->ctr_drbg, entropy_func, &req->entropy,
			(const unsigned char*) pers, strlen(pers))) != 0) {
		printf("ERROR: Failed initializing random number generator: %d\n", ret);
		return ret;
	}

	return 0;
}

int ssl_load_keys(ssl_prerequisites *req, char *priv_key_fname, char *pass)
{
	int ret;

	if ((ret = ssl_requisites_init(req)) != 0)
		goto exit;

	ret = x509parse_keyfile(&req->rsa, priv_key_fname, pass);

	if (ret != 0) {
		printf("ERROR: Failed to load server keys from file %s: %d\n\n",
				priv_key_fname, ret);
		goto exit;
	}

	unsigned char fakecert[2048];
	ret = x509_encode_fake_cert(&req->rsa.N, &req->rsa.E, fakecert,
			sizeof(fakecert));

	if (ret <= 0) {
		printf("ERROR: failed to create fake certificate %d\n", ret);
		goto exit;
	}

	ret = x509parse_crt_der(&req->srvcert, fakecert, ret);
	if (ret != 0) {
		printf("ERROR: Failed to parse fake certificate returned: %d \n", ret);
		goto exit;
	}

	exit: //
	return ret;
}

#define DEBUG_LEVEL 0

void my_ssl_debug(void *ctx, int level, const char *str)
{
	if (level < DEBUG_LEVEL) {
		fprintf((FILE *) ctx, "%s", str);
		fflush((FILE *) ctx);
	}
}

