/*
 * config.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#define VCRYPT_SERVER_DEFAULT_PORT 5566

typedef struct SERVER_SETTINGS {
	int listen_port;
	char *mysql_host;
	char *mysql_user;
	char *mysql_pass;
	char *mysql_db;

	char *priv_key_file;
	char *cert_file;
} SERVER_CONFIG;


void config_free(SERVER_CONFIG **conf);
const char *config_get_file(int argc, const char **argv);
SERVER_CONFIG * config_read(const char *file_name, int *err_line);

#endif /* CONFIG_H_ */
