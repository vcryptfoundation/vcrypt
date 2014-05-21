/*
 * config.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include <assert.h>

#define MAX_FNAME 512
static char fname[MAX_FNAME] = {0};

void config_free(SERVER_CONFIG **conf)
{
	if (*conf == NULL )
		return;

	if ((*conf)->mysql_host)
		free((*conf)->mysql_host);
	if ((*conf)->mysql_db)

		free((*conf)->mysql_db);

	if ((*conf)->mysql_user)
		free((*conf)->mysql_user);

	if ((*conf)->mysql_pass)
		free((*conf)->mysql_pass);

	if ((*conf)->cert_file)
		free((*conf)->cert_file);

	if ((*conf)->priv_key_file)
		free((*conf)->priv_key_file);

	free(*conf);
	*conf = NULL;
}

const char *config_get_file(int argc, const char **argv)
{
	fname[0] = 0;

	// will search this file in the directory where exe resides
	char def_fname[] = "server.conf";

	if (argc == 2)
		return argv[1];

	char *dir1 = strdup(*argv);
	assert(dir1);

	char *dir = dirname(dir1);

	// the full name is composed of dirname + / + def_fname +  '\0'
	int fname_len = strlen(dir) + sizeof(def_fname) + sizeof(char) * 2;

	if (fname_len >= MAX_FNAME) {
		free(dir1);
		return NULL ;
	}

	strcpy(fname, dir);
	strcat(fname, "/");
	strcat(fname, def_fname);

	free(dir1);

	return fname;
}

int count_non_blanks(const char *str)
{
	int ret = 0;

	while (*str) {
		if (!isblank(*str++))
			ret++;
	}

	return ret;
}

/* returns - on success */
int process_string_param(char **dest, const char* key, const char* value,
		int curline)
{
	if (*dest) {
		fprintf(stderr, "ERROR: Duplicate param '%s' on line %d\n", key,
				curline);
	}

	*dest = strdup(value);
	return 0;
}

#define CONF_RET {if (err_line) *err_line=curline; goto ret;}
SERVER_CONFIG * config_read(const char *file_name, int *err_line)
{
	char *key = NULL;
	int curline = -1;

	if (err_line)
		*err_line = -1;

	SERVER_CONFIG *conf = calloc(1, sizeof(SERVER_CONFIG));
	if (conf == NULL )
		return NULL ;

	FILE *f = fopen(file_name, "r");
	if (f == NULL )
		CONF_RET;

	char line[512];
	curline = 0;

	while (!feof(f)) {
		if (fgets(line, 512, f) == NULL )
			break;

		curline++;

		// terminate string where \n is
		char *srcres;
		if ((srcres = strchr(line, '\n')))
			*srcres = 0;

		// terminate string where comment begins
		if ((srcres = strchr(line, '#')))
			*srcres = 0;

		if (isblank(line[0]))
			CONF_RET;

		// check if the line contains only spaces
		int chars = count_non_blanks(line);
		if (chars == 0)
			continue;

		if (chars < 3)
			CONF_RET;

		char *value = strchr(line, '=');
		if (value == NULL )
			CONF_RET;

		// save a copy to retrieve the key later
		key = strdup(line);

		if (strlen(value) > 1) {
			value++; // pass the '=' sign

			// skip all blank chars from left
			while (isblank(*value))
				value++;

			// trim right
			if ((srcres = strchr(value, ' ')))
				*srcres = 0;
		} else {
			// value is empty
			*value = 0;
		}

		// this should not fail as we already checked
		srcres = strchr(key, '=');
		*srcres = 0;

		// find the first space and terminate it there
		if ((srcres = strchr(key, ' ')))
			*srcres = 0;

		//printf("%d: key: '%s', value: '%s'\n", curline, key, value);

		if (strcmp(key, "mysql_host") == 0) {
			if (process_string_param(&conf->mysql_host, key, value, curline))
				CONF_RET;
		} else if (strcmp(key, "mysql_user") == 0) {
			if (process_string_param(&conf->mysql_user, key, value, curline))
				CONF_RET;
		} else if (strcmp(key, "mysql_pass") == 0) {
			if (process_string_param(&conf->mysql_pass, key, value, curline))
				CONF_RET;
		} else if (strcmp(key, "mysql_db") == 0) {
			if (process_string_param(&conf->mysql_db, key, value, curline))
				CONF_RET;
		} else if (strcmp(key, "listen_port") == 0) {
			if (conf->listen_port != 0) {
				fprintf(stderr, "ERROR: Duplicate param '%s' on line %d\n", key,
						curline);
				CONF_RET;
			}

			conf->listen_port = atoi(value);

			if (conf->listen_port == 0) {
				fprintf(stderr,
						"ERROR: Wrong value for param '%s' on line %d\n", key,
						curline);
				CONF_RET;
			}
		} else if (strcmp(key, "private_key") == 0) {
			if (process_string_param(&conf->priv_key_file, key, value, curline))
				CONF_RET;
		} else if (strcmp(key, "certificate") == 0) {
			if (process_string_param(&conf->cert_file, key, value, curline))
				CONF_RET;
		} else {
			fprintf(stderr, "ERROR: Unknown param '%s' on line %d\n", key,
					curline);
			CONF_RET;
		}

		free(key);
		key = NULL;
	}

	fclose(f);

	if (conf->listen_port == 0)
		conf->listen_port = VCRYPT_SERVER_DEFAULT_PORT;

	// if we're here it means we got no error
	if (err_line)
		*err_line = 0;

	return conf;

	ret: // we got an error
	if (err_line)
		*err_line = curline;

	config_free(&conf);

	if (key)
		free(key);

	if (f)
		fclose(f);

	return NULL ;
}

