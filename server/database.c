/*
 * database.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include <string.h>
#include <pthread.h>
#include "database.h"
#include <assert.h>
#include <math.h>
#include <inttypes.h>

#include "common.h"

/* this server will have only one DB connection, it will be held here */
MYSQL *conn = NULL;
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

// for preventing server going away
#define MYSQL_IDLE_TIMEOUT 600
uint64_t mysql_last_time = 0;

static int db_lock()
{
	int ret = pthread_mutex_lock(&db_mutex);
	assert(ret == 0);
	return ret;
}

static int db_unlock()
{
	int ret = pthread_mutex_unlock(&db_mutex);
	assert(ret == 0);
	return ret;
}

/* returns 0 on success */
int db_connect(const char *host, const char* user, const char *passw,
		const char *db)
{
	mysql_last_time = time_get_ms();
	conn = mysql_init(NULL);
	return mysql_real_connect(conn, host, user, passw, db, 0, NULL, 0) == NULL;
}

int db_shutdown()
{
	if (conn == NULL)
		return 0;

	mysql_close(conn);
	mysql_library_end();
	conn = NULL;
	return 0;
}

/*
 * accepted palceholders in query:
 * %d - for 32bit numbers
 * %l - for 64bit numbers
 * %s - for strings (escaped like 'string value')
 * %b - for binary data, which requires next arg to be the lenght of the data
 *
 */
int db_query_raw(char *query, va_list arglist)
{
	char *token;
	char *escaped = NULL;
	int escaped_size = 0;
	int res = -1;

	char string[35]; // there are no bigger numbers
	int arglen;
	long escaped_arg_len;

	// assure mutex is locked
	assert(pthread_mutex_trylock(&db_mutex) != 0);

	// find and replace placeholders
	char *src = strdup(query);
	int first = 1;
	while (1) {
		if (first)
			token = strtok(src, "%");
		else
			token = strtok(NULL, "%");

		if (token == NULL)
			break;

		if (first) {
			// we have no param here, we just copy
			escaped_size = strlen(token) + 1;
			escaped = malloc(escaped_size);
			// we just copy the first part
			strcpy(escaped, token);
		} else {
			char *escaped_arg;

			// the first char is the param type
			switch (*token)
			{
			case 's': {
				char *arg_string = va_arg(arglist, char*);
				if (arg_string != NULL) {
					arglen = strlen(arg_string);
					escaped_arg = malloc(arglen * 2 + 1); // worst case when all chars are escaped
					escaped_arg_len = mysql_real_escape_string(conn,
							escaped_arg, arg_string, arglen);
				} else {
					escaped_arg = strdup("NULL");
					escaped_arg_len = strlen(escaped_arg);
				}

				escaped_size += (escaped_arg_len + strlen(token) - 1);
				if (arg_string)
					escaped_size += 2; // 2 - for the 2 quotes

				escaped = realloc(escaped, escaped_size);

				if (arg_string)
					strcat(escaped, "'");

				strcat(escaped, escaped_arg);

				if (arg_string)
					strcat(escaped, "'");

				// copy the rest of the token
				strcat(escaped, token + 1);

				free(escaped_arg);
			}
				break;
			case 'b': {
				char *arg_bin = va_arg(arglist, char*);
				arglen = va_arg(arglist, int);

				if (arg_bin != NULL) {
					escaped_arg = malloc(arglen * 2 + 1); // worst case when all bytes are escaped
					escaped_arg_len = mysql_real_escape_string(conn,
							escaped_arg, arg_bin, arglen);
				} else {
					escaped_arg = strdup("NULL"); // so we don't segfault on free() later
					escaped_arg_len = strlen(escaped_arg);
				}

				escaped_size += (escaped_arg_len + strlen(token) - 1);
				if (arg_bin)
					escaped_size += 2; // 2 - for the 2 quotes

				escaped = realloc(escaped, escaped_size);
				assert(escaped);

				if (arg_bin)
					strcat(escaped, "'");

				strcat(escaped, escaped_arg);

				if (arg_bin)
					strcat(escaped, "'");

				// copy the rest of the token
				strcat(escaped, token + 1);

				free(escaped_arg);
			}
				break;

			case 'L': { // array of int64
				int64_t *arg_int64 = va_arg(arglist, int64_t*);
				arglen = va_arg(arglist, int);

				if (arg_int64 != NULL && arglen > 0) {
					escaped_size++;
					escaped = realloc(escaped, escaped_size);
					strcat(escaped, "(");

					char temp[22]; // a 64bit number will fit there plus trailing null char and eventual minus sign
					int i, numlen;
					for (i = 0; i < arglen; i++) {
						numlen = snprintf(temp, sizeof temp, "%" PRId64,
								arg_int64[i]);
						temp[sizeof temp - 1] = 0;

						assert(numlen > 0 && numlen < sizeof temp);

						escaped_size += (numlen + (i ? 1 : 0)); // plus comma
						escaped = realloc(escaped, escaped_size);

						if (i != 0)
							strcat(escaped, ",");
						strcat(escaped, temp);
					}

					escaped_size++;
					escaped = realloc(escaped, escaped_size);
					strcat(escaped, ")");
				} else {
					assert(
							"ERROR: bad params, NULL argument not allowed here"
									&& 0);
				}

				// copy the rest of the token
				escaped_size += (strlen(token) - 1);
				escaped = realloc(escaped, escaped_size);
				strcat(escaped, token + 1);
			}
				break;

			case 'd': {
				int32_t *arg_int = va_arg(arglist, int32_t*);

				if (arg_int) {
					snprintf(string, sizeof(string), "%d", *arg_int); // TODO: not crossplatform
					string[sizeof(string) - 1] = 0;

					arglen = strlen(string);
					escaped_arg = malloc(arglen * 2 + 1); // worst case when all chars are escaped
					escaped_arg_len = mysql_real_escape_string(conn,
							escaped_arg, string, arglen);
				} else {
					escaped_arg = strdup("NULL");
					escaped_arg_len = strlen(escaped_arg);
				}

				escaped_size += (escaped_arg_len + strlen(token) - 1);
				escaped = realloc(escaped, escaped_size);

				strcat(escaped, escaped_arg);

				// copy the rest of the token
				strcat(escaped, token + 1);

				free(escaped_arg);
			}
				break;
			case 'l': {
				int64_t *arg_int64 = va_arg(arglist, int64_t*);

				if (arg_int64) {
					snprintf(string, sizeof(string), "%" PRId64, *arg_int64); // TODO: not crossplatform
					string[sizeof(string) - 1] = 0;

					arglen = strlen(string);
					escaped_arg = malloc(arglen * 2 + 1); // worst case when all chars are escaped
					escaped_arg_len = mysql_real_escape_string(conn,
							escaped_arg, string, arglen);
				} else {
					escaped_arg = strdup("NULL");
					escaped_arg_len = strlen(escaped_arg);
				}

				escaped_size += (escaped_arg_len + strlen(token) - 1);
				escaped = realloc(escaped, escaped_size);
				assert(escaped);

				strcat(escaped, escaped_arg);

				// copy the rest of the token
				strcat(escaped, token + 1);

				free(escaped_arg);
			}
				break;

			default:
				fprintf(stderr,
						"ERROR:DB: Wrong placeholder '%%%c' in query '%s'\n",
						*token, query);
				exit(1);
			}
		}

		first = 0;
	}

//	printf("DB DEBUG: %ld - %d\n%s\n", strlen(escaped) + 1, escaped_size,
//			escaped);
	assert(strlen(escaped) + 1 == escaped_size);

	res = mysql_query(conn, escaped);

	if (res) {
//		printf("ERROR in query query: %s %d:%s\n", escaped, mysql_errno(conn),
//				mysql_error(conn));
		printf("ERROR in query query: %d:%s\n", mysql_errno(conn),
				mysql_error(conn));
		goto cleanup;
	} else {
		// track only successful queries
		mysql_last_time = time_get_ms();
	}

	cleanup: //
	if (src)
		free(src);
	if (escaped)
		free(escaped);

	return res;
}
/*
 * used for insert and update queries
 * returns 0 for success
 */
int db_insert(char *query, ...)
{
	va_list arglist;
	va_start(arglist, query);

	db_lock();

	int res = db_query_raw(query, arglist);
	va_end(arglist);

	db_unlock();

	return res;
}

/*
 * used for SELECT queries
 */
MYSQL_RES* db_select(char *query, ...)
{
	va_list arglist;
	va_start(arglist, query);

	db_lock();

	if (db_query_raw(query, arglist)) {
		va_end(arglist);
		db_unlock();
		return NULL;
	}

	va_end(arglist);

	MYSQL_RES* ret = mysql_store_result(conn);
	db_unlock();

	return ret;
}

void mysql_idle_prevent()
{
	if (time_passed_ms(mysql_last_time) < MYSQL_IDLE_TIMEOUT)
		return;

	db_select("select now()");
}

MYSQL *db_connection()
{
	return conn;
}

const char* db_get_error()
{
	return mysql_error(conn);
}

int db_get_errorno()
{
	return mysql_errno(conn);
}

void db_print_error()
{
	fprintf(stderr, "MYSQL_ERROR: %s\n", db_get_error());
}
