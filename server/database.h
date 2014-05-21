/*
 * database.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef DATABASE_H_
#define DATABASE_H_

#include <mysql/mysql.h>

int db_shutdown();
int db_connect(const char *host, const char* user, const char *passw,
		const char *db);
const char* db_get_error();
void db_print_error();
MYSQL_RES* db_select(char *query, ...);
int db_insert(char *query, ...);
int db_get_errorno();
void mysql_idle_prevent();

#endif /* DATABASE_H_ */
