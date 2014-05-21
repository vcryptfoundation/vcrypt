/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include "workers.h"
#include "config.h"
#include "database.h"
#include "ssl_wrap.h"
#include <termios.h>
#include "auth.h"

/* these are loaded at config and don't change during run time */
SERVER_CONFIG *config;
static int signal_shutdown = 0;

void signal_handler(int s)
{
	if (s != 2) {
		printf("got signal %d, dont know how to process it!\n", s);
		exit(2);
	}

	if (signal_shutdown == 0) {
		fprintf(stderr,
				"\nGot SIGINT, exiting cleanly (send SIGING one more time to force shutdown)\n");
		signal_shutdown = 1;
	} else {
		fprintf(stderr, "\nGot SIGINT twice, forcing shutdown)\n");
		exit(1);
	}
}

int install_signal_handlers()
{
	struct sigaction sig_int_handler;

	sig_int_handler.sa_handler = signal_handler;
	sigemptyset(&sig_int_handler.sa_mask);
	sig_int_handler.sa_flags = 0;

	sigaction(SIGINT, &sig_int_handler, NULL );

	return 0;
}

int accept_connetions()
{
	int ret;
	int listen_fd = 0;

	ssl_prerequisites *ssl_req = server_get_ssl_req();

	if ((ret = net_bind(&listen_fd, NULL, config->listen_port)) != 0)
		goto exit;

	if ((ret = net_set_block(listen_fd)) != 0)
		goto exit;

	if ((ret = ssl_requisites_init(ssl_req)) != 0)
		goto exit;

	if ((ret = ssl_load_keys(ssl_req, config->priv_key_file, NULL )) != 0)
		goto exit;

	struct pollfd fd;
	memset(&fd, 0, sizeof(fd));

	// this is for accepting connections
	fd.fd = listen_fd;
	fd.events = POLLIN;

	while (signal_shutdown == 0) {
		int events = poll(&fd, 1, 1000);

		if (events == 0) {
			// stuff TODO here
			// check for connected but not authenticated clients
			// check for stalled clients

			mysql_idle_prevent();
			continue;
		}

		if (fd.revents & POLLIN) {
			CLIENT_CONNDATA conndata;
			memset(&conndata, 0, sizeof(conndata));
			int sin_size = sizeof(struct sockaddr_in);

			int client_fd = accept(listen_fd,
					(struct sockaddr*) &conndata.cl_addr,
					(socklen_t*) &sin_size);

			printf("Connection from: %s:%d\n",
					inet_ntoa(conndata.cl_addr.sin_addr),
					ntohs(conndata.cl_addr.sin_port));

			int *cl_idx = malloc(sizeof(int));
			*cl_idx = client_find_free();

			if (*cl_idx >= 0 && client_alloc(*cl_idx)) {
				CLIENT* cl_new = get_clients()[*cl_idx];
				cl_new->conndata = conndata;
				cl_new->socket = client_fd;

				pthread_t thread_handle;

				// thread will free cl_idx
				pthread_create(&thread_handle, NULL, server_client_thread,
						(void*) cl_idx);
				pthread_detach(thread_handle);
			} else {
				// refuse connection
				free(cl_idx);
				close(client_fd);
				printf("connection refused, can't allocate new client\n");
			}

			fd.revents = 0;
		}
	}

	printf("Signaling all threads to exit ...\n");

	int i;
	// signal all threads to exit
	for (i = 0; i < MAX_CLIENTS; i++)
		client_signal_exit(i);

	printf("Waiting for threads to terminate ...\n");

	// wait for clients to exit
	time_t start = time(NULL );
	int running;
	while (time(NULL ) - start < 5) {
		running = MAX_CLIENTS - calculate_clients_free();

		if (running) {
			printf("Still %d running threads\n", running);
			usleep(100000);
		} else {
			break;
		}
	}

	if (running) {
		printf("Timeout reached, exiting anyway\n");
	} else {
		printf("Exiting cleanly\n");
	}

	exit: //

	ssl_requisites_free(ssl_req);
	net_close(listen_fd);

	return ret;
}

int pass_getch()
{
	struct termios oldtc, newtc;
	int ch;
	tcgetattr(STDIN_FILENO, &oldtc);
	newtc = oldtc;
	newtc.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newtc);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldtc);
	return ch;
}

int pass_scanf(char *dest, size_t dest_size)
{
	int ret = 0;
	char *tmp = dest;

	while (1) {
		*tmp = pass_getch();

		if (*tmp == '\n' || *tmp == '\r')
			break;

		if (tmp - dest >= (dest_size - 1)) {
			ret = -1;
		} else {
			tmp++;
		}
	}

	*tmp = 0;

	printf("\n");
	return ret ? ret : tmp - dest;
}

int add_user(const char *username, int update)
{
	int ret;
	char pass1[MAX_USERNAME_L];
	char pass2[MAX_USERNAME_L];

	memset(pass1, 0, sizeof pass1);
	memset(pass2, 0, sizeof pass2);

	printf("Enter password: ");
	ret = pass_scanf(pass1, sizeof pass1);
	if (ret == -1) {
		printf("ERROR: passsword is too long, max %d chars\n",
				(int) sizeof pass1 - 1);
		return -2;
	} else if (ret < 0) {
		printf("ERROR: unknown error %d\n", ret);
		return -2;
	} else if (!password_validate_strength(pass1)) {
		printf("ERROR: password too short, minimum  %d chars required\n", 8);
		return -2;
	}

	printf("Repeat password: ");
	ret = pass_scanf(pass2, sizeof pass2);

	if (ret < 0 || memcmp(pass1, pass2, sizeof pass1)) {
		printf("ERROR: passwords dont match\n");
		return -2;
	}

	uint8_t out[PASSWORD_HASH_SIZE]; // space for the iteration count
	ret = password_generate_hash(pass1, username, out, PASSWORD_HASH_SIZE);

	if (ret == 0) {
		if (update) {
			ret = db_insert("update users set password=%b where username=%s",
					out, PASSWORD_HASH_SIZE, username);
		} else {
			ret = db_insert(
					"insert into users (username, password) VALUES(%s, %b)",
					username, out, PASSWORD_HASH_SIZE);
		}

		if (ret)
			return -10;
	} else {
		printf("ERROR: calculating the hmac code of the password\n");
	}

	return 0;
}

void dbtest()
{
	int64_t ids[10];
	ids[0] = 1;
	ids[1] = INT64_MIN;
	ids[2] = 3;

	MYSQL_RES *res = db_select(
			"SELECT user_id, username from users where user_id in %L", ids, 3);
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(res))) {
		printf("fetched row: %s, %s\n", row[0], row[1]);
	}
}

int main(int argc, const char** argv)
{
	int ret = 0;
	const char *config_fname = config_get_file(argc, argv);
	if (config_fname == NULL )
		goto cleanup;

	int err = -2;
	config = config_read(config_fname, &err);

	if (config == NULL ) {
		fprintf(stderr,
				"ERROR: Couldn't read the config file %s, error in line %d\n",
				config_fname, err);
		goto cleanup;
	}

	// connect to db
	if (db_connect(config->mysql_host, config->mysql_user, config->mysql_pass,
			config->mysql_db)) {
		fprintf(stderr, "ERROR: can't connect to database: %s (%s)\n",
				db_get_error(), config->mysql_host);
		goto cleanup;
	}

	if (argc == 3) {
		int ret;
		if (!strcmp(argv[1], "adduser")) {
			ret = add_user(argv[2], 0);

			printf("%s\n", ret ? "ERROR" : "SUCCESS: user added");
		} else if (!strcmp(argv[1], "changepass")) {
			ret = add_user(argv[2], 1);
			printf("%s\n", ret ? "ERROR" : "SUCCESS: password changed");
		} else {
			printf("ERROR: wrong arguments (adduser,changepass)\n");
		}

		goto cleanup;
	}

	install_signal_handlers();

	ret = accept_connetions();

	cleanup: //
	db_shutdown();
	config_free(&config);

	if (ret != 0) {
		char error_buf[100];
		error_strerror(ret, error_buf, 100);
		fprintf(stderr, "ERROR: Last error was: %d - %s\n\n", ret, error_buf);
	}

	return ret == 0 ? 0 : 1;
}
