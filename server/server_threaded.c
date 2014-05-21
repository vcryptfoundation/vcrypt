/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "protocol.h"
#include "server.h"

CLIENT *clients[MAX_CLIENTS]={NULL};

int open_listener(int port)
{
	int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		exit(1);
	}

	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		exit(1);
	}
	return sd;
}

void *server_thread(void *client_void)
{
	char buffer[256];
	struct CLIENT_CONNDATA *client = client_void;

	printf("Connection: %s:%d\n",inet_ntoa(client->cl_addr.sin_addr), ntohs(client->cl_addr.sin_port));
	//int n = write(client->socket,"I got your message\n",19);
	while(1)
	{
		// first read the packet type
		uint16_t type = 0;
		int n = read(client->socket, &type, sizeof(type));
		if (n > 0)
		{
			printf("request type: %d\n", type);
			write(client->socket, buffer, n);
		}

		if (n==1 && buffer[0]=='\n')
			break;
	}

	write(client->socket, "bye\n", 5);
	close(client->socket);

	return NULL;
}

int main(int argc, char** argv)
{
	//struct sockaddr_in my_addr;
	struct sockaddr_in client_addr;	
	int sin_size = sizeof(struct sockaddr_in);
	int client_sock;
	struct CLIENT_CONNDATA *client;
	pthread_t serverthread;
	pthread_attr_t attr;

    if ( argc != 2 )
    {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }
    
    int server = open_listener(atoi(argv[1])); 

    while(1)
    {
		if ((client_sock = (int)accept(server, (struct sockaddr*)&client_addr, (socklen_t*)&sin_size)) < 0) continue;
		
		client = (struct CLIENT_CONNDATA*)malloc(sizeof(CLIENT_CONNDATA));
		
		memcpy(&client->cl_addr, &client_addr, sin_size);
		client->socket = client_sock;
		
		pthread_attr_init (&attr);
		pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&serverthread, &attr, server_thread, (void*)client);
		pthread_attr_destroy (&attr);
    }

	return 0;
}
