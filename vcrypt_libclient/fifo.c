/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include "fifo.h"

// TODO: optimize this

FIFO* fifo_new(int32_t size)
{
	FIFO *fifo = malloc(sizeof(FIFO));
	fifo->tail = 0;
	fifo->head = 0;
	fifo->bytes_available = 0;
	fifo->size = size;
	fifo->data = malloc(size);

	pthread_mutex_init(&fifo->mutex, NULL );

	return fifo;
}

void fifo_close(FIFO *fifo)
{
	free(fifo->data);
	free(fifo);

	pthread_mutex_destroy(&fifo->mutex);
}

int fifo_write(FIFO *fifo, const char *data, int32_t size)
{
	if (fifo == NULL || fifo->data == NULL)
		return -1;

	pthread_mutex_lock(&fifo->mutex);
	int32_t i;
	for(i=0; i<size; i++) {
		// full?
		if (fifo->bytes_available == fifo->size)
			break;

		fifo->bytes_available++;
		fifo->data[fifo->head++] = data[i];

		if (fifo->head == fifo->size)
			fifo->head = 0;
	}

	pthread_mutex_unlock(&fifo->mutex);
	return i;
}

int fifo_read(FIFO *fifo, char *data, int32_t size)
{
	if (fifo == NULL || fifo->data == NULL)
		return -1;

	int i;
	pthread_mutex_lock(&fifo->mutex);
	for(i=0; i<size; i++) {
		if (fifo->bytes_available == 0)
			break;

		fifo->bytes_available--;
		data[i] = fifo->data[fifo->tail++];

		if (fifo->tail == fifo->size)
			fifo->tail = 0;
	}

	pthread_mutex_unlock(&fifo->mutex);
	return i;
}

/* returns bytes available for read */
int fifo_bytes_available(FIFO *fifo)
{
	if (fifo == NULL || fifo->data == NULL)
		return -1;

	pthread_mutex_lock(&fifo->mutex);
	int32_t bytes = fifo->bytes_available;
	pthread_mutex_unlock(&fifo->mutex);

	return bytes;
}

int fifo_test()
{
#define BUFF_SIZE 32


	char read[BUFF_SIZE];
	char write[BUFF_SIZE];

	FIFO *fifo = fifo_new(BUFF_SIZE);

	int testsize;

	printf("started\n");
	srand(time(NULL ));

	int i;
	for (i = 0; i < 10; i++) {
		testsize = rand() % BUFF_SIZE;

		memset(write, i + 1, testsize);
		int add = fifo_write(fifo, write, testsize);

		memset(read, 0, testsize);
		int rr = fifo_read(fifo, read, testsize);

		printf("%3d bytes:%3d, add:%3d, read:%3d result:%d\n", i, testsize, add, rr,
		        memcmp(write, read, testsize));
	}

	return 0;
}
