/*
s * fifo.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef FIFO_H_
#define FIFO_H_

#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FIFO {
	int32_t size;
	int32_t head;
	int32_t tail;
	/* bytes available for read */
	int32_t bytes_available;
	char *data;
	pthread_mutex_t mutex;
} FIFO;

FIFO* fifo_new(int32_t len);
void fifo_close(FIFO *fifo);
int fifo_write(FIFO *fifo, const char *data, int32_t size);
int fifo_read(FIFO *fifo, char *data, int32_t size);
int fifo_bytes_available(FIFO *fifo);

#ifdef __cplusplus
}
#endif

#endif /* FIFO_H_ */
