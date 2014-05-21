/*
 * queue.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <stdlib.h>
#include "client.h"
#include "packets.h"
#include "queue.h"
#include <assert.h>

void vqueue_init(VQUEUE *queue)
{
	int i;
	for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
		queue->entries[i].queued = 0;
	}

	queue->packets_enqueued = 0;
	queue->open = 1;

	pthread_mutex_init(&queue->mutex, NULL );
}

void vqueue_close(VQUEUE *queue)
{
	int i;
	for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
		if (queue->entries[i].queued)
			vqueue_entry_free(queue, queue->entries + i);
	}

	assert(queue->packets_enqueued == 0);
	queue->open = 0;

	pthread_mutex_destroy(&queue->mutex);
}

/* returns the index of the free packet slot in queue */
VQ_ENTRY* vqueue_find_free(VQUEUE *queue)
{
	int i;
	for (i = 0; i < VQUEUE_MAX_ENTRIES; i++)
		if (queue->entries[i].queued == 0)
			return queue->entries + i;

	return NULL ;
}

/* in case of errors the packet will be free()'d, otherwise its free'd after sending by worker
 * returns packet_id. Packet id of the packet is mantained if its 0, otherwise its filled by the next packet id
 * */
int32_t vqueue_add_packet(VQUEUE *queue, VCRYPT_PACKET *packet,
		unsigned int timeout_ms, int wait_match)
{
	static int32_t packet_id = 0;

	assert(packet != NULL);

	// we need this before the mutex, because the mutex may not be initialized yet
	if (!queue->open) {
		free(packet);
		return -ERR_SERVER_NOTCONNECTED;
	}

	pthread_mutex_lock(&queue->mutex);

	// find a free queue slot
	VQ_ENTRY *qentry = vqueue_find_free(queue);
	if (qentry == NULL ) {
		free(packet);
		pthread_mutex_unlock(&queue->mutex);
		return -ERR_QUEUE_FULL;
	}

	if (packet->queue_id == 0) {
		packet->queue_id = ++packet_id;

		if (packet_id == INT32_MAX)
			packet_id = 0;
	}

	qentry->queued = 1;
	qentry->time_ms = time_get_ms();
	qentry->time_sent_ms = 0;
	qentry->timeout = timeout_ms;
	qentry->packet = packet;
	qentry->time_server_response = 0;
	qentry->wait_match = wait_match;

	queue->packets_enqueued++;
	assert(queue->packets_enqueued <= VQUEUE_MAX_ENTRIES);

	pthread_mutex_unlock(&queue->mutex);
	return packet->queue_id;
}

int vqueue_add_packet_noid(VQUEUE *queue, VCRYPT_PACKET *packet,
		unsigned int timeout_ms)
{
	assert(packet != NULL);

	// we need this before the mutex, because the mutex may not be initialized yet
	if (!queue->open) {
		free(packet);
		return -ERR_SERVER_NOTCONNECTED;
	}

	pthread_mutex_lock(&queue->mutex);

	// find a free queue slot
	VQ_ENTRY *qentry = vqueue_find_free(queue);
	if (qentry == NULL ) {
		free(packet);
		pthread_mutex_unlock(&queue->mutex);
		return -ERR_QUEUE_FULL;
	}

	qentry->queued = 1;
	qentry->time_ms = time_get_ms();
	qentry->time_sent_ms = 0;
	qentry->timeout = timeout_ms;
	qentry->packet = packet;
	qentry->time_server_response = 0;
	qentry->wait_match = 0;

	queue->packets_enqueued++;
	assert(queue->packets_enqueued <= VQUEUE_MAX_ENTRIES);

	pthread_mutex_unlock(&queue->mutex);
	return 0;
}

int vqueue_is_queued(VQUEUE *queue, int dest, int type, const char *username)
{
	int ret = 0;
	pthread_mutex_lock(&queue->mutex);

	int i;
	for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
		if (queue->entries[i].queued == 0)
			continue;

		if (queue->entries[i].packet->dest != dest)
			continue;

		if (queue->entries[i].packet->type != type)
			continue;

		if (username && strcmp(queue->entries[i].packet->username, username))
			continue;

		ret = 1;
		goto done;
	}

	done: //
	pthread_mutex_unlock(&queue->mutex);
	return ret;
}

void vqueue_update_server_response_time(VQ_ENTRY *qentry)
{
	qentry->time_server_response = time_get_ms();
}

int vqueue_check_timeout(VQ_ENTRY *qentry)
{
	if (!qentry->queued)
		return 0;

	if ((time_passed_ms(qentry->time_ms) > qentry->timeout)) {
		if (qentry->time_sent_ms == 0) {
			// the packet was not even sent
			return -ERR_QUEUE_LOCAL_TIMEOUT;
		} else if (qentry->time_server_response == 0) {
			// there was no response from the server
			return -ERR_QUEUE_SERVER_TIMEOUT;
		} else {
			// server answered, but client didn't
			return -ERR_QUEUE_CLIENT_TIMEOUT;
		}
	}

	return 0; // not timed out yet
}

void vqueue_free_packet(VQ_ENTRY *qentry)
{
	assert(qentry->packet != NULL);

	free(qentry->packet);
	qentry->packet = NULL;
}

// removes a entry from queue (marks it as not used)
void vqueue_entry_free(VQUEUE *queue, VQ_ENTRY *qentry)
{
	assert(qentry->queued != 0);

	if (qentry->packet != NULL ) {
		vqueue_free_packet(qentry);
	}

	qentry->queued = 0;
	queue->packets_enqueued--;
}

VQ_ENTRY* vqueue_packet_matches(VQUEUE *queue, VCRYPT_PACKET *packet)
{
	if (queue->packets_enqueued == 0)
		return NULL ;

	if (!packet_is_response(packet->type))
		return NULL ;

	int i;
	for (i = 0; i < VQUEUE_MAX_ENTRIES; i++) {
		if (queue->entries[i].queued == 0)
			continue;

		if (queue->entries[i].packet->queue_id == packet->queue_id) {
			// only already sent packets must match here
			assert(queue->entries[i].time_sent_ms != 0);

			if ((packet->dest == DEST_CLIENT
					&& !strcmp(queue->entries[i].packet->username,
							packet->username)) || //
					packet->dest == DEST_SERVER) {
				return queue->entries + i;
			}
		}
	}

	return NULL ;
}
