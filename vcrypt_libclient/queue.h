/*
 * queue.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

#ifndef QUEUE_H_
#define QUEUE_H_

#define VQUEUE_MAX_ENTRIES 20

typedef struct VQ_ENTRY {
	VCRYPT_PACKET *packet;
	int queued;
	int wait_match;
	unsigned int timeout;
	uint64_t time_ms;
	uint64_t time_sent_ms;
	uint64_t time_server_response;
} VQ_ENTRY; // vcrypt queue entry

typedef struct PACKET_QUEUE {
	int open;
	VQ_ENTRY entries[VQUEUE_MAX_ENTRIES];
	int packets_enqueued;
	pthread_mutex_t mutex;
} VQUEUE; // vcrypt packet queue

void vqueue_init(VQUEUE *queue);
void vqueue_close(VQUEUE *queue);

int32_t vqueue_add_packet(VQUEUE *queue, VCRYPT_PACKET *packet,
		unsigned int timeout_ms, int wait_match);
int vqueue_add_packet_noid(VQUEUE *queue, VCRYPT_PACKET *packet,
		unsigned int timeout_ms);
void vqueue_entry_free(VQUEUE *queue, VQ_ENTRY *qentry);
void vqueue_free_packet(VQ_ENTRY *qentry);
int vqueue_check_timeout(VQ_ENTRY *qentry);
VQ_ENTRY* vqueue_packet_matches(VQUEUE *queue, VCRYPT_PACKET *packet);
void vqueue_update_server_response_time(VQ_ENTRY *qentry);
int vqueue_is_queued(VQUEUE *queue, int dest, int type, const char *username);

#endif /* QUEUE_H_ */
