/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#ifndef VCLIENT_H_
#define VCLIENT_H_

#include "config.h"
#include <stdint.h>
#include <pthread.h>
#include <opus/opus.h>
#include <opus/opus_types.h>
#include "packets.h"
#include "ssl_wrap.h"

#ifdef __ANDROID__
#include <jni.h>
#include <android/log.h>
#endif

#if HAVE_WINDOWS_H
#include <windows.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "vcrypt_errors.h"
#include "queue.h"
#include "public_keys.h"
#include "dh_keys.h"
#include "audio.h"

#define VCRYPT_SERVER_DEFAULT_PORT 5566
// wait for this time for a server response
#define VCRYPT_TIMEOUT_SERVER 		5000
/* wait for this time for a client response via server */
#define VCRYPT_TIMEOUT_CLIENT 		5000
// if the udp hp is not finished in this time frame, drop the call
//#define VCRYPT_TIMEOUT_UDP_HP  		5000
// if no answer for this time, drop the call
#define VCRYPT_TIMEOUT_CALLANSWER  10000
// when in call, if there are no packets received for this time, drop the call
#define VCRYPT_TIMEOUT_CALL 		3000

// the delay between sending udp hole punch packets
#define VCRYPT_UDP_HP_RESEND  		300

enum THREAD_STATUS {
	THREAD_NONE,
	THREAD_RUNNING,
	THREAD_SIGNAL_STOP,
	THREAD_EXIT_NORMAL,
	THREAD_EXIT_ERROR,
	THREAD_EXIT_SERVER_DISCONNECT,
	THREAD_EXIT_SERVER_CANT_CONNECT,
	THREAD_EXIT_SERVER_CANT_LOGIN,
};

enum CALL_STATUS {
	CALL_STATUS_NONE = 0,
	CALL_STATUS_RINGING,
	//CALL_STATUS_ACCEPT, // intermediary status
	//CALL_STATUS_UDP_HP,
	CALL_STATUS_AUDIO,
};

typedef unsigned char CODEC_TYPE;

struct CALL_CTX {
	enum CALL_STATUS status;
	int is_caller;
	uint64_t start_time_ms; // for global timeout
	uint64_t time_audio_start; // for last command
	uint64_t time_packet_sent; // for last command
	uint64_t time_packet_rcvd; // for last command
	int32_t packet_id;
	DH_KEY *key;

	VAUDIO_CTX audio_ctx;

//	uint64_t ring_packet_sent_ms; // time of last ring packet sent by caller
//	uint64_t ring_packet_received_ms; // ringer/answer timeout tracking
//	uint64_t packet_receive_time_ms;
//	uint64_t packet_sent_time_ms; // for waiting between sending packets
//
//	uint32_t packets_sent;
//	uint32_t packets_received;
//	uint32_t packets_lost;
//
//	uint32_t bytes_sent;
//	uint32_t bytes_received;
//
	PACKET_NR packet_nr_sent; // for tracking packet loss
	PACKET_NR packet_nr_recv; // for tracking packet loss
	//int udp_hp_response; // if we are receiving packets from the other party
	/* if call is active this shows with whom */
	struct sockaddr_in p2p_info;
	char username[MAX_USERNAME_L];
};

typedef struct VCRYPT_CONNECT_DETAILS {
	char *hostname;
	int port;
	char *username;
	char *password;
} VCRYPT_CONNECT_DETAILS;

typedef struct VCRYPT_CTX {
	int socket_server;
	int connection_in_progress;
	int socket_p2p;
	enum THREAD_STATUS flag_thread_status;
	pthread_t thread_handle;
	pthread_t thread_keys_handle;
	pthread_mutex_t mutex;

	VCRYPT_CONNECT_DETAILS login_details;

	struct CALL_CTX call_ctx;

	/* if error_id=0 it means the server connected */
	void (*callback_server_disconnect)(int error_id);

	/* updates the status*/
	void (*callback_call_status_change)(const char *username, int status, int reason);

	void (*callback_contact_add_del_response)(int command, int response,
			const char *username);

	/* will start the clients audio sending thread, should return 0 on success,
	 * otherwise the library will hang up the call */
	int (*callback_start_audio_sending)();

	// this is for receiving audio
	void (*callback_audio)(char *data, int size);
	/*
	 * this has to load contacts in the contact list, also it must free the data when finished
	 */
	void (*callback_load_contacts)(const char *data);
	/*
	 * this is called when server notifies about status change for some contacts
	 */
	void (*callback_contact_status_notify)(const char *username, int status);

	/* message must be free'd after usage
	 * msg_type;  0 - regular, 1 - system
	 * */
	void (*callback_message_received)(const char *username, char *message_f,
			int msg_type);

	void (*callback_message_sent_status_update)(const char *username,
			int32_t id, int result);

	// for server response username should be null
	void (*callback_ping_response)(const char *username, int result);

	void (*callback_password_change_response)(int result);

#ifdef __ANDROID__
	void (*callback_jni_setup)(int attach);
#endif

	/* checksum must be freed after receiving */
	void (*callback_key_generate_response)(int result, char *checksum_f);

	VQUEUE packet_queue;

	ssl_context ssl;
	ssl_prerequisites ssl_req;
	uint64_t public_key_fp_local;

	int has_valid_keys_locally; // checking keys validity is expensive, so we cache it here
	PUBLIC_KEY *public_keys;
	DH_KEY *dh_keys;
} VCRYPT_CTX;

#include "client_rsa.h"

VCRYPT_CTX* vcrypt_create(const char *keys_fname);
void vcrypt_connect_auth(VCRYPT_CTX *ctx, const char *address,
		const char *username, const char *password);
int vcrypt_close(VCRYPT_CTX *ctx, int wait);
int vcrypt_is_connected(VCRYPT_CTX *ctx);
void vcrypt_close_sockets(VCRYPT_CTX* ctx);
const char *vcrypt_get_error(int error);
void vcrypt_ping_server(VCRYPT_CTX *ctx);
void vcrypt_ping_client(VCRYPT_CTX *ctx, char *username);
void vcrypt_contact_add(VCRYPT_CTX *ctx, const char *username);
void vcrypt_contact_del(VCRYPT_CTX *ctx, const char *username);

int vcrypt_queue_audio(VCRYPT_CTX *ctx, const char *data, int size);

int32_t vcrypt_message_send(VCRYPT_CTX *ctx, const char *username,
		const char *message);
int vcrypt_message_send_prepare(VCRYPT_CTX *ctx, const char *username);

void vcrypt_password_change(VCRYPT_CTX *ctx, const char *oldpwd,
		const char *newpwd, const char *newpwd_r);

void vcrypt_destroy(VCRYPT_CTX *ctx);

int get_thread_status(VCRYPT_CTX *ctx);
void set_thread_status(VCRYPT_CTX *ctx, int val);

#ifdef __cplusplus
}
#endif

#endif // VCLIENT_H_
