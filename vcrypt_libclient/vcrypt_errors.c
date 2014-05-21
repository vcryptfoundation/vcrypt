/*
 * error_descriptions.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "error_enum.h"
#include <stdio.h>
#include <stdlib.h>

#define C (char*)

const char *vcrypt_get_error(int error) {
	static char buff[100];
	static struct _errordesc {
		int code;
		const char *message;
	} errordesc[] = {
	// SUCCESS
	{ ERR_SUCCESS, C"SUCCESS: No error" },
	{ ERR_DISCONNECT_SUCCESS, C"Disconnect success" },
	{ ERR_MSG_QUEUED, C"Operation queued" },
	{ ERR_INPROGRESS_SERVER, C"Operation in progress, server acknowledged" },
	{ ERR_MSG_INPROGRESS_CALEE, C"Operation in progress, receiver acknowledged" },
	{ ERR_PING_SERVER_OK, C"Ping OK" },
	// ERRORS
	{ ERR_CONNECTION_FAILURE, C"ERROR: Connection failure" },
	{ ERR_CONNECTION_SSL_INIT_FAILURE, C"ERROR: Could not initialize TLS" },
	{ ERR_CONNECTION_SSL_HANDSHAKE_FAILURE, C"ERROR: TLS handshake failed" },
	{ ERR_SERVER_DISCONNECT, C"ERROR: Server dropped the connection" },
	{ ERR_SERVER_TIMEOUT, C"ERROR: Timeout while reading from server" },
	{ ERR_SERVER_NOTCONNECTED, C"ERROR: Not connected to the server" },
	{ ERR_SERVER_ALREADY_CONNECTED, C"ERROR: Already connected" },
	{ ERR_P2P_SOCKET_EXISTS, C"ERROR: P2P socket already exists" },
	{ ERR_REGISTER_AUTH_FAILURE, C"ERROR: Wrong username or password" },
	{ ERR_REGISTER_UNSUPPORTED_VERSION, C"ERROR: Unsupported client version, please upgrade" },
	{ ERR_REGISTER_ALREADY_LOGGED, C"ERROR: Already logged in" },
	{ ERR_NOSUCHUSER, C"ERROR: No such user" },
	{ ERR_USER_OFFLINE, C"ERROR: User is offline" },
	{ ERR_SERVER_SOCKET, C"ERROR: Can't create server socket" },
	{ ERR_BAD_PACKET, C"ERROR: Bad packet received" },
	{ ERR_PACKET_TOO_BIG, C"ERROR: The message is too big" },
	{ ERR_HOST_RESOLVE, C"ERROR: Can't resolve hostname" },
	{ ERR_P2P_SOCKET, C"ERROR: Can't create p2p socket" },
	{ ERR_MALLOC, C"ERROR: Can't allocate memory" },
	{ ERR_DEBUG_ERROR, C"ERROR: Debug error" },
	{ ERR_UNKNOWN_ERROR, C"ERROR: Unknown error" },
	{ ERR_QUEUE_FULL, C"ERROR: Packet queue full" },
	{ ERR_PARAM_ISNULL, C"ERROR: Parameter can't be null" },
	{ ERR_UNEXPECTED_PACKET, C"ERROR: Unexpected packet received, no match in queue" },
	{ ERR_CODEC_REC_SETUP, C"ERROR: Could not setup the rec codec" },
	{ ERR_CODEC_PLAY_SETUP, C"ERROR: Could not setup the play codec" },
	{ ERR_RESAMPLER_REC_SETUP, C"ERROR: Could not setup the rec resampler" },
	{ ERR_RESAMPLER_PLAY_SETUP, C"ERROR: Could not setup the play resampler" },
	{ ERR_UNSUPPORTED_REC_SAMPLERATE, C"ERROR: Recording sample rate is not supported" },
	{ ERR_UNSUPPORTED_PLAY_SAMPLERATE, C"ERROR: Playing rate is not supported" },
	{ ERR_UNKNOWN_AUDIO_PROBLEM, C"ERROR: Could not start audio" },

	{ ERR_QUEUE_LOCAL_TIMEOUT, C"ERROR: Timeout while sending the command" },
	{ ERR_QUEUE_SERVER_TIMEOUT, C"ERROR: Timeout while waiting server response" },
	{ ERR_QUEUE_CLIENT_TIMEOUT, C"ERROR: Timeout while waiting client response" },

	{ ERR_TEMPORARY_ERROR, C"ERROR: Temporary error, try again later" },

	{ ERR_RSA_NO_KEYS, C"ERROR: No valid RSA keys" },
	{ ERR_RSA_ERROR_GENERATING_KEYS, C"ERROR: Could not generate RSA keys" },
	{ ERR_RSA_ERROR_LOADING_KEYS, C"ERROR: Could not load RSA keys" },
	{ ERR_PUBKEY_SYNC, C"ERROR: Can not sync public key to the server" },
	{ ERR_NO_PUBKEY, C"ERROR: User's public key not present" },
	{ ERR_NO_DHKEY, C"ERROR: DH key is not negociated" },
	{ ERR_DOWNLOADING_PUBKEY, C"Downloading user's public key" },
	{ ERR_DHKEY_NEGOTIATING, C"Negotiating DH key" },
	{ ERR_ENCRYPTION_ERROR, C"ERROR: Could not encrypt the message" },
	{ ERR_DECRYPTION_ERROR, C"ERROR: Could not decrypt the message" },
	{ ERR_MESSAGE_STORED, C"Message stored on server" },
	{ ERR_SIGN_ERROR, C"ERROR: Could not sign the message" },
	{ ERR_SIGN_VERIFY_ERROR, C"ERROR: Wrong RSA signature" },

	{ ERR_PASSWORD_EMPTY, C"ERROR: Password can't be empty" },
	{ ERR_PASSWORD_NOMATCH, C"ERROR: Passwords don't match" },
	{ ERR_PASSWORD_SAMEASOLD, C"ERROR: New password can't be the same with the old one" },
	{ ERR_PASSWORD_BAD, C"ERROR: This password can't be accepted by server, use another one" },

	{ ERR_PACKET_WRITE, C"ERROR: Can't write packet" },

	{ ERR_FILE_WRITE, C"ERROR: Can't write to file" },
	{ ERR_FILE_READ, C"ERROR: Can't read from file" },

	{ ERR_POSTPONE_PACKET, C"Packet must be postponed" },
	{ ERR_INPROGRESS, C"Operation already in progress" },
	{ ERR_NOT_IMPLEMENTED, C"Not implemented" },

	/* CALL related statuses
	 *
	 * * CALL_SENT - opens a new window in caller and initiates the call (for /call command)
		 * CALL_RECEIVED - opens a new window at calee where use can answer or reject
		 * CALL_ANSWERED / CALL_REJECTED - updates the status in the users window
		 * CALL_ENDED
		 * CALL_DH
		 * CALL_UDPHP*/
	{ ERR_CALL_SENT, C"Call initiated" },
	{ ERR_CALL_RECEIVED, C"Call received" },
	{ ERR_CALL_REJECTED, C"Call rejected" },
	{ ERR_CALL_ANSWERED, C"Call answered" },
	{ ERR_CALL_HANGUP, C"Hang-up" },
	{ ERR_CALL_MAINTAINSTATUS, C"Status not changed" },
	//
	{ ERR_CALL_UDP_HP, C"Punching UDP hole" },
	{ ERR_CALLANSWER_TIMEOUT, C"ERROR: Timeout while waiting for call answer" },
	{ ERR_CALL_INPROGRESS, C"ERROR: A call is already in progress" },
	{ ERR_UDP_HOLE_PUNCHING_TIMEOUT, C"ERROR: UDP hole punching timeout" },
	{ ERR_CALL_AUDIO_TIMEOUT, C"ERROR: Audio timeout" },
	{ ERR_MSG_CALLINGITSELF, C"ERROR: Not allowed to call itself" },
	{ ERR_CLIENT_CALLBUSY, C"ERROR: User busy" },
	{ ERR_CALL_DROPPED, C"ERROR: Call dropped" },
	{ ERR_CALL_NOT_RINGING, C"ERROR: No ringing call to answer/reject" },
	{ ERR_CALL_NO_ACTIVE_CALL, C"ERROR: No active call" },
	{ ERR_CALL_OTHER_HANGUP, C"ERROR: The other party hanged up" },
	{ 0, NULL },
	}; // keep this format for the enum parser

	int i;
	for (i = 0;; i++) {
		if (errordesc[i].message == NULL )
			break;

		if (errordesc[i].code == -error)
			return errordesc[i].message;
	}

	snprintf(buff, 100, "Undefined error: %d", error);

	return buff;
}



