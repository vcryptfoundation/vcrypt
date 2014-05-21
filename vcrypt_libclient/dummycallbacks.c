/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include <stdio.h>
#include "dummycallbacks.h"

// dummy callback functions
void unset_callback_debug(const char *func)
{
	dolog(D_CALLBACK, "WARNING: unset callback function %s\n", func);
}

void callback_dummy_server_disconnect(int error_id)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Server connected/disconnected: (%d) %s\n", error_id,
			vcrypt_get_error(error_id));
}

void callback_dummy_call_received(const char *username)
{
	(void) username;
	unset_callback_debug(__func__);
}

void callback_dummy_call_sent(char *username)
{
	(void) username;
	unset_callback_debug(__func__);
}

void callback_dummy_call_answer()
{
	unset_callback_debug(__func__);
}

void callback_dummy_call_hangup(const char *username, int reason)
{
	(void) username;
	(void) reason;
	unset_callback_debug(__func__);
}

void callback_dummy_call_close()
{
	unset_callback_debug(__func__);
}

void callback_dummy_call_open()
{
	unset_callback_debug(__func__);
}

void callback_dummy_load_contacts(const char *data)
{
	unset_callback_debug(__func__);
	(void) data;
}

void callback_dummy_audio(char *data, int size)
{
	unset_callback_debug(__func__);
	(void) data;
	(void) size;
}

void callback_dummy_contact_add_del_response(int command, int response,
		const char *username)
{
	(void) command;
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Add/del contact command for %s: %s\n", username,
			vcrypt_get_error(response));
}

void callback_dummy_contact_status_notify(const char *username, int status)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Status change for %s: %d\n", username, status);
}

void callback_dummy_message_received(const char *username, char *message,
		int msg_type)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- received message from %s (%s): %s\n", username,
			msg_type ? "system" : "normal", message);

	free(message);

}

void callback_dummy_message_sent_status_update(const char *username, int32_t id,
		int result)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK,
			"|--- message status update from %s, id: %d, result: %d\n",
			username, id, result);
}

void callback_dummy_message_enable_sending(const char *username, int result)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- enabled message sending for %s, result: %d\n",
			username, result);
}

void callback_dummy_ping_response(const char *username, int result)
{
	(void) result;
	(void) username;
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Ping response for %s, result: %s\n",
			username ? username : "server", vcrypt_get_error(result));
}

void callback_dummy_password_change_response(int result)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Password change response %s\n",
			vcrypt_get_error(result));
}

int callback_dummy_start_audio_sending()
{
	unset_callback_debug(__func__);
	return -ERR_NOT_IMPLEMENTED;
}

#ifdef __ANDROID__
void callback_dummy_jni_setup(int attach)
{
	unset_callback_debug(__func__);
	(void) attach;
}
#endif

void callback_dummy_key_generate_response(int result, char *checksum_f)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Key generation response %s (checksum: %s)\n",
			vcrypt_get_error(result), checksum_f ? checksum_f : "None");

//	if (checksum_f)
//		free(checksum_f);
}

void callback_dummy_call_status_change(const char *username, int status,
		int reason)
{
	unset_callback_debug(__func__);
	dolog(D_CALLBACK, "|--- Call status for %s changed to: %s / %s\n", username,
			vcrypt_get_error(status), vcrypt_get_error(reason));
}

void setup_dummy_callbacks(VCRYPT_CTX* ctx)
{
	ctx->callback_server_disconnect = callback_dummy_server_disconnect;
	ctx->callback_audio = callback_dummy_audio;

	ctx->callback_load_contacts = callback_dummy_load_contacts;
	ctx->callback_contact_add_del_response = callback_dummy_contact_add_del_response;
	ctx->callback_contact_status_notify = callback_dummy_contact_status_notify;

	ctx->callback_message_received = callback_dummy_message_received;
	ctx->callback_message_sent_status_update =
			callback_dummy_message_sent_status_update;
	ctx->callback_ping_response = callback_dummy_ping_response;
	ctx->callback_password_change_response =
			callback_dummy_password_change_response;
	ctx->callback_key_generate_response = callback_dummy_key_generate_response;
	ctx->callback_call_status_change = callback_dummy_call_status_change;
	ctx->callback_start_audio_sending = callback_dummy_start_audio_sending;

#ifdef __ANDROID__
	ctx->callback_jni_setup = callback_dummy_jni_setup;
#endif
}

