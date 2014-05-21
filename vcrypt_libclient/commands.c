/*
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */
#include "client.h"
#include "dh_sessions.h"
#include <assert.h>
#include <stdlib.h>

#include "call.h"

void command_help(VCRYPT_CTX *ctx, const char *username, const char *message);

void command_download_pubkey(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	if (!vqueue_is_queued(&ctx->packet_queue, DEST_SERVER, REQ_GET_PUBLIC_KEY,
			username)) {
		VCRYPT_PACKET *packet = packet_new(DEST_SERVER, username,
				REQ_GET_PUBLIC_KEY, 0);

		if (!packet) {
			ctx->callback_message_received(username,
					strdup(vcrypt_get_error(-ERR_MALLOC)), 1);
			return;
		}

		int res = vqueue_add_packet(&ctx->packet_queue, packet,
		VCRYPT_TIMEOUT_SERVER, 1);

		if (res < 0) {
			ctx->callback_message_received(username,
					strdup(vcrypt_get_error(res)), 1);
			return;
		}

		ctx->callback_message_received(username,
				strdup("Downloading public key..."), 1);
	} else {
		ctx->callback_message_received(username,
				strdup("Downloading is already in progress..."), 1);
	}
}

void command_pubkey_info(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	char *msg = malloc(200);
	rsa_context *rsa = public_key_list_get(ctx->public_keys, username);

	if (rsa == NULL) {
		snprintf(msg, 200, "No public key");
	} else {
		char fp[FLETCHER_SIZE_STR];
		rsa_get_public_key_fingerprint(rsa, NULL, fp);
		snprintf(msg, 200, "Public key info, %ld bit, %s ", rsa->len * 8, fp);
	}

	ctx->callback_message_received(username, msg, 1);
}

void command_dh_session_start(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	int ret = dh_start_exchange(ctx, username, DHKEY_MESSAGING);

	if (ret == 0) {
		ctx->callback_message_received(username,
				strdup("Establishing DH session..."), 1);
	} else {
		ctx->callback_message_received(username, strdup(vcrypt_get_error(ret)),
				1);
	}
}

void command_dh_session_info(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	char *msg = malloc(200);
	DH_KEY *dhkey = dh_key_list_get(ctx->dh_keys, username, DHKEY_MESSAGING);

	if (dhkey == NULL || dhkey->status != DHKEY_STATUS_READY) {
		snprintf(msg, 200, "No DH session");
	} else {
		snprintf(msg, 200, "DH session active: ");
		fletcher64_to_str(msg + strlen(msg), &dhkey->fingerprint);
	}

	ctx->callback_message_received(username, msg, 1);
}

void command_dh_session_close(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	DH_KEY *dhkey = dh_key_list_get(ctx->dh_keys, username, DHKEY_MESSAGING);

	if (dhkey != NULL) {
		dh_mark_error(ctx, DHKEY_MESSAGING, username);
	}

	ctx->callback_message_received(username, strdup("DH session closed"), 1);
}

void command_call_send(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_call(ctx, username);
}

void command_call_info(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	char *msg;
	char checksum[FLETCHER_SIZE_STR];

	switch (ctx->call_ctx.status)
	{
	case CALL_STATUS_NONE:
		msg = strdup("No active call");
		break;
	case CALL_STATUS_RINGING:
		msg = malloc(256);
		snprintf(msg, 256, "%s %s ...",
				ctx->call_ctx.is_caller ? "Calling" : "Called by",
				ctx->call_ctx.username);
		break;
//	case CALL_STATUS_UDP_HP:
//		msg = malloc(256);
//		fletcher64_to_str(checksum, &ctx->call_ctx.key->fingerprint);
//
//		snprintf(msg, 256, "UDP HP with %s (%s)", ctx->call_ctx.username,
//				checksum);
//		break;
	case CALL_STATUS_AUDIO:
		msg = malloc(256);
		fletcher64_to_str(checksum, &ctx->call_ctx.key->fingerprint);

		snprintf(msg, 256, "Audio with %s (%s)", ctx->call_ctx.username,
				checksum);
		break;
	default:
		msg = strdup("Unknown status");
		break;
	}

	ctx->callback_message_received(username, msg, 1);
}

void command_call_accept(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_call_accept(ctx, username, 0);
}

void command_call_reject(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_call_accept(ctx, username, 1);
}

void command_call_hangup(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_call_hangup(ctx, username);
}

void command_contact_del(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_contact_add(ctx, message);
}

void command_contact_add(VCRYPT_CTX *ctx, const char *username,
		const char *message)
{
	vcrypt_contact_del(ctx, message);
}

struct VCRYPT_COMMAND {
	const char *command;
	const char *descr;
	void (*callback_command)(VCRYPT_CTX *ctx, const char *username,
			const char *message);
} vcrypt_commands[] = {
//
		{"help", "displays help info", command_help}, //
		{"pkget", "downloads users public key", command_download_pubkey}, //
		{"pkinfo", "show public key info", command_pubkey_info}, //
		{"dhstart", "start ephemeral DH session", command_dh_session_start}, //
		{"dhinfo", "show DH session status", command_dh_session_info}, //
		{"dhclose", "close DH session", command_dh_session_close}, //

		{"csend", "Call this user", command_call_send}, //
		{"canswer", "Answer the call", command_call_accept}, //
		{"creject", "Reject the call", command_call_reject}, //
		{"changup", "Hang-up a call", command_call_hangup}, //
		{"cinfo", "Show the current call status", command_call_info}, //

		{"addcontact", "Adds a contact to contact list", command_contact_del}, //
		{"delcontact", "Deletes a contact from contact list",
				command_contact_add}, {NULL, NULL, NULL} //
};

void command_help(VCRYPT_CTX *ctx, const char *username, const char *message)
{
	int need_size = 0;
	struct VCRYPT_COMMAND *cmd;

	cmd = vcrypt_commands;
	while (cmd->command != NULL && cmd->callback_command != NULL) {
		need_size += strlen(cmd->command);
		need_size += strlen(cmd->descr);
		need_size += 6;
		cmd++;
	}

	char *msg = malloc(need_size + 1); // for null terminator
	msg[0] = 0;

	cmd = vcrypt_commands;
	while (cmd->command != NULL && cmd->callback_command != NULL) {
		strcat(msg, "/");
		strcat(msg, cmd->command);
		strcat(msg, " - ");
		strcat(msg, cmd->descr);
		strcat(msg, "; ");

		cmd++;
	}

	ctx->callback_message_received(username, msg, 1);
}

/* returns 1 if a command was detected */
int commands_process(VCRYPT_CTX *ctx, const char *username, const char *message)
{
	int command_len = strlen(message);
	if (command_len < 2 || message[0] != '/')
		return 0;

	int n_found = 0;
	struct VCRYPT_COMMAND *found = NULL, *cmd = vcrypt_commands;

	const char *cmddata = strchr(message, ' ');
	const char *command = message + 1;

	if (cmddata) {
		command_len = cmddata - message;
		command = alloca(command_len);
		strncpy_ex((char*) command, message + 1, command_len);
		cmddata++; // to skip the ' ' found
	}

//	dolog(0, "command: '%s', data: '%s', cmdlen: %d\n", command, cmddata, command_len);

	while (cmd->command != NULL) {
		if (strncmp(command, cmd->command, command_len - 1) == 0) {
			n_found++;
			found = cmd;
		}

		cmd++;
	}

	if (n_found == 1) {
		assert(found->callback_command);
		found->callback_command(ctx, username, cmddata);
	} else if (n_found > 1) {
		ctx->callback_message_received(username,
				strdup("Ambiguous command, use /help"), 1);
	} else {
		ctx->callback_message_received(username,
				strdup("No such command, use /help"), 1);
	}

	return 1;
}
