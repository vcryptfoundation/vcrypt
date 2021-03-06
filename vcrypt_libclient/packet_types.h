/*
 * packet_types.h
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

ENUM_BEGIN( PacketTypes )
	ENUM(REQ_AUTHENTICATE),
	ENUM(RESP_REGISTER_OK_CONTACTS),
	ENUM(RESP_REGISTER_AUTH_FAILURE),
	ENUM(RESP_REGISTER_ALREADY_LOGGED_IN),
	ENUM(RESP_REGISTER_UNSUPPORTED_VERSION),
	ENUM(RESP_REGISTER_UNKNOWN_FAILURE),

	ENUM(REQ_PING_SERVER),
	ENUM(REQ_PING_CLIENT),

	ENUM(REQ_PASSWORD_CHANGE),
	ENUM(RESP_PASSWORD_CHANGE_BAD_PASSWORD),

	// contact list operations
	ENUM(REQ_CONTACT_ADD),
	ENUM(REQ_CONTACT_DEL),
	ENUM(REQ_CONTACT_STATUS_CHANGE),

	// messaging
	ENUM(REQ_MESSAGE_SEND),
	ENUM(REQ_MESSAGE_OFFLINE),
	ENUM(RESP_MESSAGE_STORED),
	ENUM(REQ_MESSAGE_STORED_READ),
	ENUM(RESP_MESSAGE_ERR_DECRYPT),
	ENUM(REQ_MESSAGE_SEND_DH),

	// PK/DH related
	ENUM(REQ_GET_PUBLIC_KEY),
	ENUM(RESP_PUBLIC_KEY_NONE),
	ENUM(REQ_DH_SENDPARAMS),

	// Call related
	ENUM(REQ_CALL), // call step 1, to server
	ENUM(REQ_CALL_HANGUP),
	// these are returned from the calee
	ENUM(RESP_CLIENT_BUSY),
	ENUM(RESP_CALL_OK),
	ENUM(RESP_CALL_REJECTED),

	ENUM(RESP_PACKET_FORWARDED),
	ENUM(RESP_ERR_PACKET_FORWARD),

	ENUM(RESP_MSG_UNKNOWN_CLIENT_ERROR),

	ENUM(REQ_PUBKEY_UPLOAD),

	// generic responses
	ENUM(RESP_OK),
	ENUM(RESP_ERR_NOSUCHUSER),
	ENUM(RESP_ERR_USEROFFLINE),
	ENUM(RESP_ERR_DUPLICATE),
	ENUM(RESP_ERR_MYSELF),
	ENUM(RESP_ERR_NOT_IMPLEMENTED),
	ENUM(RESP_ERR_TEMPORARY), // means that user should try again later
	ENUM(RESP_UNKNOWN_SERVER_ERROR),
	ENUM(RESP_UNKNOWN_CLIENT_ERROR),

	ENUM(RESP_P2P_UNKNOWN_ERROR),
	ENUM(RESP_UNKNOWN_PACKET_ERROR),
	ENUM(RESP_ERR_PACKET_TOO_BIG)
ENUM_END( PacketTypes )
