enum VCRYPT_ERROR {
	// "SUCCESS: No error"
	ERR_SUCCESS, 
	// "Disconnect success"
	ERR_DISCONNECT_SUCCESS, 
	// "Operation queued"
	ERR_MSG_QUEUED, 
	// "Operation in progress, server acknowledged"
	ERR_INPROGRESS_SERVER, 
	// "Operation in progress, receiver acknowledged"
	ERR_MSG_INPROGRESS_CALEE, 
	// "Ping OK"
	ERR_PING_SERVER_OK, 
	// "ERROR: Connection failure"
	ERR_CONNECTION_FAILURE, 
	// "ERROR: Could not initialize TLS"
	ERR_CONNECTION_SSL_INIT_FAILURE, 
	// "ERROR: TLS handshake failed"
	ERR_CONNECTION_SSL_HANDSHAKE_FAILURE, 
	// "ERROR: Server dropped the connection"
	ERR_SERVER_DISCONNECT, 
	// "ERROR: Timeout while reading from server"
	ERR_SERVER_TIMEOUT, 
	// "ERROR: Not connected to the server"
	ERR_SERVER_NOTCONNECTED, 
	// "ERROR: Already connected"
	ERR_SERVER_ALREADY_CONNECTED, 
	// "ERROR: P2P socket already exists"
	ERR_P2P_SOCKET_EXISTS, 
	// "ERROR: Wrong username or password"
	ERR_REGISTER_AUTH_FAILURE, 
	// "ERROR: Unsupported client version, please upgrade"
	ERR_REGISTER_UNSUPPORTED_VERSION, 
	// "ERROR: Already logged in"
	ERR_REGISTER_ALREADY_LOGGED, 
	// "ERROR: No such user"
	ERR_NOSUCHUSER, 
	// "ERROR: User is offline"
	ERR_USER_OFFLINE, 
	// "ERROR: Can't create server socket"
	ERR_SERVER_SOCKET, 
	// "ERROR: Bad packet received"
	ERR_BAD_PACKET, 
	// "ERROR: The message is too big"
	ERR_PACKET_TOO_BIG, 
	// "ERROR: Can't resolve hostname"
	ERR_HOST_RESOLVE, 
	// "ERROR: Can't create p2p socket"
	ERR_P2P_SOCKET, 
	// "ERROR: Can't allocate memory"
	ERR_MALLOC, 
	// "ERROR: Debug error"
	ERR_DEBUG_ERROR, 
	// "ERROR: Unknown error"
	ERR_UNKNOWN_ERROR, 
	// "ERROR: Packet queue full"
	ERR_QUEUE_FULL, 
	// "ERROR: Parameter can't be null"
	ERR_PARAM_ISNULL, 
	// "ERROR: Unexpected packet received, no match in queue"
	ERR_UNEXPECTED_PACKET, 
	// "ERROR: Could not setup the rec codec"
	ERR_CODEC_REC_SETUP, 
	// "ERROR: Could not setup the play codec"
	ERR_CODEC_PLAY_SETUP, 
	// "ERROR: Could not setup the rec resampler"
	ERR_RESAMPLER_REC_SETUP, 
	// "ERROR: Could not setup the play resampler"
	ERR_RESAMPLER_PLAY_SETUP, 
	// "ERROR: Recording sample rate is not supported"
	ERR_UNSUPPORTED_REC_SAMPLERATE, 
	// "ERROR: Playing rate is not supported"
	ERR_UNSUPPORTED_PLAY_SAMPLERATE, 
	// "ERROR: Could not start audio"
	ERR_UNKNOWN_AUDIO_PROBLEM, 
	// "ERROR: Timeout while sending the command"
	ERR_QUEUE_LOCAL_TIMEOUT, 
	// "ERROR: Timeout while waiting server response"
	ERR_QUEUE_SERVER_TIMEOUT, 
	// "ERROR: Timeout while waiting client response"
	ERR_QUEUE_CLIENT_TIMEOUT, 
	// "ERROR: Temporary error, try again later"
	ERR_TEMPORARY_ERROR, 
	// "ERROR: No valid RSA keys"
	ERR_RSA_NO_KEYS, 
	// "ERROR: Could not generate RSA keys"
	ERR_RSA_ERROR_GENERATING_KEYS, 
	// "ERROR: Could not load RSA keys"
	ERR_RSA_ERROR_LOADING_KEYS, 
	// "ERROR: Can not sync public key to the server"
	ERR_PUBKEY_SYNC, 
	// "ERROR: User's public key not present"
	ERR_NO_PUBKEY, 
	// "ERROR: DH key is not negociated"
	ERR_NO_DHKEY, 
	// "Downloading user's public key"
	ERR_DOWNLOADING_PUBKEY, 
	// "Negotiating DH key"
	ERR_DHKEY_NEGOTIATING, 
	// "ERROR: Could not encrypt the message"
	ERR_ENCRYPTION_ERROR, 
	// "ERROR: Could not decrypt the message"
	ERR_DECRYPTION_ERROR, 
	// "Message stored on server"
	ERR_MESSAGE_STORED, 
	// "ERROR: Could not sign the message"
	ERR_SIGN_ERROR, 
	// "ERROR: Wrong RSA signature"
	ERR_SIGN_VERIFY_ERROR, 
	// "ERROR: Password can't be empty"
	ERR_PASSWORD_EMPTY, 
	// "ERROR: Passwords don't match"
	ERR_PASSWORD_NOMATCH, 
	// "ERROR: New password can't be the same with the old one"
	ERR_PASSWORD_SAMEASOLD, 
	// "ERROR: This password can't be accepted by server, use another one"
	ERR_PASSWORD_BAD, 
	// "ERROR: Can't write packet"
	ERR_PACKET_WRITE, 
	// "ERROR: Can't write to file"
	ERR_FILE_WRITE, 
	// "ERROR: Can't read from file"
	ERR_FILE_READ, 
	// "Packet must be postponed"
	ERR_POSTPONE_PACKET, 
	// "Operation already in progress"
	ERR_INPROGRESS, 
	// "Not implemented"
	ERR_NOT_IMPLEMENTED, 
	// "Call initiated"
	ERR_CALL_SENT, 
	// "Call received"
	ERR_CALL_RECEIVED, 
	// "Call rejected"
	ERR_CALL_REJECTED, 
	// "Call answered"
	ERR_CALL_ANSWERED, 
	// "Hang-up"
	ERR_CALL_HANGUP, 
	// "Status not changed"
	ERR_CALL_MAINTAINSTATUS, 
	// "Punching UDP hole"
	ERR_CALL_UDP_HP, 
	// "ERROR: Timeout while waiting for call answer"
	ERR_CALLANSWER_TIMEOUT, 
	// "ERROR: A call is already in progress"
	ERR_CALL_INPROGRESS, 
	// "ERROR: UDP hole punching timeout"
	ERR_UDP_HOLE_PUNCHING_TIMEOUT, 
	// "ERROR: Audio timeout"
	ERR_CALL_AUDIO_TIMEOUT, 
	// "ERROR: Not allowed to call itself"
	ERR_MSG_CALLINGITSELF, 
	// "ERROR: User busy"
	ERR_CLIENT_CALLBUSY, 
	// "ERROR: Call dropped"
	ERR_CALL_DROPPED, 
	// "ERROR: No ringing call to answer/reject"
	ERR_CALL_NOT_RINGING, 
	// "ERROR: No active call"
	ERR_CALL_NO_ACTIVE_CALL, 
	// "ERROR: The other party hanged up"
	ERR_CALL_OTHER_HANGUP, 
};
