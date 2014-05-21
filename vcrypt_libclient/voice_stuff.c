/*
 * voice_stuff.c
 *
 *      Author: 655518d74018d1215d9d5a8597a99cba
 */

//while (ctx->flag_thread_status == THREAD_RUNNING && 0) {
//	FD_ZERO(&sock_fds_r);
//	FD_ZERO(&sock_fds_w);
//
//	if (ctx->socket_server > 0)
//	FD_SET(ctx->socket_server, &sock_fds_r);
//	if (ctx->socket_p2p)
//	FD_SET(ctx->socket_p2p, &sock_fds_r);
//
//	struct timeval timeout;
//	timeout.tv_sec = 0;
//	timeout.tv_usec = 1000;
//
//	if (ctx->call_ctx.status == CALL_STATUS_AUDIO) {
//		// check for timeout
//		if (time_passed_ms(
//						ctx->call_ctx.packet_receive_time_ms) > VCRYPT_TIMEOUT_CALL) {
//			client_close_call(ctx);
//			fprintf(stderr, "call timeout\n");
//			continue;
//		}
//
//		// check if we have the needed number of frames
//		//			if (fifo_bytes_available(ctx->audio_fifo_send)
//		//					>= (ctx->codec_samples * ctx->channels
//		//							* (int) sizeof(int16_t))) {
//		//				FD_SET(ctx->socket_p2p, &sock_fds_w);
//		//			}
//	}
//
//	int events = select(ctx->socket_server + 1, &sock_fds_r, &sock_fds_w,
//			NULL, &timeout);
//
//	// poll() /select() events have priority, queued commands are processed only if there are no other events
//	if (events == 0) {
//		// TODO: do this via POLLOUT
//		// here we process server commands like CALL, PING, and others
//		process_queued_commands(ctx);
//
//		// sending udp hole punching packets, to establish p2p connection
//		if (ctx->call_ctx.status == CALL_STATUS_UDP_HP) {
//			// check for timeout
//			if (time_passed_ms(
//							ctx->call_ctx.start_time_ms) > VCRYPT_TIMEOUT_UDP_HP) {
//				//ctx->callback_notify_error(-ERR_UDP_HOLE_PUNCHING_TIMEOUT);
//				ctx->callback_call_ended(ctx->call_ctx.username,
//						-ERR_UDP_HOLE_PUNCHING_TIMEOUT);
//				client_close_call(ctx);
//			}
//
//			if (time_passed_ms(
//							ctx->call_ctx.packet_sent_time_ms) > VCRYPT_UDP_HP_RESEND) {
//				// todo: use proper way here, like hashes and stuff, also replace this with send_packet
//				sendto(ctx->socket_p2p, &ctx->call_ctx.udp_hp_response, 1,
//						0, (struct sockaddr*) &ctx->call_ctx.p2p_info,
//						sizeof(struct sockaddr_in));
//
//				ctx->call_ctx.packet_sent_time_ms = time_get_ms();
//				ctx->call_ctx.packets_sent++;
//			}
//		}
//
//		if (ctx->call_ctx.status == CALL_STATUS_RINGING) {
//			// this is for both caller and callee
//			if (time_passed_ms(
//							ctx->call_ctx.start_time_ms) > VCRYPT_TIMEOUT_CALLANSWER) {
//				client_close_call(ctx); //TODO: may be we need to pass the reason here
//				fprintf(stderr, "call closed, no answer\n");
//			}
//
//			this is only for caller, it must send a RING command each second, otherwise
//			* the call will be dropped by callee.
//
//			if (ctx->call_ctx.is_caller) {
//				// check if callee answers our ring commands
//				if (time_passed_ms(ctx->call_ctx.ring_packet_received_ms)
//						> 3000) {
//					client_close_call(ctx);
//					fprintf(stderr,
//							"call closed, no answer on RING command\n");
//				}
//
//				// send RING command to callee, each second
//				if (time_passed_ms(ctx->call_ctx.ring_packet_sent_ms)
//						> 1000) {
//					client_send_p2p_command(ctx, P2P_CALL_RING);
//					ctx->call_ctx.ring_packet_sent_ms = time_get_ms();
//				}
//			}
//
//			// check if callee answers our CALL_RING packets with CALL_RINGING
//
//			// this is for callee, if it doesn't receive a P2P_RING packet for X seconds, call is dropped
//			if (!ctx->call_ctx.is_caller
//					&& time_passed_ms(ctx->call_ctx.ring_packet_received_ms)
//					> VCRYPT_TIMEOUT_RING) {
//				client_close_call(ctx);
//				fprintf(stderr,
//						"call dropped because the caller stopped sending RING commands\n");
//			}
//		}
//
//		if (!ctx->call_ctx.is_caller) {
//			if (ctx->call_ctx.status == CALL_STATUS_REJECT) {
//				client_send_p2p_command(ctx, P2P_CALL_REJECT);
//				ctx->callback_call_ended(ctx->call_ctx.username,
//						-ERR_CALL_REJECTED);
//				client_close_call(ctx);
//			}
//
//			if (ctx->call_ctx.status == CALL_STATUS_ACCEPT) {
//				client_send_p2p_command(ctx, P2P_CALL_ACCEPT);
//				ctx->call_ctx.status = CALL_STATUS_RINGING;
//				// the caller must respond with a CALL_ACCEPT packet too
//			}
//		}
//
//		// this is for both parties
//		if (ctx->call_ctx.status == CALL_STATUS_HANGUP) {
//			client_send_p2p_command(ctx, P2P_CALL_HANGUP);
//			client_close_call(ctx);
//			fprintf(stderr, "hangup signal sent\n");
//		}
//
//		continue; // as there are no events anyway
//	} else {
//
//		// handle P2P I/O
//		if (FD_ISSET(ctx->socket_p2p, &sock_fds_r)) {
//			struct sockaddr_in from_addr;
//			socklen_t slen = sizeof(struct sockaddr);
//			// setting bufflen to zero will simply discard the packet
//			int bufflen =
//			(ctx->call_ctx.status == CALL_STATUS_NONE) ?
//			0 : BUFFER_P2P_SIZE;
//
//			int n = recvfrom(ctx->socket_p2p, buffer_p2p, bufflen, 0,
//					(struct sockaddr*) &from_addr, &slen);
//
//			if (bufflen && n >= BUFFER_P2P_SIZE) {
//				fprintf(stderr,
//						"WARNING: The read buffer is completely full, some data may be lost!\n");
//			}
//
//			//			fprintf(stderr, "recvfrom: %s:%d (%d bytes)\n",
//			//			        inet_ntoa(from_addr.sin_addr), ntohs(from_addr.sin_port),
//			//			        n);
//
//			// TODO: remove this...
//			if (ctx->call_ctx.status == CALL_STATUS_NONE) {
//				fprintf(stderr,
//						"packet discarded due to no call context\n");
//				continue;
//			}
//
//			if (!packet_matches_callctx(ctx, &from_addr)) {
//				fprintf(stderr,
//						"packet discarded due to wrong sender address\n");
//				continue;
//			}
//
//			ctx->call_ctx.packet_receive_time_ms = time_get_ms();
//
//			if (ctx->call_ctx.status == CALL_STATUS_UDP_HP) {
//				// we got a packet form the other party
//				ctx->call_ctx.udp_hp_response = 1;
//
//				// if the other party says it got response too
//				if (buffer_p2p[0]) {
//					// At this point, ringing starts
//					ctx->call_ctx.status = CALL_STATUS_RINGING;
//					// use start as new reference for call answer timeout
//					ctx->call_ctx.start_time_ms = time_get_ms();
//				}
//
//				// TODO: use send_command()
//				sendto(ctx->socket_p2p, &ctx->call_ctx.udp_hp_response, 1,
//						0, (struct sockaddr*) &ctx->call_ctx.p2p_info,
//						sizeof(struct sockaddr_in));
//
//				ctx->call_ctx.packet_sent_time_ms = time_get_ms();
//				ctx->call_ctx.ring_packet_received_ms =
//				ctx->call_ctx.packet_sent_time_ms;
//				ctx->call_ctx.packets_sent++;
//			} else if (ctx->call_ctx.status == CALL_STATUS_RINGING) {
//				if (ctx->call_ctx.is_caller) {
//					// replies for caller
//					switch (((P2P_PACKET*) buffer_p2p)->type)
//					{
//						case P2P_CALL_RINGING:
//						ctx->call_ctx.ring_packet_received_ms =
//						time_get_ms();
//						break;
//						case P2P_CALL_ACCEPT:
//						client_send_p2p_command(ctx, P2P_CALL_ACCEPT);
//						ctx->call_ctx.status = CALL_STATUS_AUDIO;
//						ctx->call_ctx.packet_nr_recv = 0;
//						ctx->call_ctx.packet_nr_sent = 0;
//						// tell the GUI the call is accepted
//						ctx->callback_call_answered(ctx->call_ctx.username);
//						break;
//						case P2P_CALL_REJECT:
//						ctx->callback_call_ended(ctx->call_ctx.username,
//								-ERR_CALL_REJECTED);
//						// tell the GUI the call is rejected
//						client_close_call(ctx);
//						break;
//						case P2P_CALL_HANGUP:
//						client_close_call(ctx);
//						break;
//					}
//				} else {
//					// replies for callee
//					switch (((P2P_PACKET*) buffer_p2p)->type)
//					{
//						case P2P_CALL_RING: // caller still ringing
//						client_send_p2p_command(ctx, P2P_CALL_RINGING);// notify the caller we are ringing
//						ctx->call_ctx.ring_packet_received_ms =
//						time_get_ms();
//						break;
//						case P2P_CALL_HANGUP:// caller hung up
//						client_close_call(ctx);
//						break;
//						case P2P_CALL_ACCEPT:
//						ctx->call_ctx.status = CALL_STATUS_AUDIO;
//						ctx->call_ctx.packet_nr_recv = 0;
//						ctx->call_ctx.packet_nr_sent = 0;
//						//ctx->callback_notify_error(-ERR_CALL_STARTED);
//						ctx->callback_call_answered(ctx->call_ctx.username);
//						break;
//					}
//				}
//			} else if (ctx->call_ctx.status == CALL_STATUS_AUDIO) {
//				switch (((P2P_PACKET*) buffer_p2p)->type)
//				{
//					case P2P_CALL_HANGUP:
//					//ctx->callback_notify_error(-ERR_CALL_HANGUP);
//					client_close_call(ctx);
//					fprintf(stderr, "hangup signal received\n");
//					break;
//					case P2P_CALL_AUDIO:
//					if (ctx->call_ctx.status == CALL_STATUS_AUDIO)
//					client_receive_audio_from_socket(ctx, buffer_p2p,
//							n);
//					break;
//				}
//			} else {
//				fprintf(stderr,
//						"packet discarded due to no call context\n");
//			}
//		}
//
//		if (FD_ISSET(ctx->socket_p2p, &sock_fds_w)) {
//			if (ctx->call_ctx.status == CALL_STATUS_AUDIO) {
//				if (fifo_bytes_available(ctx->audio_fifo_send)
//						>= ctx->codec_samples * ctx->channels
//						* (int) sizeof(int16_t)) {
//					client_send_audio_to_socket(ctx);
//				}
//			}
//		}
//
//		//		else if (fds[1].revents != 0) {
//		//			// somehow this is never reached
//		//			fprintf(stderr, "error p2p: %d\n", fds[1].revents);
//		//		}
//	}
//}

