/* 
clear ; gcc /home/user/Code/TorX/src/core/libevent2.c -levent_core -o /tmp/libevent2 && /./tmp/libevent 2

cd /usr/include/event2/ ; grep -a EV_PERSIST *
cd /usr/include/event2/ ; grep -a evbuffer_free *

re: evbuffer_lock "You only need to lock the evbuffer manually when you have more than one operation that need to execute without another thread butting in." https://libevent.org/libevent-book/Ref7_evbuffer.html

XXX	To Do		XXX
	* having functions that read/write file data to disk on the same thread as libevent might be a bottleneck, considering the presumably limited buffer size of sockets
	* test sending the same file to multiple people at once. not sure what will happen. should be OK because they have different .fd
	* delete SING from file without taking down ( takedown_onion(onion,2); ) after receiving connection. Ensures that no funny business can happen. Then takedown_onion(onion,0); after handshake.
	* we noted that some messages get sent on sockets that are in fact down (but tor binary doesn't know it yet)
		if such connections are always going to be reported as successful, then our only option is to require a byte of return receipt.

*/

//TODO: Stop libevent from taking more than the required number of bytes on sing/mult connections. I think it could hypothetically buffer up to 4096 bytes? (hard coded)
// It should break the connection immediately if it receives too many bytes.

//TODO: see "KNOWN BUG:" On a successful sing or MULT, the socket does not close due to the CTRL coming up. It is not the same socket nor the same port. We don't know what is going on.
// Something to do with serv_init being a child process, I think. The socket doesn't close until the child process that called it ends.

static void peer_online(const int n)
{ // Internal Function only. Use the callback. Note: We store our onion rather than peeronion because this will be checked on initiation where peeronion won't be ready yet.
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner != ENUM_OWNER_CTRL && owner != ENUM_OWNER_GROUP_PEER)
		return; // not CTRL
	const time_t last_seen = time(NULL); // current time
	setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
	peer_online_cb(n);
	if(threadsafe_read_uint8(&mutex_global_variable,&log_last_seen) == 1)
	{
		char p1[21];
		snprintf(p1,sizeof(p1),"%ld",last_seen);
		const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
		sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
	}
	if(threadsafe_read_uint8(&mutex_global_variable,&auto_resume_inbound)) // XXX Experimental 2023/10/29: Might need to prevent FILE_REQUEST from being sent when we are potentially already receiving data... not sure if this will be an issue
		for(int f = 0; getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size)) > 0; f++)
		{
			const uint8_t file_status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
			if(file_status == ENUM_FILE_INBOUND_ACCEPTED) // re-send request for previously accepted file
		//	{
		//		printf("Checkpoint ENUM_PROTOCOL_FILE_REQUEST 3 n==%d\n",n);
				file_request_internal(n,f);
		//	}
		}
}

static void disconnect_forever(struct bufferevent *bev, void *ctx)
{ // Do NOT call from out of libevent thread. TODO find a way to call from takedown_onion
	error_simple(0,YELLOW"Checkpoint disconnect_forever"RESET);
	if(ctx)
	{
		struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
		const int n = event_strc->n;
		const int8_t fd_type = event_strc->fd_type;
		peer_offline(n,fd_type); // internal callback
	}
	bufferevent_free(bev); // call before each event_base_loopexit() *and* after each close_conn() or whenever desiring to close a connection and await a new accept_conn
	event_base_loopexit(bufferevent_get_base(bev), NULL);
}

/*void enter_thread_to_disconnect_forever(evutil_socket_t fd,short event,void *arg)
{
	error_printf(YELLOW"Checkpoint enter_thread_to_disconnect_forever"RESET);
	(void) fd;
	(void) event;
	struct bufferevent *bev_recv = (struct bufferevent*)arg;
	disconnect_forever(bev_recv,NULL);
}*/

static inline void pipe_auth_and_request_peerlist(const int n)
{ // Send ENUM_PROTOCOL_PIPE_AUTH && ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST
	char peeronion[56+1];
	getter_array(&peeronion,sizeof(peeronion),n,INT_MIN,-1,-1,offsetof(struct peer_list,peeronion));
	message_send(n,ENUM_PROTOCOL_PIPE_AUTH,peeronion,PIPE_AUTH_LEN);
	sodium_memzero(peeronion,sizeof(peeronion));
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_PEER)
	{ // sanity check, more or less.
		const int g = set_g(n,NULL);
		const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		const uint32_t trash = htobe32(peercount);
		message_send(n,ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,&trash,sizeof(trash));
	}
	else
		printf(RED"Checkpoint pipe_auth_and_request_peerlist CTRL\n"RESET);
}

static inline int pipe_auth_inbound(const int n,const int8_t fd_type,const char *buffer,const uint32_t buffer_len)
{ // Handle Inbound ENUM_PROTOCOL_PIPE_AUTH. Returns n if valid, or -1 if invalid. Relies on message being signed.
	int ret = -1;
	char onion_group_n[56+1];
	getter_array(&onion_group_n,sizeof(onion_group_n),n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
	if(fd_type == 0 && buffer_len == PIPE_AUTH_LEN + crypto_sign_BYTES && !memcmp(onion_group_n,buffer,56))
		ret = n;
	sodium_memzero(onion_group_n,sizeof(onion_group_n));
	return ret;
}

static inline void begin_cascade_recv(const int n)
{
	const int max_i = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,min_i));
	for(int i = min_i; i <= max_i; i++)
	{
		const uint8_t stat = getter_uint8(n,i,-1,-1,offsetof(struct message_list,stat));
		const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
		if(p_iter > -1)
		{ // important check, to snuff out deleted messages
			pthread_rwlock_rdlock(&mutex_protocols);
			const uint8_t stream = protocols[p_iter].stream;
			pthread_rwlock_unlock(&mutex_protocols);
			if(stat == ENUM_MESSAGE_FAIL && stream == 0)
				if(!send_prep(n,i,p_iter,0)) // Will do nothing if there are no messages to send
					break; // allow cascading effect in output_cb
		}
	}
}

static inline size_t packet_removal(const int n,const int8_t fd_type,const size_t drain_len)
{
	size_t drained = 0;
	time_t time_oldest = LONG_MAX; // must initialize as a very high value
	time_t nstime_oldest = LONG_MAX; // must initialize as a very high value
	int o_oldest = -1;
	pthread_rwlock_wrlock(&mutex_packet);
	for(uint8_t cycle = 0 ; cycle < 2 ; cycle++)
		for(int o = 0 ; o <= highest_ever_o ; o++)
		{
			const int packet_n = packet[o].n;
			const int8_t packet_fd_type = packet[o].fd_type;
			if(packet_n == n && packet_fd_type == fd_type)
			{ // Found a potential winner, now see if it is oldest before handling
				if(o != o_oldest)
				{ // Occurs every o on cycle 0, or when not the oldest on cycle 1
					if(time_oldest > packet[o].time || (time_oldest == packet[o].time && nstime_oldest > packet[o].nstime))
					{ // This packet is older than the current oldest. ( can only ever trigger on cycle 0 )
						time_oldest = packet[o].time;
						nstime_oldest = packet[o].nstime;
						o_oldest = o;
					}
					continue;
				}
				const int p_iter = packet[o].p_iter;
				const int packet_f_i = packet[o].f_i;
				const uint16_t packet_len = packet[o].packet_len;
				const uint64_t packet_start = packet[o].start;
				packet[o].n = -1; // release it for re-use.
				packet[o].f_i = INT_MIN; // release it for re-use.
				packet[o].packet_len = 0; // release it for re-use.
				packet[o].p_iter = -1; // release it for re-use.
				packet[o].fd_type = -1; // release it for re-use.
				packet[o].start = 0; // release it for re-use.
				packet[o].time = 0;
				packet[o].nstime = 0;
				pthread_rwlock_unlock(&mutex_packet);
				time_oldest = 0;
				nstime_oldest = 0;
				o_oldest = -1;
				drained += packet_len;
				if(!drain_len)
				{ // For drain_len, we don't do anything except 0 the packets above
					pthread_rwlock_rdlock(&mutex_protocols);
					const uint16_t protocol = protocols[p_iter].protocol;
					const uint8_t stream = protocols[p_iter].stream;
					const char *name = protocols[p_iter].name;
					pthread_rwlock_unlock(&mutex_protocols);
					if(protocol == ENUM_PROTOCOL_FILE_PIECE)
					{
						const int f = packet_f_i;
						torx_write(n) // XXX
						peer[n].file[f].outbound_transferred[packet_fd_type] += packet_len-16;
						torx_unlock(n) // XXX
						const uint64_t transferred = calculate_transferred(n,f);
						torx_read(n) // XXX
						uint8_t file_status = peer[n].file[f].status;
						const uint64_t current_pos = peer[n].file[f].outbound_start[fd_type] + peer[n].file[f].outbound_transferred[fd_type];
						const uint64_t current_end = peer[n].file[f].outbound_end[fd_type]+1;
						torx_unlock(n) // XXX
						if(current_pos == current_end)
						{
							error_printf(0,"Outbound File Section Completed on fd_type=%d",fd_type);
							if(fd_type == 0)
								close_sockets(n,f,peer[n].file[f].fd_out_recvfd)
							else /* fd_type == 1 */
								close_sockets(n,f,peer[n].file[f].fd_out_sendfd)
							const uint64_t size = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size));
							if(transferred >= size) // All Requested Sections Fully Completed
							{
								if(transferred > size) // 2024/03/20 + 2024/05/26(+482 bytes) Occured after a bunch of restarts. Reason unknown. File not corrupted.
									error_printf(0,"Checkpoint output_cb exceeded size of file by %lu bytes",transferred - size);
								file_status = ENUM_FILE_OUTBOUND_COMPLETED;
								setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&file_status,sizeof(file_status));
							}
							transfer_progress(n,f,transferred);
						}
						else if(file_status == ENUM_FILE_OUTBOUND_ACCEPTED)
						{
							transfer_progress(n,f,transferred); // probably best to have this *before* send_prep, but it might not matter
							send_prep(n,f,p_iter,fd_type); // sends next packet on same fd, or closes it
						}
					}
					else
					{ // All protocols that contain a message size on the first packet of a message
						const int i = packet_f_i;
						torx_write(n) // XXX Warning: don't use getter/setter for ++/+= operations. Increases likelihood of race condition.
						if(packet_start == 0) // first packet of a message, has message_len prefix
							peer[n].message[i].pos += packet_len - (2+2+4);
						else // subsequent packet (ie, second or later packet in a message > PACKET_SIZE_MAX)
							peer[n].message[i].pos += packet_len - (2+2);
						const uint32_t message_len = peer[n].message[i].message_len;
						const uint32_t pos = peer[n].message[i].pos;
						torx_unlock(n) // XXX
						if(pos == message_len)
						{ // complete message, complete send
							carry_on_regardless: {}
							if(stream)
							{ // discard/delete message and attempt rollback
								torx_write(n) // XXX
								zero_i(n,i);
								torx_unlock(n) // XXX
							/*	printf("Checkpoint actually deleted group_peer's i\n");
								// TODO we should zero the group_n's message, but we don't know when to do it. Can't do it in message_send, and its hard to do here because we don't know how many group_peers its going out to.
								// TODO give up and hope group_msg and stream rarely go together? lets wait for it to become a real problem. TODO see: sfaoij2309fjfw */
							}
							else
							{
								const uint8_t stat = ENUM_MESSAGE_SENT;
								setter(n,i,-1,-1,offsetof(struct message_list,stat),&stat,sizeof(stat));
								sql_update_message(n,i);
								print_message_cb(n,i,2);
								if(protocol == ENUM_PROTOCOL_KILL_CODE)
								{
									error_simple(1,"Successfully sent a kill code. Deleting peer.");
									const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
									takedown_onion(peer_index,1);
									error_simple(0,"TODO should probably return here to avoid actions on deleted n.1");
								//	disconnect_forever(peer [n]. bev_send); // this prevents the send from finishing, so instead we rely on connection error to break libevent main loop
								}
							}
							torx_write(n) // XXX
							peer[n].socket_utilized[fd_type] = -1;
							torx_unlock(n) // XXX
							error_printf(0,WHITE"output_cb  peer[%d].socket_utilized[%d] = -1"RESET,n,fd_type);
							error_printf(0,CYAN"OUT%d-> %s %u"RESET,fd_type,name,message_len);
							if(protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
								pipe_auth_and_request_peerlist(n); // this will trigger cascade // send ENUM_PROTOCOL_PIPE_AUTH
							else
							{
								const int max_i = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,max_i));
								for(int next_i = i+1; next_i <= max_i ; next_i++)
								{
									const uint8_t next_stat = getter_uint8(n,next_i,-1,-1,offsetof(struct message_list,stat));
									const int next_p_iter = getter_int(n,next_i,-1,-1,offsetof(struct message_list,p_iter));
									if(next_stat == ENUM_MESSAGE_FAIL && next_p_iter > -1)
										if(!send_prep(n,next_i,next_p_iter,fd_type))
											break; // cascading effect
								}
							}
						}
						else if(pos > message_len)
						{ // 2024/05/04 This is happening when massive amounts of sticker requests come in on same peer. Unknown reason. Possibly caused by race on deleted (stream) i.
							error_printf(0,PINK"output_cb reported message pos > message_len: %u > %u. Protocol: %s. Likely will corrupt message. Packet len was %u. Coding error. Report this."RESET,pos,message_len,name,packet_len);
						//	breakpoint(); // not breaking because it can annoyingly lock up UI because GTK sucks
							goto carry_on_regardless; // SOMETIMES prevents illegal read in send_prep (beyond message len)
						}
						else // incomplete message, complete send
						{
						//	printf("Checkpoint partial message, complete send: n=%d i=%d fd=%d packet_len=%u pos=%u of %u\n",n,i,fd_type,packet_len,pos,message_len); // partial incomplete
							printf("."); fflush(stdout);
							send_prep(n,i,p_iter,fd_type); // send next packet on same fd
						}
					}
				}
				o = -1; // see if there are more packets
				pthread_rwlock_wrlock(&mutex_packet);
			}
		}
	pthread_rwlock_unlock(&mutex_packet);
	if(!drained)
		error_simple(0,"Remove packet failed to remove anything. Coding error. Report this.");
	else if(drain_len && drained != drain_len)
		error_printf(0,"Remove packet drained less than expected: %lu != %lu. Coding error. Report this.",drained,drain_len);
	return drained;
}

static inline void output_cb(void *ctx)
{ // Note: A *lot* of redundancy with packet_removal()
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	packet_removal(event_strc->n,event_strc->fd_type,0);
}

static void write_finished(struct bufferevent *bev, void *ctx)
{ /* This write callback is triggered when write buffer has depleted (bufferevent.h) */ // It follows read_conn()
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const int n = event_strc->n;
	output_cb(ctx);
	const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{
		disconnect_forever(bev,ctx); // Run last, will exit event base
		error_simple(0,"Peer is not a friend. Disconnecting from write_finished.");
		return;
	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
	{
		if(event_strc->fresh_n > -1) // sanity check of n returned by load_onion()
		{
			const uint8_t status_fresh = getter_uint8(event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peeronion));
			if(status_fresh == ENUM_STATUS_FRIEND)
				error_printf(3,"Handshake occured. Peer saved as %s on friends list.",peeronion);
			else if(status_fresh == ENUM_STATUS_PENDING)
			{
				error_printf(3,"Handshake occured. Peer saved as %s on pending list.",peeronion);
				incoming_friend_request_cb(event_strc->fresh_n);
			}
			const uint16_t peerversion = getter_uint16(event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion));
			char privkey[88+1];
			getter_array(&privkey,sizeof(privkey),event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,privkey));
			char peernick[56+1];
			getter_array(&peernick,sizeof(peernick),event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
			const int peer_index_fresh = sql_insert_peer(ENUM_OWNER_CTRL,status_fresh,peerversion,privkey,peeronion,peernick,0);
			sodium_memzero(peernick,sizeof(peernick));
			sodium_memzero(peeronion,sizeof(peeronion));
			sodium_memzero(privkey,sizeof(privkey));
			setter(event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index),&peer_index_fresh,sizeof(peer_index_fresh));
			sql_update_peer(event_strc->fresh_n);
			peer_new_cb(event_strc->fresh_n);
		}
		if(owner == ENUM_OWNER_SING) //do not call disconnect_forever(bev); need to respond
		{
			const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
			takedown_onion(peer_index,1); // XXX NOTE: n is just going to show 000000 after takedown(onion,1) and be useless.
			disconnect_forever(bev,ctx);
		}
	}
}

static void close_conn(struct bufferevent *bev, short events, void *ctx)
{ /* Peer closes connection, or we do. (either of us closes software) */
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const int n = event_strc->n;
	const int8_t fd_type = event_strc->fd_type;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
	error_printf(0,YELLOW"Close_conn: n=%d fd_type=%d owner=%u status=%u"RESET,n,fd_type,owner,status);
	if(events & BEV_EVENT_ERROR)
	{ // 2024/02/20 happened during outbound file transfer when peer (or we) went offline
		error_simple(0,"Error from bufferevent caused connection closure."); // 2023/10/30 occurs when a peer went offline during file transfer
	//	breakpoint(); XXX REMOVING because was_inbound_transferring is typically 0 when we are doing outbound transfer, and this error still occurs XXX
	}
	else if(events & BEV_EVENT_EOF) 
		error_simple(3,"Peer sent EOF, indicating that they closed connection."); // TODO 2022/08/12: "Error caused closed on 0000", after inbound handshake on our sing
	else // not an error but maybe we can use this
		error_simple(2,"Some unknown type of unknown close_conn() occured.");

	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER) // not GROUP_CTRL because CTRL never goes offline
	{
		error_simple(2,"Connection closed by peer.");
		peer_offline(n,fd_type); // internal callback
	}
	else if(owner == ENUM_OWNER_SING) // NOTE: this doesnt trigger for successful handshakes because .owner becomes 0000
	{
		error_simple(0,"Spoiled onion due to close.");
		const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
		takedown_onion(peer_index,3);
		disconnect_forever(bev,ctx); // Run last, will exit event base
	}
	section_unclaim(n,-1,-1,fd_type); // MUST be AFTER peer_offline
	if(fd_type == 1)
	{ // Fix issues caused by unwanted resumption of inbound PM transfers
		struct evbuffer *output = bufferevent_get_output(bev);
		const size_t to_drain = evbuffer_get_length(output);
		if(to_drain)
		{ // Note: there is an infinately small chance of a race condition by calling packet_removal before ev_buffer_drain. Unavoidable unless we use evbuffer locks.
			printf("Checkpoint draining up to n=%d bytes=%lu\n",n,to_drain);
			const size_t to_actually_drain = packet_removal(n,fd_type,to_drain);
			evbuffer_drain(output,to_actually_drain); // do not pass to_drain because one packet can remain on buffer for ??? reasons
		}
	}
	if(fd_type == 0) // XXX added 2023/09 with authenticated_pipe_n
	{
		torx_free((void*)&event_strc->buffer);
		torx_free((void*)&ctx);
	}
	torx_write(n) // XXX
	if(peer[n].socket_utilized[fd_type] > -1)
	{
		peer[n].socket_utilized[fd_type] = -1;
		error_printf(0,WHITE"close_conn peer[%d].socket_utilized[%d] = -1"RESET,n,fd_type);
	}
	torx_unlock(n) // XXX
	bufferevent_free(bev); // relevant to CTRL and SING, which are the only ones that will hit this. Especially important for CTRL.
}

static void read_conn(struct bufferevent *bev, void *ctx)
{ // Message Received // Followed by write_finished() in the case of incoming friend requests.
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	int n = event_strc->n;
	const int8_t fd_type = event_strc->fd_type;
	const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{ // ENUM_STATUS_FRIEND seems to include active SING/MULT
		error_simple(0,"Pending user or blocked user received unexpected message. Disconnecting. Report this."); // 2024/05/06 Happens on deleted CTRL, of which the RECV connection stays up because we can't find a threadsafe way to call disconnect_forever from takedown_onion
		disconnect_forever(bev,ctx); // Run last, will exit event base
		return; // 2024/03/11 hit this after deleting a group. probably didn't takedown the event properly after group delete
	}
	struct evbuffer *input = bufferevent_get_input(bev);
	const int8_t local_debug = torx_debug_level(-1);
	uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
	{ // Bytes to Read on CTRL
		unsigned char read_buffer[PACKET_SIZE_MAX]; // free'd // == "EVBUFFER_MAX_READ_DEFAULT" variable from libevent. could set this to 64kb to be safe, in case libevent increases one day
		int group_peer_n; // DO NOT USE except for signed group messages
		int group_ctrl_n; // DO NOT USE except for signed group messages
		uint8_t continued = 0;
		uint16_t protocol = 0; // NOTE: Until this is set, it could be 0 or the prior packet's protocol
		uint16_t packet_len = 0;
		while(1)
		{ // not a real while loop, just eliminating goto. Do not attempt to eliminate. We use a lot of 'continue' here.
			group_ctrl_n = group_peer_n = -1;
			if(continued == 1)
			{// we came here from continue, so we should flush out whatever complete (but worthless) packet was in the buffer
				sodium_memzero(read_buffer,packet_len);
				if(protocol != ENUM_PROTOCOL_FILE_PIECE)
				{ // Must not 0 on ENUM_PROTOCOL_FILE_PIECE because it doesn't use buffer/buffer_len. Zeroing will interfere with other protocols which do.
					event_strc->buffer_len = 0;
					torx_free((void*)&event_strc->buffer); // freeing here so we don't have to free before every continue
				}
			}
			continued = 1;
			uint16_t trash_int = 0;
			uint16_t minimum_length = 2+2; // packet length + protocol
			if(evbuffer_get_length(input) < minimum_length || evbuffer_copyout(input,&trash_int,2) != 2)
				return; // too short to get protocol and length
			packet_len = be16toh(trash_int);
			uint16_t cur = 2; // current position, after reading packet len
			if(evbuffer_get_length(input) < (size_t) packet_len)
				return; // not enough data yet, only partial packet. Minimize CPU cycles and allocations before this. Occurs on about 20% of packets without EV_ET and 25% of packets with EV_ET.
			if(packet_len > PACKET_SIZE_MAX)
			{ // Sanity check
				error_simple(0,"Major unexpected problem, either an invalid packet size or an oversized packet. Packet is being discarded."); // \npacket_len:\t%d\ttrash_int:\t%d\n",packet_len,trash_int);
				evbuffer_drain(input,(size_t)packet_len);
				return;
			}
			if(evbuffer_remove(input,read_buffer,(size_t)packet_len) != packet_len) // multiples of PACKET_SIZE_MAX, up to 4096 max, otherwise bytes get lost to the ether.
			{ // This is a libevent bug because we already checked length is sufficient.
				error_simple(0,"This should not occur 12873. should never occur under any circumstances. report this.");
				sodium_memzero(read_buffer,packet_len); // important, could be in a continue or have something sensitive
				breakpoint();
				return;
			}
			protocol = be16toh(align_uint16((void*)&read_buffer[cur]));
			cur += 2; // 2 --> 4
			if(protocol == ENUM_PROTOCOL_FILE_PIECE)
				minimum_length += 4 + 8; // truncated checksum + start
			else if(event_strc->buffer_len == 0)
				minimum_length += 4; // length of message or start (starting position for file piece)
			if(packet_len < minimum_length)
			{ // TODO make protocol specific minimum lengths?
				error_simple(0,"Unreasonably small packet received. Peer likely buggy. Report this.");
				breakpoint();
				return;
			}
			if(owner == ENUM_OWNER_CTRL && fd_type == 0 && event_strc->authenticated == 0 && (protocol != ENUM_PROTOCOL_PIPE_AUTH && protocol != ENUM_PROTOCOL_PROPOSE_UPGRADE))
			{ // NOTE: Do not ever attempt downgrades here or elsewhere. There are many reasons why it is a bad idea.
				error_printf(0,"Unexpected protocol received on ctrl before PIPE_AUTH: %u. Closing.",protocol);
				sodium_memzero(read_buffer,packet_len);
				bufferevent_free(bev); // close a connection and await a new accept_conn
				return;
			}
			else if(owner == ENUM_OWNER_GROUP_CTRL)
			{ // TODO decomplexify this sanity check. make it less expensive/redundant
				const int g = set_g(n,NULL);
				const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
				if((g_invite_required == 1 && (protocol != ENUM_PROTOCOL_PIPE_AUTH && protocol != ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST))
				|| (g_invite_required == 0 && (protocol != ENUM_PROTOCOL_PIPE_AUTH && protocol != ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)))
				{
					error_printf(0,"Unexpected protocol received on group ctrl before PIPE_AUTH: %u. Closing.",protocol);
					sodium_memzero(read_buffer,packet_len);
					bufferevent_free(bev); // close a connection and await a new accept_conn
					return;
				}
			}
			if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			{ // Received Message type: Raw File data // TODO we do too much processing here. this might get CPU intensive.
				int nn = n;
				try_group_n: {}
				const int f = set_f(nn,&read_buffer[cur],4); // find F from truncated_checksum
				cur += 4; // 4 --> 8
				if(f < 0)
				{
					if(n == nn && owner == ENUM_OWNER_GROUP_PEER)
					{
						const int g = set_g(n,NULL);
						nn = getter_group_int(g,offsetof(struct group_list,n));
						cur -= 4; // 8 --> 4 DO NOT DELETE, will break things
						goto try_group_n;
					}
					error_printf(0,"Invalid raw data packet received from owner: %u",owner); // TODO consider blocking peer if this triggers. this peer is probably buggy or malicious.
					continue;
				}
				umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // umask 600 equivalent. man 2 umask
				FILE **fd_active = {0};
				torx_read(nn) // XXX
				if(fd_type == 0) // recvfd, inbound
					fd_active = &peer[nn].file[f].fd_in_recvfd;
				else /* if(fd_type == 1) */ // sendfd, inbound
					fd_active = &peer[nn].file[f].fd_in_sendfd;
				if(!*fd_active)
				{ // Should already be open from file_accept but just in case its not
					error_simple(0,"Re-opening file pointer which we assumed would be open.");
					const char *file_path = peer[nn].file[f].file_path;
					torx_unlock(nn) // XXX
					torx_fd_lock(nn,f) // XXX
					*fd_active = fopen(file_path, "a");
					torx_fd_unlock(nn,f) // XXX
					if(!file_path || *fd_active == NULL)
					{
						error_printf(0,"Failed to open for writing: %s",file_path);
						continue;
					}
					torx_fd_lock(nn,f) // XXX
					fclose(*fd_active); *fd_active = NULL;
					*fd_active = fopen(file_path, "r+");
					torx_fd_unlock(nn,f) // XXX
					if(*fd_active == NULL)
					{
						error_printf(0,"Failed to open for writing2: %s",file_path);
						continue;
					}
				}
				else
					torx_unlock(nn) // XXX
				uint64_t trash_start; // network order
				memcpy(&trash_start,&read_buffer[cur],8);
				cur += 8; // 8 --> 16
				uint64_t packet_start = be64toh(trash_start);
				torx_read(nn) // XXX
				const uint64_t *split_info = peer[nn].file[f].split_info;
				torx_unlock(nn) // XXX
				if(split_info == NULL)
					initialize_split_info(nn,f);
				const uint64_t size = getter_uint64(nn,INT_MIN,f,-1,offsetof(struct file_list,size));
				uint16_t section = 0;
				uint64_t section_start = 0;
				uint64_t section_end = 0;
				const uint8_t splits_nn = getter_uint8(nn,INT_MIN,f,-1,offsetof(struct file_list,splits));
				if(splits_nn == 0)
					section_end = size-1;
				else
				{ // XXX DO NOT MODIFY. This is the result of extensive testing. Can cause big issues if improperly modified. XXX
					uint64_t next_section_start = 0;
					while(packet_start + 1 > (next_section_start = calculate_section_start(size,splits_nn,section + 1)))
						section++;
					section_start = calculate_section_start(size,splits_nn,section);
					section_end = next_section_start - 1;
				}
				torx_read(nn) // XXX
				const int *split_status = peer[nn].file[f].split_status;
				const int8_t *split_status_fd = peer[nn].file[f].split_status_fd;
				const uint64_t section_info_current = peer[nn].file[f].split_info[section];
				torx_unlock(nn) // XXX
				if(packet_start + packet_len-cur > section_end + 1)
				{
					error_simple(0,"Peer asked us to write beyond file size. Buggy peer. Bailing.");
					continue;
				}
				else if(packet_start != section_start + section_info_current)
				{
					error_printf(0,"Peer asked us to write non-sequentially: %lu != %lu + %lu. Could be caused by lost packets or pausing/unpausing rapidly before old stream stopped. Bailing.",packet_start,section_start,section_info_current);
					continue;
				}
				else if(split_status == NULL || split_status_fd == NULL || split_status[section] != n || split_status_fd[section] != fd_type)
				{ // TODO TODO TODO 2024/02/27 this can result in _FILE_PAUSE reply spam. sending a pause (or thousands) isn't a perfect solution.
				//	if(split_status)
				//		printf("Checkpoint split status EXISTS: %d ?= %d\n",split_status[section],n);
				//	if(split_status_fd)
				//		printf("Checkpoint split status_fd EXISTS: %d ?= %d\n",split_status_fd[section],fd_type);
				//	printf("Checkpoint section: %u start==%lu end==%lu\n",section,calculate_section_start(size,splits_nn,section),section_end);
					error_simple(0,"Peer asked us to write to an improper section or to a complete file. This can happen if connections break or when a pause is issued."); // No harm if not excessive. Just discard.
					if(split_status && split_status_fd)
						error_printf(0,"Checkpoint improper: %d %d , n=%d f=%d, section = %d, %d != %d , %d != %d, start position: %lu\n",split_status ? 1 : 0,split_status_fd ? 1 : 0,n,f,section,split_status[section],n,split_status_fd[section],fd_type,packet_start);
					else
						error_printf(0,"Checkpoint improper split_status and/or split_status_fd null\n");
				//	breakpoint();
				/*	if(!sent_pause++)
					{
						unsigned char checksum[CHECKSUM_BIN_LEN];
						getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
						message_send(n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
						sodium_memzero(checksum,sizeof(checksum));
						section_unclaim(n,-1); // we dont know precisely what fd the file_pause will go out on, so unclaim all.
					} */
					continue;
				}
				torx_fd_lock(nn,f) // XXX
				FILE *local = *fd_active;
				torx_fd_unlock(nn,f) // XXX
				fseek(local,(long int)packet_start,SEEK_SET); // TODO bad to cast here
				const size_t wrote = fwrite(&read_buffer[cur],1,packet_len-cur,local);
				torx_fd_lock(nn,f) // XXX
				*fd_active = local;
				torx_fd_unlock(nn,f) // XXX
				section_update(nn,f,packet_start,wrote,fd_type,section,section_end,n);
				if(wrote == 0)
					error_simple(0,"Failed to write a file packet. Check disk space (this message will repeat for every packet).");
				else if(wrote != (size_t) packet_len-cur) // Should inform user that they are out of disk space, or IO error.
					error_simple(-1,"Failed to write a file packet. Check disk space (this message will NOT repeat).");
				const uint8_t file_status = getter_uint8(nn,INT_MIN,f,-1,offsetof(struct file_list,status));
				const uint64_t transferred = calculate_transferred(nn,f);
				if(file_status == ENUM_FILE_INBOUND_ACCEPTED || file_status == ENUM_FILE_INBOUND_COMPLETED)
					transfer_progress(nn,f,transferred); // calling every packet is a bit extreme but necessary. It should handle or we could put an intermediary function.
			}
			else
			{
				const int p_iter = protocol_lookup(protocol);
				if(p_iter < 0)
					goto bad_p_iter;
				pthread_rwlock_rdlock(&mutex_protocols);
				const uint8_t group_mechanics = protocols[p_iter].group_mechanics;
				const uint32_t date_len = protocols[p_iter].date_len;
				const uint32_t signature_len = protocols[p_iter].signature_len;
				const uint8_t file_offer = protocols[p_iter].file_offer;
				const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
				const uint8_t utf8 = protocols[p_iter].utf8;
				const uint8_t group_pm = protocols[p_iter].group_pm;
				const uint8_t group_msg = protocols[p_iter].group_msg;
				const uint8_t stream = protocols[p_iter].stream;
				const char *name = protocols[p_iter].name;
				pthread_rwlock_unlock(&mutex_protocols);
				if(p_iter < 0 || (owner != ENUM_OWNER_GROUP_CTRL && owner != ENUM_OWNER_GROUP_PEER && (group_mechanics || group_pm)))
				{
					if(group_pm) // TODO delete this check and error message
						error_simple(0,"Checkpoint message was group_pm. If this triggers in 2024/05, remove group_pm check above and verify elsewhere");
					bad_p_iter: {}
					error_printf(0,"Unknown protocol message received (%u) on Owner (%u) and n (%d). User should be notified.",protocol,owner,n); // Should find the length and send this to front-end in a callback:
				}
				else
				{ // Process messages
					int8_t complete = 0; // if incomplete, do not print it or save it to file yet
					if(event_strc->buffer_len == 0)
					{ // this is only on FIRST PACKET of message // protocol check is a sanity check. it is optional.
					//	printf("Checkpoint setting event_strc->untrusted_message_len = %u\n",event_strc->untrusted_message_len);
						event_strc->untrusted_message_len = be32toh(align_uint32((void*)&read_buffer[cur]));
						cur += 4;
					}
					if(event_strc->buffer_len + (packet_len - cur) == event_strc->untrusted_message_len) // 2024/02/16 can be == , >= is to catch excessive, just in case
						complete = 1;
					else if(event_strc->buffer_len > 0 && event_strc->buffer_len + (packet_len - cur) > event_strc->untrusted_message_len)
					{ // XXX Experiemntal XXX 2023/10/24 should disable this, since it generally can't trigger if we have >= above // 2024/06/20 this triggered with all bad info when we were debugging a race condition elsewhere
						error_printf(0,"Disgarding a corrupted message of protocol: %u, buffer_len: %u, packet_len: %u, cur: %u, untrusted_message_len: %u. Report this for science.",protocol,event_strc->buffer_len,packet_len,cur,event_strc->untrusted_message_len);
						event_strc->buffer_len = 0;
						breakpoint();
						evbuffer_drain(input,evbuffer_get_length(input)); // 2024/03/11 THIS IS RIGHT! It destroys the one/two messages that corrupted us and carries on.
						break;
					}
					// Allocating only enough space for current packet, not enough for .untrusted_message_len , This is slow but safe... could allocate larger blocks though
					if(event_strc->buffer)
						event_strc->buffer = torx_realloc(event_strc->buffer,event_strc->buffer_len + (packet_len - cur));
					else
						event_strc->buffer = torx_secure_malloc(event_strc->buffer_len + (packet_len - cur));
					memcpy(&event_strc->buffer[event_strc->buffer_len],&read_buffer[cur],packet_len - cur); // TODO segfault on 2023/10/26 twice. send a 1 byte file to replicate. segfaulted on 2023/11/22 also, on larger file
					event_strc->buffer_len += packet_len - cur;
					if(complete) // XXX XXX XXX NOTE: All SIGNED messages must be in the COMPLETE area. XXX XXX XXX
					{ // This has to be after the file struct is loaded (? what?)
						if(event_strc->buffer_len < null_terminated_len + date_len + signature_len)
						{
							error_printf(0,"Unreasonably short message received from peer. Discarding entire message protocol: %u owner: %u size: %u of reported: %u",protocol,owner,event_strc->buffer_len,event_strc->untrusted_message_len);
							continue;
						}
						error_printf(0,CYAN"<--IN%d %s %u"RESET,fd_type,name,event_strc->untrusted_message_len);
						if(signature_len)
						{ // XXX Signed and Signed Date messages only
							if(owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER) // XXX adding GROUP_PEER without testing for full duplex
							{ // Check signatures of group messages (unknown sender), then handle any actions that should be taken for specific message types
								const int g = set_g(n,NULL);
								const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
								group_ctrl_n = getter_group_int(g,offsetof(struct group_list,n));
								group_peer_n = group_check_sig(g,event_strc->buffer,event_strc->buffer_len,protocol,(unsigned char *)&event_strc->buffer[event_strc->buffer_len - crypto_sign_BYTES],NULL);
								if(group_peer_n < 0)
									continue; // Disgard if not signed by someone in group TODO notify user? print anonymous message?
								if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
								{ // After receiving this, we should be able to process unsigned messages as having known receiver, on this connection.
									if(owner != ENUM_OWNER_GROUP_CTRL || pipe_auth_inbound(group_ctrl_n,fd_type,event_strc->buffer,event_strc->buffer_len) < 0)
									{
										error_printf(0,"Received a INVALID ENUM_PROTOCOL_PIPE_AUTH on GROUP_CTRL: fd_type=%d owner=%u len=%u",fd_type,owner,event_strc->buffer_len);
										sodium_memzero(read_buffer,packet_len);
										bufferevent_free(bev); // close a connection and await a new accept_conn
										return; // Invalid. Might not hit this because we close buffer.
									}
									// Success. Set recvfd in the appropriate GROUP_PEER to enable full duplex on that GROUP_PEER
									torx_read(n) // XXX Do not mess with this block. (below)
									struct bufferevent *bev_recv = peer[n].bev_recv;
									torx_unlock(n) // XXX
									torx_write(group_peer_n) // XXX
									peer[group_peer_n].bev_recv = bev_recv; // 1st, order important
									torx_unlock(group_peer_n) // XXX
									torx_write(n) // XXX
									peer[n].bev_recv = NULL; // 2nd, order important. do not free.
									torx_unlock(n) // XXX Do not mess with this block. (above.. also some below. This whole thing is important)
									n = group_peer_n; // 3rd, order important. DO NOT PUT SOONER.
									owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner)); // should 100% be ENUM_OWNER_GROUP_PEER ?
									setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd),&event_strc->sockfd,sizeof(event_strc->sockfd)); // important
									const uint8_t recvfd_connected = 1; // important
									setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));
									event_strc->n = n; // important
								} // no need to return here, can carry on evaluating further data in buffer. could continue to avoid storing ENUM_PROTOCOL_PIPE_AUTH in ram
								else if(protocol == ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST) // TODO some rate limiting might be prudent
								{
									if(event_strc->buffer_len != sizeof(uint32_t) + DATE_SIGN_LEN)
									{
										error_simple(0,"Peer sent totally empty REQUEST_PEERLIST. Buggy peer.");
										continue;
									}
									const uint32_t peer_g_peercount = be32toh(align_uint32((void*)event_strc->buffer));
									const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
									if(peer_g_peercount < g_peercount)
									{ // Peer has less in their list than us, lets give them our list
										error_printf(0,"Sending peerlist because %u < %u\n",peer_g_peercount,g_peercount);
										if(g_invite_required)
											message_send(group_peer_n,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(g),GROUP_PEERLIST_PRIVATE_LEN);
										else
											message_send(group_peer_n,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(g),GROUP_PEERLIST_PUBLIC_LEN);
									}
									else
										error_printf(0,"NOT sending peerlist because %u !< %u\n",peer_g_peercount,g_peercount);
								}
								else if(protocol == ENUM_PROTOCOL_GROUP_PEERLIST)
								{ // Audited 2024/02/16 // Format: g_peercount + onions + ed25519 keys + invitation sigs
									if(event_strc->buffer_len < sizeof(uint32_t) + DATE_SIGN_LEN)
									{
										error_simple(0,"Peer sent totally empty PEERLIST. Buggy peer.");
										continue;
									}
									const uint32_t g_peercount = be32toh(align_uint32((void*)event_strc->buffer));
									size_t expected_len;
									if(g_invite_required)
										expected_len = GROUP_PEERLIST_PRIVATE_LEN;
									else
										expected_len = GROUP_PEERLIST_PUBLIC_LEN;
									if(!g_peercount || expected_len + DATE_SIGN_LEN != event_strc->buffer_len)
									{ // Prevent illegal reads from malicious message
										error_simple(0,"Peer sent an invalid sized ENUM_PROTOCOL_GROUP_PEERLIST. Bailing.");
										printf("Checkpoint mystery %u: %lu != %u\n",g_peercount,expected_len,event_strc->buffer_len);
										continue;
									}
									int added_one = 1;
									while(added_one)
									{ // need to re-do the whole loop every time one or more is added because it might have invited someone
										for(uint32_t nnn = 0 ; nnn < g_peercount ; nnn++)
										{ // Try each proposed peeronion...
											added_one = 0;
											const char *proposed_peeronion = &event_strc->buffer[sizeof(int32_t)+nnn*56];
											const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[sizeof(int32_t)+g_peercount*56+nnn*crypto_sign_PUBLICKEYBYTES];
											int ret;
											if(g_invite_required) // pass inviter's signature
											{
												const unsigned char *group_peer_invitation = (unsigned char *)&event_strc->buffer[sizeof(int32_t)+g_peercount*(56+crypto_sign_PUBLICKEYBYTES)+nnn*crypto_sign_BYTES];
											//	printf("Checkpoint invitation/sig in at %lu of %u: %s\n",sizeof(int32_t)+g_peercount*(56+crypto_sign_PUBLICKEYBYTES)+nnn*crypto_sign_BYTES,event_strc->buffer_len,b64_encode(group_peer_invitation,crypto_sign_BYTES));
												ret = group_add_peer(g,proposed_peeronion,NULL,group_peer_ed25519_pk,group_peer_invitation);
											}
											else
												ret = group_add_peer(g,proposed_peeronion,NULL,group_peer_ed25519_pk,NULL);
											if(ret == -1)
											{
												error_simple(0,"Incoming peerlist has errors. Bailing.");
												break;
											}
											else if(ret != -2)
											{ // -2 is "already have it"
												added_one++;
												error_simple(0,RED"Checkpoint New group peer! (read_conn 1)"RESET);
												if(g_invite_required)
													message_send(ret,ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST,itovp(g),GROUP_PRIVATE_ENTRY_REQUEST_LEN);
												else
												{
													unsigned char ciphertext_new[GROUP_BROADCAST_LEN];
													broadcast_prep(ciphertext_new,g);
													message_send(ret,ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,ciphertext_new,GROUP_BROADCAST_LEN);
													sodium_memzero(ciphertext_new,sizeof(ciphertext_new));
												}
											}
										}
									}
								}
							}
							else
							{ // Check signatures of non-group messages (known sender)
							/*	if(be16toh(align_uint16((void*)&event_strc->buffer[event_strc->buffer_len - (sizeof(uint16_t) + crypto_sign_BYTES)])) != protocol)
								{
									error_simple(0,"Signed protocol differs from untrusted protocol. Bailing out without verifying signature. Report this.");
									continue;
								}*/
								unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
								getter_array(&peer_sign_pk,sizeof(peer_sign_pk),n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_sign_pk));
								char *prefixed_message = affix_protocol_len(protocol,event_strc->buffer,event_strc->buffer_len - crypto_sign_BYTES);
								if(crypto_sign_verify_detached((unsigned char *)&event_strc->buffer[event_strc->buffer_len - crypto_sign_BYTES],(unsigned char *)prefixed_message,2+4+event_strc->buffer_len - crypto_sign_BYTES,peer_sign_pk) != 0)
								{
									sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
									error_printf(0,"Invalid signed (%u) message of len (%u) received from peer.",protocol,event_strc->buffer_len);
									char *signature_b64 = b64_encode(event_strc->buffer,crypto_sign_BYTES);
									error_printf(3,"Inbound Signature: %s",signature_b64);
									torx_free((void*)&signature_b64);
									torx_free((void*)&prefixed_message);
									continue;
								}
								sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
								torx_free((void*)&prefixed_message);

								if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
								{
									if(pipe_auth_inbound(n,fd_type,event_strc->buffer,event_strc->buffer_len) < 0)
									{
										error_printf(0,"Received a INVALID ENUM_PROTOCOL_PIPE_AUTH on CTRL: fd_type=%d owner=%u len=%u",fd_type,owner,event_strc->buffer_len);
										sodium_memzero(read_buffer,packet_len);
										bufferevent_free(bev); // close a connection and await a new accept_conn
										return; // Invalid. Might not hit this because we close buffer.
									}
									event_strc->authenticated = 1;
									const uint8_t recvfd_connected = 1;
									setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));
									begin_cascade_recv(n);
									peer_online(n);
									if(threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled) == 1)
									{ // propose upgrade
										printf(PINK"Checkpoint ENUM_PROTOCOL_PROPOSE_UPGRADE 2\n"RESET);
										const uint16_t trash_version = htobe16(torx_library_version[0]);
										message_send(n,ENUM_PROTOCOL_PROPOSE_UPGRADE,&trash_version,sizeof(trash_version));
									}
									printf(RED"Checkpoint authed a CTRL\n"RESET);
								}
							}
						}
						int nn;
						if(group_peer_n > -1)
							nn = group_peer_n; // save message to GROUP_PEER not GROUP_CTRL so that we know who sent it without having to determine it again
						else
							nn = n;
						if(file_offer)
						{ // Receive File offer, any type
							if(process_file_offer_inbound(nn,p_iter,event_strc->buffer,event_strc->buffer_len) == -1)
								continue; // important to discard invalid offer
						}
						else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
						{ // Receive File Request (acceptance) // TODO possible source of race conditions if actively transferring when received? (common scenario, not sure how dangerous)
							const int f = set_f(nn,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN);
							const uint8_t owner_nn = getter_uint8(nn,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
							uint64_t size;
							torx_read(nn) // XXX
							char *file_path = peer[nn].file[f].file_path;
							torx_unlock(nn) // XXX
							uint8_t file_status;
							if(file_path == NULL && owner_nn == ENUM_OWNER_GROUP_PEER)
							{ // Triggers on requests for group files (non-pm)
								printf("Checkpoint group file request trigger 1\n");
								const int g = set_g(nn,NULL);
								const int group_n = getter_group_int(g,offsetof(struct group_list,n));
								const int group_n_f = set_f(group_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN);
								torx_read(group_n) // XXX
								file_path = peer[group_n].file[group_n_f].file_path;
								torx_unlock(group_n) // XXX
								size = getter_uint64(group_n,INT_MIN,group_n_f,-1,offsetof(struct file_list,size));
								setter(nn,INT_MIN,f,-1,offsetof(struct file_list,size),&size,sizeof(size)); // XXX see below NOTICE. this might be necessary for a peer specific transfer_progress, or something
								file_status = getter_uint8(group_n,INT_MIN,group_n_f,-1,offsetof(struct file_list,status));
							}
							else
							{ // pm or regular transfer
								printf("Checkpoint non-group (or pm) file request trigger 2\n");
								size = getter_uint64(nn,INT_MIN,f,-1,offsetof(struct file_list,size));
								file_status = getter_uint8(nn,INT_MIN,f,-1,offsetof(struct file_list,status));
							}
							if(file_status != ENUM_FILE_OUTBOUND_PENDING && file_status != ENUM_FILE_OUTBOUND_ACCEPTED && file_status != ENUM_FILE_OUTBOUND_COMPLETED && file_status != ENUM_FILE_INBOUND_PENDING && file_status != ENUM_FILE_INBOUND_ACCEPTED && file_status != ENUM_FILE_INBOUND_COMPLETED)
							{ // Do not modify without extensive testing and thinking
								error_simple(0,"Peer requested a file that is of a status we're not willing to send.");
								printf("Checkpoint status=%d\n",file_status);
								continue;
							}
							//	const uint8_t owner_real = getter_uint8(n_real,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
							const uint64_t requested_start = be64toh(align_uint64((void*)&event_strc->buffer[CHECKSUM_BIN_LEN]));
							const uint64_t requested_end = be64toh(align_uint64((void*)&event_strc->buffer[CHECKSUM_BIN_LEN+sizeof(uint64_t)]));
							if(file_path == NULL || requested_start > size - 1 || requested_end > size - 1)
							{ // Sanity check on request. File might not exist if size is 0
								error_simple(0,"Unknown file or peer requested more data than exists. Bailing. Report this.");
								printf("Checkpoint start=%lu end=%lu size=%lu\n",requested_start,requested_end,size);
								printf("Checkpoint path: %s\n",file_path);
								continue;
							}
							// XXX NOTICE: For group transfers, the following are in the GROUP_PEER, which lacks filename and path, which only exists in GROUP_CTRL. 
							torx_write(nn) // XXX
							peer[nn].file[f].outbound_start[fd_type] = requested_start;
							peer[nn].file[f].outbound_end[fd_type] = requested_end;
							peer[nn].file[f].outbound_transferred[fd_type] = 0;
							peer[nn].file[f].status = ENUM_FILE_OUTBOUND_ACCEPTED;
							torx_unlock(nn) // XXX
							// file pipe START (useful for resume) Section 6RMA8obfs296tlea
							FILE **fd_active = {0};
							torx_read(nn) // XXX
							if(fd_type == 0) // recvfd, outbound
								fd_active = &peer[nn].file[f].fd_out_recvfd;
							else /*if(fd_type == 1)*/ // sendfd, outbound
								fd_active = &peer[nn].file[f].fd_out_sendfd;
							torx_unlock(nn) // XXX
							torx_fd_lock(nn,f) // XXX
							*fd_active = fopen(file_path, "r");
							torx_fd_unlock(nn,f) // XXX
							if(*fd_active == NULL)
							{ // NULL sanity check is important TODO triggered 2023/11/10
								error_printf(0,"Cannot open file path %s for sending. Check permissions.",file_path);
								continue;
							}
							printf("Checkpoint read_conn sending: %s from %lu to %lu on fd_type==%d owner==%d\n",file_path,requested_start,requested_end,fd_type,owner_nn);
					/* jwofe9j20w*/	torx_fd_lock(nn,f) // XXX
							fseek(*fd_active,(long int)requested_start,SEEK_SET);
							torx_fd_unlock(nn,f) // XXX
							send_prep(nn,f,protocol_lookup(ENUM_PROTOCOL_FILE_PIECE),fd_type);
							// file pipe END (useful for resume) Section 6RMA8obfs296tlea
						}
						else if(protocol == ENUM_PROTOCOL_FILE_PAUSE || protocol == ENUM_PROTOCOL_FILE_CANCEL)
						{
						//	printf("Checkpoint receiving PAUSE or CANCEL is experimental with groups/PM: owner=%d\n",owner);
							int f = set_f(n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
							int relevant_n = n;
							if(f < 0 && owner == ENUM_OWNER_GROUP_PEER)
							{ // potential group file transfer, non-pm
								const int g = set_g(n,NULL);
								relevant_n = getter_group_int(g,offsetof(struct group_list,n));
								f = set_f(relevant_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
							}
							if(f < 0) // NOT else if, we set f again above
							{
								error_simple(0,"Received a pause or cancel for an unknown file. Bailing out.");
								continue;
							}
							torx_read(relevant_n) // XXX
							const unsigned char *split_hashes = peer[relevant_n].file[f].split_hashes;
							torx_unlock(relevant_n) // XXX
							section_unclaim(relevant_n,f,n,-1); // must go before process_pause_cancel
							if(split_hashes == NULL) // avoid triggering for group (non-pm) file transfer
								process_pause_cancel(relevant_n,f,protocol,ENUM_MESSAGE_RECV);
							const uint8_t file_status = getter_uint8(relevant_n,INT_MIN,f,-1,offsetof(struct file_list,status)); // must go after process_pause_cancel
							if(protocol == ENUM_PROTOCOL_FILE_CANCEL && file_status == ENUM_FILE_INBOUND_CANCELLED)
							{ // Delete partial inbound files + split. Must go after process_pause_cancel (which sets file_status and closes fd)
								torx_read(relevant_n) // XXX
								const char *file_path = peer[relevant_n].file[f].file_path;
								torx_unlock(relevant_n) // XXX
								destroy_file(file_path); // delete partially sent inbound files (note: may also delete fully transferred but that can never be guaranteed)
								split_update(relevant_n,f,-1); // destroys split file and frees/nulls resources
							}
							if(owner == ENUM_OWNER_GROUP_PEER && split_hashes && is_inbound_transfer(file_status))
							{ // Group transfer (non-pm). Build a fake 0/0/0/0 offer to process, as if we received it from peer, to show peer is now offering nothing
								const int p_iter_partial = protocol_lookup(ENUM_PROTOCOL_FILE_OFFER_PARTIAL);
								const uint8_t splits = getter_uint8(relevant_n,INT_MIN,f,-1,offsetof(struct file_list,splits));
								const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
								char fake_message[FILE_OFFER_PARTIAL_LEN];
								torx_read(relevant_n) // XXX
								memcpy(fake_message,peer[relevant_n].file[f].checksum,CHECKSUM_BIN_LEN); // checksum
								*(uint8_t*)(void*)&fake_message[CHECKSUM_BIN_LEN] = splits; // splits
								memcpy(&fake_message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],peer[relevant_n].file[f].split_hashes,split_hashes_len); // split hashes
								uint64_t trash = htobe64(peer[relevant_n].file[f].size); // size
								memcpy(&fake_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len],&trash,sizeof(trash)); // size
								torx_unlock(relevant_n) // XXX
								trash = htobe64(0);
								for(uint8_t section = 0; section <= splits; section++) // 0/0/0/0
									memcpy(&fake_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + section*sizeof(uint64_t)],&trash,sizeof(trash));
								process_file_offer_inbound(n,p_iter_partial,fake_message,FILE_OFFER_PARTIAL_LEN);
							}
							const uint64_t last_transferred = getter_uint64(relevant_n,INT_MIN,f,-1,offsetof(struct file_list,last_transferred));// peer[n].file[f].last_transferred;
							transfer_progress(relevant_n,f,last_transferred); // triggering a stall
						}
						else if(protocol == ENUM_PROTOCOL_KILL_CODE)
						{ // Receive Kill Code
							error_simple(1,"Successfully received a kill code. Deleting peer.");
							if(threadsafe_read_uint8(&mutex_global_variable,&kill_delete))
							{
								const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
								takedown_onion(peer_index,1);
							}
							else // just block, dont delete user and history (BAD IDEA)
								block_peer(n);
							disconnect_forever(bev,ctx);
							error_simple(0,"TODO should probably return here to avoid actions on deleted n.2");
							continue; // TODO added 2023/10/27 without testing TODO 
						}
						else if(protocol == ENUM_PROTOCOL_PROPOSE_UPGRADE)
						{ // Receive Upgrade Proposal // Note: as of current, the effect of this will likely be delayed until next program start
							const uint16_t new_peerversion = be16toh(align_uint16((void*)&event_strc->buffer[0]));
							const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion));
							if(new_peerversion > peerversion)
							{ // Note: currently not facilitating downgrades because we would have to take down sendfd
								error_printf(0,"Received an upgrade proposal: %u > %u",new_peerversion,peerversion);
								setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion),&new_peerversion,sizeof(new_peerversion));
								sql_update_peer(n);
							/*	if(fd_type == 0 && new_peerversion < 2)
									event_strc->authenticated = 0; */
							}
						}
						else if(protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
						{ // Receive GROUP_OFFER
							const int g = set_g(-1,event_strc->buffer); // reserved
							const int group_n = getter_group_int(g,offsetof(struct group_list,n));
							if(group_n < 0)
							{ // new group, never received offer before
								if(be32toh(align_uint32((void*)&event_strc->buffer[GROUP_ID_SIZE])) > MAX_STREAMS_GROUP)
								{ // rudementary sanity check
									error_simple(0,"Received obviously invalid group size in offer from buggy or malicious peer. Bailing out.");
									continue;
								}
								const uint8_t invite_required = *(uint8_t*)&event_strc->buffer[GROUP_ID_SIZE+sizeof(uint32_t)];
								setter_group(g,offsetof(struct group_list,invite_required),&invite_required,sizeof(invite_required));
							}
						}
						else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY)
						{ // Format: group_id + accepter's onion + accepter's ed25519_pk (NOTE: These protocols are exclusively between two OWNER_CTRL)
						 // TODO should ONLY respond IF we verify that we already sent this peer an invitation, otherwise could be issues (ie, a malicious peer could accept multiple times and bring in a bunch of people)
							const int g = set_g(-1,event_strc->buffer); // reserved, already existing
							const int group_n = getter_group_int(g,offsetof(struct group_list,n));
							if(group_n < -1)
							{
								error_simple(0,"Sanity check failed on a received Group Offer Accept.");
								continue;
							}
							const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
							if(g_invite_required == 0)
							{ // Sanity check continued
								error_simple(0,"Public groups are not accepted in this manner. One client is buggy. Coding error. Report this.");
								breakpoint(); // 2024/03/11 triggered upon startup after deleting a group that didn't complete handshake
							}
							else
							{
								unsigned char invitation[crypto_sign_BYTES];
								getter_array(&invitation,sizeof(invitation),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,invitation));
								const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[GROUP_ID_SIZE+56];
								pthread_rwlock_rdlock(&mutex_expand_group);
								const int *peerlist = group[g].peerlist;
								pthread_rwlock_unlock(&mutex_expand_group);
								if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
								{
									if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST && is_null(invitation,crypto_sign_BYTES))
									{ // NOTE: race condition. Once we set the invitation, anyone else who accepts our invite ... umm... lost thought there.
										unsigned char verification_message[56+crypto_sign_PUBLICKEYBYTES];
										getter_array(verification_message,56,group_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
										unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
										getter_array(&sign_sk,sizeof(sign_sk),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,sign_sk));
										crypto_sign_ed25519_sk_to_pk(&verification_message[56],sign_sk);
										sodium_memzero(sign_sk,sizeof(sign_sk));
										// XXX 2023/10/21 I think we have no signed protocol to be checking here, because this is not a signed message... its different
										if(crypto_sign_verify_detached((unsigned char *)&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES],verification_message,sizeof(verification_message),group_peer_ed25519_pk) != 0)
										{ // verify inbound invitation with our group_n onion + group_n pk, against their provided group_peer_ed25519_pk, before saving
											error_simple(0,"Failure to receive a valid incoming signature. Peer error.");
											sodium_memzero(invitation,sizeof(invitation));
											sodium_memzero(verification_message,sizeof(verification_message));
											continue;
										}
										sodium_memzero(verification_message,sizeof(verification_message));
										error_simple(2,"Receiving a valid group invitation signature.");
										memcpy(invitation,&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES],crypto_sign_BYTES);
										setter(group_n,INT_MIN,-1,-1,offsetof(struct peer_list,invitation),&invitation,sizeof(invitation));
										sql_update_peer(group_n);
									}
								//	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
								//		message_send(n,ENUM_PROTOCOL_GROUP_PEERLIST,itoa(g)); // send a peerlist because this person doesn't have one
								//	group_add_peer(g,group_peeronion,peer[n].peernick,group_peer_ed25519_pk,invitation); // note: was in message_send, moving up instead
									struct int_char int_char;
									int_char.i = g;
									int_char.p = &event_strc->buffer[GROUP_ID_SIZE]; // group_peeronion;
									int_char.up = group_peer_ed25519_pk;
								//	printf("Checkpoint sending ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY. If this was sent as a private message, this needs to be sent to group_peer_n not n\n"); // TODO delete message if non-applicable
									message_send(n,ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY,&int_char,GROUP_OFFER_ACCEPT_REPLY_LEN); // this calls group_add_peer
								}
								else if(peerlist == NULL) // ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY
								{ // If peerlist not NULL, this is a malicious message possibly.
									if(is_null(invitation,crypto_sign_BYTES))
									{ // collect their signature of our group ctrl ( will always be passed, but we don't always need to take it if we already have one )
									// TODO TODO TODO XXX Exploitable??? if this is *always* passed, then malicious actors can switch theirs and change who invited them to the channel??
									// TODO Prevent by not sending ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY unless we already sent them an offer. So, we need to track offers.
										error_simple(2,"Receiving a group invitation signature.");
										memcpy(invitation,&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES],crypto_sign_BYTES);
										setter(group_n,INT_MIN,-1,-1,offsetof(struct peer_list,invitation),&invitation,sizeof(invitation));
										sql_update_peer(group_n);
									}
									unsigned char invitor_invitation[crypto_sign_BYTES];
									memcpy(invitor_invitation,&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES],crypto_sign_BYTES);
									char peernick[56+1];
									getter_array(&peernick,sizeof(peernick),n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
									const int peer_n = group_add_peer(g,&event_strc->buffer[GROUP_ID_SIZE],peernick,group_peer_ed25519_pk,invitor_invitation);
									if(peer_n > -1)
									{
										error_simple(0,RED"Checkpoint New group peer!(read_conn 2)"RESET);
									//	const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
									//	if(peercount == 1) // This only *needs* to run on first connection.... in any other circumstance, new peers should find us.
									//		message_send(peer_n,ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,NULL,0);
									//	else
									//		printf("Checkpoint NOT REQUESTING peerlist2. Peercount==%u\n",peercount);
									}
									sodium_memzero(peernick,sizeof(peernick));
									sodium_memzero(invitor_invitation,sizeof(invitor_invitation));
								}
								else
									breakpoint();
								sodium_memzero(invitation,sizeof(invitation));
							}
						}
						else if(protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST) // New peer wants to connect to a group we are in. 
						{ // Format: their onion + their ed25519_pk + invitation signature of their onion+pk (by someone already in group). Message itself is not signed but the onion+pk they pass is signed
							if(owner != ENUM_OWNER_GROUP_CTRL) // should ONLY come in on a GROUP_CTRL
							{
								error_simple(0,"Received private entry request on wrong owner type. Possibly malicious intent or buggy peer.");
								printf("Checkpoint received request on owner: %d\n",owner);
								breakpoint();
								continue;
							}
							const int g = set_g(n,NULL); // should be existing but reserving anyway.
							const int invitor_n = group_check_sig(g,event_strc->buffer,56+crypto_sign_PUBLICKEYBYTES,0,(unsigned char *)&event_strc->buffer[56+crypto_sign_PUBLICKEYBYTES],NULL); // 0 is fine for protocol here because protocol is not signed
							if(invitor_n < 0)// (1) We should verify the signature is from some peer we have
							{
								error_simple(0,"Disregarding a GROUP_PRIVATE_ENTRY_REQUEST from someone.");
								continue; // Disgard if not signed by someone in group
							}				
						//	else
						//		error_simple(0,"New private group peer connected with invitation.");
							const char *proposed_peeronion = event_strc->buffer;
							const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[56];
							const unsigned char *inviter_signature = (unsigned char *)&event_strc->buffer[56+crypto_sign_PUBLICKEYBYTES];
		 					const int new_peer = group_add_peer(g,proposed_peeronion,NULL,group_peer_ed25519_pk,inviter_signature); // (2) We group_add_peer them.
							if(new_peer == -1)
							{ // Error
								error_simple(0,"New peer is -1 therefore there was an error. Bailing.");
								continue;
							}
							else if(new_peer != -2)
							{ // Approved a new peer
								error_simple(0,RED"Checkpoint New group peer! (read_conn 3)"RESET);
						//		error_simple(3,"Received ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST. Responding with peerlist.");
						//		const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
						//		message_send(new_peer,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(g),GROUP_PEERLIST_PRIVATE_LEN); // (3) respond with peerlist
							}
						}
						else if(protocol == ENUM_PROTOCOL_GROUP_BROADCAST || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)
						{
							if(event_strc->buffer_len == GROUP_BROADCAST_LEN)
								broadcast_inbound(n,(unsigned char *)event_strc->buffer); // this can rebroadcast or handle
							else
							{
								error_printf(0,"Requested rebroadcast of bad broadcast. Bailing. Protocol: %u with an odd lengthed broadcast: %u instead of expected %u.",protocol,event_strc->buffer_len,GROUP_BROADCAST_LEN);
								breakpoint(); // TODO NOTICE: if this gets hit, its probably due to our DATE_SIGN_LEN. delete it if the math permits.
								continue;
							}
						}
						else if(null_terminated_len && utf8 && !utf8_valid(event_strc->buffer,event_strc->buffer_len - (null_terminated_len + date_len + signature_len)))
						{
							error_simple(0,"Non-UTF8 message received. Discarding entire message.");
							continue;
						}
						if(stream)
						{ // certain protocols discarded after processing, others stream_cb to UI
							if(protocol != ENUM_PROTOCOL_PIPE_AUTH && protocol != ENUM_PROTOCOL_FILE_OFFER_PARTIAL && protocol != ENUM_PROTOCOL_PROPOSE_UPGRADE)
								stream_cb(nn,p_iter,event_strc->buffer,event_strc->buffer_len);
						}
						else
						{
							time_t time = 0;
							time_t nstime = 0;
							if(signature_len && date_len)
							{ // handle messages that come with date (typically any group messages)
								time = (time_t)be32toh(align_uint32((void*)&event_strc->buffer[event_strc->buffer_len - (2*sizeof(uint32_t) + crypto_sign_BYTES)]));
								nstime = (time_t)be32toh(align_uint32((void*)&event_strc->buffer[event_strc->buffer_len - (sizeof(uint32_t) + crypto_sign_BYTES)]));
							}
							else
								set_time(&time,&nstime);
							const int i = getter_int(nn,INT_MIN,-1,-1,offsetof(struct peer_list,max_i)) + 1; // need to set this to prevent issues with full-duplex
							expand_message_struc(nn,i);
							torx_write(nn) // XXX
							peer[nn].max_i++; // NOTHING CAN BE DONE WITH "peer[n].message[peer[n].max_i]." AFTER THIS
							if(group_peer_n > -1 && group_peer_n == group_ctrl_n) // we received a message that we signed... it as resent to us.
								peer[nn].message[i].stat = ENUM_MESSAGE_SENT;
							else
								peer[nn].message[i].stat = ENUM_MESSAGE_RECV;
							peer[nn].message[i].p_iter = p_iter;
							peer[nn].message[i].message = event_strc->buffer;
							peer[nn].message[i].message_len = event_strc->buffer_len;
							peer[nn].message[i].time = time;
							peer[nn].message[i].nstime = nstime;
							torx_unlock(nn) // XXX
						//	const char *name = protocols[p_iter].name;
						//	printf("Checkpoint read_conn nn=%d i=%d proto=%s\n",nn,i,name);
							int repeated = 0; // same time/nstime as another
							if(owner == ENUM_OWNER_GROUP_PEER && (group_msg || group_pm))
							{ // Handle group messages
								const int g = set_g(n,NULL);
								repeated = message_insert(g,nn,i);
							}
							if(repeated)
							{
								torx_write(nn) // XXX
								zero_i(nn,i);
								torx_unlock(nn) // XXX
							}
							else
							{ // unique same time/nstime
								print_message_cb(nn,i,1); // GUI CALLBACK
								sql_insert_message(nn,i); // DO NOT set these to nn, use n/GROUP_CTRL
							}
						}
						event_strc->buffer = NULL; // XXX IMPORTANT: to prevent the message from being torx_free'd if we hit a continue;
						event_strc->buffer_len = 0;
					}
					else
						continued = 0; // important or oversized messages will break
				}
			}
		}
	}
	else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
	{ // Handle incoming friend request
		char buffer_ln[2+56+crypto_sign_PUBLICKEYBYTES];
		int removed;
		if((removed = evbuffer_remove(input,buffer_ln,sizeof(buffer_ln))) < 1)
		{ // TODO Should spoil onion.
			error_simple(0,"This should not occur 830302. should never occur under any circumstances. report this.");
			return;
		}
		size_t len = (size_t)removed;
		if(len == sizeof(buffer_ln))
		{ // Generate, send, and save ctrl
			uint8_t former_owner = owner; // use to mitigate race condition caused by deletion of SING
			char fresh_privkey[88+1] = {0};
			char peernick[56+1];
			getter_array(&peernick,sizeof(peernick),n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
			event_strc->fresh_n = generate_onion(ENUM_OWNER_CTRL,fresh_privkey,peernick);
			sodium_memzero(peernick,sizeof(peernick));
			if(former_owner == ENUM_OWNER_SING) // XXX DO NOT USE N AFTER THIS or risk race conditon XXX
				bufferevent_disable(bev, EV_READ); // this will cause onion to be deleted i think !!!
			const uint16_t fresh_peerversion = be16toh(align_uint16((void*)&buffer_ln[0]));
			char fresh_peeronion[56+1];
			memcpy(fresh_peeronion,&buffer_ln[2],56);
			fresh_peeronion[56] = '\0';
			unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
			unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];
			crypto_sign_keypair(ed25519_pk,ed25519_sk);
			unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
			memcpy(peer_sign_pk,&buffer_ln[2+56],sizeof(peer_sign_pk));
			char peernick_fresh_n[56+1];
			getter_array(&peernick_fresh_n,sizeof(peernick_fresh_n),event_strc->fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
			int fresh_n = -1; // for double chcking
			if(former_owner == ENUM_OWNER_SING || (former_owner == ENUM_OWNER_MULT && threadsafe_read_uint8(&mutex_global_variable,&auto_accept_mult)))
				fresh_n = load_peer_struc(-1,ENUM_OWNER_CTRL,ENUM_STATUS_FRIEND,fresh_privkey,fresh_peerversion,fresh_peeronion,peernick_fresh_n,ed25519_sk,peer_sign_pk,NULL);
			else if	(former_owner == ENUM_OWNER_MULT && !threadsafe_read_uint8(&mutex_global_variable,&auto_accept_mult))
				fresh_n = load_peer_struc(-1,ENUM_OWNER_CTRL,ENUM_STATUS_PENDING,fresh_privkey,fresh_peerversion,fresh_peeronion,peernick_fresh_n,ed25519_sk,peer_sign_pk,NULL);
			else
				error_simple(0,"Coding error 129012. Report this.");
			sodium_memzero(peernick_fresh_n,sizeof(peernick_fresh_n));
			if(fresh_n == -1 || event_strc->fresh_n != fresh_n)
			{ // Coding error or buggy/malicious peer. TODO Should spoil onion.
				printf("Checkpoint FAIL 2323fsadf event_strc->fresh_n == %d,fresh_n==%d\n",event_strc->fresh_n,fresh_n );
				sodium_memzero(buffer_ln,sizeof(buffer_ln));
				sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
				sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
				sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
				return;
			}
			load_onion(fresh_n);
			// XXX WARNING: Use event_strc->fresh_n (ctrl) not n (SING/MULT) XXX Note that saving occurs in write_finished not here
			sodium_memzero(fresh_privkey,sizeof(fresh_privkey));
			uint16_t trash;
			if(!threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled))
				trash = htobe16(1);
			else
				trash = htobe16(torx_library_version[0]);
			memcpy(&buffer_ln[0],&trash,sizeof(uint16_t));
			getter_array(&buffer_ln[2],56,fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
			memcpy(&buffer_ln[2+56],ed25519_pk,sizeof(ed25519_pk));
			if(local_debug > 2)
				error_printf(3,"Received Version: %u Onion: %s",fresh_peerversion,fresh_peeronion);
			evbuffer_add(bufferevent_get_output(bev), buffer_ln,sizeof(buffer_ln)); // XXX MUST be AFTER load_onion() because it results in write_finished which requires event_strc->fresh_n
			sodium_memzero(fresh_peeronion,sizeof(fresh_peeronion));
			sodium_memzero(buffer_ln,sizeof(buffer_ln));
			sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
			sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
			sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
		}
		else if(owner == ENUM_OWNER_SING)
		{ // Spoil SING after bad handshake
			error_printf(0,"Wrong size connection attempt of size %lu received. Onion spoiled. Report this.",len);
			const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
			takedown_onion(peer_index,3);// 2022/08/12, was ,2 but 2 is "delete without taking down". XXX If it says anything other than 250, put the 2 back, otherwise remove this.
			disconnect_forever(bev,ctx);
		}
		else if(owner == ENUM_OWNER_MULT)
			error_printf(0,"Invalid attempt of size %lu received on mult. Should notify user of this.",len);
	}
	else
	{
		error_simple(0,"Received a message on an unexpected owner. Coding error. Report this.");
		breakpoint();
	}
}

static void accept_conn(struct evconnlistener *listener, evutil_socket_t sockfd, struct sockaddr *address, int socklen, void *ctx)
{ /* We got a new inbound connection! Set up a bufferevent for it. */
	(void) address; // not using it, this just suppresses -Wextra warning
	(void) socklen; // not using it, this just suppresses -Wextra warning
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const int n = event_strc->n;
	const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND) // Disconnect if anything other than status 1
	{
		error_simple(0,"Coding error 32402. Report this.");
		breakpoint();
	//	disconnect_forever(bev); // Run last, will exit event base
		return;
	}
	torx_read(n) // XXX
	struct bufferevent *bev_recv_existing = peer[n].bev_recv;
	torx_unlock(n) // XXX
	if(bev_recv_existing != NULL)
	{ // TODO 2024/07/13 figure out how to free/destroy the old one (though we seemed fine not doing so up until now?)
		error_simple(0,"There is already an existing bev_recv. Replacing it might have unintended consequences if we don't free/destroy the old one. Replacing regardless."); // And if we *do*, there are *also* unintended consequences, which we must mitigate!
	/*	torx_write(n) // XXX
		bufferevent_free(peer[n].bev_recv);
		torx_unlock(n) // XXX
		peer[n].bev_recv = NULL; */ // DO NOT DELETE THIS BLOCK. We probably have to make it work.
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
		const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion));
		if(owner == ENUM_OWNER_CTRL && (!local_v3auth_enabled || peerversion < 2))
			event_strc->authenticated = 0; // must de-authenticate because we have no idea who is connecting in this case
	}
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev_recv = bufferevent_socket_new(base, sockfd, BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE); // XXX 2023/09 we should probably not just be overwriting bev_recv every time we get a connection?? or we should make it local?? seems we only use it in this function and in send_prep

	// event_strc_unique for use with bufferevent_setcb(), being a total copy of event_strc. Will set authenticated_pipe_n in read_conn.
	struct event_strc *event_strc_unique = torx_insecure_malloc(sizeof(struct event_strc));
	memcpy(event_strc_unique,event_strc,sizeof(struct event_strc));

	evbuffer_enable_locking(bufferevent_get_output(bev_recv),NULL); // 2023/08/11 Necessary for full-duplex. Will lock and unlock automatically, no need to manually evbuffer_lock/evbuffer_unlock.
	bufferevent_setcb(bev_recv, read_conn, write_finished, close_conn, event_strc_unique);
	bufferevent_enable(bev_recv, EV_READ); // XXX DO NOT ADD EV_WRITE because it triggers write_finished() immediately on connect, which has invalid fresh_n, segfault.
	torx_write(n) // XXX
	peer[n].bev_recv = bev_recv; // 2024/07/13 TODO TODO TODO XXX Maybe this should have a null check before we replace bev_recv.
	torx_unlock(n) // XXX

	if(event_strc->authenticated)
	{ // MUST check if it is authenticated, otherwise we're permitting sends to an unknown peer (relevant to CTRL without v3auth)
		const uint8_t recvfd_connected = 1;
		setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));

		const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL)
			error_simple(1,"Existing Peer has connected to us.");
		else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
			error_simple(1,"New potential peer has connected.");

		if(owner == ENUM_OWNER_CTRL)
			begin_cascade_recv(n);
		if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL)
			peer_online(n); // internal callback, keep after peer[n].bev_recv = bev_recv; AND AFTER send_prep
	}
}

static void error_conn(struct evconnlistener *listener, void *ctx)
{ // Only used on fd_type==0 // TODO should re-evaluate this. maybe it should do nothing (probably) or maybe it should be == close_conn (not sure)
// TODO March 2 2023 test if this comes up after long term connections (many hours) like it occurs with LCD main.c ( "Too many open files" )
	struct event_base *base = evconnlistener_get_base(listener);
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const int n = event_strc->n;
	const int8_t fd_type = event_strc->fd_type;
	peer_offline(n,fd_type); // internal callback
	const int err = EVUTIL_SOCKET_ERROR();
	error_printf(0, "Shutting down event base. Report this. Got the following error from libevent: %s",evutil_socket_error_to_string(err)); // this is const, do not assign and free.
	breakpoint();
	event_base_loopexit(base, NULL);
} // TODO TEST: this caused our whole application to shutdown on 2022/07/29 when deleting a peer. Got an error 22 (Invalid argument) on the listener. Shutting down.

void *torx_events(void *arg)
{ /* Is called ONLY ONCE for .recvfd (which never closes, unless block/delete), but MULTIPLE TIMES for .sendfd (which closes every time there is disconnect) */
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	struct event_strc *event_strc = (struct event_strc*) arg; // Casting passed struct
	const int n = event_strc->n;
	const int8_t fd_type = event_strc->fd_type;
	if(fd_type == 0)
	{
		torx_write(n) // XXX
		pusher(zero_pthread,(void*)&peer[n].thrd_recv)
		torx_unlock(n) // XXX
	}
	struct event_base *base = event_base_new();
	if(!base)
	{
		error_simple(0,"Couldn't open event base.");
		torx_free((void*)&arg); // free CTX
		return 0;
      	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	while(1)
	{ // not a real while loop, just to avoid goto
		if(fd_type == 0)
		{ /* Exclusively comes here from load_onion_events */
			struct evconnlistener *listener = evconnlistener_new(base, accept_conn, arg, LEV_OPT_THREADSAFE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE/*|EVLOOP_ONCE*/, -1, event_strc->sockfd);	// |LEV_OPT_DEFERRED_ACCEPT could cause issues. It is the source of problems if connections fail
			if(!listener)
			{
				error_simple(0,"Couldn't create libevent listener. Report this.");
				break;
			}
			evconnlistener_set_error_cb(listener, error_conn);
		}
		else if(fd_type == 1)
		{ /* Exclusively comes here from send_init() */
			struct bufferevent *bev_send = bufferevent_socket_new(base, event_strc->sockfd, BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE);
			if(bev_send == NULL) // -1 replacing sockfd for testing
			{
				error_simple(0,"Couldn't create bev_send.");
				break;
			}
			evbuffer_enable_locking(bufferevent_get_output(bev_send),NULL); // 2023/08/11 Necessary for full-duplex. Will lock and unlock automatically, no need to manually evbuffer_lock/evbuffer_unlock.
			bufferevent_setcb(bev_send, read_conn, write_finished, close_conn,arg);
	//		bufferevent_disable(bev_send,EV_WRITE); // ENABLED BY DEFAULT, TESTING DISABLED
			bufferevent_enable(bev_send, EV_READ/*|EV_ET|EV_PERSIST*/);
			torx_write(n) // XXX
			peer[n].bev_send = bev_send;
			torx_unlock(n) // XXX
			// TODO 0u92fj20f230fjw ... to here. TODO
			const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion));
			/// Handle message types that should be in front of the queue
			const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
			if(owner == ENUM_OWNER_CTRL && (local_v3auth_enabled == 0 || peerversion < 2))
				pipe_auth_and_request_peerlist(n); // send ENUM_PROTOCOL_PIPE_AUTH
			if(owner == ENUM_OWNER_CTRL && local_v3auth_enabled == 1/* && peerversion < torx_library_version[0]*/)
			{ // propose upgrade (NOTE: this won't catch if they are already > 1, so we also do it elsewhere)
				printf(PINK"Checkpoint ENUM_PROTOCOL_PROPOSE_UPGRADE 1\n"RESET);
				const uint16_t trash_version = htobe16(torx_library_version[0]);
				message_send(n,ENUM_PROTOCOL_PROPOSE_UPGRADE,&trash_version,sizeof(trash_version)); // TODO this will fail 100% of the time because its STREAM
			}
			if(owner == ENUM_OWNER_GROUP_PEER)
			{ // Put this in front of the queue.
				const uint8_t stat = getter_uint8(n,0,-1,-1,offsetof(struct message_list,stat));
				uint8_t first_connect = 0;
				if(stat == ENUM_MESSAGE_FAIL)
				{ // Put queue skipping protocols first, if unsent, before pipe auth
					const int p_iter = getter_int(n,0,-1,-1,offsetof(struct message_list,p_iter));
					pthread_rwlock_rdlock(&mutex_protocols);
					const uint16_t protocol = protocols[p_iter].protocol;
					pthread_rwlock_unlock(&mutex_protocols);
					if(stat == ENUM_MESSAGE_FAIL && (protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST))
					{
						send_prep(n,0,p_iter,1);
						first_connect = 1;
					}
				}
				if(!first_connect) // otherwise wait for successful entry, or messages could end up out of order.
					pipe_auth_and_request_peerlist(n); // send ENUM_PROTOCOL_PIPE_AUTH
			}
			peer_online(n); // internal callback, keep after pipe auth, after peer[n].bev_recv = bev_recv; AND AFTER send_prep
		}
		else
		{
			error_simple(0,"Did not specify socket type (send, recv). Report this.");
			breakpoint();
			break;
		}
		event_base_dispatch(base); // XXX this is the important loop... this is the blocker
		torx_write(n) // XXX
		if(fd_type == 0)
			peer[n].bev_send = NULL;
		else if(fd_type == 1)
			peer[n].bev_send = NULL;
		torx_unlock(n) // XXX
		const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
		if(status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL) && fd_type == 0) // Its not an error for a 0'd (deleted) onion to get here.
		{
			const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,sendfd_connected));
			const uint8_t recvfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected));
			error_printf(0,"Recv ctrl got out of base. It will die but this is unexpected. NOTE: fd_type recv should not get out unless deleted or blocked. sendfd: %d recvfd: %d owner: %u fd_type: %d",sendfd_connected,recvfd_connected,owner,fd_type); 	/* NOTICE: ONLY SING AND PIPEMODE WILL EVER GET OUT OF BASE edit: i think no one gets out */ 
		}
		break;
	}
	event_base_free(base);
	torx_free((void*)&event_strc->buffer);
	torx_free((void*)&arg); // free CTX
	return 0;
}
