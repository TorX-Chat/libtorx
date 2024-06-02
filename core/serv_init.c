
int send_prep(const int n,const int f_i,const int p_iter,const int8_t fd_type)
{ // Puts a message into evbuffer and registers the packet info. Should be run in a while loop on startup and reconnections, and once per message_send
	uint16_t protocol_verify;
	int f = -1; // DO NOT INITIALIZE, we want the warnings... but our compiler is not playing nice so we have to
	int i = -1; // DO NOT INITIALIZE, we want the warnings... but our compiler is not playing nice so we have to
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const char *name = protocols[p_iter].name;
	const uint8_t socket_swappable = protocols[p_iter].socket_swappable;
	pthread_rwlock_unlock(&mutex_protocols);
	uint64_t start = 0;
	if(protocol == ENUM_PROTOCOL_FILE_PIECE)
	{ // f is passed as f_i
		f = f_i;
		protocol_verify = ENUM_PROTOCOL_FILE_PIECE;
	}
	else
	{ // i is passed as f_i
		i = f_i;
		const int true_p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
		if(p_iter != true_p_iter) // TODO 2024/03/21 more efficient would be to just *not* pass p_iter as an arg. We just need to pass whether or not its ENUM_PROTOCOL_FILE_PIECE
		{
			if(true_p_iter < 0)
			{
				error_printf(0,"Message deleted: %s. Cannot send_prep. Coding error. Report this.",name);
				goto failure;
			}
			pthread_rwlock_rdlock(&mutex_protocols);
			const char *true_name = protocols[true_p_iter].name;
			pthread_rwlock_unlock(&mutex_protocols);
			error_printf(-1,"Sanity check fail in send_prep. %s != %s. Coding error. Report this.",name,true_name);
		}
		protocol_verify = protocol;
		start = getter_uint32(n,i,-1,-1,offsetof(struct message_list,pos));
		if(socket_swappable && fd_type > -1 && start == 0)
		{
			torx_read(n) // XXX
			const int socket_utilized = peer[n].socket_utilized[fd_type];
			torx_unlock(n) // XXX
			if(socket_utilized > -1 && socket_utilized != i)
			{ // TODO this ignores the fact that the prior_i message could be going out on another fd_type (we could track that and potentially even switch this message to another fd)
			// TODO this is probably going to cause any further messages to not go until connection breaks and is re-established
				torx_read(n) // XXX
				const int utilized_recv = peer[n].socket_utilized[0];
				const int utilized_send = peer[n].socket_utilized[1];
				torx_unlock(n) // XXX
				if(utilized_send == -1 && fd_type == 0)
					return send_prep(n,f_i,p_iter,1);
				else if(utilized_recv == -1 && fd_type == 1)
					return send_prep(n,f_i,p_iter,0);
				else
				{
					error_printf(0,"Refusing to send_prep because sockets all utilized: %s",name);
					printf("Checkpoint send_prep refusal on n==%d\n",n);
					goto failure;
				}
			}
		}
	}
	if(protocol != ENUM_PROTOCOL_FILE_PIECE && protocol != protocol_verify && (protocol != ENUM_PROTOCOL_GROUP_OFFER || protocol_verify != ENUM_PROTOCOL_GROUP_OFFER_FIRST))
	{ // this is a sanity check for i iter messages stored in messages struct. does NOT apply to f/ENUM_PROTOCOL_FILE_PIECE messages.
		error_printf(0,"Inconsistency between passed protocol and protocol in struct. %u vs %u. Not sending. Report this.",protocol,protocol_verify);
		breakpoint();
		goto failure;
	}
	uint8_t connected;
	FILE **fd_active = {0};
	const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status));
	torx_read(n) // XXX
	if(fd_type == 0 && peer[n].bev_recv)
	{
		connected = peer[n].recvfd_connected;
		if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			fd_active = &peer[n].file[f].fd_out_recvfd;
	}
	else if(fd_type == 1 && peer[n].bev_send)
	{
		connected = peer[n].sendfd_connected;
		if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			fd_active = &peer[n].file[f].fd_out_sendfd;
	}
	else
	{ // This occurs when message_send is called before torx_events. It sends later when the connection comes up.
		torx_unlock(n) // XXX
		error_printf(3,"Checkpoint Cannot send_prep yet. Invalid fd_type or (more likely) .bev_send or .bev_recv does not exist yet. Protocol==%u fd_type==%d status==%u",protocol,fd_type,status);
		if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			error_printf(0,"Checkpoint ENUM_PROTOCOL_FILE_PIECE send_prep fail: owner==%u n==%d f_i==%d fd_type==%d",owner,n,f_i,fd_type);
		if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
			error_printf(0,"Checkpoint ENUM_PROTOCOL_PIPE_AUTH send_prep fail (too early) fd_type=%d",fd_type);
		else
			error_printf(0,"Checkpoint send_prep %s too early, fd_type=%d will be ignored. Owner: %u",name,fd_type,owner);
		goto failure;
	}
	torx_unlock(n) // XXX
	char send_buffer[PACKET_SIZE_MAX]; // zero'd // NOTE: no need to {0} this, so don't.
	if(connected && status == ENUM_STATUS_FRIEND) // It is not necessary to check recvfd, but it is not a bad idea to ensure that both sides are up before sending
	{ // TODO 2024/03/24 there can be a race on output. it can be free'd by libevent between earlier check and usage. should re-fetch it
		uint16_t packet_len = 0;
		if(protocol == ENUM_PROTOCOL_FILE_PIECE)
		{ // XXX (only f is initialized)
			torx_read(n) // XXX
			if(!*fd_active || (start = (uint64_t)ftell(*fd_active)) == (uint64_t)-1)
			{
				torx_unlock(n) // XXX
				error_simple(1,"Null filepointer in send_prep, possibly caused by file being completed.");
				return -1;
			}
			if(peer[n].file[f].outbound_start[fd_type] + peer[n].file[f].outbound_transferred[fd_type] != start) // THIS IS NOT AN ERROR.
			{ // TODO 2024/03/20 Moved from jwofe9j20w to reduce corruption. Might increase corruption! Needs testing. Comment out and uncomment jwofe9j20w if corruption.
				printf("Checkpoint fail: %lu + %lu != %lu\n",peer[n].file[f].outbound_start[fd_type],peer[n].file[f].outbound_transferred[fd_type],start);
				torx_unlock(n) // XXX
				torx_fd_lock(n,f) // XXX
				fseek(*fd_active,(long int)start,SEEK_SET);
				torx_fd_unlock(n,f) // XXX
				torx_read(n) // XXX
			} // Appears NOT to be our (main?) cause of corruption. Best guess is failing to properly close file descriptors on shutdown.
		//	printf("Checkpoint send_prep type=%d start=%lu\n",fd_type,start); // XXX highly useful for debugging
			const uint64_t endian_corrected_start = htobe64(start);
			uint16_t data_size = PACKET_SIZE_MAX-16;
			if(start + data_size > peer[n].file[f].outbound_end[fd_type]) // avoid sending beyond requested amount
				data_size = (uint16_t)(peer[n].file[f].outbound_end[fd_type] - start + 1); // hopefully this +1 means "inclusive" because we were losing a byte in the middle
			torx_unlock(n) // XXX
			if(data_size == 0)
			{ // TODO 2023/11/10 this should NOT trigger (except if peer requests 0 bytes) during transfer because file should already be marked ENUM_FILE_OUTBOUND_COMPLETED by output_cb_v1/output_cb_v2 TODO
				error_simple(0,"Appears we completed a section? Or peer requested 0 bytes.");
				return -1;
			}
			torx_fd_lock(n,f) // XXX // TODO TODO TODO XXX 2024/02/04 this blocks (bad), need to have an local file descriptor that has the proper location, then after fread, write the new location to the proper file pointer (avoids lockup if/while read hangs)
			const size_t bytes = fread(&send_buffer[16],1,data_size,*fd_active);
			torx_fd_unlock(n,f) // XXX should probably enable? but this could block...
		//	printf("Checkpoint send_prep %lu from %lu on %d\n",data_size,start,fd_type);
			if(bytes > 0)
			{ // Handle bytes read from file
				packet_len = 2+2+4+8+(uint16_t)bytes; //  packet len, protocool, truncated file checksum, start position, data itself
				uint16_t trash = htobe16(packet_len);
				memcpy(&send_buffer[0],&trash,sizeof(uint16_t));
				trash = htobe16(protocol);
				memcpy(&send_buffer[2],&trash,sizeof(uint16_t));
				torx_read(n) // XXX
				memcpy(&send_buffer[4],peer[n].file[f].checksum,4);
				torx_unlock(n) // XXX
				//printf("Checkpoint read start: %ld\nContents of packet:\n%s\n",be64toh(endian_corrected_start),&send_buffer[18]);
				memcpy(&send_buffer[8],&endian_corrected_start,8);
			}
			else // if(!bytes) // No more to read (legacy complete or IO error)
			{ // TODO entire block is legacy, no longer triggers because of refinements. File completion is in output_cb. 
				error_simple(0,"File completed in a legacy manner. Coding error or IO error. Report this."); // could be falsely triggered by file shrinkage
				const uint8_t file_status = ENUM_FILE_OUTBOUND_COMPLETED;
				setter(n,-1,f,-1,offsetof(struct file_list,status),&file_status,sizeof(file_status));
				close_sockets(n,f,*fd_active)
				transfer_progress(n,f,calculate_transferred(n,f)); // calling this because we set file status ( not necessary when calling message_send which calls print_message_cb )
				sodium_memzero(send_buffer,(size_t)packet_len);
				return -1;
			}
		}
		else
		{ // Anything except ENUM_PROTOCOL_FILE_PIECE XXX (only i is initialized)
			const uint8_t stat = getter_uint8(n,i,-1,-1,offsetof(struct message_list,stat));
			pthread_rwlock_rdlock(&mutex_protocols);
			const uint8_t group_mechanics = protocols[p_iter].group_mechanics;
			pthread_rwlock_unlock(&mutex_protocols);
			if(p_iter < 0 || (owner != ENUM_OWNER_GROUP_PEER && group_mechanics))
			{
				error_simple(0,"Illegal request or unrecognized protocol in send_prep. Coding error. Report this.");
				goto illegal; // these messages can only go out to ENUM_OWNER_GROUP_PEER
			}
			if(protocol == ENUM_PROTOCOL_KILL_CODE && stat == ENUM_MESSAGE_SENT)
				goto failure; // Kill code already sent on other peer associated socket
			else if(stat == ENUM_MESSAGE_FAIL)
			{ // All protocols that contain a message size on the first packet of a message // Attempt send of messages marked :fail: or resend
				const uint32_t message_len = getter_uint32(n,i,-1,-1,offsetof(struct message_list,message_len));
				uint32_t prefix_len = 2+2;
				if(start == 0)
				{ // Only place length at the beginning of message, not on every message
					torx_write(n) // XXX
					peer[n].socket_utilized[fd_type] = i;
					torx_unlock(n) // XXX
					error_printf(0,WHITE"Checkpoint send_prep1 peer[%d].socket_utilized[%d] = %d"RESET,n,fd_type,i);
					const uint32_t trash = htobe32(message_len);
					memcpy(&send_buffer[prefix_len],&trash,sizeof(uint32_t));
					prefix_len += 4;
				}
				else if(start >= message_len)
					error_simple(-1,"Start >= message_len. Coding error. Report this."); // Added check 2024/05/04
				if(prefix_len + message_len - start < PACKET_SIZE_MAX)
					packet_len = (uint16_t)(prefix_len + message_len - start);
				else // oversized message
					packet_len = PACKET_SIZE_MAX;
				uint16_t trash = htobe16(packet_len);
				memcpy(&send_buffer[0],&trash,sizeof(uint16_t)); // packet length
				trash = htobe16(protocol_verify);
				memcpy(&send_buffer[2],&trash,sizeof(uint16_t)); // protocol
				/* XXX Unnecessary sanity check start */
				const size_t allocated = torx_allocation_len(peer[n].message[i].message);
				const size_t reading = start + (size_t)packet_len - prefix_len;
				const size_t writing = prefix_len + (size_t)packet_len - prefix_len;
				if(sizeof(send_buffer) < writing)
					error_printf(-1,"Critical error will result in illegal write: %lu < (%u + %lu - %u)",sizeof(send_buffer),prefix_len,packet_len,prefix_len);
				else if(allocated < reading) // TODO hit on 2024/05/04: 98234 < 98796 (actual message size: 98234)
					error_printf(-1,"Critical error will result in illegal read: %lu < (%lu + %lu - %u)",allocated,start,packet_len,prefix_len);
				/* Unnecessary sanity check end XXX */
				torx_read(n) // XXX
				memcpy(&send_buffer[prefix_len],&peer[n].message[i].message[start],(size_t)packet_len - prefix_len);
				torx_unlock(n) // XXX
			}
			else
			{ // XXX XXX XXX NOTICE: This CANNOT catch ALL _SENT messages because send_prep can be called twice before output_cb. Therefore, the solution is to PREVENT SEND_PREP from being called twice on the same message, as we do for queue skipping protocols in torx_events.
				illegal: {}
				error_printf(0,"Issue in send_prep: %u or unexpected stat: %u from owner: %u. Not sending. Report this.",protocol,stat,owner);
				breakpoint();
				goto failure;
			}
		}
		struct evbuffer *output = NULL; // XXX If getting issues at bufferevent_get_output in valgrind, it means .bev_recv or .bev_send is not being NULL'd properly in libevent after closing
		torx_read(n) // XXX
		struct bufferevent *bev_recv = peer[n].bev_recv;
		struct bufferevent *bev_send = peer[n].bev_send;
		torx_unlock(n) // XXX
		if(fd_type == 0 && bev_recv)
			output = bufferevent_get_output(bev_recv); // 2023/05/12 TODO got a non-fatal invalid read here
		else if(fd_type == 1 && bev_send)
			output = bufferevent_get_output(bev_send); // 2023/10/19 TODO invalid read here
		if(output)
		{
		//	printf("Checkpoint evbuffer_add %s %u <= %d\n",name,packet_len,PACKET_SIZE_MAX);
			int o = 0;
			evbuffer_lock(output); // XXX seems to have no beneficial effect. purpose is to prevent mutex_packet lockup
			pthread_rwlock_wrlock(&mutex_packet); // TODO XXX CAN BLOCK in rare circumstances (ex: receiving a bunch of STICKER_REQUEST concurrently), yet... highly necessary to wrap evbuffer_add, do not move, otherwise race condition occurs where output_cb can (and will on some devices) trigger before we register packet
			while(o < SIZE_PACKET_STRC && packet[o].n != -1) // find first re-usable or empty iter
				o++;
			if(o > highest_ever_o) // Debugging only, just for learning about what kind o levels we utilize. TODO delete before release
				highest_ever_o = o;
			if(o >= SIZE_PACKET_STRC)
			{
				pthread_rwlock_unlock(&mutex_packet);
				evbuffer_unlock(output); // XXX
				sodium_memzero(send_buffer,(size_t)packet_len);
				error_simple(-1,"Fatal error. Exceeded size of SIZE_PACKET_STRC. Report this.");
			}
			packet[o].n = n; // claim it. set first.
			packet[o].start = start;
			packet[o].packet_len = packet_len;
			packet[o].fd_type = fd_type;
			packet[o].f_i = f_i;
			packet[o].p_iter = p_iter; // set last, this is what we look for when reading
			evbuffer_add(
				output,
				send_buffer,
				(size_t)packet_len); // TODO does this have a size limit?
			pthread_rwlock_unlock(&mutex_packet);
			evbuffer_unlock(output); // XXX
			sodium_memzero(send_buffer,(size_t)packet_len);
			return 0;
		}
		else
			error_simple(0,WHITE"Checkpoint send_prep2 NO AVAILABLE OUTPUT, should -1 next"RESET);
	}
	else
		error_simple(0,"Send prep failed for reasons.");
	failure: {}
	torx_write(n) // XXX
	if(protocol != ENUM_PROTOCOL_FILE_PIECE && peer[n].socket_utilized[fd_type] == i)
	{
		error_printf(0,WHITE"Checkpoint send_prep6 peer[%d].socket_utilized[%d] = -1"RESET,n,fd_type);
		peer[n].socket_utilized[fd_type] = -1;

	}
	torx_unlock(n) // XXX
	return -1;
}

static inline int outgoing_auth_x25519(const char *peeronion,const char *privkey) // XXX HUGE THANKS TO ms7821 for helping get this working, and need to submit a bug / pull to libsodium regarding https://github.com/jedisct1/libsodium/blob/6d56607/src/libsodium/crypto_sign/ed25519/ref10/keypair.c be sure to see oct 10th 2021 #crypto chat history for reference.
{// Client Auth for outgoing connections to V3Auth'd peer onion using v3key https://community.torproject.org/onion-services/advanced/client-auth/ ONION_CLIENT_AUTH_REMOVE can be used to delete these things, when deleting a peer. CLOSESTREAM also relevant.
//	baseencode_error_t err = {0}; // for base32_decode/encode functions
	unsigned char v3_priv_decoded[64] = {0}; // zero'd
	unsigned char ed25519_sk[32]; // zero'd NOTE: XXX remember, this is NOT a real ed25519_sk. see notes elsewhere.
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES] = {0}; // zero'd
//	unsigned char x25519_sk[32] = {0}; // XXX do not delete. #crypto ms7821. might need this in future if libsodium fixes bug.
//	char *p;
	if(b64_decode(v3_priv_decoded,sizeof(v3_priv_decoded),privkey) != 64)
	{ // If 66, its because a random string of 88 characters was passed instead of 86 characters + ==
		error_simple(0,"outgoing_auth_x25519 failure. Bailing out. Report this.");
		return -1;
	}
	memcpy(ed25519_sk,v3_priv_decoded,32);
	sodium_memzero(v3_priv_decoded,sizeof(v3_priv_decoded));
	const int8_t local_debug = torx_debug_level(-1);
	if(local_debug > 4)
	{
		crypto_scalarmult_ed25519_base(ed25519_pk,ed25519_sk); // this generates pub key for debugging
		char ed25519_pk_b32[56+1];
		const size_t len = base32_encode((unsigned char*)ed25519_pk_b32,ed25519_pk,sizeof(ed25519_pk)); 
		error_printf(5,"Re-gen PubKey from Head (b32, 32 bytes): %s",ed25519_pk_b32);
		if(len != 56) 
			error_simple(0,"Uncaught error in outgoing_auth_x25519.");
	}
/*	if(crypto_sign_ed25519_sk_to_curve25519(x25519_sk,ed25519_sk) < 0) // XXX do not delete. #crypto ms7821. might need this in future if libsodium fixes bug. (FALSE, bad assumption)
		error("Fatal private key conversion issue");*/
	char apibuffer[512];
	char *p = b64_encode(ed25519_sk,sizeof(ed25519_sk));
	snprintf(apibuffer,512,"%s%s%s%s%s%s\n","authenticate \"",control_password_clear,"\"\nONION_CLIENT_AUTH_ADD ",peeronion," x25519:",p); // torx_free((void*)&)'d
	torx_free((void*)&p);
	tor_call(NULL,-1,apibuffer);
	sodium_memzero(apibuffer,sizeof(apibuffer));
	if(local_debug > 2)
	{
		error_printf(3,"Outgoing Auth: %s",p=b64_encode(ed25519_sk,32));
		torx_free((void*)&p);
	}
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	return 0;
}

static inline void *send_init(void *arg)
{ /* This should be called for every peer on startup and should set the peer [n]. sendfd. */
	const int n = vptoi(arg);
	torx_write(n) // XXX
	pusher(zero_pthread,(void*)&peer[n].thrd_send)
	torx_unlock(n) // XXX
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
	char peeronion[56+1];
	getter_array(&peeronion,sizeof(peeronion),n,-1,-1,-1,offsetof(struct peer_list,peeronion));
	uint8_t status; // must constantly re-check
	char suffixonion[56+6+1]; // Correct length to handle the .onion suffix required.
	memcpy(suffixonion,peeronion,56);
	snprintf(&suffixonion[56],sizeof(suffixonion)-56,".onion");
/*	if(show_log_days > 0)
	{
		sql_populate_message(peer_index,show_log_days);
		if(peer[n].message_n > 0)
			print_log_cb(n,peer[n].message_n);
	} */ // suspicious of redunancy
	const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
	const uint8_t peerversion = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,peerversion));
	char privkey[88+1];
	getter_array(&privkey,sizeof(privkey),n,-1,-1,-1,offsetof(struct peer_list,privkey));
	if(local_v3auth_enabled == 1 && peerversion > 1 && owner == ENUM_OWNER_CTRL && outgoing_auth_x25519(peeronion,privkey))
	{
		sodium_memzero(peeronion,sizeof(peeronion));
		sodium_memzero(privkey,sizeof(privkey));
		sodium_memzero(suffixonion,sizeof(suffixonion));
		error_simple(0,"Failure of send_init due to outgoing_auth_x25519. Bailing. Report this.");
		return 0;
	}
	sodium_memzero(peeronion,sizeof(peeronion));
	sodium_memzero(privkey,sizeof(privkey));
	const uint16_t vport = getter_uint16(n,-1,-1,-1,offsetof(struct peer_list,vport));
	char port_string[21];
	snprintf(port_string,sizeof(port_string),"%u",vport);
	while((status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status))) == ENUM_STATUS_FRIEND)
	{
		const int socket = socks_connect(suffixonion,port_string);
		if(socket < 1)
		{ // this causes blocking only until connected TODO endless segfaults here for unexplained reasons
			const uint8_t sendfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
			if(sendfd_connected)
			{ // TODO this occured on 2024/05/18 when doing repeated blocks/unblocks of online peer. unsure of implications. lots of warnings happened after.
				error_simple(0,"Nulling a .bev_send here possibly without doing any necessary free in libevent. Report this!!!");
				breakpoint();
				peer_offline(n,1);
			}
			sleep(1); // slow down attempts to reconnect. This is one place we should have sleep.
		}
		else
		{
			DisableNagle(socket);
			evutil_make_socket_nonblocking(socket); // for libevent
			setter(n,-1,-1,-1,offsetof(struct peer_list,sendfd),&socket,sizeof(socket));
			error_simple(1,"Connected to existing peer.");
			const uint8_t sendfd_connected = 1;
			setter(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected),&sendfd_connected,sizeof(sendfd_connected));
			struct event_strc *event_strc = torx_insecure_malloc(sizeof(struct event_strc));
			event_strc->sockfd = socket;
			event_strc->fd_type = 1; // sendfd
			event_strc->n = n;
			event_strc->fresh_n = -1;
			event_strc->buffer = NULL;
			event_strc->buffer_len = 0;
			event_strc->untrusted_message_len = 0;
			torx_events(event_strc); // NOTE: deleted peers will come out of here with owner "0000"
			if(evutil_closesocket(socket) == -1) // no need to check return on this. Sometimes -1, sometimes 0. Its just for ensuring cleanup
				error_printf(3,"Failed to close socket. 02312. Owner: %u. Status: %u.",owner,status);
			else
				error_simple(3,"Bingo. 02312"); // this sometimes occurs.
		}
	}
//	torx_free((void*)&port_string);
	sodium_memzero(suffixonion,sizeof(suffixonion));
	return 0; // peer blocked TODO did we close sockets?
}

void load_onion_events(const int n)
{ /* Passable to tor_call as callback after load_onion */ // TODO should check if this n is still valid and not deleted (or blocked?)
	const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER)
	{
		torx_read(n) // XXX
		pthread_t *thrd_send = &peer[n].thrd_send;
		torx_unlock(n) // XXX
		if(pthread_create(thrd_send,&ATTR_DETACHED,&send_init,itovp(n)))
			error_simple(-1,"Failed to create thread1");
	}
	if(owner == ENUM_OWNER_GROUP_PEER)
		return; // done, do not need to load listener because we no sockets to listen on... authenticated streams might change this TODO
	else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL)
	{ // Open .recvfd for a SING/MULT/CTRL/GROUP_CTRL onion, then call torx_events() on it
		struct sockaddr_in serv_addr = {0};//, cli_addr;
		const uint16_t tport = getter_uint16(n,-1,-1,-1,offsetof(struct peer_list,tport));
		if(tport < 1025)
		{
			error_simple(0,"No valid port provided.");
			return;
		}
		const int sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0)
		{
			error_simple(0,"Failed to open socket for recvfd");
			return;
		}
		DisableNagle(sock);
		evutil_make_socket_nonblocking(sock); // for libevent
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr(TOR_CTRL_IP); // IP associated with tport, not TOR_CTRL_IP
		serv_addr.sin_port = htobe16(tport);
		if(bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{
			error_simple(0,"Failed to bind. Perhaps the random port is already in use. Coding fail."); //  TODO hit this on 2023/08/11
			if(evutil_closesocket(sock) < 0)
				error_simple(0,"Unlikely socket failed to close error.6");
			return;
		}
		setter(n,-1,-1,-1,offsetof(struct peer_list,recvfd),&sock,sizeof(sock));
		struct event_strc *event_strc = torx_insecure_malloc(sizeof(struct event_strc));
		event_strc->sockfd = sock;
		event_strc->fd_type = 0; // recvfd
		event_strc->n = n;
		event_strc->fresh_n = -1;
		event_strc->buffer = NULL;
		event_strc->buffer_len = 0;
		event_strc->untrusted_message_len = 0;
		torx_read(n) // XXX
		pthread_t *thrd_recv = &peer[n].thrd_recv;
		torx_unlock(n) // XXX
		if(pthread_create(thrd_recv,&ATTR_DETACHED,&torx_events,(void*)event_strc))
			error_simple(-1,"Failed to create thread from load_onion_events");
	}
	else
	{ // Error if this is called on ENUM_OWNER_PEER
		error_printf(0,"Called load_onion_events on something wrong. Owner: %d. Report this.",owner);
		breakpoint();
	}
}
