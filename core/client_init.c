
void DisableNagle(const int sendfd)
{ // Might slightly reduce latency. As far as we can see, it is having no effect at all, because the OS or something is still implementing Nagle.
	const int on = 1;
	if(setsockopt(sendfd, IPPROTO_TCP, TCP_NODELAY, OPTVAL_CAST &on, sizeof(on)) == -1) 
	{
		error_simple(0,"Error in DisableNagle setting TCP_NODELAY. Report this.");
		perror("getsockopt");
	}
	const int sndbuf_size = SOCKET_SO_SNDBUF;
	const int recvbuf_size = SOCKET_SO_RCVBUF;
	if(sndbuf_size)
		if(setsockopt(sendfd, SOL_SOCKET, SO_SNDBUF, OPTVAL_CAST &sndbuf_size, sizeof(sndbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
	if(recvbuf_size)
		if(setsockopt(sendfd, SOL_SOCKET, SO_RCVBUF, OPTVAL_CAST &recvbuf_size, sizeof(recvbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
}

static inline int unclaim(const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p).
	const uint8_t peer_owner = getter_uint8(peer_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(n < 0 || f < 0 || peer_n < 0 || peer_owner == ENUM_OWNER_GROUP_CTRL)
	{
		error_printf(0,"Unclaim sanity check fail: n=%d f=%d peer_n=%d peer_owner=%u\n",n,f,peer_n,peer_owner);
		return 0;
	}
	int was_transferring = 0;
	const uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	if(status == ENUM_FILE_INBOUND_ACCEPTED)
	{
		uint16_t active_transfers_ongoing = 0;
		torx_read(n) // XXX
		if(peer[n].file[f].split_status == NULL || peer[n].file[f].split_status_fd == NULL)
		{
			torx_unlock(n) // XXX
			return was_transferring;
		}
		for(uint16_t section = peer[n].file[f].splits+1; section-- ; )
		{ // yes this is right, dont change it
			if(peer[n].file[f].split_status[section] == peer_n && (peer[n].file[f].split_status_fd[section] == fd_type || fd_type < 0))
			{
				torx_unlock(n) // XXX
				torx_write(n) // XXX
				peer[n].file[f].split_status[section] = -1; // unclaim section
				peer[n].file[f].split_status_fd[section] = -1;
				torx_unlock(n) // XXX
				error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status[%d] = -1"RESET,n,f,section);
				was_transferring = 1;
				torx_read(n) // XXX
			}
			else if(peer[n].file[f].split_status[section] > -1)
				active_transfers_ongoing++;
		}
		torx_unlock(n) // XXX
		if(active_transfers_ongoing == 0)
		{ // call transfer_progress with .last_transferred to trigger a stall
			stall: {}
			const uint64_t last_transferred = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,last_transferred));
			transfer_progress(n,f,last_transferred);
		}
	}
	else if(status == ENUM_FILE_OUTBOUND_ACCEPTED)
	{
		const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,sendfd_connected));
		const uint8_t recvfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected));
		if(!recvfd_connected && !sendfd_connected)
			process_pause_cancel(n,f,ENUM_PROTOCOL_FILE_PAUSE,ENUM_MESSAGE_RECV); // close file descriptors, set to OUTBOUND_PENDING
		goto stall; // Stall check any outbound transfers. This is NOT as effective as section_unclaim because this doesn't verify that there aren't other active sockets. Its not fully reliable.
	}
	return was_transferring;
}

int section_unclaim(const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p) // To unclaim all sections, pass fd_type == -1
	if(n < 0)
	{ // All other things can be -1
		error_simple(0,"Section unclaim failed sanity check.");
		return 0;
	}
	int peer_n_local = peer_n;
	if(peer_n < 0)
		peer_n_local = n;
	int was_transferring = 0; // TODO we should call progress cb and inform the UI that the transfer stopped... but only if both stopped...
	if(f > -1)  // Unclaim sections of a specific file (typical upon pause)
		was_transferring += unclaim(n,f,peer_n_local,fd_type);
	else // Unclaim sections of all files (typical when a socket closes during inbound transfer)
	{
		torx_read(n) // XXX
		for(int ff = 0 ; !is_null(peer[n].file[ff].checksum,CHECKSUM_BIN_LEN) ; ff++)
		{
			torx_unlock(n) // XXX
			was_transferring += unclaim(n,ff,peer_n_local,fd_type);
			torx_read(n) // XXX
		}
		torx_unlock(n) // XXX
	}
	return was_transferring;
}

static inline char *message_prep(uint32_t *message_len_p,int *section_p,const int target_n,const int8_t fd_type,const int n,const int f,const int g,const int p_iter,const time_t time,const time_t nstime,const void *arg,const uint32_t base_message_len)
{ // Prepare messages
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	char *base_message = torx_secure_malloc(base_message_len + null_terminated_len);
	uint64_t file_size = 0;
	if(f > -1)
		file_size = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size));
	int group_n = -1;
	uint32_t peercount = 0;
	uint8_t invite_required = 0;
	char onion_group_n[56+1];
	unsigned char sign_sk_group_n[crypto_sign_SECRETKEYBYTES];
	if(g > -1)
	{ // Note: relevant group, not target group
		group_n = getter_group_int(g,offsetof(struct group_list,n));
		invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
		peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		getter_array(&onion_group_n,sizeof(onion_group_n),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
		getter_array(&sign_sk_group_n,sizeof(sign_sk_group_n),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,sign_sk));
	}
	if(protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE)
	{ // CHECKSUM[64] + SIZE[8] + MODIFIED[4] + FILENAME (no null termination)
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
		const uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash64,sizeof(uint64_t));
		const time_t modified = getter_time(n,INT_MIN,f,-1,offsetof(struct file_list,modified));
		uint32_t trash32 = htobe32((uint32_t)modified);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
		torx_read(n) // XXX
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],peer[n].file[f].filename,strlen(peer[n].file[f].filename)); // second time calling strlen
		torx_unlock(n) // XXX
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
	{ // HashOfHashes + Splits[1] + CHECKSUM_BIN_LEN *(splits + 1)) + SIZE[8] (+ MODIFIED[4] + FILENAME (no null termination)) or, if partial (+ split_info[section] *(splits + 1))
		torx_read(n) // XXX
		const unsigned char *split_hashes = peer[n].file[f].split_hashes;
		torx_unlock(n) // XXX
		if(split_hashes == NULL)
		{
			error_simple(0,"split_hashes is NULL. This is unacceptable at this point.");
			breakpoint();
			goto error;
		}
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,-1,offsetof(struct file_list,checksum)); // hash of hashes + size, not hash of file
		const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
		*(uint8_t*)(void*)&base_message[CHECKSUM_BIN_LEN] = splits;
		const size_t split_hashes_len = (size_t)(CHECKSUM_BIN_LEN *(splits + 1));
		torx_read(n) // XXX
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],peer[n].file[f].split_hashes,split_hashes_len);
		torx_unlock(n) // XXX
		uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len],&trash64,sizeof(uint64_t));
		if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
			for(uint8_t section = 0; section <= splits; section++)
			{ // Add how much is completed on each section
				torx_read(n) // XXX
				trash64 = htobe64(peer[n].file[f].split_info[section]);
				torx_unlock(n) // XXX
				memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + section * sizeof(uint64_t)],&trash64,sizeof(uint64_t));
			}
		else /* if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED) */
		{ // Add modification date and filename
			const time_t modified = getter_time(n,INT_MIN,f,-1,offsetof(struct file_list,modified));
			const uint32_t trash32 = htobe32((uint32_t)modified);
			memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
			torx_read(n) // XXX
			memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t)],peer[n].file[f].filename,strlen(peer[n].file[f].filename)); // second time calling strlen
			error_printf(3,"Checkpoint message_send group file offer: %lu %s %s\n",file_size,peer[n].file[f].filename,b64_encode(base_message,CHECKSUM_BIN_LEN));
			torx_unlock(n) // XXX
		}

	}
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{ // CHECKSUM[64] + START[8] + END[8]
		torx_read(n) // XXX
		const int *split_status = peer[n].file[f].split_status;
		const int8_t *split_status_fd = peer[n].file[f].split_status_fd;
		torx_unlock(n) // XXX
		if(split_status == NULL || split_status_fd == NULL)
		{ // TODO Can trigger upon Accept -> Reject / Cancel -> Re-offer -> Accept
			error_simple(0,"Split_status is NULL. This is unacceptable at this point. Should call split_read or section_update first, either of which will initialize.");
			split_read(n,f);
		}
		const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
		torx_read(n) // XXX
		for(int section = 0; section <= splits; section++)
			if(peer[n].file[f].split_status_fd[section] == fd_type && peer[n].file[f].split_status[section] == target_n)
			{ // Catch where there is already a request for a section of this file on this FD from this peer. We need to catch this because otherwise they will corrupt each other.
				torx_unlock(n) // XXX
				error_printf(0,"File request already exists n=%d fd=%d. Bailing.",n,fd_type);
				goto error;
			}
		torx_unlock(n) // XXX
		int section = 0;
		section_done: {}
		int current_n;
		torx_read(n) // XXX
		while((current_n = peer[n].file[f].split_status[section]) != -1 && section < splits)
			section++; // find an section not currently utilized for receiving
		const uint64_t current = peer[n].file[f].split_info[section];
		torx_unlock(n) // XXX
		if(current_n != -1)
		{ // very necessary check
			error_simple(1,"No free sections to request from message_send. Bailing. (not necessarily error)"); // error message not required
			goto error;
		}
		const uint64_t start = calculate_section_start(file_size,splits,section) + current;
		const uint64_t end = calculate_section_start(file_size,splits,section+1)-1;
		if(start >= file_size)
			goto error; // last section, is done, do not request it (other sections might have been requested on cycle 0)
		else if(start > end)
		{
			section++;
			goto section_done;
		}
		if((int64_t)end == -1) // 18446744073709551615
		{ // bail out. calculate_section_start returned an error (this can happen if we are requesting 1 byte files in full duplex)
			error_simple(0,"Presently no support for requesting 1 and 0 byte length files.");
			goto error; // abandoning attempts to support until we abolish message_send cycles
		}
		torx_write(n) // XXX
		error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status[%d] = %d, fd_type = %d"RESET,n,f,section,target_n,fd_type);
		peer[n].file[f].split_status[section] = target_n; // XXX claim it. NOTE: do NOT have any 'goto error' after this. MUST NOT ERROR AFTER CLAIMING XXX
		peer[n].file[f].split_status_fd[section] = fd_type;
		torx_unlock(n) // XXX
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
		error_printf(0,"Checkpoint request sec=%d %lu to %lu on fd==%d",section,start,end,fd_type);
		uint64_t trash = htobe64(start);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash,sizeof(uint64_t));
		trash = htobe64(end);
		memcpy(&base_message[CHECKSUM_BIN_LEN+sizeof(uint64_t)],&trash,sizeof(uint64_t));
		*section_p = section;
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_PEERLIST)
	{ // Audited 2024/02/16 // Format: Peercount[4] + onions (56*peercount) + ed25519_pk(56*peercount) (if relevant: + invitation signature(56*peercount)) // NOTE: If this is first-connect, ie peerlist == NULL, trust and connect to the owner. Otherwise, ignore the owner and group_add_peer everyone else only.
		if(peercount < 1)
		{
			error_simple(0,"Attempted to send GROUP_PEERLIST that doesn't exist. Coding error. Report this.");
			breakpoint();
			goto error;
		}
		const uint32_t trash = htobe32(peercount);
		memcpy(&base_message[0],&trash,sizeof(uint32_t));
		size_t cur = sizeof(uint32_t); // current position
		#define obtain_specific_peer \
			pthread_rwlock_rdlock(&mutex_expand_group);\
			const int specific_peer = group[g].peerlist[nn];\
			pthread_rwlock_unlock(&mutex_expand_group);
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{ // Peeronions first
			obtain_specific_peer
			getter_array(&base_message[cur],56,specific_peer,INT_MIN,-1,-1,offsetof(struct peer_list,peeronion));
			cur += 56;
		}
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{ // Peer public keys
			obtain_specific_peer
			getter_array(&base_message[cur],crypto_sign_PUBLICKEYBYTES,specific_peer,INT_MIN,-1,-1,offsetof(struct peer_list,peer_sign_pk));
			cur += crypto_sign_PUBLICKEYBYTES;
		}
		if(invite_required)
			for(uint32_t nn = 0 ; nn < peercount ; nn++)
			{ // Inviter signatures of peeronions ( non-applicable to public groups )
				obtain_specific_peer
				getter_array(&base_message[cur],crypto_sign_BYTES,specific_peer,INT_MIN,-1,-1,offsetof(struct peer_list,invitation));
				cur += crypto_sign_BYTES;
			}
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
	{ // Onion[56] + ed25519_pk[32] + signed by invitor[64]
		memcpy(base_message,onion_group_n,56);
		crypto_sign_ed25519_sk_to_pk((unsigned char*)&base_message[56],sign_sk_group_n);
		getter_array(&base_message[56+crypto_sign_PUBLICKEYBYTES],crypto_sign_BYTES,group_n,INT_MIN,-1,-1,offsetof(struct peer_list,invitation));
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
	{ // Audited 2024/02/15 // GROUP_ID[32] + Peercount[4] + invite_required[1] { + GROUP_CTRL's onion + ed25519_pk[32] }
		pthread_rwlock_rdlock(&mutex_expand_group);
		memcpy(base_message,group[g].id,GROUP_ID_SIZE); // affix group_id
		pthread_rwlock_unlock(&mutex_expand_group);
		const uint32_t trash = htobe32(peercount);
		memcpy(&base_message[GROUP_ID_SIZE],&trash,sizeof(uint32_t)); // affix peercount
		*(uint8_t*)&base_message[GROUP_ID_SIZE+sizeof(uint32_t)] = invite_required; // affix invite_required
		if(protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
		{ // Pass our GROUP_CTRL because we just created the group and no one signed our GROUP_CTRL yet. We need our first GROUP_PEER to sign it (invite us to our own group)
			memcpy(&base_message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)],onion_group_n,56);
			crypto_sign_ed25519_sk_to_pk((unsigned char*)&base_message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)+56],sign_sk_group_n);
		}
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
	{ // Audited 2024/02/15 // TODO should probably have some checks here because ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY is automatically sent from libevent and we don't verify that the group and onions exist. should cancel if no.
		pthread_rwlock_rdlock(&mutex_expand_group);
		memcpy(base_message,group[g].id,GROUP_ID_SIZE);
		pthread_rwlock_unlock(&mutex_expand_group);
		memcpy(&base_message[GROUP_ID_SIZE],onion_group_n,56);
		crypto_sign_ed25519_sk_to_pk((unsigned char*)&base_message[GROUP_ID_SIZE+56],sign_sk_group_n);
		if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
		{
			const struct int_char *int_char = (const struct int_char*) arg; // (re-)Casting passed struct
			unsigned char to_sign[56+crypto_sign_PUBLICKEYBYTES];
			memcpy(to_sign,int_char->p,56); // their onion
			memcpy(&to_sign[56],int_char->up,crypto_sign_PUBLICKEYBYTES); // their ed25519_pk
			unsigned char invitation[crypto_sign_BYTES];
			unsigned long long siglen = 0;
			if(crypto_sign_detached(invitation,&siglen,to_sign,sizeof(to_sign),sign_sk_group_n) != 0 || siglen != crypto_sign_BYTES)
			{ // OUR SIGNATURE OF THEIR ONION + PK
				error_simple(0,"Unable to sign their peeronion.");
				sodium_memzero(to_sign,sizeof(to_sign));
				goto error;
			}
			sodium_memzero(to_sign,sizeof(to_sign));
			memcpy(&base_message[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES],invitation,crypto_sign_BYTES);
			if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY)
			{ // Append our group[g].invitation after (which we received from someone else when we joined the group)
				getter_array(&base_message[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES],crypto_sign_BYTES,group_n,INT_MIN,-1,-1,offsetof(struct peer_list,invitation));
				char peernick[56+1];
				getter_array(&peernick,sizeof(peernick),target_n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
				if(group_add_peer(g,int_char->p,peernick,int_char->up,invitation) > -1) // we are working with two invitations... this is the correct one
					error_simple(0,RED"Checkpoint New group peer! (message_prep)"RESET);
				sodium_memzero(peernick,sizeof(peernick));
			}
			sodium_memzero(invitation,sizeof(invitation));
		}
	}
	else if(arg && base_message_len) // Necessary check?
	{ // If we simply need to add a null byte, we'll do it here rather than in message_sign, to avoid copying
		memcpy(base_message,arg,base_message_len); // this is a necessary copy
		if(null_terminated_len)
			base_message[base_message_len] = '\0';
	}
	char *message_new;
	if(signature_len)
	{ // Sign message
		unsigned char *sk;
		const uint8_t owner_target = getter_uint8(target_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		unsigned char sign_sk_target_n[crypto_sign_SECRETKEYBYTES];
		if(owner_target == ENUM_OWNER_GROUP_PEER)
			sk = sign_sk_group_n;
		else
		{
			getter_array(&sign_sk_target_n,sizeof(sign_sk_target_n),target_n,INT_MIN,-1,-1,offsetof(struct peer_list,sign_sk));
			sk = sign_sk_target_n;
		}
		if(date_len)
			message_new = message_sign(message_len_p,sk,time,nstime,p_iter,base_message,base_message_len);
		else
			message_new = message_sign(message_len_p,sk,0,0,p_iter,base_message,base_message_len);
		if(owner_target != ENUM_OWNER_GROUP_PEER)
			sodium_memzero(sign_sk_target_n,sizeof(sign_sk_target_n));
	}
	else
	{ // Unsigned
		if(date_len)
			message_new = message_sign(message_len_p,NULL,time,nstime,p_iter,base_message,base_message_len);
		else
		{
			message_new = base_message;
			*message_len_p = base_message_len + null_terminated_len;
		}
	}
	if(g > -1)
	{
		sodium_memzero(sign_sk_group_n,sizeof(sign_sk_group_n));
		sodium_memzero(onion_group_n,sizeof(onion_group_n));
	}
	if(message_new != base_message)
		torx_free((void*)&base_message);
	return message_new;
	error: {}
	if(g > -1)
	{
		sodium_memzero(sign_sk_group_n,sizeof(sign_sk_group_n));
		sodium_memzero(onion_group_n,sizeof(onion_group_n));
	}
	torx_free((void*)&base_message);
	*message_len_p = 0;
	return NULL;
}

static inline int message_distribute(const uint8_t skip_prep,const int n,const uint8_t owner,const int target_n,const int f,const int g,const int target_g,const uint32_t target_g_peercount,const int p_iter,const void *arg,const uint32_t base_message_len,time_t time,time_t nstime)
{ // TODO WARNING: Sanity checks will interfere with message_resend. Message_send + message_distribute + message_prep are highly functional spagetti.
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t stream = protocols[p_iter].stream;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols);
	uint8_t send_both = 0;
	uint8_t v3auth;
	if(skip_prep) // message resend, n is -1
		v3auth = getter_uint8(target_n,INT_MIN,-1,-1,offsetof(struct peer_list,v3auth));
	else
	{ // Note: send_both must not be set if target_g > -1 because it will interfere with cycle variable
		v3auth = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,v3auth));
		send_both = (target_g < 0 && (protocol == ENUM_PROTOCOL_KILL_CODE || (protocol == ENUM_PROTOCOL_FILE_REQUEST && v3auth && getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,full_duplex)) && getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits)) > 0)));
	}
	uint32_t cycle = 0;
	int repeated = 0; // MUST BE BEFORE other_fd:{}
	other_fd: {} // NOTE: This is a totally new message, unlike messages that just get sent to all peers in a group (see while below)
	// XXX Step 4: Set date if unset, and set fd
	if(!time && !nstime)
		set_time(&time,&nstime);
	int8_t fd_type; // TODO
	if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
		fd_type = 1; // PIPE_AUTH is exclusively sent out on sendfd
	else if(cycle == 0 && send_both)
		fd_type = 1;
	else if(v3auth && getter_uint8(target_n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected)))
		fd_type = 0; // put on recvfd for reliability & speed
	else
		fd_type = 1; // put on sendfd for safety (safer when not using v3auth, unless using authorized pipe)
	// XXX Step 5: Build base message
	char *message;
	uint32_t message_len;
	int requested_section = -1; // must initialize. Will only be > -1 if ENUM_PROTOCOL_FILE_REQUEST
	if(skip_prep)
	{ // For re-send only. Warning: Highly experimental.
		message_len = base_message_len;
		message = torx_secure_malloc(message_len);
		memcpy(message,arg,message_len);
	}
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		message = message_prep(&message_len,&requested_section,target_n,fd_type,n,f,g,p_iter,time,nstime,arg,base_message_len);
	else
		message = message_prep(&message_len,NULL,target_n,fd_type,n,f,g,p_iter,time,nstime,arg,base_message_len);
	if(message_len < 1)
	{ // (could just be cycle 2 of a file resumption of a file thats half-done)
		if(cycle == 0 && send_both)
		{ // Only triggers on FILE_REQUEST, where message_prep decided to not to send anything (probably because this fd is utilized already for a section)
			cycle++;
			goto other_fd; // TODO 2023/11/16 I don't like this goto but eliminating it is complex
		}
		if(protocol != ENUM_PROTOCOL_FILE_REQUEST)
			error_printf(0,"Checkpoint message_send 0 length. Bailing. fd=%d protocol=%u send_both=%u",fd_type,protocol,send_both);
		goto error;
	}
	// XXX Step 6: Iterate message
	const int i = getter_int(target_n,INT_MIN,-1,-1,offsetof(struct peer_list,max_i)) + 1;
	expand_message_struc(target_n,i);
	torx_write(target_n) // XXX
	peer[target_n].max_i++; // this is critical NOTHING CAN BE DONE WITH "peer[n].message[peer[n].max_i]." AFTER THIS
	peer[target_n].message[i].time = time;
	peer[target_n].message[i].nstime = nstime;
	peer[target_n].message[i].message = message;
	peer[target_n].message[i].message_len = message_len;
	peer[target_n].message[i].p_iter = p_iter;
	peer[target_n].message[i].stat = ENUM_MESSAGE_FAIL;
	torx_unlock(target_n) // XXX
	// XXX Step 7: Send_prep as appropriate
	while(1)
	{
		int nnnn = target_n;
		int iiii = i;
		uint8_t owner_nnnn = getter_uint8(nnnn,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		if(target_g > -1)
		{ // This is for messages to all GROUP_PEER. "Public message"
			pthread_rwlock_rdlock(&mutex_expand_group);
			nnnn = group[target_g].peerlist[cycle];
			pthread_rwlock_unlock(&mutex_expand_group);
			if(nnnn < 0 || (owner_nnnn = getter_uint8(nnnn,INT_MIN,-1,-1,offsetof(struct peer_list,owner))) != ENUM_OWNER_GROUP_PEER)
			{ // sanity check
				error_printf(0,"Attempting to send group message on non-GROUP_PEER. Bailing. Report this. Details: nnnn: %d Owner: %u Protocol: %u Peercount: %u",nnnn,owner_nnnn,protocol,target_g_peercount);
				breakpoint();
				goto error;
			}
			torx_read(target_n) // XXX
			const time_t local_time = peer[target_n].message[i].time;
			const time_t local_nstime = peer[target_n].message[i].nstime;
			const uint32_t local_message_len = peer[target_n].message[i].message_len;
			char *local_message = peer[target_n].message[i].message;
			torx_unlock(target_n) // XXX

			iiii = getter_int(nnnn,INT_MIN,-1,-1,offsetof(struct peer_list,max_i)) + 1;
			expand_message_struc(nnnn,iiii);
			torx_write(nnnn) // XXX
			peer[nnnn].max_i++; // this is critical NOTHING CAN BE DONE WITH "peer[n].message[peer[n].max_i]." AFTER THIS
			peer[nnnn].message[iiii].time = local_time; // needs to be duplicate so that we can do lookup later
			peer[nnnn].message[iiii].nstime = local_nstime;
			peer[nnnn].message[iiii].message_len = local_message_len;
			peer[nnnn].message[iiii].message = local_message;
			peer[nnnn].message[iiii].stat = ENUM_MESSAGE_FAIL;
			peer[nnnn].message[iiii].p_iter = p_iter;
			torx_unlock(nnnn) // XXX
		}
		int ret;
		if((ret = send_prep(nnnn,iiii,p_iter,fd_type)) == -1 && protocol == ENUM_PROTOCOL_FILE_REQUEST && f > -1 && requested_section > -1)
		{ // Unclaim section due to failure to immediately send, and delete the message TODO would be nice to prevent creating the message instead
			torx_write(nnnn) // XXX
			zero_i(nnnn,iiii);
			torx_unlock(nnnn) // XXX
			section_unclaim(n,f,nnnn,fd_type);
		}
		else if(ret == -1 && stream)
		{ // delete unsuccessful stream message
			torx_write(nnnn) // XXX
			zero_i(nnnn,iiii);
			torx_unlock(nnnn) // XXX
			if(target_g < 0)
				return -1; // WARNING: do not attempt to free. pointer is already pointing to bunk location after zero_i. will segfault. experimental 2024/03/09
		}
		else if(!stream)
		{ // Save non-stream message to peer struct and potentially disk
			if(cycle == 0)
			{
				if(target_g > -1 || (owner == ENUM_OWNER_GROUP_PEER && group_pm))
				{ // Complicated logic, be careful here. Group messages or PM.
					int local_g = g; // NOTE: maybe we can just use g but we can't use target_g because its used for conditions elsewhere
					if(local_g < 0 && target_g < 0) // PM of some type
						local_g = set_g(target_n,NULL);
					else if(local_g < 0)
						local_g = target_g;
					repeated = message_insert(local_g,target_n,i); // repeated likely means resent message. No print, no insert.
				}
				if(!repeated)
				{ // unique same time/nstime, so print and save
					print_message_cb(target_n,i,1); // GUI Callback
					sql_insert_message(target_n,i); // This should go before setting .all_sent = 0, to ensure that it happens before send (which will trigger :sent: write)
				}
			}
			if(!repeated && target_g > -1) // MUST go after the first sql_insert_message call (which saves the message initially to GROUP_CTRL)
				sql_insert_message(nnnn,iiii); // trigger save in each GROUP_PEER
		}
		if(cycle == 0 && send_both)
		{ // must send start point on each respective fd. 
			cycle++;
			goto other_fd; // TODO 2023/11/16 I don't like this goto but eliminating it is complex
		}
		if(owner_nnnn != ENUM_OWNER_GROUP_PEER || target_g < 0 || ++cycle >= target_g_peercount)
			break; // be careful of the logic here and after. note the ++
	}
/*	if(target_g > -1 && stream)
	{ // Finally zero the GROUP_CTRL's message (the GROUP_PEER's messages are zero'd earlier or in outbound_cb TODO NO. cannot do it here. have to do it somehow in outbound_cb after the last 
		printf("Checkpoint hypothetically deleting group_ctrl's i\n"); // TODO see: sfaoij2309fjfw
		torx_write(nnnn) // XXX
		zero_i(nnnn,iiii);
		torx_unlock(nnnn) // XXX
	} */
	return 0;
	error: {}
	torx_free((void*)&message);
	return -1;
}

int message_resend(const int n,const int i)
{ // Primarily for signed group_msg in private groups (both SENT and RECV), but also works on any type of OUTBOUND message. CAVEAT / LIMITATION: SENT can be spoofed (by original sender). We can modify our outbound message then re-send... hypothetically this could facilitate "recall" and "modify sent" in an unreliable way. (but currently we don't permit that. We just discard anything that fails message_insert)
	int p_iter;
	uint8_t owner;
	if(n < 0 || (owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner))) < 1 || (p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter))) < 0)
	{
		error_simple(0,"message_resend failed sanity check. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	int target_g = -1;
	uint32_t target_g_peercount = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL && group_msg)
	{	target_g = set_g(n,NULL);
		if((target_g_peercount = getter_group_uint32(target_g,offsetof(struct group_list,peercount))) < 1)
		{ // this isn't necessarily an error. this would be an OK place to bail out in some circumstances like broadcast messages
			error_simple(0,"Group has no users. Refusing to queue message. This is fine.");
			breakpoint();
			return -1;
		}
	}
	time_t time = 0;
	time_t nstime = 0;
	torx_read(n) // XXX
	const char *message = peer[n].message[i].message;
	const uint32_t message_len = peer[n].message[i].message_len;
	if(target_g > -1 && date_len && signature_len)
	{ // Keep the existing times (ie, resend only) only if its a group using signed && dated messages (ie private groups)
		time = peer[n].message[i].time;
		nstime = peer[n].message[i].nstime;
	}
	torx_unlock(n) // XXX
	message_distribute(1,-1,owner,n,-1,-1,target_g,target_g_peercount,p_iter,message,message_len,time,nstime);
	return 0;	
}

int message_send(const int target_n,const uint16_t protocol,const void *arg,const uint32_t base_message_len)
{ // To send a message to all members of a group, pass the group_n as target_n. The group_n will store the message but each peer will have copies of the time, protocol, status.
	int p_iter;
	uint8_t owner;
	if(target_n < 0 || protocol < 1 || (owner = getter_uint8(target_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner))) < 1 || (p_iter = protocol_lookup(protocol)) < 0)
	{
		error_printf(0,"message_send failed sanity check: %d %u %u %d. Coding error. Report this.",target_n,protocol,owner,p_iter);
		breakpoint();
		return -1;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	pthread_rwlock_unlock(&mutex_protocols);
	int g = -1;
	int f = -1;
	int target_g = -1; // LIMITED USE currently DO NOT USE EXTENSIVELY
	uint32_t target_g_peercount = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL && group_msg)
	{ // XXX Step 1: Set the group for messages going out to all multiple GROUP_PEER
		target_g = set_g(target_n,NULL);
		target_g_peercount = getter_group_uint32(target_g,offsetof(struct group_list,peercount));
		if(target_g_peercount < 1)
		{ // this isn't necessarily an error. this would be an OK place to bail out in some circumstances like broadcast messages
			error_printf(0,"Group has no users. Refusing to queue message. This is fine. Protocol: %u",protocol);
			return -1;
		}
	/*	pthread_rwlock_rdlock(&mutex_protocols);
		const uint8_t group_mechanics = protocols[p_iter].group_mechanics;
		const uint8_t stream = protocols[p_iter].stream;
		const uint32_t date_len = protocols[p_iter].date_len;
		const uint32_t signature_len = protocols[p_iter].signature_len;
		pthread_rwlock_unlock(&mutex_protocols);
		const uint8_t target_invite_required = getter_group_uint8(target_g,offsetof(struct group_list,invite_required));
		if(target_invite_required == 1 && (date_len == 0 || signature_len == 0) && group_mechanics == 0 && stream == 0 && protocol != ENUM_PROTOCOL_GROUP_BROADCAST)
		{
			error_printf(0,"Warning: Attempting to send non-date-signed message into a private group. Protocol: %u. Possible coding error. Report this. Not bailing out.",protocol);
			breakpoint();
		} */
	}
	// XXX Step 2: Handle passed arg from certain protocols that pass integer or struct
	int n = target_n;
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{
		const struct int_int *int_int = (const struct int_int*) arg; // Casting passed struct
		n = int_int->n;
		f = int_int->i;
		owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	}
	else if(file_offer)
		f = vptoi(arg);
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
		g = vptoi(arg);
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
	{ // Note: The rest of the passed struct is accessed in message_distribute --> message_prep
		const struct int_char *int_char = (const struct int_char*) arg; // Casting passed struct
		g = int_char->i;
	}
	else if(owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
		g = set_g(n,NULL);
	// XXX Step 3:
	if(message_distribute(0,n,owner,target_n,f,g,target_g,target_g_peercount,p_iter,arg,base_message_len,0,0) == -1)
		return -1;
	return 0; // could also return i
}

void kill_code(const int n)
{ /* -1 (global) deletes all SING/MULT, cycles through CTRL list and add a kill_code on each */ // Does nothing for outgoing friend requests ("peer")
	if(n == -1)
	{ /* Global kill code */
		for(int peer_index,nn = 0 ; (peer_index = getter_int(nn,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index))) > -1 || getter_byte(nn,INT_MIN,-1,-1,offsetof(struct peer_list,onion)) != 0 ; nn++)
		{
			if(peer_index < 0)
				continue;
			const uint8_t owner_nn = getter_uint8(nn,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
			if(owner_nn == ENUM_OWNER_CTRL)
			{ /* Saves the kill code message to message log even if logging is turned off, to survive reboot */
				sql_delete_history(peer_index);
				message_send(nn,ENUM_PROTOCOL_KILL_CODE,NULL,0);
			}
			else if(owner_nn == ENUM_OWNER_SING || owner_nn == ENUM_OWNER_MULT)
				takedown_onion(peer_index,1);
		}
	}
	else
	{ // Specific peer
		const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
		sql_delete_history(peer_index);
		message_send(n,ENUM_PROTOCOL_KILL_CODE,NULL,0);
	}
}

static inline int select_peer(const int group_n,const int f)
{ // Check: blacklist, online status, how much data they have. Determine which group peer to request file from // TODO enhance this function to select
	const uint8_t owner = getter_uint8(group_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner != ENUM_OWNER_GROUP_CTRL)
	{
		error_simple(0,"Select_peer can only be called on GROUP_CTRL. Coding error. Report this.");
		return -1;
	}
	const uint8_t splits = getter_uint8(group_n,INT_MIN,f,-1,offsetof(struct file_list,splits));
	int o = 0;
	int tentative_n = 0;
	uint64_t tentative_progress = 0;
	uint8_t tentative_section = 0; // TODO utilize, should probably pass it to message_send
	for(int offerer_n ; (offerer_n = getter_int(group_n,INT_MIN,f,o,offsetof(struct offer_list,offerer_n))) != -1 ; o++)
	{
		const uint8_t sendfd_connected = getter_uint8(offerer_n,INT_MIN,-1,-1,offsetof(struct peer_list,sendfd_connected));
		const uint8_t recvfd_connected = getter_uint8(offerer_n,INT_MIN,-1,-1,offsetof(struct peer_list,recvfd_connected));
		const uint8_t online = recvfd_connected + sendfd_connected;
	//	const uint8_t utilized = getter_uint8(n,INT_MIN,f,o,offsetof(struct offer_list,utilized));
		const uint8_t blacklisted = getter_uint8(offerer_n,INT_MIN,-1,-1,offsetof(struct peer_list,blacklisted));
		if(/*utilized >= */!online || blacklisted) // check blacklist and online status
		{
		//	printf("Checkpoint o=%d already utilized or blacklisted (%u). %u >= %u\n",o,blacklisted,utilized,online);
			continue;
		}
		int utilized = 0;
		for(uint8_t section = 0; section <= splits; section++)
		{ // Loop through all peers looking for the largest (most complete) section... literally any section.
			torx_read(group_n) // XXX
			const uint64_t offerer_progress = peer[group_n].file[f].offer[o].offer_info[section];
			torx_unlock(group_n) // XXX

			// TODO TODO TODO TODO
			// 	continue if we have completed this section or if it is already being requested from someone else
			if(peer[group_n].file[f].split_status[section] == offerer_n)
				utilized++;
			if(utilized >= online)
				break;
			if(peer[group_n].file[f].split_status[section] != -1)
				continue;
			if(peer[group_n].file[f].split_info[section] >= offerer_progress)
				continue;
			// TODO TODO TODO TODO

			if(offerer_progress >= tentative_progress)
			{ // >= should result in the largest most recent offer being selected
				tentative_n = offerer_n;
				tentative_progress = offerer_progress;
				tentative_section = section;
			}
		}
	}
	if(o && tentative_progress)
	{
		o--; // THIS IS CRITICAL, do not remove
	//	torx_write(group_n) // XXX
		printf("Choosing group_n=%d n=%d o=%d with progress=%lu on section=%u\n",group_n,tentative_n,o,tentative_progress,tentative_section);
	//	printf("Choosing n=%d o=%d with progress=%lu on section=%u utilized=%u\n",tentative_n,o,tentative_progress,tentative_section,peer[n].file[f].offer[o].utilized);
	//	peer[n].file[f].offer[o].utilized++; // TODO perhaps this should be later, not in this function, otherwise the message could fail and leave someone permanently utilized... but we also don't want to call it too late
	//	printf("Checkpoint now utilized: %u\n",peer[n].file[f].offer[o].utilized);
	//	torx_unlock(group_n) // XXX
		if(getter_uint8(tentative_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner)) != ENUM_OWNER_GROUP_PEER)
			error_simple(-1,"Tentative_n can only be GROUP_PEER. Coding error. Report this.");
		return tentative_n;
	}
	// XXX put debug info here, like how many peers online, how many utilized, 
	return -1;
}

static inline int file_unwritable(const int n,const int f,char *file_path)
{ // Check whether file permissions issues exist at the destination before requesting a file. Pass either n+f or file_path.
	if((n < 0 || f < 0) && file_path == NULL)
	{
		error_simple(0,"Sanity check in file_unwritable failed.");
		breakpoint();
		return 1;
	}
	FILE *fp;
	if(file_path)
		fp = fopen(file_path, "a");
	else
	{
		torx_read(n) // XXX
		fp = fopen(peer[n].file[f].file_path, "a");
		torx_unlock(n) // XXX
	}
	if(fp)
	{
		fclose(fp);
		fp = NULL;
		return 0;
	}
	else
	{ // TODO not sure if this is a good idea but its simplifying things at the moment
		error_simple(0,"File location permissions issue. Refusing to request file. Cleaing the file_path and setting to INBOUND_PENDING if n,f was passed so that it can be reset.");
		torx_write(n) // XXX
		torx_free((void*)&peer[n].file[f].file_path);
		torx_free((void*)&peer[n].file[f].split_path);
		if(peer[n].file[f].status == ENUM_FILE_INBOUND_ACCEPTED)
			peer[n].file[f].status = ENUM_FILE_INBOUND_PENDING;
		torx_unlock(n) // XXX
		return 1;
	}
}

void file_request_internal(const int n,const int f)
{ // Internal function only, do not call from UI. Use file_accept
	if(n < 0 || f < 0)
		return;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	torx_read(n) // XXX
	const char *file_path = peer[n].file[f].file_path;
	torx_unlock(n) // XXX
	if(file_path)
	{
		if(file_unwritable(n,f,NULL))
			return;
	}
	else if(owner == ENUM_OWNER_GROUP_PEER)
	{ // has no file path, unless PM transfer
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int g_f = set_f(group_n,checksum,sizeof(checksum));
		sodium_memzero(checksum,sizeof(checksum));
		if(file_unwritable(group_n,g_f,NULL))
			return;
	}
	else
	{
		error_simple(0,"Lack of file_path in file_request_internal. Coding error. Report this.");
		breakpoint();
		return;
	}
	struct int_int int_int;
	int_int.n = n; // potentially group_n
	int_int.i = f;
	if(owner != ENUM_OWNER_GROUP_CTRL)
		message_send(n,ENUM_PROTOCOL_FILE_REQUEST,&int_int,FILE_REQUEST_LEN);
	else						// this check could be is_inbound_transfer ??
		for(int target_n ; status != ENUM_FILE_OUTBOUND_PENDING && status != ENUM_FILE_OUTBOUND_ACCEPTED && (target_n = select_peer(n,f)) > -1 ; )
			message_send(target_n,ENUM_PROTOCOL_FILE_REQUEST,&int_int,FILE_REQUEST_LEN);
}

void file_set_path(const int n,const int f,const char *path)
{ // To be called before file_accept. This is a helper function for FFI/Flutter.
	size_t len;
	if(!path || !(len = strlen(path)))
	{
		error_simple(0,"Zero length or null path passed to file_set_path");
		return;
	}
	torx_write(n) // XXX
	if(peer[n].file[f].file_path == NULL)
	{
		peer[n].file[f].file_path = torx_secure_malloc(len+1);
		memcpy(peer[n].file[f].file_path,path,len+1);
		torx_unlock(n) // XXX
	}
	else
	{
		torx_unlock(n) // XXX
		error_simple(0,"Currently, changing file_path is not facilitated. (we would have to change file name too and make sure its not active, maybe move the actual file...");
	}
}

void file_accept(const int n,const int f)
{ // Toggle to accept or pause file transfer
	if(n < 0 || f < 0)
		return;
	torx_read(n) // XXX
	const uint8_t owner = peer[n].owner;
	uint8_t status = peer[n].file[f].status;
	const char *filename = peer[n].file[f].filename;
	torx_unlock(n) // XXX
	if(filename == NULL)
	{ // probably ENUM_OWNER_GROUP_PEER, non-PM message, or where the file path is not yet set by UI
		error_simple(0,"File information not provided. Cannot accept. Coding error. Report this.");
		printf("Checkpoint file_accept owner: %u status: %d\n",owner,status);
		return;
	}
	if(status == ENUM_FILE_INBOUND_ACCEPTED || status == ENUM_FILE_OUTBOUND_ACCEPTED)
	{ // pause in/outbound transfer. Reciever can unpause it.  // Much redundancy in logic applies with file cancel
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
		if(owner == ENUM_OWNER_GROUP_CTRL)
		{ // Send pause to all peers sending us data and unclaim relevant sections.
			torx_read(n) // XXX
			if(peer[n].file[f].split_status == NULL || peer[n].file[f].split_status_fd == NULL)
			{
				torx_unlock(n) // XXX
				return;
			}
			for(uint16_t section = peer[n].file[f].splits+1; section-- ; )
			{ // yes this is right, dont change it
				const int peer_n = peer[n].file[f].split_status[section];
				if(peer_n > -1)
				{
					torx_unlock(n) // XXX
					message_send(peer_n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
					if(status == ENUM_FILE_INBOUND_ACCEPTED)
						section_unclaim(n,f,peer_n,-1);
					torx_read(n) // XXX
				}
			}
			torx_unlock(n) // XXX
		}
		else
		{
			message_send(n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
			if(status == ENUM_FILE_INBOUND_ACCEPTED)
				section_unclaim(n,f,-1,-1);
		}
		sodium_memzero(checksum,sizeof(checksum));
		process_pause_cancel(n,f,ENUM_PROTOCOL_FILE_PAUSE,ENUM_MESSAGE_FAIL); // set status and close file descriptors, must be set AFTER section_unclaim
		const uint64_t last_transferred = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,last_transferred));
		transfer_progress(n,f,last_transferred); // trigger a stall // TODO TODO TODO is this too early? should it be after process_pause_cancel?
	}
	else if(status == ENUM_FILE_OUTBOUND_PENDING || status == ENUM_FILE_OUTBOUND_REJECTED || status == ENUM_FILE_OUTBOUND_CANCELLED)
	{ // User unpause by re-offering file (safer than setting _ACCEPTED and directly start re-pushing (Section 6RMA8obfs296tlea), even though it could mean some packets / data is sent twice.)
		if(status == ENUM_FILE_OUTBOUND_REJECTED || status == ENUM_FILE_OUTBOUND_CANCELLED)
		{
			status = ENUM_FILE_OUTBOUND_PENDING;
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
		}
		if(owner == ENUM_OWNER_GROUP_CTRL)
		{
			const int g = set_g(n,NULL);
			const uint8_t invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
			const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
			if(invite_required)
				message_send(n,ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,itovp(f),FILE_OFFER_GROUP_LEN);
			else
				message_send(n,ENUM_PROTOCOL_FILE_OFFER_GROUP,itovp(f),FILE_OFFER_GROUP_LEN);
		}
		else if(owner == ENUM_OWNER_GROUP_PEER)
			message_send(n,ENUM_PROTOCOL_FILE_OFFER_PRIVATE,itovp(f),FILE_OFFER_LEN);
		else
			message_send(n,ENUM_PROTOCOL_FILE_OFFER,itovp(f),FILE_OFFER_LEN);
		// DO NOT CALL process_pause_cancel here, do not set _ACCEPTED ; we wait for peer to accept
	}
	else if(status == ENUM_FILE_INBOUND_PENDING)
	{ // Accept, re-accept, or unpause a file
		pthread_rwlock_rdlock(&mutex_global_variable);
		const char *local_download_dir = download_dir;
		pthread_rwlock_unlock(&mutex_global_variable);
		torx_read(n) // XXX
		const char *file_path = peer[n].file[f].file_path;
		torx_unlock(n) // XXX
		if(local_download_dir != NULL && file_path == NULL)
		{ // Setting file_path to inside download_dir if existing. Client may have already set .file_path, preventing this from occuring.
			torx_write(n) // XXX
			pthread_rwlock_rdlock(&mutex_global_variable);
			const size_t allocated_size = strlen(download_dir)+1+strlen(peer[n].file[f].filename)+1;
			peer[n].file[f].file_path = torx_secure_malloc(allocated_size);
			snprintf(peer[n].file[f].file_path,allocated_size,"%s%c%s",download_dir,platform_slash,peer[n].file[f].filename);
			pthread_rwlock_unlock(&mutex_global_variable);
			torx_unlock(n) // XXX
		}
		else if(local_download_dir == NULL && file_path == NULL)
		{
			error_simple(0,"Cannot accept file. Have not set file path nor download directory.");
			return;
		}
		const uint8_t v3auth = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,v3auth));
		uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
		torx_read(n) // XXX
		const unsigned char *split_hashes = peer[n].file[f].split_hashes;
		torx_unlock(n) // XXX
		if(v3auth && threadsafe_read_uint8(&mutex_global_variable,&full_duplex_requests) && splits == 0 && split_hashes == NULL)
		{ // set splits to 1 if not already, but not on group files
			splits = 1; // set default before split_read, which might overwrite it.
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,splits),&splits,sizeof(splits));
		}
		initialize_split_info(n,f); // calls split_read(n,f);
		const uint64_t size = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size));
		if(calculate_transferred(n,f) < size)
		{
			status = ENUM_FILE_INBOUND_ACCEPTED;
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
			file_request_internal(n,f);
		}
		else // Complete. Not checking if oversized or wrong hash.
		{ // XXX This should NEVER trigger because the .split file should have been deleted if transferred == .size, unless split_read() is redesigned to check file size
			error_simple(0,"This code should never execute. If it executes, the split file hasn't been deleted but should have been. Report this.");
			printf("Checkpoint %lu of %lu transferred\n",calculate_transferred(n,f),size);
			breakpoint();
			status = ENUM_FILE_INBOUND_COMPLETED;
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
			transfer_progress(n,f,calculate_transferred(n,f)); // calling this because we set file status ( not necessary when calling message_send which calls print_message_cb )
		}
	}
	else
	{
		error_printf(0,"Attempted file_accept on file %d with unrecognized status: %u. Coding error. Report this.",f,status);
		breakpoint();
	}
}

void file_cancel(const int n,const int f)
{ // Much redundancy in logic applies with file pause
	if(n < 0 || f < 0)
		return;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	unsigned char checksum[CHECKSUM_BIN_LEN];
	getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
	if(status == ENUM_FILE_INBOUND_PENDING || status == ENUM_FILE_INBOUND_ACCEPTED || status == ENUM_FILE_OUTBOUND_PENDING || status == ENUM_FILE_OUTBOUND_ACCEPTED || status == ENUM_FILE_OUTBOUND_COMPLETED || status == ENUM_FILE_OUTBOUND_REJECTED)
	{
		const int is_inbound = is_inbound_transfer(status);
		if(owner == ENUM_OWNER_GROUP_CTRL && is_inbound)
		{ // Send cancel to all peers sending us data and unclaim relevant sections.
			torx_read(n) // XXX
			if(peer[n].file[f].split_status == NULL || peer[n].file[f].split_status_fd == NULL)
			{
				torx_unlock(n) // XXX
				return;
			}
			for(uint16_t section = peer[n].file[f].splits+1; section-- ; )
			{ // yes this is right, dont change it
				const int peer_n = peer[n].file[f].split_status[section];
				if(peer_n > -1)
				{
					torx_unlock(n) // XXX
					message_send(peer_n,ENUM_PROTOCOL_FILE_CANCEL,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
					if(status == ENUM_FILE_INBOUND_ACCEPTED)
						section_unclaim(n,f,peer_n,-1);
					torx_read(n) // XXX
				}
			}
			torx_unlock(n) // XXX
		}
		else// if(is_inbound)
		{
			message_send(n,ENUM_PROTOCOL_FILE_CANCEL,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
			if(status == ENUM_FILE_INBOUND_PENDING || status == ENUM_FILE_INBOUND_ACCEPTED)
				section_unclaim(n,f,-1,-1);
		}
		sodium_memzero(checksum,sizeof(checksum));
		process_pause_cancel(n,f,ENUM_PROTOCOL_FILE_CANCEL,ENUM_MESSAGE_FAIL); // set status and close file descriptors, must be set AFTER section_unclaim
		if(status == ENUM_FILE_INBOUND_PENDING || status == ENUM_FILE_INBOUND_ACCEPTED)
		{ // these are old statuses, which would have been changed by process_pause_cancel, so be aware not to read fresh here
			torx_read(n) // XXX
			const char *file_path = peer[n].file[f].file_path;
			torx_unlock(n) // XXX
			destroy_file(file_path); // delete partially sent inbound files (note: may also delete fully transferred but that can never be guaranteed)
			split_update(n,f,-1); // destroys split file and frees/nulls resources
		}
		const uint64_t last_transferred = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,last_transferred));
		transfer_progress(n,f,last_transferred); // trigger a stall // TODO TODO TODO is this too early? should it be after process_pause_cancel?
	}
	else
		error_printf(0,"Attempted file_cancel on file with unrecognized status: %u. UI Coding error. Report this to UI devs.",status);
}

static inline void *file_init(void *arg)
{ // Send File Offer
	struct file_strc *file_strc = (struct file_strc*) arg; // Casting passed struct
	const int n = file_strc->n;
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL); // TODO not utilized. Need to track then pthread_cleanup_push + pop + thread_kill
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	unsigned char checksum[CHECKSUM_BIN_LEN];
	size_t size = 0;
	uint8_t splits = 0;
	unsigned char *split_hashes_and_size = NULL;
//	printf("Checkpoint file_init owner==%u path==%s\n",owner,file_strc->path);
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Determine split count, allocate and populate split_hashes, generate hash of hashes
		splits = UINT8_MAX;
		printf("Checkpoint checking file size 1\n");
		size = get_file_size(file_strc->path);
		while(splits && size / splits < MINIMUM_SECTION_SIZE)
			splits--;
		const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
		split_hashes_and_size = torx_secure_malloc(split_hashes_len+sizeof(uint64_t));
		size_t size_total = 0; // sum of sections
		for(int section = 0; section <= splits; section++)
		{ // populate split_hashes
			const uint64_t start = calculate_section_start(size,splits,section);
			const uint64_t end = calculate_section_start(size,splits,section+1)-1;
			const uint64_t len = end-start+1;
		//	printf("Checkpoint section %d %lu %lu\n",section,start,len);
			size_total += b3sum_bin(&split_hashes_and_size[CHECKSUM_BIN_LEN*section],file_strc->path,NULL,start,len);
		}
		if(size != size_total)
		{
			error_simple(0,"Coding or IO error. File size != sum of sections");
			printf("Checkpoint %lu != %lu\n",size,size_total);
			goto error;
		}
		const uint64_t trash = htobe64(size);
		memcpy(&split_hashes_and_size[split_hashes_len],&trash,sizeof(uint64_t));
		b3sum_bin(checksum,NULL,split_hashes_and_size,0,split_hashes_len+sizeof(uint64_t)); // hash of hashes and size
	}
	else // TODO running a checksum on a file to determine its f value. Might already have it but didn't bother checking from the path + time. (note: different checksum type on group files, cannot check GROUP_CTRL's files)
		size = b3sum_bin(checksum,file_strc->path,NULL,0,0);
	if(size < 1)
	{
		error_printf(0,"File is empty: %s",file_strc->path);
		goto error;
	}
	const int f = process_file_offer_outbound(n,checksum,splits,split_hashes_and_size,size,file_strc->modified,file_strc->path);
//	printf("Checkpoint file_init n==%d f==%d size==%lu checksum==%s\n",n,f,size,b64_encode(checksum,CHECKSUM_BIN_LEN));
	sodium_memzero(checksum,sizeof(checksum));
	uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	if(status == ENUM_FILE_OUTBOUND_REJECTED || status == ENUM_FILE_OUTBOUND_CANCELLED)
	{
		status = ENUM_FILE_OUTBOUND_PENDING;
		setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
	}
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		const int g = set_g(n,NULL);
		const uint8_t invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
		if(invite_required)
			message_send(n,ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,itovp(f),FILE_OFFER_GROUP_LEN);
		else
			message_send(n,ENUM_PROTOCOL_FILE_OFFER_GROUP,itovp(f),FILE_OFFER_GROUP_LEN);
	}
	else if(owner == ENUM_OWNER_GROUP_PEER)
		message_send(n,ENUM_PROTOCOL_FILE_OFFER_PRIVATE,itovp(f),FILE_OFFER_LEN);
	else
		message_send(n,ENUM_PROTOCOL_FILE_OFFER,itovp(f),FILE_OFFER_LEN);
	error: {}
	torx_free((void*)&split_hashes_and_size);
	torx_free((void*)&file_strc->path);
	torx_free((void*)&file_strc);
	return 0;
}

int file_send(const int n,const char *path)
{ // Caller is responsible for freeing *path
	if(n < 0 || path == NULL || path[0] == '\0')
		return -1;
	struct stat file_stat = {0}; // TODO st_size is available but is limited to 4gb/int32_t. if it could be used, we could depreciate get_file_size() https://unix.stackexchange.com/questions/621157/why-is-the-type-of-stat-st-size-not-unsigned-int
	if(stat(path, &file_stat) < 0)
	{
		error_simple(0,"File seems to not exist. Cannot send.");
		return -1;
	}
	struct file_strc *file_strc = torx_insecure_malloc(sizeof(struct file_strc));
	file_strc->modified = file_stat.st_mtime;
	file_strc->n = n;
	const size_t path_len = strlen(path);
	file_strc->path = torx_secure_malloc(path_len+1);
	snprintf(file_strc->path,path_len+1,"%s",path);
	pthread_t thrd_file_init; // TODO 2024/03/25 track this thread somehow and/or put a mutex inside file_init? both are of questionable utility.
	if(pthread_create(&thrd_file_init,&ATTR_DETACHED,&file_init,(void*)file_strc))
		error_simple(-1,"Failed to create thread6");
	return 0;
}
