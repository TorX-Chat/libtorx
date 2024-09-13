/*	This file contains core TorX functions that require disk interaction (currently all except search_file(), initial()	
XXX Known Bug List XXX
	* on 2022/08/15, a unrecognized config option _pwhash_ALG with value: 2, resulted in the salt being overwritten and therefore all files destroyed
		issue: a line was written to the beginning of the .key file instead of the end, overwriting several newlines (we need to prevent this)
			could have been caused by a lack of mutex, or a bug somewhere. Should resolve it via mutex + prevent overwriting a \n
	* change_password is not possible to change to empty password, only from empty password
	* /accept <b2sum> // on our OWN OFFER seems to have the result of "finished transfer"
	* MLF1 loads up peer[n].file[f]. without regard to whether the file has already completed transfer. It needs a :done: :canc: etc to interpret status.
	* takedown_onion does not take down detached onions
	getinfo onions/detached shows nothing. fuck. we might need to run all commands from a single levent control connection

XXX To Do List XXX
	* have delete_history, taking a single message iter OR to delete a whole peer's history
		note: need a way to clear those zero'd lines (which requires re-writing the whole log file... might need to just keep log files in a reasonable length range so this can be done every time a manual delete is requested, without wasting too much disk IO)
	* Add "logging 1/0" as a write_config() for each peer. Refer to "Proposed New statuses" below for codes. (but do NOT use .conf because we cannot risk corruption)
	* delete server should zero any "last_seen-" times (the setting name and value) in .key
	* delete server should zero any "logging-" times (the setting name and value) in .key
		perhaps these two can be implemented by "write_config_setting_ll(0,setting_name,"",NULL);" call
	* delete server should zero and delete any message history 
	* verify that we are closing our outbound socket / cancelling send_init() etc when we block someone
	* have a function that can mark :recv: as :read: (certain clients might expect that)
	* certain functions can be combined if they have the same return and same arguments (like in file_magic)
		alternatively, where that is not appropriate, we can start passint structs rather than long lines of args

XXX Notes XXX
	* we will not be able to fully defeat a log correlation attack (two devices seized, both logging) unless:
		we save ALL peer chat history in a SINGLE file, AND
		we have a random length string on each line ending
	^ Doing so however will prevent us from using "find_log_backwards()" properly and could result in scanning the ENTIRE chat history on startup
		unless we indexed the location of the messages, but that could create a new avenue for log correlation (whatever file we used). (NOT viable)
		or we load based on "show x days history" instead of "show x messages history" (VIABLE SOLUTION)
		^ we'll call it encryption == 2 and we'll do it with binary data instead of base64 to save 40% space

XXX WARNINGS XXX
	* don't use a file descriptor after close or it could result in corruption, according to https://www.sqlite.org/howtocorrupt.html
*/

int is_inbound_transfer(const uint8_t file_status)
{
	if(file_status == ENUM_FILE_OUTBOUND_PENDING || file_status == ENUM_FILE_OUTBOUND_ACCEPTED || file_status == ENUM_FILE_OUTBOUND_COMPLETED || file_status == ENUM_FILE_OUTBOUND_REJECTED || file_status == ENUM_FILE_OUTBOUND_CANCELLED)
		return 0; // File Transfer Direction is Outbound ( we are sender )
	else if(file_status == ENUM_FILE_INBOUND_PENDING || file_status == ENUM_FILE_INBOUND_ACCEPTED || file_status == ENUM_FILE_INBOUND_COMPLETED || file_status == ENUM_FILE_INBOUND_REJECTED || file_status == ENUM_FILE_INBOUND_CANCELLED)
		return 1; // File Transfer Direction is Inbound ( we are receiver )
	else
		error_simple(-1,"Unrecognized file_status passed to is_inbound_transfer. Coding error. Report this.");
	return -1; // this is a junk reply, should exit program before this. this is just to suppress warning.
}

void process_pause_cancel(const int n,const int f,const uint16_t protocol,const uint8_t message_stat)
{ // XXX This WILL NOT properly handle group file shares. Also this function is one-way (to PENDING/CANCELLED/REJECTED), not a toggle.
/*	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		if(message_stat == ENUM_MESSAGE_RECV)
			error_simple(0,"Received a pause or cancel on Group CTRL or with regards ");
		else
			error_simple(0,"");
		return;
	}	*/
	const uint8_t old_file_status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	uint8_t new_file_status = old_file_status;
	if(protocol == ENUM_PROTOCOL_FILE_PAUSE)
	{
		if(old_file_status == ENUM_FILE_OUTBOUND_ACCEPTED)
			new_file_status = ENUM_FILE_OUTBOUND_PENDING;
		else if(old_file_status == ENUM_FILE_INBOUND_ACCEPTED)
			new_file_status = ENUM_FILE_INBOUND_PENDING;
	}
	else if(protocol == ENUM_PROTOCOL_FILE_CANCEL)
	{
		if(message_stat == ENUM_MESSAGE_RECV)
		{
			if(old_file_status == ENUM_FILE_OUTBOUND_PENDING || old_file_status == ENUM_FILE_OUTBOUND_ACCEPTED || old_file_status == ENUM_FILE_OUTBOUND_COMPLETED)
				new_file_status = ENUM_FILE_OUTBOUND_REJECTED; // Outbound file recieved cancel --> _REJECTED
			else if(old_file_status == ENUM_FILE_INBOUND_PENDING || old_file_status == ENUM_FILE_INBOUND_ACCEPTED/* || old_file_status == ENUM_FILE_INBOUND_COMPLETED*/)
				new_file_status = ENUM_FILE_INBOUND_CANCELLED; // Inbound file recieved cancel --> _CANCELLED
		}
		else
		{
			if(old_file_status == ENUM_FILE_OUTBOUND_PENDING || old_file_status == ENUM_FILE_OUTBOUND_ACCEPTED || old_file_status == ENUM_FILE_OUTBOUND_COMPLETED || old_file_status == ENUM_FILE_OUTBOUND_REJECTED)
				new_file_status = ENUM_FILE_OUTBOUND_CANCELLED; // Outbound file SENT cancel --> _CANCELLED
			else if(old_file_status == ENUM_FILE_INBOUND_PENDING || old_file_status == ENUM_FILE_INBOUND_ACCEPTED/* || old_file_status == ENUM_FILE_INBOUND_COMPLETED*/)
				new_file_status = ENUM_FILE_INBOUND_REJECTED; // Inbound file SENT cancel --> _REJECTED
		}
	}
	if(new_file_status == old_file_status)
		return; // no changes, no action.
	setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&new_file_status,sizeof(new_file_status));
	if(new_file_status == ENUM_FILE_OUTBOUND_CANCELLED || new_file_status == ENUM_FILE_OUTBOUND_REJECTED)
	{ // Close outbound fd
		close_sockets(n,f,peer[n].file[f].fd_out_recvfd)
		close_sockets(n,f,peer[n].file[f].fd_out_sendfd)
	}
	else if(new_file_status == ENUM_FILE_INBOUND_CANCELLED || new_file_status == ENUM_FILE_INBOUND_REJECTED)
	{ // Close inbound fd
		close_sockets(n,f,peer[n].file[f].fd_in_recvfd)
		close_sockets(n,f,peer[n].file[f].fd_in_sendfd)
	}
}

int process_file_offer_outbound(const int n,const unsigned char *checksum,const uint8_t splits,const unsigned char *split_hashes_and_size,const uint64_t size,const time_t modified,const char *file_path)
{ // Populates peer[n].file[f].{stuff} for outbound ENUM_PROTOCOL_FILE_OFFER
	if(n < 0 || !checksum || !file_path || !size)
	{
		error_simple(0,"Sanity check failed in process_file_offer_outbound. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	const int f = set_f(n,checksum,CHECKSUM_BIN_LEN);
//	printf("Checkpoint file_init n==%d f==%d checksum==%s\n",n,f,b64_encode(checksum,CHECKSUM_BIN_LEN));
	if(split_hashes_and_size)
	{ // set splits and split_hashes for group files
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		if(owner != ENUM_OWNER_GROUP_CTRL)
		{
			error_simple(0,"Improperly attempting to set split_hashes for a non-GROUP_CTRL. Outbound. Coding error. Report this.");
			breakpoint();
			return -1;
		}
		setter(n,INT_MIN,f,-1,offsetof(struct file_list,splits),&splits,sizeof(splits));
		const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
		torx_write(n) // XXX
		peer[n].file[f].split_hashes = torx_secure_malloc(split_hashes_len+sizeof(uint64_t));
		memcpy(peer[n].file[f].split_hashes,split_hashes_and_size,split_hashes_len+sizeof(uint64_t));
		torx_unlock(n) // XXX
	}
	const size_t file_path_len = strlen(file_path);
	char path_copy[file_path_len+1]; // Both dirname() and basename() may modify the contents of path, so it may be desirable to pass a copy when calling one of these functions.
	memcpy(path_copy,file_path,file_path_len+1); // copy null byte
	const char *filename = basename(path_copy);
	const size_t filename_len = strlen(filename);
	torx_write(n) // XXX
	peer[n].file[f].filename = torx_secure_malloc(filename_len+1);
	snprintf(peer[n].file[f].filename,filename_len+1,"%s",filename);
	peer[n].file[f].file_path = torx_secure_malloc(file_path_len+1);
	snprintf(peer[n].file[f].file_path,file_path_len+1,"%s",file_path);
	torx_unlock(n) // XXX
	setter(n,INT_MIN,f,-1,offsetof(struct file_list,size),&size,sizeof(size));
	uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	if(status == 0) // presumably this will always be true?
	{
		status = ENUM_FILE_OUTBOUND_PENDING;
		setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
	}
	setter(n,INT_MIN,f,-1,offsetof(struct file_list,modified),&modified,sizeof(modified));
	sodium_memzero(path_copy,sizeof(path_copy)); // DO NOT DO THIS EARLIER as it modifies 'filename' variable
	return f;
}

int process_file_offer_inbound(const int n,const int p_iter,const char *message,const uint32_t message_len)
{ // processes inbound ENUM_PROTOCOL_FILE_OFFER
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL || message == NULL || p_iter < 0 || n < 0 || message_len == 0)
	{ // could do more extensive sanity check on message_len here. we do that later though, so no need
		error_simple(0,"process_file_offer_inbound triggered on group ctrl or sanity check fail. Coding error. Report this.");
		printf("Checkpoint %u %d %d %d %u",owner,message ? 1 : 0,p_iter,n,message_len);
		breakpoint();
		return -1;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t utf8 = protocols[p_iter].utf8;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	int f;
	if(protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE)
	{ // Receive File offer
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t) + 1)
			goto error;
		f = set_f(n,(const unsigned char*)message,CHECKSUM_BIN_LEN); // using checksum is correct here
		const size_t filename_len = message_len - (CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t));
		if(utf8 && !utf8_valid(&message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],filename_len))
		{
			error_simple(0,"Peer offered a file with a non-UTF8 filename. Discarding offer.");
			return -1;
		}
		torx_write(n) // XXX
		if(peer[n].file[f].filename) // wipe if existing // this might be undesirable? especially if already accepted. should be fine. the old .split file/partial transfer will be abandoned?
			torx_free((void*)&peer[n].file[f].filename); // TODO could cause issue if someone renamed a file then offered it again, in the same instance, after a partial transfer already occured? idk
		peer[n].file[f].filename = torx_secure_malloc(filename_len+1);
		memcpy(peer[n].file[f].filename,&message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],filename_len); // source is not null terminated
		peer[n].file[f].filename[filename_len] = '\0';
		peer[n].file[f].size = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN]));
		peer[n].file[f].modified = be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint64_t)]));
		if(!peer[n].file[f].status || peer[n].file[f].status == ENUM_FILE_INBOUND_REJECTED || peer[n].file[f].status == ENUM_FILE_INBOUND_CANCELLED) // prevent overriding an existing status
			peer[n].file[f].status = ENUM_FILE_INBOUND_PENDING;
		torx_unlock(n) // XXX
		// not setting .transferred, will default to 0 if the destination file is empty // TODO open file/split?
		// file_path is also set elsewhere
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
	{ // HashOfHashes + sizeof(uint8_t) + CHECKSUM_BIN_LEN *(splits + 1)) + sizeof(uint64_t) + (protocol specitic other)
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint8_t))
			goto error;
		const uint8_t splits = *(const uint8_t*)(const void*)&message[CHECKSUM_BIN_LEN];
		const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
		if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL && message_len < FILE_OFFER_PARTIAL_LEN) // CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint64_t) * (splits + 1) + date_len + signature_len)
			goto error;
		else if((protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED) && message_len < CHECKSUM_BIN_LEN + sizeof(uint8_t) + (size_t)(CHECKSUM_BIN_LEN *(splits + 1)) + sizeof(uint64_t) + sizeof(uint32_t) + 1 + date_len + signature_len)
			goto error;
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		if(group_n < 0)
			goto error; // received protocol on normal CTRL?
		f = set_f(group_n,(const unsigned char*)message,CHECKSUM_BIN_LEN); // Note: passing full length will register checksum, if not existing
		size_t filename_len = 0;
		if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
		{
			const size_t prefix = CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t);
			filename_len = message_len - (prefix + date_len + signature_len);
			if(utf8 && !utf8_valid(&message[prefix],filename_len))
			{ // sanity check filename
				for(size_t zzz = 0; zzz < filename_len ; zzz++)
					printf("Checkpoint: (%c)\n",message[prefix + zzz]);
			//	error_simple(0,"Peer offered a file with a non-UTF8 filename. Discarding offer.");
			//	printf("Checkpoint filename: %s\n",&message[prefix]);
				return -1;
			}
		}
		unsigned char hash_of_hashes[CHECKSUM_BIN_LEN];
		if(b3sum_bin(hash_of_hashes,NULL,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],0,split_hashes_len+sizeof(uint64_t)) != split_hashes_len+sizeof(uint64_t) || memcmp(hash_of_hashes,message,CHECKSUM_BIN_LEN))
		{ // this probably will also error out if peer sends a wrong number of splits, which is necessary to check
			error_simple(0,"Received invalid group file offer. Invalid hash of hashes.");
			sodium_memzero(hash_of_hashes,sizeof(hash_of_hashes));
			return -1;
		}
		sodium_memzero(hash_of_hashes,sizeof(hash_of_hashes));
		torx_read(group_n) // XXX
		const unsigned char *split_hashes = peer[group_n].file[f].split_hashes;
		const char *filename = peer[group_n].file[f].filename;
		torx_unlock(group_n) // XXX
		if(!split_hashes && !filename)
		{
			torx_write(group_n) // XXX
			peer[group_n].file[f].splits = splits; // verified via hash of hashes
			peer[group_n].file[f].split_hashes = torx_secure_malloc(split_hashes_len+sizeof(uint64_t)); // verified via hash of hashes
			memcpy(peer[group_n].file[f].split_hashes,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],split_hashes_len+sizeof(uint64_t));
			peer[group_n].file[f].size = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len])); // verified via hash of hashes
			if(protocol != ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
			{ // handle filename
				peer[group_n].file[f].modified = be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)]));
				peer[group_n].file[f].filename = torx_secure_malloc(filename_len+1);
				memcpy(peer[group_n].file[f].filename,&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t)],filename_len);
				peer[group_n].file[f].filename[filename_len] = '\0';
				printf("Checkpoint inbound GROUP FILE_OFFER nos=%u size=%"PRIu64" %s\n",splits,peer[group_n].file[f].size,peer[group_n].file[f].filename);
			}
			if(!peer[group_n].file[f].status) // prevent overriding an existing status
				peer[group_n].file[f].status = ENUM_FILE_INBOUND_PENDING;
			torx_unlock(group_n) // XXX
		}
		uint8_t status = getter_uint8(group_n,INT_MIN,f,-1,offsetof(struct file_list,status));
		if(status == ENUM_FILE_INBOUND_REJECTED || status == ENUM_FILE_INBOUND_CANCELLED)
		{
			status = ENUM_FILE_INBOUND_PENDING;
			setter(group_n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
		}
	//	else // We only check in groups because malicious peers
	//		error_simple(0,"Received file offer for file we already have in struct (partial or full). (NOT Allocating split hashes)");
		const uint64_t size = getter_uint64(group_n,INT_MIN,f,-1,offsetof(struct file_list,size));
		const int o = set_o(group_n,f,n);
		setter(group_n,INT_MIN,f,o,offsetof(struct offer_list,offerer_n),&n,sizeof(n));
		torx_write(group_n) // XXX
		if(peer[group_n].file[f].offer[o].offer_info == NULL)
			peer[group_n].file[f].offer[o].offer_info = torx_insecure_malloc(sizeof(uint64_t)*(splits+1));
		if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
			for(int section = 0; section <= splits; section++)
				peer[group_n].file[f].offer[o].offer_info[section] = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + (size_t)section*sizeof(uint64_t)]));
		else
			for(int section = 0; section <= splits; section++)
			{ // setting every section to 100% because this offer type is of a complete file
				const uint64_t start = calculate_section_start(size,splits,section);
				const uint64_t end = calculate_section_start(size,splits,section+1)-1;
				peer[group_n].file[f].offer[o].offer_info[section] = end - start + 1;
			}
		torx_unlock(group_n) // XXX
		if(status == ENUM_FILE_INBOUND_ACCEPTED)
			file_request_internal(group_n,f);
	}
	return 0;
	error: {}
	error_simple(0,"Got a complete file offer below minimum size. Bailing. Report this.");
	printf("Checkpoint below minimum size: %u protocol: %u\n",message_len,protocol);
	return -1;
}

static inline size_t stripbuffer_b32_len51(char *buffer)
{ // For stealth addresses. This function strips anything other than 2-7 and A-Z, and strips away anything longer than 51 characters. The result should be a TorX-ID that was previously obscured with invalid and/or extraneous characters. DO NOT use this for handshakes, which contain non-base32 characters.
	size_t j = 1; // necessary to initialize as 1 in case of 0 length
	for(size_t i = 0; buffer[i] != '\0'; ++i) 
	{
		while(!(buffer[i] >= 'a' && buffer[i] <= 'z') && !(buffer[i] >= 'A' && buffer[i] <= 'Z') && !(buffer[i] >= '2' && buffer[i] <= '7') && !(buffer[i] == '\0')) 
		{
			for(j = i; buffer[j] != '\0'; ++j) 
				buffer[j] = buffer[j + 1];
			buffer[j] = '\0';
		}
		if(i == 51)
		{
			buffer[i] = '\0';
			return i;
		}
	}
	if(j-1 == 0 && buffer != NULL) // workaround for case where no modifications need to be done to string
		j = j + strlen(buffer);
	return j-1;
}

static inline void *peer_init(void *arg)
{ /* For sending an outgoing friend request */
	const int n = vptoi(arg);
	torx_write(n) // XXX
	pusher(zero_pthread,(void*)&peer[n].thrd_send)
	torx_unlock(n) // XXX
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	char suffixonion[56+6+1];
	getter_array(suffixonion,56,n,INT_MIN,-1,-1,offsetof(struct peer_list,peeronion));
	snprintf(&suffixonion[56],6+1,"%6s",".onion");
	const uint16_t vport = INIT_VPORT;
	setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,vport),&vport,sizeof(vport));
	char port_string[21];
	snprintf(port_string,sizeof(port_string),"%d",vport);
	evutil_socket_t proxyfd;
	while((proxyfd = socks_connect(suffixonion,port_string)) < 1) // this is blocking
		sleep(1); // not sure if necessary. could probably be eliminated or reduced without any ill effect
	char fresh_privkey[88+1] = {0};
	char peernick[56+1];
	getter_array(&peernick,sizeof(peernick),n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
	const int fresh_n = generate_onion(ENUM_OWNER_CTRL,fresh_privkey,peernick);
	// generate keypair here, do not store it yet except locally
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(ed25519_pk,ed25519_sk);
	char buffer[2+56+crypto_sign_PUBLICKEYBYTES];
	uint16_t trash;
	if(!threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled))
		trash = htobe16(1);
	else
		trash = htobe16(torx_library_version[0]);
	memcpy(&buffer[0],&trash,sizeof(uint16_t));
	getter_array(&buffer[2],56,fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
	memcpy(&buffer[2+56],ed25519_pk,sizeof(ed25519_pk));
	DisableNagle(proxyfd); // DO NOT REMOVE THIS it helps packets stay together
	listen(SOCKET_CAST_OUT proxyfd,1); // Maximum one connect at a time
	const ssize_t s = send(SOCKET_CAST_OUT proxyfd,buffer,sizeof(buffer),0); // this is blocking
	if(s < 0)
		error_simple(0,"Error writing to client socket. should probably try again?");
	else if(s != sizeof(buffer))
		error_printf(0,"Message only partially sent: %ld bytes. This probably means our peer will spoil their onion.",s);
	else // 2+56+32
	{ /* Good send, Expecting response */
		const ssize_t r = recv(SOCKET_CAST_OUT proxyfd,buffer,sizeof(buffer),0); // XXX BLOCKING
		while(1)
		{ // not a real while loop... just avoiding goto
			if(r >= (ssize_t) sizeof(buffer))
			{
	//printf("Checkpoint correct size reply of %d\n",r);
				if(fresh_n > -1) // sanity check of n
				{ // XXX WARNING: Use fresh_n (ctrl) not n (peer) XXX
					unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
					memcpy(peer_sign_pk,&buffer[2+56],sizeof(peer_sign_pk));
					buffer[2+56] = '\0';// null terminate our expected onion, which corrupts our already removed peer_sign_pk
					stripbuffer(buffer); // stripping invalid characters after we remove binary data
					const uint16_t fresh_peerversion = be16toh(align_uint16((void*)&buffer[0]));
					char fresh_peeronion[56+1];
					memcpy(fresh_peeronion,&buffer[2],56);
					fresh_peeronion[56] = '\0'; // necessary null termination
					if(load_peer_struc(-1,ENUM_OWNER_CTRL,ENUM_STATUS_FRIEND,fresh_privkey,fresh_peerversion,fresh_peeronion,peernick,ed25519_sk,peer_sign_pk,NULL) != fresh_n)
					{
						error_simple(0,"Error 12091241. Report this.");
						breakpoint();
						sodium_memzero(fresh_peeronion,sizeof(fresh_peeronion));
						sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
						break;
					}
					char peernick_fresh_n[56+1];
					getter_array(&peernick_fresh_n,sizeof(peernick_fresh_n),fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
					const int peer_index = sql_insert_peer(ENUM_OWNER_CTRL,ENUM_STATUS_FRIEND,fresh_peerversion,fresh_privkey,fresh_peeronion,peernick_fresh_n,0);
					setter(fresh_n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
					error_printf(3,"Outbound Handshake occured with %s who has freshonion %s",peernick,fresh_peeronion);
					sodium_memzero(peernick_fresh_n,sizeof(peernick_fresh_n));
					sodium_memzero(fresh_peeronion,sizeof(fresh_peeronion));
					sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
					sql_update_peer(fresh_n);
					load_onion(fresh_n);
					peer_new_cb(fresh_n);
				}
			}
			else
				error_printf(0,"Wrong sized init reply received from peer of length: %ld after sending length: %ld. Handshake failed.",r,s); //  Could consider deleting peer (no, because their onion could be a mult)
			break;
		}
		const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
		takedown_onion(peer_index,1); // delete our PEER XXX after load_onion, otherwise we'll have zeros in our new onion's peernick
	}
	if(evutil_closesocket(proxyfd) == -1)
		error_simple(0,"Failed to close socket. 3414");
	sodium_memzero(peernick,sizeof(peernick));
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	sodium_memzero(buffer,sizeof(buffer));
	sodium_memzero(fresh_privkey,sizeof(fresh_privkey));
	sodium_memzero(suffixonion,sizeof(suffixonion));
	return 0;
}

int peer_save(const char *arg1,const char *arg2) // peeronion, peernick.
{ // Initiate a friend request. // XXX Untested "Stealth Addresses" functionality where invalid (non-base32) and excessive (beyond 51 character) characters are stripped. To utilize, take a 51 length TorX-ID, sprinkle invalid characters throughout it as desired, add unlimited length suffix trailing it, and then pass to peer_save. Should "work". XXX
	if(arg1 == NULL || arg2 == NULL || strlen(arg1) == 0 || strlen(arg2) == 0)
	{
		error_simple(0,"Passed null or 0 length peeronion or peernick to peer_save. Not allowed.");
		return -1;
	}
	size_t id_len = strlen(arg1);
	if(id_len == 44 && arg1[43] == '=')
	{ // could like... use a return value other than -1, and do something productive with this.
		error_simple(0,"Highly likely that user attempted to save a public group ID as a peer.");
		return -1;
	}
	char arg1_local[id_len+1];
	snprintf(arg1_local,sizeof(arg1_local),"%s",arg1);
	if(id_len == 56) // OnionID
		id_len = stripbuffer(arg1_local);
	else // TorX-ID
		id_len = stripbuffer_b32_len51(arg1_local);
	char peeronion_or_torxid[56+1];
	char peernick[56+1];
	snprintf(peeronion_or_torxid,sizeof(peeronion_or_torxid),"%s",arg1_local);
	sodium_memzero(arg1_local,sizeof(arg1_local));
	snprintf(peernick,sizeof(peernick),"%s",arg2);
	char *peeronion = {0}; // must set null in case of error
	while(1)
	{ // not a real while loop, just don't want to use goto
		if(id_len == 56)
		{ // onion, check the checksum
			char *torxid = torxid_from_onion(peeronion_or_torxid);
			peeronion = onion_from_torxid(torxid);
			if(peeronion == NULL)
			{ // Invalid input, maybe contained junk.
				error_simple(0,"Save_peer Invalid input, maybe contained junk.");
				torx_free((void*)&torxid);
				break;
			}
			torx_free((void*)&torxid);
			if(strncmp(peeronion,peeronion_or_torxid,56)) // this could be 55 if we wanted to preserve potential forward compatibility (dont do this or people will mess up the d/version byte)
			{
				error_simple(0,"Onion checksum does not match, or unrecognized version. Please verify that it is typed correctly.");
				break;
			}
		}
		else if(id_len > 0 && id_len < 56)
		{
			peeronion = onion_from_torxid(peeronion_or_torxid);
			if(peeronion == NULL)
			{
				error_simple(0,"Save_peer Invalid TorX-ID. Report this.");
				break; // Invalid TorX-ID. This should be rare.
			}
		}
		else // peeronion_or_torxid == NULL, coding error?
			break;
	//	torx_free((void*)&peeronion_or_torxid);
		sodium_memzero(peeronion_or_torxid,sizeof(peeronion_or_torxid));
		int n = set_n(-1,peeronion);
		uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		if(owner != 0)
		{
			error_simple(0,"Peer already exists.");
			break;
		}
		error_simple(1,"Peer did not exist.");
		if((n = load_peer_struc(-1,ENUM_OWNER_PEER,0,NULL,0,peeronion,peernick,NULL,NULL,NULL)) == -1)
			break;
		owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner)); // probably unnecessary, n should be the same as before?
		const uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
		const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,-1,offsetof(struct peer_list,peerversion));
		char privkey[88+1];
		getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,-1,offsetof(struct peer_list,privkey));
		char peeronion_local[56+1];
		getter_array(&peeronion_local,sizeof(peeronion_local),n,INT_MIN,-1,-1,offsetof(struct peer_list,peeronion));
		const int peer_index = sql_insert_peer(owner,status,peerversion,privkey,peeronion_local,peernick,0);
		sodium_memzero(privkey,sizeof(privkey));
		sodium_memzero(peeronion_local,sizeof(peeronion_local));
		setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
		torx_free((void*)&peeronion);
		sodium_memzero(peernick,sizeof(peernick));
		const uint16_t vport = INIT_VPORT;
		setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,vport),&vport,sizeof(vport));
		torx_read(n) // XXX
		pthread_t *thrd_send = &peer[n].thrd_send;
		torx_unlock(n) // XXX
		if(pthread_create(thrd_send,&ATTR_DETACHED,&peer_init,itovp(n)))
			error_simple(-1,"Failed to create thread1");
		return 0;
	}
	sodium_memzero(peeronion_or_torxid,sizeof(peeronion_or_torxid));
	sodium_memzero(peernick,sizeof(peernick));
	torx_free((void*)&peeronion);
	return -1;
}

void peer_accept(const int n)
{ // Was file_magic("incomingpendinglist",onion)
	uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{ // sanity check
		error_simple(1,"Accepting a peer.");
		status = ENUM_STATUS_FRIEND;
		setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,status),&status,sizeof(status));
		sql_update_peer(n);
		load_onion(n);
	}
}

void change_nick(const int n,const char *freshpeernick)
{
	char peernick[56+1];
	snprintf(peernick,56+1,"%s",freshpeernick);
	setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick),&peernick,sizeof(peernick));
	sodium_memzero(peernick,sizeof(peernick));
	sql_update_peer(n);
}

void block_peer(const int n)
{
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_GROUP_PEER)
	{
		uint8_t status = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,status));
		char peernick[56+1];
		getter_array(&peernick,sizeof(peernick),n,INT_MIN,-1,-1,offsetof(struct peer_list,peernick));
		if(status == ENUM_STATUS_FRIEND)
		{
			if(owner == ENUM_OWNER_CTRL)
				error_printf(3,"Blocking %s",peernick);
			else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
				error_printf(3,"Disabling %s",peernick);
			status = ENUM_STATUS_BLOCKED;
			setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,status),&status,sizeof(status));
			sql_update_peer(n);
			const int peer_index = getter_int(n,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index));
			takedown_onion(peer_index,0);
		}
		else if(status == ENUM_STATUS_BLOCKED)
		{
			if(owner == ENUM_OWNER_CTRL)
				error_printf(3,"Unblocking %s",peernick);
			else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
				error_printf(3,"Enabling %s",peernick);
			status = ENUM_STATUS_FRIEND;
			setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,status),&status,sizeof(status));
			sql_update_peer(n);
			load_onion(n);
		}
		else
		{
			error_printf(0,"Tried to toggle block status of status=%u. Coding error. Report this.",status);
			breakpoint();
		}
		sodium_memzero(peernick,sizeof(peernick));
	}
	else
	{
		error_printf(0,"Tried to toggle block status of owner=%u. Coding error. Report this.",owner);
		breakpoint();
	}
}

uint64_t get_file_size(const char *file_path)
{ // rarely used, usually we get it from other functions. We use stat instead of opening the file and fseeking the end because we tested it to be 5 times faster.
	struct stat file_stat;
	if (stat(file_path, &file_stat) != 0)
		return 0;
	return (uint64_t)file_stat.st_size;
}

void destroy_file(const char *file_path)
{ /* XXX This function works well. Do not mess with it without extensive testing. XXX */ // 2024/03/17 Consider deleting any .split file in this function, if discovered. Low priority. Couldn't hurt.
	if(file_path == NULL)
		return;
	char new_file_name[20+1];
	random_string(new_file_name,sizeof(new_file_name));
	const size_t file_path_len = strlen(file_path);
	char path_copy[file_path_len+1];
	snprintf(path_copy,sizeof(path_copy),"%s",file_path); // Both dirname() and basename() may modify the contents of path, so it may be desirable to pass a copy when calling one of these functions.
	char *directory = dirname(path_copy);
	char new_file_path[file_path_len+20+4+1];
	snprintf(new_file_path,sizeof(new_file_path), "%s%c%s.tmp",directory,platform_slash,new_file_name);
	sodium_memzero(path_copy,sizeof(path_copy)); // DO NOT do this before using directory. Basename and dirname are peculiar
	if(rename(file_path, new_file_path) != 0)
	{
		error_simple(0,"Error renaming file destroy_file. Probably deleting an empty history?");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	FILE *fp;
	if((fp = fopen(new_file_path, "a")) == NULL)
	{
		error_simple(0,"Error opening file for appending in destroy_file");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	const long int size = ftell(fp);
	fclose(fp); fp = NULL;
	if((fp = fopen(new_file_path, "r+")) == NULL || size == -1)
	{
		error_simple(0,"Error opening file for write in destroy_file");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	size_t left = (size_t)size;
	size_t written_current = 0;
	unsigned char buf[4096];
	do
	{
		size_t amount;
		if(left < sizeof(buf))
			amount = left;
		else
			amount = sizeof(buf);
		randombytes(buf, (long long unsigned int)amount);
		written_current = fwrite(buf, 1, amount, fp); // this is CORRECT use of fwrite() DO NOT CHANGE IT.
		left -= written_current;
	}
	while (left > 0 && written_current > 0);
	fclose(fp); fp = NULL;
	if(remove(new_file_path) != 0)
		error_simple(0,"Error deleting file in destroy_file");
	sodium_memzero(new_file_path,sizeof(new_file_path));
}

static void set_split_path(const int n,const int f)
{
	torx_read(n) // XXX
	if(!peer[n].file[f].filename || !peer[n].file[f].file_path)
	{
		torx_unlock(n) // XXX
		error_simple(0,"Cannot set split path due to lack of filename or path. Coding error. Report this.");
		return;
	}
	torx_unlock(n) // XXX
	torx_write(n) // XXX
	if(peer[n].file[f].split_path)
		torx_free((void*)&peer[n].file[f].split_path);
	size_t allocation_size;
	pthread_rwlock_rdlock(&mutex_global_variable);
	if(split_folder)
	{
		allocation_size = strlen(split_folder) + 1 + strlen(peer[n].file[f].filename) + 6 + 1;
		peer[n].file[f].split_path = torx_secure_malloc(allocation_size);
		snprintf(peer[n].file[f].split_path,allocation_size,"%s%c%s.split",split_folder,platform_slash,peer[n].file[f].filename);
		pthread_rwlock_unlock(&mutex_global_variable);
	}
	else
	{
		pthread_rwlock_unlock(&mutex_global_variable);
		allocation_size = strlen(peer[n].file[f].file_path) + 6 + 1;
		peer[n].file[f].split_path = torx_secure_malloc(allocation_size);
		snprintf(peer[n].file[f].split_path,allocation_size,"%s.split",peer[n].file[f].file_path);
	}
	torx_unlock(n) // XXX
}

static inline int split_read(const int n,const int f)
{ // File is in binary format. Checksum,nos,split_info
	char *split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	if(!split_path)
		set_split_path(n,f);
	split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	FILE *fp = fopen(split_path, "r"); // read file contents, while checking compliance of checksum.
	torx_free((void*)&split_path);
	uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
	if(fp)
	{
		unsigned char checksum_local[CHECKSUM_BIN_LEN];
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
		if(fread(checksum_local,1,CHECKSUM_BIN_LEN,fp) != CHECKSUM_BIN_LEN)
			error_simple(0,"Failed to read checksum from split file. Invalid split file exists."); // read checksum
		else if(memcmp(checksum,checksum_local,CHECKSUM_BIN_LEN))
			error_simple(0,"Checksum did not match. Invalid split file exists."); // compare checksum
		else if(fread(&splits,1,sizeof(splits),fp) == 0)
			error_simple(0,"Failed to read number of splits from split file. Invalid split file exists."); // read splits
		else
		{ // this is correct, the previous else if modified splits
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,splits),&splits,sizeof(splits));
			sodium_memzero(checksum,sizeof(checksum));
		}
	}
//	else
//		printf("Checkpoint no split file found\n");
	uint16_t sections = splits+1;
	const size_t read_size = sizeof(uint64_t)*sections;
//	printf("Checkpoint split_read allocating n=%d f=%d splits=%u\n",n,f,splits);
	uint64_t *split_info = torx_insecure_malloc(read_size);
	int *split_status = torx_insecure_malloc(sizeof(int)*sections);
	int8_t *split_status_fd = torx_insecure_malloc(sizeof(int8_t)*sections);
	while(sections--)
	{ // initialize info to zero and status to -1 (invalid n)
		split_info[sections] = 0;
		split_status[sections] = -1; // no one yet claims this
		split_status_fd[sections] = -1; // no one yet claims this
	}
	if(fp && fread(split_info,1,read_size,fp) != read_size)
		error_simple(0,"Could not open split file or found an invalid checksum."); // read sections
	torx_write(n) // XXX
	peer[n].file[f].split_info = split_info;
	peer[n].file[f].split_status = split_status;
	peer[n].file[f].split_status_fd = split_status_fd;
	torx_unlock(n) // XXX
	if(fp)
	{ // condition is necessary with fclose it seems
	//	printf("Checkpoint Reading nos: %d\n",peer[n].file[f].splits);
	//	printf("Checkpoint Reading split data: %lu %lu\n",peer[n].file[f].split_info[0],peer[n].file[f].split_info[1]);
		fclose(fp); fp = NULL;
		return 0; // successfully read
	}
	return -1; // no file exists, wrong checksum, or cannot be read
}

int initialize_split_info(const int n,const int f)
{ // Should read split file and set the details, or create and initialize split file ( as 0,0,0,0,etc ). File is in binary format. Checksum,nos,split_info.
	const uint64_t size = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size));
	torx_read(n) // XXX
	if(peer[n].file[f].split_path && peer[n].file[f].split_info)
	{
		torx_unlock(n) // XXX
	//	printf("Checkpoint split info appears already initialized. No need to do it again.\n");
		return 0;
	}
	if(size == 0 || peer[n].file[f].file_path == NULL)
	{
		torx_unlock(n) // XXX
		error_simple(0,"Cannot initialize split info. Sanity check failed.");
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		printf("Checkpoint owner==%d size==%"PRIu64"\n",owner,size);
		return -1;
	}
	char *split_path = peer[n].file[f].split_path;
	torx_unlock(n) // XXX
	if(split_path == NULL)
		set_split_path(n,f);
	torx_read(n) // XXX
	const uint64_t *split_info = peer[n].file[f].split_info;
	torx_unlock(n) // XXX
	if(split_info == NULL)
	{ // Initialize if not already
		split_read(n,f); // reads split file or initializes in memory
		struct stat file_stat = {0};
		torx_read(n) // XXX
		const int stat_file = stat(peer[n].file[f].file_path, &file_stat);
		torx_unlock(n) // XXX
		const uint8_t local_full_duplex_requests = threadsafe_read_uint8(&mutex_global_variable,&full_duplex_requests);
		const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
		split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
		if(local_full_duplex_requests && stat_file == 0 && stat(split_path, &file_stat) == 0) // note: we use stat() for speed because it doesn't need to open the files. If the file isn't readable, it'll error out elsewhere. Do not change.
		{ // check if file exists. if yes, check if split exists. if yes, read the split file and set the file as INBOUND_ACCEPTED
			printf("Checkpoint found an old .split file. Setting file as ACCEPTED.\n");
		//	split_read(n,f); // reads split file
			if(threadsafe_read_uint8(&mutex_global_variable,&auto_resume_inbound) && calculate_transferred(n,f) < size)
			{
				const uint8_t status = ENUM_FILE_INBOUND_ACCEPTED;
				setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
			}
		}
		else if((local_full_duplex_requests || splits > 0) && stat_file == 0)
		{
			const uint8_t status = ENUM_FILE_INBOUND_COMPLETED; // NOTE: we don't ftell, just consider it complete
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
		}
	//	else if(full_duplex_requests && splits == 0)
	//		error_simple(0,"Uncaught error in initialize_split_info. Coding error. Report this."); // TODO Full duplex enabled but splits == 0
		else if(local_full_duplex_requests && splits > 0)
		{ // partial file does not exist, write an initialized .split file
			umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // umask 600 equivalent. man 2 umask
			FILE *fp;
			if((fp = fopen(split_path,"w+")) == NULL)
			{ // BAD, permissions issue, cannot create file
				error_printf(0,"Check permissions. Cannot open split file1: %s",split_path);
				torx_free((void*)&split_path);
				return -1;
			}
			torx_free((void*)&split_path);
			unsigned char checksum[CHECKSUM_BIN_LEN];
			getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
			fwrite(checksum,1,CHECKSUM_BIN_LEN,fp);
			sodium_memzero(checksum,sizeof(checksum));
			uint64_t relevant_split_info[splits+1];
			torx_read(n) // XXX
			memcpy(relevant_split_info,peer[n].file[f].split_info,sizeof(relevant_split_info));
			torx_unlock(n) // XXX
			fwrite(&splits,1,sizeof(splits),fp);
			fwrite(relevant_split_info,1,sizeof(relevant_split_info),fp);
			fclose(fp); fp = NULL;
		}
		else if(local_full_duplex_requests == 0 && stat_file == 0)
		{ // Read half-duplex
			printf("Checkpoint initializing a half-duplex\n");
			char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
			const uint64_t file_size = get_file_size(file_path);
			torx_free((void*)&file_path);
			if(file_size)
			{
				if(file_size > size)
					error_simple(0,"End of packet exceeds file size. Report this.");
				else if(file_size == size)
				{ // i think end will never be greater than .size - 1? besides this block is useless, we set completed elsewhere
					printf("Checkpoint probably will not trigger. If never triggering, delete block\n"); // TODO
					const uint8_t status = ENUM_FILE_INBOUND_COMPLETED;
					setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
					transfer_progress(n,f,calculate_transferred(n,f)); // calling this because we set file status ( not necessary when calling message_send which calls print_message_cb )
				}
				else
				{
					torx_write(n) // XXX
					peer[n].file[f].split_info[0] = file_size;
					torx_unlock(n) // XXX
				}
			}
			else // file does not exist
			{
				torx_write(n) // XXX
				peer[n].file[f].split_info[0] = 0;
				torx_unlock(n) // XXX
			}
		}
	}
	return 0;
}

void split_update(const int n,const int f,const int section)
{ // Updates split or deletes it if complete. section starts at 0. One split == 2 sections, 0 and 1. Set them via: 	peer[n].file[f].split_info[0] = 123; peer[n].file[f].split_info[1] = 456; split_update (n,f);
	const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
	torx_read(n) // XXX
	const char *split_path = peer[n].file[f].split_path;
	torx_unlock(n) // XXX
	if(splits == 0 || split_path == NULL)
		return;
	const uint8_t status = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,status));
	split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	if(status == ENUM_FILE_INBOUND_COMPLETED || status == ENUM_FILE_INBOUND_REJECTED || status == ENUM_FILE_INBOUND_CANCELLED) // || section == -1
	{ //  destroying split file in case of ENUM_FILE_INBOUND_CANCELLED would be bad in group chats.
	//	peer[n].file[f]. splits = 0;
	//	printf("Checkpoint split_update DELETING\n"); 
		destroy_file(split_path);
		torx_free((void*)&split_path);
		torx_write(n) // XXX
		torx_free((void*)&peer[n].file[f].split_path);
//		free(peer[n].file[f].split_info); peer[n].file[f].split_info = NULL;
		torx_free((void*)&peer[n].file[f].split_status);
		torx_free((void*)&peer[n].file[f].split_status_fd);
		torx_unlock(n) // XXX
		return;
	}
	if(section > -1) // sanity check, should be unnecessary
	{
		FILE *fp;
		if((fp = fopen(split_path,"r+")) == NULL)
			if((fp=fopen(split_path,"w+")) == NULL)
			{
				error_printf(0,"Check permissions. Cannot open split file2: %s",split_path);
				torx_free((void*)&split_path);
				return;
			}
		torx_free((void*)&split_path);
		torx_read(n) // XXX
		const uint64_t relevant_split_info = peer[n].file[f].split_info[section];
		torx_unlock(n) // XXX
		fseek(fp,(long int)(CHECKSUM_BIN_LEN+sizeof(splits)+sizeof(uint64_t)*(size_t)section), SEEK_SET); // jump to correct location based upon number of splits TODO might be +1 byte off
		fwrite(&relevant_split_info,1,sizeof(relevant_split_info),fp); // write contents
		fclose(fp); fp = NULL;
	}
}

void section_update(const int n,const int f,const uint64_t packet_start,const size_t wrote,const int8_t fd_type,const uint16_t section,const uint64_t section_end,const int peer_n)
{ // INBOUND FILE TRANSFER ONLY To be called after write during file transfer. Updates .split_info, determines whether to call split_update. peer_n is only used for blacklisting.
	if(wrote < 1)
		return;
	const uint64_t size = getter_uint64(n,INT_MIN,f,-1,offsetof(struct file_list,size));
	const uint8_t splits = getter_uint8(n,INT_MIN,f,-1,offsetof(struct file_list,splits));
	torx_write(n) // XXX yes, its a write, see +=
	const uint64_t section_info_current = peer[n].file[f].split_info[section] += wrote;
	torx_unlock(n) // XXX
	if(packet_start + wrote == section_end + 1)
	{ // Section complete. Close file descriptors (flushing data to disk)
		if(fd_type == 0) // recvfd, inbound
			close_sockets(n,f,peer[n].file[f].fd_in_recvfd)
		else /* if(fd_type == 1) */ // sendfd, inbound
			close_sockets(n,f,peer[n].file[f].fd_in_sendfd)
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
		char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
		if(owner == ENUM_OWNER_GROUP_CTRL)
		{ // Run checksum on the group file's individual section
			const uint64_t start = calculate_section_start(size,splits,section);
			const uint64_t end = calculate_section_start(size,splits,section+1)-1;
			const uint64_t len = end-start+1;
			unsigned char checksum[CHECKSUM_BIN_LEN];
			const uint64_t ret1 = b3sum_bin(checksum,file_path,NULL,start,len);
			torx_read(n) // XXX
			const int ret2 = memcmp(checksum,&peer[n].file[f].split_hashes[CHECKSUM_BIN_LEN*section],CHECKSUM_BIN_LEN);
			torx_unlock(n) // XXX
			sodium_memzero(checksum,sizeof(checksum));
			if(ret1 == 0 || ret2)
			{ // TODO Untested
				error_simple(0,"Bad section checksum. Blacklisting peer and marking section as incomplete.");
				printf("Checkpoint bad section: %"PRIu64" %d\n",ret1,ret2);
				torx_write(n) // XXX
				peer[n].file[f].split_info[section] = 0;
				torx_unlock(n) // XXX
				torx_write(peer_n) // XXX
				peer[peer_n].blacklisted++;
				torx_unlock(peer_n) // XXX
			}
			else
			{
				printf("Checkpoint VERIFIED checksum section==%d\n",section);
				message_send(n,ENUM_PROTOCOL_FILE_OFFER_PARTIAL,itovp(f),FILE_OFFER_PARTIAL_LEN);
			}
		}
		section_unclaim(n,f,peer_n,fd_type); // must be before file_request_internal
		if(calculate_transferred(n,f) == size)
		{
			if(CHECKSUM_ON_COMPLETION && owner != ENUM_OWNER_GROUP_CTRL) // Note: Group file generate section hashes and compare individually. Not necessary to check hash of hashes or size.
			{ // TODO This blocks, so it should be used for debug purposes only
				unsigned char checksum_complete[CHECKSUM_BIN_LEN];
				unsigned char checksum[CHECKSUM_BIN_LEN];
				getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,-1,offsetof(struct file_list,checksum));
				if(b3sum_bin(checksum_complete,file_path,NULL,0,0) && !memcmp(checksum_complete,checksum,CHECKSUM_BIN_LEN))
					error_simple(0,"Successfully VERIFIED checksum.");
				else
				{
					error_simple(0,"Checkpoint Failed checksum verification."); // non-group
					breakpoint();
				}
				sodium_memzero(checksum,sizeof(checksum));
				sodium_memzero(checksum_complete,sizeof(checksum_complete));
			}
			struct utimbuf new_times;
			new_times.actime = time(NULL); // set access time to current time
			torx_read(n) // XXX
			new_times.modtime = peer[n].file[f].modified; // set modification time
			torx_unlock(n) // XXX
			if(utime(file_path, &new_times))
			{ // Failed to set modification time (this is fine)
				struct stat file_stat = {0};
				if(!stat(file_path, &file_stat))
				{ // Read modification time from disk instead
					torx_write(n) // XXX
					peer[n].file[f].modified = file_stat.st_mtime;
					torx_unlock(n) // XXX
				}
			}
			const uint8_t status = ENUM_FILE_INBOUND_COMPLETED; // NOTE: we don't ftell, just consider it complete
			setter(n,INT_MIN,f,-1,offsetof(struct file_list,status),&status,sizeof(status));
		}
		torx_free((void*)&file_path);
		file_request_internal(n,f);
		split_update(n,f,section); // should usually occur when a section is finished, ie == Writes may go slightly beyond a section. This might be OK (with non-malicious peers) because it will just incur minor overwrites later, since that overwrite area will still be requested again, but would be bad from a malicious peer TODO
	}
	else if(splits && (section_info_current - wrote) / (120*SPLIT_DELAY*1024) != section_info_current / (120*SPLIT_DELAY*1024)) // Checking whether to call split_update
		split_update(n,f,section); // ~8 times per 1mb with SPLIT_DELAY = 1
}

size_t b3sum_bin(unsigned char checksum[CHECKSUM_BIN_LEN],const char *file_path,const unsigned char *data,const uint64_t start,const uint64_t len)
{ // Generates Blake3 checksum in binary and returns file size in bytes. Pass data OR file_path, not both, for hashing. If no end is passed, it is treated as until EOF for file.
	if(checksum == NULL || (file_path == NULL && data == NULL) || (file_path != NULL && data != NULL) || (data && len == 0))
	{
		error_simple(0,"Checksum failed due to sanity check fail");
		return 0;
	}
	uint64_t size = 0;
	struct blake3 ctx;
	blake3_init(&ctx);
	if(file_path)
	{
		FILE *fp = fopen(file_path, "r");
		if(!fp || fseek(fp,(long int)start,SEEK_SET) == -1) // TODO bad cast
		{
			error_simple(0,"Failed to open file for generating blake checksum.");
			return 0;
		}
		unsigned char buf[4096];
		while(!feof(fp) && (!len || size < len))
		{
			size_t to_read = sizeof(buf);
			if(len && len - size < sizeof(buf))
				to_read = len - size;
			const size_t read = fread(buf, 1, to_read, fp);
			if(len && read != to_read)
			{
				error_simple(0,"Read less than expected when calculating checksum. Coding or disk error.");
			//	printf("Checkpoint read: %lu\nCheckpoint to_read: %lu\nCheckpoint size: %lu\n",read,to_read,size);
				return 0;
			}
			blake3_update(&ctx, buf, read);
			size += read;
		}
		sodium_memzero(buf,sizeof(buf));
		fclose(fp);
		fp = NULL;
	}
	else /* if(data) */
	{
		blake3_update(&ctx, &data[start], len);	
		size = len;
	}
	blake3_out(&ctx, checksum, CHECKSUM_BIN_LEN);
	return (size_t)size; // XXX will return -1 if cannot open or fully read file
}

char *custom_input_file(const char *hs_ed25519_secret_key_file) // hs_ files have already had crypto_hash_sha512() applied to them, meaning the ed25519 SK is FOREVER LOST
{ // This must be used in conjunction with custom_input() // cat hs_ed25519_secret_key | tail --bytes=64 | base64 <--- "privkey"
	if(hs_ed25519_secret_key_file == NULL)
		return NULL;
	char privkey_decoded[64] = {0};
	FILE *hs_ed25519_secret_key_file_pointer = fopen(hs_ed25519_secret_key_file,"r");
	if(hs_ed25519_secret_key_file_pointer == NULL)
	{
		error_simple(0,"Failed to open custom input file.");
		return NULL;
	}
	const char correct_header[29+1] = "== ed25519v1-secret: type0 ==";
	char header[29]; // no null termination, do not assume string
	const size_t read = fread(header,1,sizeof(header),hs_ed25519_secret_key_file_pointer);
	fseek(hs_ed25519_secret_key_file_pointer,(long int)-sizeof(privkey_decoded),SEEK_END);
	if(read != sizeof(header) || memcmp(header,correct_header,sizeof(header)) || fread(privkey_decoded,1,sizeof(privkey_decoded),hs_ed25519_secret_key_file_pointer) < 64)
	{
		error_simple(0,"Custom input file was less than 64 bytes or lacked expected header. Bailing.");
		return NULL;
	}
	char *privkey = b64_encode(privkey_decoded,sizeof(privkey_decoded));
	sodium_memzero(privkey_decoded,sizeof(privkey_decoded));
	fclose(hs_ed25519_secret_key_file_pointer);
	hs_ed25519_secret_key_file_pointer = NULL;
	return privkey;
}

void takedown_onion(const int peer_index,const int delete) // 0 no, 1 yes, 2 delete without taking down, 3 spoil SING onion (delete, take down).
{ // Takedown PEER/SING/MULT/CTRL TODO delete values and actions are confusing. 0 is possibly redundant with block_peer()
  // TODO deleting individual GROUP_PEER without deleting the GROUP_CTRL is not yet supported... its complex because they would need to be removed from the peerlist/peercount... and it would be added back the next time a peerlist is received. Just block/ignore instead.
	if(peer_index < 0)
	{
		error_printf(0,"Invalid peer_index in takedown_onion: %d. Bailing. Report this.",peer_index);
		breakpoint();
		return;
	}
	const int n = set_n(peer_index,NULL);
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner)); // DO NOT ELIMINATE THIS VARIABLE because .owner will get zero'd
	int g = -1;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Recursively takedown all GROUP_PEER in peerlist // TODO consider sending a kill code to online peers first ( pro: wastes less peer resources. Con: takes more time to shutdown, peers will be added again when someone who didn't get the kill code shares the peerlist . Conclusion: don't bother.)
		uint32_t count = 0;
		g = set_g(n,NULL);
		uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		while(count < g_peercount)
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int specific_peer = group[g].peerlist[count++];
			pthread_rwlock_unlock(&mutex_expand_group);
			takedown_onion(getter_int(specific_peer,INT_MIN,-1,-1,offsetof(struct peer_list,peer_index)),delete);
		}
		error_printf(0,"Took down %u GROUP_PEER associated with group.",count); // TODO increase debug level after confirming this works
	}
	if(delete > 0)
	{
		if(owner == ENUM_OWNER_GROUP_PEER) // This if statement saves a bit of IO/processing but only makes sense if we never delete GROUP_PEER without deleting GROUP_CTRL at he same time
			delete_log(n); // when called with GROUP_CTRL, it should delete GROUP_PEER, so no need to call it twice.
		sql_delete_peer(peer_index); // This should cascading delete anything delete_log missed, or in case we were wrong above
	}
	if(delete != 2 && owner != ENUM_OWNER_PEER)
	{ // 2==delete from file but don't take down // != ENUM_OWNER_PEER because OWNER_PEER doesn't use peer [n]. sendfd
	// TODO find a way to call disconnect_forever() here in a threadsafe manner
	//	torx_read(n) // XXX
	//	struct bufferevent *bev_recv = peer[n].bev_recv;
	//	torx_unlock(n) // XXX
	//	bufferevent_free(peer[n].bev); // not threadsafe // TODO segfaults, even with event_base_once or evbuffer_lock. Do not attempt, give up.
	//	event_base_loopexit(bufferevent_get_base(bev_recv), NULL); // not threadsafe
	/*	evbuffer_lock(bev_recv); // XXX
		struct event_base *base = bufferevent_get_base(bev_recv);
		evbuffer_unlock(bev_recv); // XXX
		event_base_once(base, -1, EV_TIMEOUT, enter_thread_to_disconnect_forever, bev_recv, NULL);*/
		char onion[56+1];
		getter_array(&onion,sizeof(onion),n,INT_MIN,-1,-1,offsetof(struct peer_list,onion));
		char apibuffer[512];
		snprintf(apibuffer,512,"%s%s%s%s%s","authenticate \"",control_password_clear,"\"\ndel_onion ",onion,"\n");
		sodium_memzero(onion,sizeof(onion));
	//	printf("Checkpoint tor_call takedown_onion\n");
		tor_call(NULL,-1,apibuffer);
		sodium_memzero(apibuffer,sizeof(apibuffer));
		torx_write(n) // XXX
		int ret_send = 0;
		int ret_recv = 0;
		if(peer[n].sendfd > 0)
			ret_send = evutil_closesocket(peer[n].sendfd);
		if(peer[n].recvfd > 0)
			ret_recv = evutil_closesocket(peer[n].recvfd);
		torx_unlock(n) // XXX
		if(ret_send == -1 || ret_recv == -1)
			error_printf(0,"Failed to close a socket in takedown_onion. Owner=%u send=%d recv=%d",owner,ret_send,ret_recv);
	} // From control-spec:   It is the Onion Service server application's responsibility to close existing client connections if desired after the Onion Service has been removed via "DEL_ONION".
	if(delete == 1 || delete == 3)
	{
		error_simple(1,"Found matching entry in memory. Zeroing.");
		torx_write(n) // XXX
		zero_n(n);
		torx_unlock(n) // XXX
		if(delete == 3)
			onion_deleted_cb(20,n);
		else
			onion_deleted_cb(owner,n);
	}
	else if(delete == 0) // Block only
	{ // TODO WE SHOULD NOT SET MEMORY STATUS TO 0 HERE ??? because we might be taking it down for other reaons, like in write_finished()
		error_simple(1,"Notice: Found matching entry in memory. Changing to status 1 (block) in memory.");
		const uint8_t status = ENUM_STATUS_BLOCKED;
		setter(n,INT_MIN,-1,-1,offsetof(struct peer_list,status),&status,sizeof(status));
	}
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		broadcast_remove(g);
		zero_g(g);
	}
}
