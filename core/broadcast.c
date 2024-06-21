void broadcast_add(const int origin_n,const unsigned char broadcast[GROUP_BROADCAST_LEN])
{ // Add or discard a broadcast, depending on queue and whether it has already been added/sent
// "Broadcast should be added to queue if checksum (single int) is not in broadcast_history array. Queue should store an integer hash of each sent broadcast to avoid repetition. It should also be rate limited (random rate, random delays) to avoid facilitating mapping of the network. Broadcast thread should run perpetually if there is anything in the queue, otherwise close. Broadcasts exceeding queue should be discarded? Undecided."
// TODO (?) Queue should take note of how many broadcasts came from each user
	if(!broadcast)
	{
		error_simple(0,"Sanity check fail in broadcast_add. Coding error. Report this.");
		breakpoint();
		return;
	}
	const uint32_t hash = fnv1a_32_salted(broadcast,GROUP_BROADCAST_LEN);
	pthread_rwlock_rdlock(&mutex_broadcast);
	for(int iter1 = 0; iter1 < BROADCAST_HISTORY_SIZE; iter1++)
	{
		if(broadcast_history[iter1] == 0)
		{ // Not in queued/sent list, add it
			int iter2 = 0;
			for(; iter2 < BROADCAST_QUEUE_SIZE; iter2++)
				if(broadcasts_queued[iter2].hash == 0)
				{ // found empty slot
					pthread_rwlock_unlock(&mutex_broadcast);
					pthread_rwlock_wrlock(&mutex_broadcast);
					broadcasts_queued[iter2].hash = hash;
					memcpy(broadcasts_queued[iter2].broadcast,broadcast,GROUP_BROADCAST_LEN);
					int origin_group_n = origin_n;
					if(origin_n > -1)
					{ // This can only trigger from goto send_out
						const uint8_t owner = getter_uint8(origin_n,-1,-1,-1,offsetof(struct peer_list,owner));
						if(owner == ENUM_OWNER_GROUP_PEER)
						{
							const int g = set_g(origin_n,NULL);
							origin_group_n = getter_group_int(g,offsetof(struct group_list,n));
						}
					}
					int iter3 = BROADCAST_MAX_PEERS - 1;
					int n = 0;
					torx_read(n) // XXX
					while(iter3 > -1)
					{
						if(peer[n].onion[0] == '\0' && peer[n].peer_index == -2)
							break;
						const uint8_t owner = peer[n].owner;
						const uint8_t status = peer[n].status;
						if(n != origin_group_n && status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER))
							broadcasts_queued[iter2].peers[iter3] = n; // TODO using GROUP_PEER instead of GROUP_CTRL so we can check online status later
						torx_unlock(n++) // XXX
						torx_read(n) // XXX
						iter3--;
					}
					torx_unlock(n) // XXX
					error_printf(0,"Broadcast added and slotted, peers=%d",BROADCAST_MAX_PEERS-iter3);
					break;
				}
			if(iter2 == BROADCAST_QUEUE_SIZE)
			{
				error_simple(0,"Queue is full. Broadcast will be discarded.");
				break; // queue is full, bail out. broadcast will be discarded.
			}
			broadcast_history[iter1] = hash; // NOTE: this is sent OR queued
			break;
		}
		else if(broadcast_history[iter1] == hash)
		{
			error_simple(0,"Broadcast already queued. Will be discarded.");
			break; // Already in queued/sent list, bail
		}
	}
	pthread_rwlock_unlock(&mutex_broadcast);
}

static inline void broadcast_remove(const int g)
{ // Remove hash from queue because we joined the group successfully, or for other reasons
	if(g < 0)
		return;
	pthread_rwlock_rdlock(&mutex_expand_group);
	const uint32_t hash = group[g].hash;
	pthread_rwlock_unlock(&mutex_expand_group);
	if(!hash)
		return;
	pthread_rwlock_rdlock(&mutex_broadcast);
	for(int iter1 = 0; iter1 < BROADCAST_QUEUE_SIZE; iter1++)
		if(broadcasts_queued[iter1].hash == hash)
		{
			pthread_rwlock_unlock(&mutex_broadcast);
			pthread_rwlock_wrlock(&mutex_broadcast);
			broadcasts_queued[iter1].hash = 0;
			sodium_memzero(broadcasts_queued[iter1].broadcast,GROUP_BROADCAST_LEN);
			for(int iter2 = 0; iter2 < BROADCAST_MAX_PEERS; iter2++)
				broadcasts_queued[iter1].peers[iter2] = -1;
			error_simple(0,WHITE"Checkpoint removed a hash successfully"RESET); // great!
			break;
		}
	pthread_rwlock_unlock(&mutex_broadcast);
}

void broadcast_prep(unsigned char ciphertext[GROUP_BROADCAST_LEN],const int g)
{ // Audited 2024/02/15 // ciphertext must be an array sized 48 + 16 + 56 + 32 (crypto_box_SEALBYTES + crypto_pwhash_SALTBYTES + 56 + crypto_box_PUBLICKEYBYTES)
	if(ciphertext == NULL || g < 0)
	{
		error_simple(0,"Sanity check in broadcast_prep failed. Coding error. Report this.");
		breakpoint();
		return;
	}
	const int group_n = getter_group_int(g,offsetof(struct group_list,n));
	unsigned char message[GROUP_BROADCAST_DECRYPTED_LEN];
	randombytes_buf(message,crypto_pwhash_SALTBYTES); // salt the message. crypto_pwhash_SALTBYTES is 16
	getter_array(&message[crypto_pwhash_SALTBYTES],56,group_n,-1,-1,-1,offsetof(struct peer_list,onion)); // affix the group_n
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	getter_array(&sign_sk,sizeof(sign_sk),group_n,-1,-1,-1,offsetof(struct peer_list,sign_sk));
	crypto_sign_ed25519_sk_to_pk(&message[crypto_pwhash_SALTBYTES+56],sign_sk); // affix the pk of size crypto_box_PUBLICKEYBYTES
	sodium_memzero(sign_sk,sizeof(sign_sk));
	unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
	pthread_rwlock_rdlock(&mutex_expand_group);
	crypto_scalarmult_base(recipient_pk, group[g].id); // convert sk_to_pk
	pthread_rwlock_unlock(&mutex_expand_group);
	crypto_box_seal(ciphertext, message, sizeof(message), recipient_pk); // add some error checking? is of value or perhaps not?
	sodium_memzero(message,sizeof(message));
	sodium_memzero(recipient_pk,sizeof(recipient_pk));

	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	if(!g_peercount)
	{ // store the hash so that we can broadcast_remove the broadcast from queue after we join the group
		const uint32_t hash = fnv1a_32_salted(ciphertext,GROUP_BROADCAST_LEN);
		pthread_rwlock_wrlock(&mutex_expand_group);
		group[g].hash = hash;
		pthread_rwlock_unlock(&mutex_expand_group);
	}
}

void broadcast(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN])
{ // Origin_n is utilized on recv, origin_n == -1 is utilized when sending
	// TODO put message_send here on some sort of queuing system to prevent timing based network topography analysis
	// TODO store a integer hash of sent broadcast messages in some sort of array to prevent resending the same message multiple times? (per session)
	// TODO determine some way to avoid sending out broadcast messages (on startup) if we created the group? how do we know that?
	if(ciphertext == NULL)
	{
		error_simple(0,"Sanity check failed in broadcast function. Report this.");
		breakpoint();
		return;
	}
	if(origin_n < 0)
	{ // Attempting to join a public group (or, if send_out, re-broadcast). We should be queuing. TODO
		send_out: {}
		if(BROADCAST_QUEUE)
			broadcast_add(origin_n,ciphertext);
		else
		{
			int origin_group_n = origin_n;
			if(origin_n > -1)
			{ // This can only trigger from goto send_out
				const uint8_t owner = getter_uint8(origin_n,-1,-1,-1,offsetof(struct peer_list,owner));
				if(owner == ENUM_OWNER_GROUP_PEER)
				{
					const int g = set_g(origin_n,NULL);
					origin_group_n = getter_group_int(g,offsetof(struct group_list,n));
				}
			}
			for(int n = 0 ; getter_byte(n,-1,-1,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index)) > -1 ; n++)
			{ // Send to EVERYONE other than orign_n and origin_n's group
				const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
				const uint8_t status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status));
				if(n != origin_group_n && status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL))
					message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,ciphertext,GROUP_BROADCAST_LEN);
			}
		}
	}
	else // if(origin_n > -1) // this if statement must be here because we reserve with set_g in group_join (???)
	{ // Handle Inbound Broadcast
		pthread_rwlock_rdlock(&mutex_expand_group);
		for(int group_n,g = 0 ; (group_n = group[g].n) > -1 || !is_null(group[g].id,GROUP_ID_SIZE); g++)
		{ // Attempt decryption of ciphertext, in all circumstances
			if(group_n < 0)
				continue; // this group is deleted, skip checking it
			pthread_rwlock_unlock(&mutex_expand_group);
			const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
			if(!g_invite_required)
			{ // Only try public groups
				unsigned char x25519_pk[crypto_box_PUBLICKEYBYTES]; // 32
				unsigned char x25519_sk[crypto_box_SECRETKEYBYTES]; // 32
				pthread_rwlock_rdlock(&mutex_expand_group);
				memcpy(x25519_sk,group[g].id,sizeof(x25519_sk));
				pthread_rwlock_unlock(&mutex_expand_group);
				crypto_scalarmult_base(x25519_pk, x25519_sk); // convert sk_to_pk
				unsigned char decrypted[GROUP_BROADCAST_DECRYPTED_LEN];
				if(crypto_box_seal_open(decrypted,ciphertext,GROUP_BROADCAST_LEN,x25519_pk, x25519_sk) == 0)
				{ // Successful decryption, meaning we have this group
					sodium_memzero(x25519_pk,sizeof(x25519_pk));
					sodium_memzero(x25519_sk,sizeof(x25519_sk));
					char onion[56+1];
					getter_array(&onion,sizeof(onion),group_n,-1,-1,-1,offsetof(struct peer_list,onion)); // TODO 2024/02/19 hit this with group_n being -1, which is a possible race because we *have* this group or we couldn't decrypt
					if(!memcmp(onion,&decrypted[crypto_pwhash_SALTBYTES],56)) // TODO hit error here in valgrind on 2023/10/24
					{ // Check if this is our own broadcast being returned to us (which is fine and normal)
						sodium_memzero(onion,sizeof(onion));
						sodium_memzero(decrypted,sizeof(decrypted));
						error_simple(1,"Public broadcast returned to us (our onion was encrypted). Do nothing, ignore.");
						return;
					}
					else
					{ // Some user wants into a group we are in.
						sodium_memzero(onion,sizeof(onion));
						const int new_peer = group_add_peer(g,(char*)&decrypted[crypto_pwhash_SALTBYTES],NULL,&decrypted[crypto_pwhash_SALTBYTES+56],NULL);
						sodium_memzero(decrypted,sizeof(decrypted));
						if(new_peer > -1)
						{ // Send them a peerlist
							error_simple(0,RED"Checkpoint New group peer!(broadcast)"RESET);
							broadcast_remove(g);
						//	error_simple(1,"Sending a peerlist to our brand new peer in public group");
						//	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
						//	message_send(new_peer,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(g),GROUP_PEERLIST_PUBLIC_LEN);
							unsigned char ciphertext_new[GROUP_BROADCAST_LEN];
							broadcast_prep(ciphertext_new,g);
						/*	torx_read(new_peer) // TODO remove
							const uint8_t owner = peer[new_peer].owner; // TODO remove
							torx_unlock(new_peer) // TODO remove
							printf("Checkpoint REQUESTING RECIPROCITY via GROUP_BROADCAST to specific peer: %u =? 5\n",owner); // TODO remove // should be ENUM_OWNER_GROUP_PEER ??? but isn't by the time we go to message_send
							if(owner != 5) // TODO remove
								breakpoint(); // TODO remove
							printf("Checkpoint ciphertext: %s\n",b64_encode(ciphertext_new,sizeof(ciphertext_new)));	*/
							message_send(new_peer,ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,ciphertext_new,GROUP_BROADCAST_LEN);  // REQUEST RECIPROCITY CONNECTION (critical)
						//	printf("Checkpoint did it message_send?\n");
							sodium_memzero(ciphertext_new,sizeof(ciphertext_new));
						}
						else if(new_peer == -1)
						{ // == -2 is already have it
							error_simple(0,"New peer is -1 therefore there was an error. Bailing.");
						}
						return;
					}
				}
				sodium_memzero(x25519_pk,sizeof(x25519_pk));
				sodium_memzero(x25519_sk,sizeof(x25519_sk));
			//	printf("Checkpoint decryption fail on g==%d\n",g);
			}
			pthread_rwlock_rdlock(&mutex_expand_group);
		} // If getting here, means unable to decrypt ciphertext with any public group ID. Carry on.
		pthread_rwlock_unlock(&mutex_expand_group);
		goto send_out;
	}
}

static inline void *broadcast_threaded(void *arg)
{ // TODO this runs forever even when nothing is queued. TODO for safety, it should ONLY RUN WHEN WE ARE CONNECTED, otherwise it will queue up all our messages and then send them all at once when we get online... totally defeating the purpose of a queue
	(void) arg;
	pusher(zero_pthread,(void*)&thrd_broadcast)
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	unsigned int broadcast_delay_local;
	while(1)
	{
		broadcast_delay_local = BROADCAST_DELAY_SLEEP;
		pthread_rwlock_rdlock(&mutex_broadcast);
		int random_start_1 = rand() % BROADCAST_QUEUE_SIZE; // Call rand() once as the starting position then iterate.
		for(int iter1 = 0; iter1 < BROADCAST_QUEUE_SIZE ; iter1++,random_start_1++)
		{ // choose a random broadcast
			int random_broadcast = random_start_1;
			if(random_broadcast >= BROADCAST_QUEUE_SIZE)
				random_broadcast -= BROADCAST_QUEUE_SIZE;
			if(broadcasts_queued[random_broadcast].hash)
			{ // found one
			//	error_simple(0,"Checkpoint 1: chose random broadcast");
				int random_start_2 = rand() % BROADCAST_MAX_PEERS; // Call rand() once as the starting position then iterate.
				for(int iter2 = 0; iter2 < BROADCAST_MAX_PEERS ; iter2++,random_start_2++)
				{ // choose a random peer to send it to
					int random_peer = random_start_2;
					if(random_peer >= BROADCAST_MAX_PEERS)
						random_peer -= BROADCAST_MAX_PEERS;
					const int n = broadcasts_queued[random_broadcast].peers[random_peer]; // note: we're not checking if peer is online because might be a group
					if(n == -1) // faster to have this check before we retrieve owner/online status
						continue;
					const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
					const uint8_t sendfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t recvfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t online = sendfd_connected + recvfd_connected;
					if(online || owner == ENUM_OWNER_GROUP_CTRL)
					{ // chose one and send to it, then delist if applicable
						error_printf(0,"Checkpoint 2: chose ONLINE victim owner=%u",owner); // TODO this must trigger if 1 triggers TODO
						message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						pthread_rwlock_unlock(&mutex_broadcast);
						pthread_rwlock_wrlock(&mutex_broadcast);
						broadcasts_queued[random_broadcast].peers[random_peer] = -1;
						int more_peers = -1;
						for(int iter3 = 0; iter3 < BROADCAST_MAX_PEERS ; iter3++)
							if((more_peers = broadcasts_queued[random_broadcast].peers[iter3]) > -1)
							{
								error_simple(1,"Checkpoint still peers to send to");
								break;
							}
						if(more_peers > -1)
							break;
						error_simple(0,"Checkpoint broadcast sent to all peers");
						broadcasts_queued[random_broadcast].hash = 0; // broadcast has been sent to last peer
						sodium_memzero(broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						broadcast_delay_local = BROADCAST_DELAY; // sent something, so set the lower delay
						break;
					}
//printf("Checkpoint 2: chose OFFLINE victim owner=%u\n",owner); // TODO this must trigger if 1 triggers TODO
				}
				break;
			}
		}
		pthread_rwlock_unlock(&mutex_broadcast);
		sleep(broadcast_delay_local);
	}
	return NULL;
}

void broadcast_start(void)
{ // Should run from late in initial_keyed, after everything is loaded
	if(pthread_create(&thrd_broadcast,&ATTR_DETACHED,&broadcast_threaded,NULL))
		error_simple(-1,"Failed to create broadcast thread");
}