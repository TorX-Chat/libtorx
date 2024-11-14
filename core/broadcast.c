/*
TorX: Metadata-safe Tor Chat Library
Copyright (C) 2024 TorX

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3 as published by the Free
Software Foundation.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <https://www.gnu.org/licenses/>.

Appendix:

Section 7 Exceptions:

1) Modified versions of the material and resulting works must be clearly titled
in the following manner: "Unofficial TorX by Financier", where the word
Financier is replaced by the financier of the modifications. Where there is no
financier, the word Financier shall be replaced by the organization or
individual who is primarily responsible for causing the modifications. Example:
"Unofficial TorX by The United States Department of Defense". This amended
full-title must replace the word "TorX" in all source code files and all
resulting works. Where utilizing spaces is not possible, underscores may be
utilized. Example: "Unofficial_TorX_by_The_United_States_Department_of_Defense".
The title must not be replaced by an acronym or short title in any form of
distribution.

2) Modified versions of the material and resulting works must be distributed
with alternate logos and imagery that is substantially different from the
original TorX logo and imagery, especially the 7-headed snake logo. Modified
material and resulting works, where distributed with a logo or imagery, should
choose and distribute a logo or imagery that reflects the Financier,
organization, or individual primarily responsible for causing modifications and
must not cause any user to note similarities with any of the original TorX
imagery. Example: Modifications or works financed by The United States
Department of Defense should choose a logo and imagery similar to existing logos
and imagery utilized by The United States Department of Defense.

3) Those who modify, distribute, or finance the modification or distribution of
modified versions of the material or resulting works, shall not avail themselves
of any disclaimers of liability, such as those laid out by the original TorX
author in sections 15 and 16 of the License.

4) Those who modify, distribute, or finance the modification or distribution of
modified versions of the material or resulting works, shall jointly and
severally indemnify the original TorX author against any claims of damages
incurred and any costs arising from litigation related to any changes they are
have made, caused to be made, or financed. 

5) The original author of TorX may issue explicit exemptions from some or all of
the above requirements (1-4), but such exemptions should be interpreted in the
narrowest possible scope and to only grant limited rights within the narrowest
possible scope to those who explicitly receive the exemption and not those who
receive the material or resulting works from the exemptee.

6) The original author of TorX grants no exceptions from trademark protection in
any form.

7) Each aspect of these exemptions are to be considered independent and
severable if found in contradiction with the License or applicable law.
*/
void broadcast_add(const int origin_n,const unsigned char broadcast[GROUP_BROADCAST_LEN])
{ // Add or discard a broadcast, depending on queue and whether it has already been added/sent. "Broadcast should be added to queue if checksum (single int) is not in broadcast_history array. Queue should store an integer hash of each sent broadcast to avoid repetition. It should also be rate limited (random rate, random delays) to avoid facilitating mapping of the network. Broadcast thread should run perpetually if there is anything in the queue, otherwise close. Broadcasts exceeding queue should be discarded? Undecided."
	if(!broadcast)
	{ // Sanity check
		error_simple(0,"Sanity check fail in broadcast_add. Coding error. Report this.");
		breakpoint();
		return;
	}
	if(origin_n > -1)
	{ // Check if peer already sent too many broadcasts
		const uint32_t broadcasts_inbound = getter_uint32(origin_n,INT_MIN,-1,-1,offsetof(struct peer_list,broadcasts_inbound));
		if(broadcasts_inbound > BROADCAST_MAX_INBOUND_PER_PEER)
		{
			error_simple(0,"Peer has already sent > BROADCAST_MAX_INBOUND_PER_PEER. Not accepting their new broadcast.");
			return;
		}
	}
	const uint32_t hash = fnv1a_32_salted(broadcast,GROUP_BROADCAST_LEN);
	pthread_rwlock_rdlock(&mutex_broadcast);
	for(int iter_hist = 0; iter_hist < BROADCAST_HISTORY_SIZE; iter_hist++)
	{ // Check history for hash
		if(broadcast_history[iter_hist] == 0) // Not in history, queue it
			for(int iter_queue = 0; iter_queue < BROADCAST_QUEUE_SIZE; iter_queue++)
			{ // Find an available slot in queue
				if(broadcasts_queued[iter_queue].hash == 0)
				{ // Found empty slot
					pthread_rwlock_unlock(&mutex_broadcast);
					pthread_rwlock_wrlock(&mutex_broadcast);
					broadcast_history[iter_hist] = hash; // Put hash in history
					broadcasts_queued[iter_queue].hash = hash; // Put hash in queue
					memcpy(broadcasts_queued[iter_queue].broadcast,broadcast,GROUP_BROADCAST_LEN); // Put broadcast in queue
					int origin_or_group_n = origin_n;
					if(origin_n > -1)
					{ // Broadcast is being resent for peers, need to avoid sending it to the group we received it from, if applicable
						const uint8_t owner = getter_uint8(origin_n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
						if(owner == ENUM_OWNER_GROUP_PEER)
						{
							const int g = set_g(origin_n,NULL);
							origin_or_group_n = getter_group_int(g,offsetof(struct group_list,n));
						}
					}
					int iter_peer = 0;
					for(int n = 0; iter_peer < BROADCAST_MAX_PEERS && n <= max_peer; n++)
					{ // Queue suitable peers
						torx_read(n) // XXX
						if(peer[n].peer_index > -1 && n != origin_or_group_n && peer[n].status == ENUM_STATUS_FRIEND && (peer[n].owner == ENUM_OWNER_CTRL || peer[n].owner == ENUM_OWNER_GROUP_CTRL))
							broadcasts_queued[iter_queue].peers[iter_peer++] = n;
						torx_unlock(n++) // XXX
					}
					error_printf(0,"Broadcast added and slotted %d times",iter_peer);
					torx_write(origin_n) // XXX
					peer[origin_n].broadcasts_inbound++;
					torx_unlock(origin_n) // XXX
					break;
				}
				else if(iter_queue == BROADCAST_QUEUE_SIZE - 1)
				{
					error_simple(0,"Broadcast queue is full. Broadcast will be discarded.");
					break;
				}
			}
		else if(broadcast_history[iter_hist] == hash) // Already in history, bail
			error_simple(0,"Broadcast already exists in history. Will be discarded.");
		else // Complex logic, do not remove
			continue; // Complex logic, do not remove
		break; // Complex logic, do not remove
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
	for(int iter_queue = 0; iter_queue < BROADCAST_QUEUE_SIZE; iter_queue++)
		if(broadcasts_queued[iter_queue].hash == hash)
		{ // Found hash in queue, lets remove it.
			pthread_rwlock_unlock(&mutex_broadcast);
			pthread_rwlock_wrlock(&mutex_broadcast);
			broadcasts_queued[iter_queue].hash = 0; // Re-initialize hash
			sodium_memzero(broadcasts_queued[iter_queue].broadcast,GROUP_BROADCAST_LEN); // Re-initialize broadcast
			for(int iter_peer = 0; iter_peer < BROADCAST_MAX_PEERS; iter_peer++)
				broadcasts_queued[iter_queue].peers[iter_peer] = -1; // Re-initialize target peers
			pthread_rwlock_unlock(&mutex_broadcast);
			pthread_rwlock_wrlock(&mutex_expand_group);
			group[g].hash = 0;
			pthread_rwlock_unlock(&mutex_expand_group);
			error_simple(0,PINK"Removed a hash successfully."RESET);
			return;
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
	getter_array(&message[crypto_pwhash_SALTBYTES],56,group_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion)); // affix the group_n
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	getter_array(&sign_sk,sizeof(sign_sk),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,sign_sk));
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

void broadcast_inbound(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN])
{ // Handle Inbound Broadcast
	if(origin_n < 0 || ciphertext == NULL)
	{
		error_simple(0,"Sanity check failed in broadcast_inbound. Coding error. Report this.");
		breakpoint();
		return;
	}
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
				getter_array(&onion,sizeof(onion),group_n,INT_MIN,-1,-1,offsetof(struct peer_list,onion)); // TODO 2024/02/19 hit this with group_n being -1, which is a possible race because we *have* this group or we couldn't decrypt
				if(!memcmp(onion,&decrypted[crypto_pwhash_SALTBYTES],56))
					error_simple(1,"Public broadcast returned to us (our onion was encrypted). Do nothing, ignore.");
				else
				{ // Some user wants into a group we are in.
					const int new_peer = group_add_peer(g,(char*)&decrypted[crypto_pwhash_SALTBYTES],NULL,&decrypted[crypto_pwhash_SALTBYTES+56],NULL);
					if(new_peer > -1)
					{ // Send them a peerlist
						error_simple(0,RED"Checkpoint New group peer!(broadcast_inbound)"RESET);
						broadcast_remove(g);
						unsigned char ciphertext_new[GROUP_BROADCAST_LEN];
						broadcast_prep(ciphertext_new,g);
						message_send(new_peer,ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,ciphertext_new,GROUP_BROADCAST_LEN);
						sodium_memzero(ciphertext_new,sizeof(ciphertext_new));
					}
					else if(new_peer == -1) // NOT ELSE: as == -2 is already have it
						error_simple(0,"New peer is -1 therefore there was an error. Bailing.");
				}
				sodium_memzero(onion,sizeof(onion));
				sodium_memzero(decrypted,sizeof(decrypted));
				return; // do not rebroadcast, since we have this group
			}
			sodium_memzero(x25519_pk,sizeof(x25519_pk));
			sodium_memzero(x25519_sk,sizeof(x25519_sk));
		}
		pthread_rwlock_rdlock(&mutex_expand_group);
	} // If getting here, means unable to decrypt ciphertext with any public group ID. Carry on and rebroadcast it.
	pthread_rwlock_unlock(&mutex_expand_group);
	broadcast_add(origin_n,ciphertext);
}

static inline void *broadcast_threaded(void *arg)
{ // This runs forever even when nothing is queued. TODO for safety, it should ONLY RUN WHEN WE ARE CONNECTED, otherwise it will queue up all our messages and then send them all at once when we get online... totally defeating the purpose of a queue
	(void) arg;
	pusher(zero_pthread,(void*)&thrd_broadcast)
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	unsigned int broadcast_delay_local;
	while(1)
	{
		broadcast_delay_local = BROADCAST_DELAY_SLEEP;
		pthread_rwlock_rdlock(&mutex_broadcast);
		for(int iter_queue = 0,random_start_1 = randombytes_random() % BROADCAST_QUEUE_SIZE; iter_queue < BROADCAST_QUEUE_SIZE ; iter_queue++,random_start_1++)
		{ // choose a random broadcast by calling randombytes_random() once as the starting position then iterate and wrap around as necessary.
			int random_broadcast = random_start_1;
			if(random_broadcast >= BROADCAST_QUEUE_SIZE)
				random_broadcast -= BROADCAST_QUEUE_SIZE; // Wrap around
			if(broadcasts_queued[random_broadcast].hash)
			{ // Chose random broadcast
				for(int iter_peer = 0,random_start_2 = randombytes_random() % BROADCAST_MAX_PEERS; iter_peer < BROADCAST_MAX_PEERS ; iter_peer++,random_start_2++)
				{ // Choose a random peer to send it to
					int random_peer = random_start_2;
					if(random_peer >= BROADCAST_MAX_PEERS)
						random_peer -= BROADCAST_MAX_PEERS; // Wrap around
					const int n = broadcasts_queued[random_broadcast].peers[random_peer];
					if(n < 0)
						continue;
					const uint8_t owner = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,owner));
					const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t recvfd_connected = getter_uint8(n,INT_MIN,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t online = sendfd_connected + recvfd_connected;
					if(online || owner == ENUM_OWNER_GROUP_CTRL)
					{ // chose one and send to it, then delist if applicable
						if(owner == ENUM_OWNER_GROUP_CTRL)
						{ // Make sure the group has peers (ie: that we're not attempting to broadcast into the group we're trying to join). TODO Could also check that >0 are online.
							if(!getter_group_uint32(set_g(n,NULL),offsetof(struct group_list,peercount)))
								continue;
						}
						error_printf(0,"Broadcast chose ONLINE victim owner=%u",owner);
						message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						pthread_rwlock_unlock(&mutex_broadcast);
						pthread_rwlock_wrlock(&mutex_broadcast);
						broadcasts_queued[random_broadcast].peers[random_peer] = -1;
						int more_peers = -1;
						for(int iter_peer_check = 0; iter_peer_check < BROADCAST_MAX_PEERS ; iter_peer_check++)
							if((more_peers = broadcasts_queued[random_broadcast].peers[iter_peer_check]) > -1)
								break; // still peers to send to
						if(more_peers > -1)
							break;
						error_simple(0,"Checkpoint broadcast sent to all peers");
						broadcasts_queued[random_broadcast].hash = 0; // broadcast has been sent to last peer
						sodium_memzero(broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						broadcast_delay_local = BROADCAST_DELAY; // sent something, so set the lower delay
						break;
					}
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
