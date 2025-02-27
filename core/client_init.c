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

void DisableNagle(const evutil_socket_t sendfd)
{ // Might slightly reduce latency. As far as we can see, it is having no effect at all, because the OS or something is still implementing Nagle.
	const int on = 1;
	if(setsockopt(SOCKET_CAST_OUT sendfd, IPPROTO_TCP, TCP_NODELAY, OPTVAL_CAST &on, sizeof(on)) == -1)
	{
		error_simple(0,"Error in DisableNagle setting TCP_NODELAY. Report this.");
		perror("getsockopt");
	}
	const int sndbuf_size = SOCKET_SO_SNDBUF;
	const int recvbuf_size = SOCKET_SO_RCVBUF;
	if(sndbuf_size)
		if(setsockopt(SOCKET_CAST_OUT sendfd, SOL_SOCKET, SO_SNDBUF, OPTVAL_CAST &sndbuf_size, sizeof(sndbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
	if(recvbuf_size)
		if(setsockopt(SOCKET_CAST_OUT sendfd, SOL_SOCKET, SO_RCVBUF, OPTVAL_CAST &recvbuf_size, sizeof(recvbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
}

static inline int unclaim(uint16_t *active_transfers_ongoing,const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p).
	const uint8_t peer_owner = getter_uint8(peer_n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(n < 0 || f < 0 || peer_n < 0 || peer_owner == ENUM_OWNER_GROUP_CTRL || active_transfers_ongoing == NULL)
	{
		error_printf(0,"Unclaim sanity check fail: n=%d f=%d peer_n=%d peer_owner=%u\n",n,f,peer_n,peer_owner);
		return 0;
	}
	int was_transferring = 0;
	torx_write(n) // 🟥🟥🟥 YES, must be write, because we can't unlock or we could have races
	if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL || peer[n].file[f].split_status_req == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		return was_transferring;
	}
	for(int16_t section = 0; section <= peer[n].file[f].splits; section++)
	{
		if(peer[n].file[f].split_status_n[section] == peer_n && (peer[n].file[f].split_status_fd[section] == fd_type || fd_type < 0))
		{
			peer[n].file[f].split_status_n[section] = -1; // unclaim section
			peer[n].file[f].split_status_fd[section] = -1;
			peer[n].file[f].split_status_req[section] = 0;
			error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status_n[%d] = -1"RESET,n,f,section); // TODO this triggers a callback within a mutex
			was_transferring++;
		}
		else if(peer[n].file[f].split_status_n[section] > -1)
			*active_transfers_ongoing = *active_transfers_ongoing + 1; // cannot use ++ here. Would be invalid pointer math.
	}
	torx_unlock(n) // 🟩🟩🟩
	return was_transferring;
}

int section_unclaim(const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p) // To unclaim all sections, pass fd_type == -1
	if(n < 0 || peer_n < 0)
	{ // All other things can be -1
		error_simple(0,"Section unclaim failed sanity check.");
		return 0;
	}
	uint16_t active_transfers_ongoing = 0;
	int was_transferring = 0;
	if(f > -1)  // Unclaim sections of a specific file (typical upon pause)
		was_transferring += unclaim(&active_transfers_ongoing,n,f,peer_n,fd_type);
	else
	{ // Unclaim sections of all files (typical when a socket closes during inbound transfer)
		torx_read(n) // 🟧🟧🟧
		for(int ff = 0 ; !is_null(peer[n].file[ff].checksum,CHECKSUM_BIN_LEN) ; ff++)
		{
			torx_unlock(n) // 🟩🟩🟩
			uint16_t ongoing = 0;
			was_transferring += unclaim(&ongoing,n,ff,peer_n,fd_type);
			active_transfers_ongoing += ongoing;
			torx_read(n) // 🟧🟧🟧
		}
		torx_unlock(n) // 🟩🟩🟩
	}
	if(!active_transfers_ongoing && f > -1)
		transfer_progress(n,f); // XXX This intentionally triggers a stall because no transfer has occurred since last_transferred was last updated. XXX
	return was_transferring;
}

static inline char *message_prep(uint32_t *message_len_p,const int target_n,const int16_t section,const uint64_t start,const uint64_t end,const int n,const int f,const int g,const int p_iter,const time_t time,const time_t nstime,const void *arg,const uint32_t base_message_len)
{ // Prepare messages // WARNING: There are no sanity checks. This function can easily de-reference a null pointer if bad/insufficient args are passed.
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	char *base_message = torx_secure_malloc(base_message_len + null_terminated_len);
	int group_n = -1;
	uint32_t peercount = 0;
	uint8_t invite_required = 0;
	char onion_group_n[56+1];
	unsigned char sign_sk_group_n[crypto_sign_SECRETKEYBYTES];
	if(g > -1)
	{ // Note: relevant group, not necessarily target group
		group_n = getter_group_int(g,offsetof(struct group_list,n));
		invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
		peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		getter_array(&onion_group_n,sizeof(onion_group_n),group_n,INT_MIN,-1,offsetof(struct peer_list,onion));
		getter_array(&sign_sk_group_n,sizeof(sign_sk_group_n),group_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
	}
	if(protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE)
	{ // CHECKSUM[64] + SIZE[8] + MODIFIED[4] + FILENAME (no null termination)
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,offsetof(struct file_list,checksum));
		const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
		const uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash64,sizeof(uint64_t));
		const time_t modified = getter_time(n,INT_MIN,f,offsetof(struct file_list,modified));
		uint32_t trash32 = htobe32((uint32_t)modified);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
		torx_read(n) // 🟧🟧🟧
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],peer[n].file[f].filename,strlen(peer[n].file[f].filename)); // second time calling strlen
		torx_unlock(n) // 🟩🟩🟩
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
	{ // HashOfHashes + Splits[1] + split_progress[section] *(splits + 1)
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,offsetof(struct file_list,checksum)); // hash of hashes
		const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
		*(uint8_t*)(void*)&base_message[CHECKSUM_BIN_LEN] = splits;
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].split_progress == NULL) // Necessary sanity check
		{ // If a file path exists, we are the offerer here.
			const uint8_t file_path_exists = peer[n].file[f].file_path ? 1 : 0;
			torx_unlock(n) // 🟩🟩🟩
			const uint64_t size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
			for(int16_t section_local = 0; section_local <= splits; section_local++)
			{ // Simulate that each section is fully complete, since we are assuming that we offered this file and have it fully.
				uint64_t section_end;
				const uint64_t section_start = calculate_section_start(&section_end,size,splits,section_local);
				const uint64_t our_progress = file_path_exists ? section_end - section_start + 1 : 0;
				const uint64_t trash64 = htobe64(our_progress);
				memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + sizeof(uint64_t)*(size_t)section_local],&trash64,sizeof(uint64_t));
			}
		}
		else
		{
			for(int16_t section_local = 0; section_local <= splits; section_local++)
			{ // Add how much is completed on each section
				const uint64_t trash64 = htobe64(peer[n].file[f].split_progress[section_local]);
				memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + sizeof(uint64_t)*(size_t)section_local],&trash64,sizeof(uint64_t));
			}
			torx_unlock(n) // 🟩🟩🟩
		}
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
	{ // HashOfHashes + Splits[1] + CHECKSUM_BIN_LEN *(splits + 1)) + SIZE[8] + MODIFIED[4] + FILENAME (no null termination)
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,offsetof(struct file_list,checksum)); // hash of hashes + size, not hash of file
		const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
		*(uint8_t*)(void*)&base_message[CHECKSUM_BIN_LEN] = splits;
		const size_t split_hashes_len = (size_t)(CHECKSUM_BIN_LEN *(splits + 1));
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].split_hashes) // Necessary sanity check to prevent race conditions
			memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],peer[n].file[f].split_hashes,split_hashes_len);
		else
		{
			torx_unlock(n) // 🟩🟩🟩
			error_simple(0,"split_hashes is NULL. This is unacceptable at this point.");
			breakpoint();
			goto error;
		}
		torx_unlock(n) // 🟩🟩🟩
		const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
		const uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len],&trash64,sizeof(uint64_t));
		const time_t modified = getter_time(n,INT_MIN,f,offsetof(struct file_list,modified));
		const uint32_t trash32 = htobe32((uint32_t)modified);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
		torx_read(n) // 🟧🟧🟧
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t)],peer[n].file[f].filename,strlen(peer[n].file[f].filename)); // second time calling strlen
	//	error_printf(3,"Checkpoint message_send group file offer: %lu %s %s\n",file_size,peer[n].file[f].filename,b64_encode(base_message,CHECKSUM_BIN_LEN));
		torx_unlock(n) // 🟩🟩🟩
	}
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{ // CHECKSUM[64] + START[8] + END[8]
		if(section < 0)
			goto error;
		getter_array(base_message,CHECKSUM_BIN_LEN,n,INT_MIN,f,offsetof(struct file_list,checksum));
	//	error_printf(0,"Checkpoint request n=%d f=%d sec=%d %lu to %lu peer_n=%d",n,f,section,start,end,target_n);
		uint64_t trash = htobe64(start);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash,sizeof(uint64_t));
		trash = htobe64(end);
		memcpy(&base_message[CHECKSUM_BIN_LEN+sizeof(uint64_t)],&trash,sizeof(uint64_t));
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
			getter_array(&base_message[cur],56,specific_peer,INT_MIN,-1,offsetof(struct peer_list,peeronion));
			cur += 56;
		}
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{ // Peer public keys
			obtain_specific_peer
			getter_array(&base_message[cur],crypto_sign_PUBLICKEYBYTES,specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_sign_pk));
			cur += crypto_sign_PUBLICKEYBYTES;
		}
		if(invite_required)
			for(uint32_t nn = 0 ; nn < peercount ; nn++)
			{ // Inviter signatures of peeronions ( non-applicable to public groups )
				obtain_specific_peer
				getter_array(&base_message[cur],crypto_sign_BYTES,specific_peer,INT_MIN,-1,offsetof(struct peer_list,invitation));
				cur += crypto_sign_BYTES;
			}
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
	{ // Onion[56] + ed25519_pk[32] + signed by invitor[64]
		memcpy(base_message,onion_group_n,56);
		crypto_sign_ed25519_sk_to_pk((unsigned char*)&base_message[56],sign_sk_group_n);
		getter_array(&base_message[56+crypto_sign_PUBLICKEYBYTES],crypto_sign_BYTES,group_n,INT_MIN,-1,offsetof(struct peer_list,invitation));
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
		invitee_add(g,target_n);
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
				getter_array(&base_message[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES],crypto_sign_BYTES,group_n,INT_MIN,-1,offsetof(struct peer_list,invitation));
				char *peernick = getter_string(NULL,target_n,INT_MIN,-1,offsetof(struct peer_list,peernick));
				if(group_add_peer(g,int_char->p,peernick,int_char->up,invitation) > -1) // we are working with two invitations... this is the correct one
					error_simple(0,RED"Checkpoint New group peer! (message_prep)"RESET);
				torx_free((void*)&peernick);
			}
			sodium_memzero(invitation,sizeof(invitation));
		}
	}
	else if(arg && (base_message_len || null_terminated_len))
	{ // If we simply need to add a null byte, we'll do it here rather than in message_sign, to avoid copying
		memcpy(base_message,arg,base_message_len); // this is a necessary copy
		if(null_terminated_len)
			base_message[base_message_len] = '\0';
	}
	char *message_new;
	if(signature_len)
	{ // Sign message
		unsigned char *sk;
		const uint8_t owner_target = getter_uint8(target_n,INT_MIN,-1,offsetof(struct peer_list,owner));
		unsigned char sign_sk_target_n[crypto_sign_SECRETKEYBYTES];
		if(owner_target == ENUM_OWNER_GROUP_PEER)
			sk = sign_sk_group_n;
		else
		{
			getter_array(&sign_sk_target_n,sizeof(sign_sk_target_n),target_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
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

static inline int message_distribute(const uint8_t skip_prep,const int n,const uint8_t owner,const int target_n,const int f,const int g,const int target_g,const uint32_t target_g_peercount,const int p_iter,const void *arg,const uint32_t base_message_len,time_t time,time_t nstime,const int8_t fd_type,const int16_t section,const uint64_t start,const uint64_t end)
{ // TODO WARNING: Sanity checks will interfere with message_resend. Message_send + message_distribute + message_prep are highly functional spagetti.
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t stream = protocols[p_iter].stream;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols);
	if((protocol == ENUM_PROTOCOL_FILE_REQUEST && fd_type < 0) || ((protocol == ENUM_PROTOCOL_PIPE_AUTH || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST) && fd_type == 0))
	{ // The reason is because select_peer MUST have already been called and claimed a specific fd_type. If we err out with fd_type==-1, we'll unclaim all sections (bad).
		error_printf(0,"Sanity check failure in message_distribute: owner=%u protocol=%u fd_type=%d. Coding error. Report this.",owner,protocol,fd_type);
		goto error;
	}
	//if(protocol == ENUM_PROTOCOL_FILE_REQUEST) printf("Checkpoint send_both owner%u: %u = (%d < 0 && (%d || %d && %d && %u && %d))\n",owner,send_both,target_g,protocol == ENUM_PROTOCOL_KILL_CODE,owner != ENUM_OWNER_GROUP_CTRL,protocol == ENUM_PROTOCOL_FILE_REQUEST,getter_uint8(n,INT_MIN,f,offsetof(struct file_list,full_duplex)),getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits)) > 0);
	// XXX Step 4: Set date if unset, and set fd
	if(!time && !nstime)
		set_time(&time,&nstime);
	// XXX Step 5: Build base message
	char *message;
	uint32_t message_len;
	if(skip_prep)
	{ // For re-send only. Warning: Highly experimental.
		message_len = base_message_len;
		message = torx_secure_malloc(message_len);
		memcpy(message,arg,message_len);
	}
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		message = message_prep(&message_len,target_n,section,start,end,n,f,g,p_iter,time,nstime,arg,base_message_len);
	else
		message = message_prep(&message_len,target_n,-1,0,0,n,f,g,p_iter,time,nstime,arg,base_message_len);
	if(message_len < 1/* || message == NULL*/)
	{ // Not necessary to check both
		if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
			section_unclaim(n,f,target_n,fd_type);
		else
			error_printf(0,"Checkpoint message_send 0 length. Bailing. fd=%d protocol=%u",fd_type,protocol);
		goto error;
	}
	// XXX Step 6: Iterate message
	const int i = increment_i(target_n,0,time,nstime,ENUM_MESSAGE_FAIL,fd_type,p_iter,message,message_len);
	// XXX Step 7: Send_prep as appropriate
	uint32_t cycle = 0;
	int repeated = 0;
	while(1)
	{
		int nnnn = target_n;
		int iiii = i;
		uint8_t owner_nnnn = getter_uint8(nnnn,INT_MIN,-1,offsetof(struct peer_list,owner));
		if(target_g > -1)
		{ // This is for messages to all GROUP_PEER. "Public message"
			pthread_rwlock_rdlock(&mutex_expand_group);
			nnnn = group[target_g].peerlist[cycle];
			pthread_rwlock_unlock(&mutex_expand_group);
			if(nnnn < 0 || (owner_nnnn = getter_uint8(nnnn,INT_MIN,-1,offsetof(struct peer_list,owner))) != ENUM_OWNER_GROUP_PEER)
			{ // sanity check
				error_printf(0,"Attempting to send group message on non-GROUP_PEER. Bailing. Report this. Details: nnnn: %d Owner: %u Protocol: %u Peercount: %u",nnnn,owner_nnnn,protocol,target_g_peercount);
				breakpoint();
				goto error;
			}
			iiii = increment_i(nnnn,0,time,nstime,ENUM_MESSAGE_FAIL,fd_type,p_iter,message,message_len);
		}
		if(!stream)
		{ // Stream messages, if logged, are logged in packet_removal after they send
			if(cycle == 0)
			{
				if(target_g > -1 || (owner == ENUM_OWNER_GROUP_PEER && group_pm))
					repeated = message_insert(target_g > -1 ? target_g : g,target_n,i); // repeated likely means resent message. No print, no insert.
				if(!repeated) // NOT else if, do not eliminate check
				{ // unique same time/nstime, so print and save
					message_new_cb(target_n,i);
					sql_insert_message(target_n,i); // This should go before setting .all_sent = 0, to ensure that it happens before send (which will trigger :sent: write)
				}
			}
			if(!repeated && target_g > -1) // MUST go after the first sql_insert_message call (which saves the message initially to GROUP_CTRL)
				sql_insert_message(nnnn,iiii); // trigger save in each GROUP_PEER
		}
		if(send_prep(nnnn,-1,iiii,p_iter,fd_type) == -1 && stream == ENUM_STREAM_DISCARDABLE) // NOT else if
		{ // delete unsuccessful discardable stream message
			printf("Checkpoint disgarding stream: n=%d i=%d fd_type=%d protocol=%u\n",nnnn,iiii,fd_type,protocol);
			torx_write(nnnn) // 🟥🟥🟥
			zero_i(nnnn,iiii);
			torx_unlock(nnnn) // 🟩🟩🟩
			if(target_g < 0)
				return INT_MIN; // WARNING: do not attempt to free. pointer is already pointing to bunk location after zero_i. will segfault. experimental 2024/03/09
		}
		if(owner_nnnn != ENUM_OWNER_GROUP_PEER || target_g < 0 || ++cycle >= target_g_peercount) // NOT else if
			break; // be careful of the logic here and after. note the ++
	}
	return i;
	error: {}
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		section_unclaim(n,f,target_n,fd_type);
	torx_free((void*)&message);
	return INT_MIN;
}

int message_resend(const int n,const int i)
{ // Primarily for signed group_msg in private groups (both SENT and RECV), but also works on any type of OUTBOUND message. CAVEAT / LIMITATION: SENT can be spoofed (by original sender). We can modify our outbound message then re-send... hypothetically this could facilitate "recall" and "modify sent" in an unreliable way. (but currently we don't permit that. We just discard anything that fails message_insert)
	int p_iter;
	uint8_t owner;
	if(n < 0 || (owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner))) < 1 || (p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter))) < 0)
	{
		error_simple(0,"message_resend failed sanity check. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const char *name = protocols[p_iter].name;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t socket_swappable = protocols[p_iter].socket_swappable;
	pthread_rwlock_unlock(&mutex_protocols);
	if(!socket_swappable)
	{ // We shouldn't (and should have no purpose to) re-send non-swappable messages. Seeing this message likely indicates a UI coding error.
		error_printf(0,"message_resend cannot process the following message type because it is non-swappable: %s",name);
		return -1;
	}
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
	if(target_g > -1 && date_len && signature_len)
	{ // Keep the existing times (ie, resend only) only if its a group using signed && dated messages (ie private groups)
		torx_read(n) // 🟧🟧🟧
		time = peer[n].message[i].time;
		nstime = peer[n].message[i].nstime;
		torx_unlock(n) // 🟩🟩🟩
	}
	uint32_t message_len;
	char *message = getter_string(&message_len,n,i,-1,offsetof(struct message_list,message));
	message_distribute(1,-1,owner,n,-1,-1,target_g,target_g_peercount,p_iter,message,message_len,time,nstime,-1,-1,0,0);
	torx_free((void*)&message);
	return 0;	
}

int message_send(const int target_n,const uint16_t protocol,const void *arg,const uint32_t base_message_len)
{ // To send a message to all members of a group, pass the group_n as target_n. The group_n will store the message but each peer will have copies of the time, protocol, status.
	int p_iter = -1; // must initialize so long as we have the error_printf that could use it
	uint8_t owner = 0; // must initialize so long as we have the error_printf that could use it
	int8_t fd_type = -1;
	int n = target_n;
	int f = -1;
	if(target_n < 0 || protocol < 1 || (owner = getter_uint8(target_n,INT_MIN,-1,offsetof(struct peer_list,owner))) < 1 || (p_iter = protocol_lookup(protocol)) < 0)
	{
		error_printf(0,"message_send failed sanity check: %d %u %u %d. Coding error. Report this.",target_n,protocol,owner,p_iter);
		breakpoint();
		goto end;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	pthread_rwlock_unlock(&mutex_protocols);
	int g = -1;
	int target_g = -1; // LIMITED USE currently DO NOT USE EXTENSIVELY
	uint32_t target_g_peercount = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL && group_msg)
	{ // XXX Step 1: Set the group for messages going out to all multiple GROUP_PEER
		target_g = set_g(target_n,NULL);
		target_g_peercount = getter_group_uint32(target_g,offsetof(struct group_list,peercount));
		if(target_g_peercount < 1)
		{ // this isn't necessarily an error. this would be an OK place to bail out in some circumstances like broadcast messages
			error_printf(0,"Group has no users. Refusing to queue message. This is fine. Protocol: %u",protocol);
			goto end;
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
	int16_t section = -1;
	uint64_t start = 0;
	uint64_t end = 0;
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{
		const struct file_request_strc *file_request_strc = (const struct file_request_strc*) arg; // Casting passed struct
		n = file_request_strc->n;
		f = file_request_strc->f;
		fd_type = file_request_strc->fd_type;
		section = file_request_strc->section;
		start = file_request_strc->start;
		end = file_request_strc->end;
		owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	}
	else if(file_offer)
	{
		const struct file_request_strc *file_request_strc = (const struct file_request_strc*) arg; // Casting passed struct
		n = file_request_strc->n;
		f = file_request_strc->f;
		if((protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE) && n != target_n)
		{ // Could also check that target_n is within the same group as file_n, if target_n != file_n
			error_simple(0,"file_n != target_n when it should be. Coding error. Report this.");
			goto end;
		}
	}
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
		g = vptoi(arg);
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
	{ // Note: The rest of the passed struct is accessed in message_distribute --> message_prep
		const struct int_char *int_char = (const struct int_char*) arg; // Casting passed struct
		g = int_char->i;
	}
	// XXX Step 3:
	if(g < 0 && (owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)) // NOT else if
		g = set_g(n,NULL);
	return message_distribute(0,n,owner,target_n,f,g,target_g,target_g_peercount,p_iter,arg,base_message_len,0,0,fd_type,section,start,end); // i or INT_MIN upon error
	end: {}
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		section_unclaim(n,f,target_n,fd_type);
	return INT_MIN;
}

void kill_code(const int n,const char *explanation)
{ /* -1 (global) deletes all SING/MULT, cycles through CTRL list and add a kill_code on each */ // Does nothing for outgoing friend requests ("peer")
	const char *explanation_local;
	if(explanation)
		explanation_local = explanation;
	else
		explanation_local = "None";
	const uint32_t explanation_len = (uint32_t) strlen(explanation_local);
	if(n == -1)
	{ /* Global kill code */
		for(int peer_index,nn = 0 ; (peer_index = getter_int(nn,INT_MIN,-1,offsetof(struct peer_list,peer_index))) > -1 || getter_byte(nn,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 ; nn++)
		{
			if(peer_index < 0)
				continue;
			const uint8_t owner_nn = getter_uint8(nn,INT_MIN,-1,offsetof(struct peer_list,owner));
			if(owner_nn == ENUM_OWNER_CTRL)
			{ /* Saves the kill code message to message log even if logging is turned off, to survive reboot */
				sql_delete_history(peer_index);
				message_send(nn,ENUM_PROTOCOL_KILL_CODE,explanation_local,explanation_len);
			}
			else if(owner_nn == ENUM_OWNER_SING || owner_nn == ENUM_OWNER_MULT)
				takedown_onion(peer_index,1);
		}
	}
	else
	{ // Specific peer
		const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		sql_delete_history(peer_index);
		message_send(n,ENUM_PROTOCOL_KILL_CODE,explanation_local,explanation_len);
	}
}

static inline int calculate_file_request_start_end(uint64_t *start,uint64_t *end,const int n,const int f,const int o,const int16_t section)
{ // NOTE: This does NOT account for contents of peer offer, unless o is passed. This accounts mainly for what we already have.
	if(!start || !end || n < 0 || f < 0 || section < 0)
	{
		error_simple(0,"Sanity check failed in calculate_file_request_start_end1. Coding error. Report this.");
		return -1;
	}
	const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_progress == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Sanity check failed in calculate_file_request_start_end2. Coding error. Report this.");
		goto error;
	}
	const uint64_t our_progress = peer[n].file[f].split_progress[section];
	torx_unlock(n) // 🟩🟩🟩
	const uint64_t section_start = calculate_section_start(end,file_size,splits,section);
	*start = section_start + our_progress;
	if(o > -1)
	{ // Group transfer
		uint64_t peer_progress;
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].offer && peer[n].file[f].offer[o].offer_progress)
			peer_progress = peer[n].file[f].offer[o].offer_progress[section];
		else
			peer_progress = 0;
		torx_unlock(n) // 🟩🟩🟩
		if(!peer_progress)
			goto error; // XXX DO NOT ELIMINATE THIS CHECK, otherwise we can get a negative int overflow on the next line
		*end = section_start + peer_progress - 1; // XXX previously was followed by -1
	//	printf("Checkpoint calculate_file_request_start_end %lu = %lu + %lu\n",*end,section_start,peer_progress);
	}
	if(*start > *end)
		goto error; // Section appears finished. Cannot request any data.
	return 0;
	error: {}
	*start = *end = 0;
	return -1;
}

static inline int select_peer(const int n,const int f,const int8_t fd_type)
{ // Check: blacklist, online status, how much data they have. Determine which group peer to request file from. Claim section. Used to be called section_claim().
	if(n < 0 || f < 0)
	{
		error_simple(0,"Sanity check failed in select_peer. Coding error. Report this.");
		return -1;
	}
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL)
	{ // TODO Can trigger upon Accept -> Reject / Cancel -> Re-offer -> Accept
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Sanity check failure. Something is unexpectantly NULL in select_peer. Should call split_read or section_update first, either of which will initialize. Coding error. Report this.");
		return -1; // TODO split_read(n,f); We did this prior to 2025/01/15
	}
	torx_unlock(n) // 🟩🟩🟩
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	struct file_request_strc file_request_strc = {0};
	file_request_strc.n = n; // potentially group_n. THIS IS NOT target_n
	file_request_strc.f = f;
	int target_n = -1;
	uint64_t target_progress = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Group transfers, non-PM
		int target_o = -1;
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].offer && peer[n].file[f].split_status_n && peer[n].file[f].split_progress && peer[n].file[f].split_status_fd)
		{
			if(peer[n].file[f].offer[0].offerer_n == -1)
			{ // Request _PARTIAl from everyone because we don't have any offers (we probably just retarted our client)
				torx_unlock(n) // 🟩🟩🟩
				unsigned char checksum[CHECKSUM_BIN_LEN];
				getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
				message_send(n,ENUM_PROTOCOL_FILE_PARTIAL_REQUEST,checksum,CHECKSUM_BIN_LEN);
				sodium_memzero(checksum,sizeof(checksum));
			}
			else
			{
				for(int o = 0 ; peer[n].file[f].offer[o].offerer_n != -1 ; o++)
				{
					const uint8_t sendfd_connected = peer[peer[n].file[f].offer[o].offerer_n].sendfd_connected;
					const uint8_t recvfd_connected = peer[peer[n].file[f].offer[o].offerer_n].recvfd_connected;
					const uint8_t online = recvfd_connected + sendfd_connected;
					const uint8_t blacklisted = peer[peer[n].file[f].offer[o].offerer_n].blacklisted;
					if(!online || blacklisted) // check blacklist and online status
						continue;
					uint8_t utilized = 0;
					int8_t utilized_fd_type = -1;
					for(int16_t section = 0; section <= splits; section++)
					{ // Making sure we don't request more than two sections of the same file from the same peer concurrently, nor more than one on one fd_type.
						const int relevant_split_status_n = peer[n].file[f].split_status_n[section];
						const int8_t tmp_fd_type = peer[n].file[f].split_status_fd[section];
						if(relevant_split_status_n == peer[n].file[f].offer[o].offerer_n)
						{
							utilized++;
							utilized_fd_type = tmp_fd_type;
						}
					}
					if(utilized >= online)
						continue; // We already have 2+ requests of this file from this peer. Go to the next peer.
					for(int16_t section = 0; section <= splits; section++)
					{ // Loop through all peers looking for the largest (most complete) section... literally any section. Continue if we have completed this section or if it is already being requested from someone else.
						const uint64_t offerer_progress = peer[n].file[f].offer[o].offer_progress[section];
						const int relevant_split_status_n = peer[n].file[f].split_status_n[section];
						const uint64_t relevant_progress = peer[n].file[f].split_progress[section];
						const int8_t relevant_split_status_fd = peer[n].file[f].split_status_fd[section];
						if(relevant_split_status_n != -1 || relevant_progress >= offerer_progress)
						{
							if(relevant_split_status_fd > -1)
								printf("Checkpoint select_peer existing: n=%d fd=%d sec=%d %lu of %lu\n",relevant_split_status_n,relevant_split_status_fd,section,relevant_progress,offerer_progress);
							continue; // Already requested from another peer, or the progress is less than we have. Go to the next section.
						}
						if(offerer_progress >= target_progress)
						{ // >= should result in the largest most recent offer being selected
							target_n = peer[n].file[f].offer[o].offerer_n;
							target_progress = offerer_progress;
							file_request_strc.section = section;
							target_o = o;
							if(utilized && utilized_fd_type == 0) // XXX must prevent requesting two different sections of the same file concurrently on the same socket!!!
								file_request_strc.fd_type = 1;
							else if(utilized && utilized_fd_type == 1)
								file_request_strc.fd_type = 0;
							else if(sendfd_connected)
								file_request_strc.fd_type = 1; // we'll prefer sendfd for transfers because we prefer recvfd for messages
							else
								file_request_strc.fd_type = 0;
						}
					}
				}
				torx_unlock(n) // 🟩🟩🟩
			}
		}
		if(target_n > -1)
		{
			if(getter_uint8(target_n,INT_MIN,-1,offsetof(struct peer_list,owner)) != ENUM_OWNER_GROUP_PEER)
			{ // Sanity check, should be unnecessary
				error_simple(0,"target_n can only be GROUP_PEER. Coding error. Report this.");
				return -1;
			}
			if(calculate_file_request_start_end(&file_request_strc.start,&file_request_strc.end,n,f,target_o,file_request_strc.section))
			{
				error_simple(0,"calculate_file_request_start_end failed with a group_ctrl. Coding error. Report this."); // possible race if this occurs?
				return -1;
			}
			printf(BRIGHT_GREEN"Checkpoint select_peer n=%d f=%d target_o=%d splits=%u section=%d start=%lu end=%lu\n"RESET,n,f,target_o,splits,file_request_strc.section,file_request_strc.start,file_request_strc.end);
		}
	}
	else
	{ // _CTRL or _GROUP_PEER, ie: PM/p2p, not group transfers. This section is NOT suitable for group transfers because we pass -1 as offer_o to calculate_file_request_start_end, which means we are assuming our peer has 100% of the file.
		printf(BRIGHT_GREEN"Checkpoint select_peer _CTRL or _GROUP_PEER owner=%u n=%d f=%d splits=%u\n"RESET,owner,n,f,splits);
		if(fd_type == -1)
		{ // Sanity check
			error_simple(0,"Wrong fd_type passed to select_peer. Coding error. Report this.");
			return -1;
		}
		target_n = n;
		file_request_strc.fd_type = fd_type; // must be set by caller
		for(file_request_strc.section = 0; file_request_strc.section <= splits ; file_request_strc.section++)
		{ // There should only be 1 or 2 sections, 0 or 1 splits.
			torx_read(n) // 🟧🟧🟧
			if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL)
			{ // Sanity check to prevent race condition
				torx_unlock(n) // 🟩🟩🟩
				error_simple(0,"select_peer file is probably cancelled1. Possible coding error. Report this.");
				return -1;
			}
			const int relevant_split_status_n = peer[n].file[f].split_status_n[file_request_strc.section];
			const int8_t tmp_fd_type = peer[n].file[f].split_status_fd[file_request_strc.section];
			torx_unlock(n) // 🟩🟩🟩
			if(relevant_split_status_n != -1 && tmp_fd_type == fd_type)
			{ // Cannot concurrently request more than one section of the same file on the same file descriptor or we'll have errors about non-consecutive writes.
				error_simple(0,"Request already exists for a section of this file on this fd_type. Coding error. Report this.");
				return -1;
			}
			if(relevant_split_status_n == -1 && calculate_file_request_start_end(&file_request_strc.start,&file_request_strc.end,n,f,-1,file_request_strc.section) == 0)
				break; // Target section aquired
		}
		if(file_request_strc.section > splits)
			return -1; // No unfinished sections available to request.
		const uint64_t section_start = calculate_section_start(NULL,file_size,splits,file_request_strc.section);
		target_progress = file_request_strc.end - section_start + 1; // MUST utilize section_start, not file_request_strc.start // NOTE: This is unnecessary/unutilized in non-group transfers.
	}
	if(target_n > -1)
	{
		if(file_request_strc.end >= file_size)
		{
			error_printf(0,"Sanity check failure in select_peer: end=%lu >= size=%lu",file_request_strc.end,file_size);
			return -1;
		}
		torx_write(n) // 🟥🟥🟥
		if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL || peer[n].file[f].split_status_req == NULL)
		{ // Sanity check to prevent race condition
			torx_unlock(n) // 🟩🟩🟩
			error_simple(0,"select_peer file is probably cancelled2. Possible coding error. Report this.");
			return -1;
		}
		peer[n].file[f].split_status_n[file_request_strc.section] = target_n; // XXX claim it. NOTE: do NOT have any 'goto error' after this. MUST NOT ERROR AFTER CLAIMING XXX
		peer[n].file[f].split_status_fd[file_request_strc.section] = file_request_strc.fd_type;
		peer[n].file[f].split_status_req[file_request_strc.section] = target_progress;
		torx_unlock(n) // 🟩🟩🟩
		error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status_n[%d] = %d, fd_type = %d"RESET,n,f,file_request_strc.section,target_n,file_request_strc.fd_type);
		message_send(target_n,ENUM_PROTOCOL_FILE_REQUEST,&file_request_strc,FILE_REQUEST_LEN);
		return target_n;
	}
	return -1;
}

static inline int file_unwritable(const int n,const int f,const char *file_path)
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
		char *file_path_local = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
		fp = fopen(file_path_local, "a");
		torx_free((void*)&file_path_local);
	}
	if(fp)
	{
		close_sockets_nolock(fp);
		return 0;
	}
	else if(file_path == NULL)
	{ // n,f was necessarily passed
		torx_write(n) // 🟥🟥🟥
		torx_free((void*)&peer[n].file[f].file_path);
		torx_free((void*)&peer[n].file[f].split_path);
		torx_unlock(n) // 🟩🟩🟩
	}
	error_simple(0,"File location permissions issue. Refusing to request file. Cleaing the file_path if n,f was passed so that it can be reset.");
	return 1;
}

void file_request_internal(const int n,const int f,const int8_t fd_type)
{ // Internal function only, do not call from UI. Use file_accept
	if(n < 0 || f < 0)
		return;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	torx_read(n) // 🟧🟧🟧
	const char *file_path = peer[n].file[f].file_path;
	torx_unlock(n) // 🟩🟩🟩
	if(file_path)
	{
		if(file_unwritable(n,f,NULL))
			return;
	}
	else
	{
		error_simple(0,"Lack of file_path in file_request_internal. Coding error. Report this.");
		breakpoint();
		return;
	}
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		while(select_peer(n,f,-1) > -1)
			continue; // Request from lots of people concurrently.
	}
	else
	{ // These are _CTRL(p2p) and _GROUP_CTRL(PM) transfers
		if(fd_type == -1)
		{ // Probably got here from file_accept
			if(getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected))) // DO NOT MAKE else if
				select_peer(n,f,1);
			if(getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected))) // DO NOT MAKE else if
				select_peer(n,f,0);
		}
		else // Probably got here from packet_removal
			select_peer(n,f,fd_type);
	}
}

void file_offer_internal(const int target_n,const int file_n,const int f,const uint8_t send_partial)
{ // Internal function only, do not call from UI. Use file_send
	const uint8_t owner = getter_uint8(file_n,INT_MIN,-1,offsetof(struct peer_list,owner)); // yes, MUST be file_n owner
	if(owner != ENUM_OWNER_GROUP_CTRL && target_n != file_n)
	{ // Could also check that target_n is in the same group as file_n, but should be unnecessary.
		error_simple(0,"Sanity check failure in file_offer_internal. Coding error. Report this.");
		return;
	}
	struct file_request_strc file_request_strc = {0};
	file_request_strc.n = file_n;
	file_request_strc.f = f;
	torx_read(file_n) // 🟧🟧🟧
	const size_t filename_len = strlen(peer[file_n].file[f].filename);
	const uint8_t splits = peer[file_n].file[f].splits;
	torx_unlock(file_n) // 🟩🟩🟩
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		const int g = set_g(file_n,NULL);
		const uint8_t invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
		if(invite_required)
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,&file_request_strc,FILE_OFFER_GROUP_LEN);
		else
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_GROUP,&file_request_strc,FILE_OFFER_GROUP_LEN);
		if(send_partial) // NOT else if
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_PARTIAL,&file_request_strc,FILE_OFFER_PARTIAL_LEN); // tell them that we have 100%
	}
	else if(owner == ENUM_OWNER_GROUP_PEER)
		message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_PRIVATE,&file_request_strc,FILE_OFFER_LEN);
	else
		message_send(target_n,ENUM_PROTOCOL_FILE_OFFER,&file_request_strc,FILE_OFFER_LEN);
}

void file_set_path(const int n,const int f,const char *path)
{ // To be called before file_accept. This is a helper function for FFI/Flutter. TODO Have this function utilize torx_fd_lock and other things to move/rename an existing file, mid transfer or otherwise.
	size_t len;
	if(!path || !(len = strlen(path)))
	{
		error_simple(0,"Zero length or null path passed to file_set_path");
		return;
	}
	torx_write(n) // 🟥🟥🟥
	if(peer[n].file[f].file_path == NULL)
	{
		peer[n].file[f].file_path = torx_secure_malloc(len+1);
		memcpy(peer[n].file[f].file_path,path,len+1);
		torx_unlock(n) // 🟩🟩🟩
	}
	else
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Currently, changing file_path is not facilitated. (we would have to change file name too and make sure its not active, maybe move the actual file...");
	}
}

void file_accept(const int n,const int f)
{ // Toggle to accept or pause file transfer
	if(n < 0 || f < 0)
		return;
	torx_read(n) // 🟧🟧🟧
	const uint8_t owner = peer[n].owner;
	const char *filename = peer[n].file[f].filename;
	torx_unlock(n) // 🟩🟩🟩
	const int file_status = file_status_get(n,f);
	if(filename == NULL)
	{ // probably ENUM_OWNER_GROUP_PEER, non-PM message, or where the file path is not yet set by UI
		error_simple(0,"File information not provided. Cannot accept. Coding error. Report this.");
		printf("Checkpoint file_accept owner: %u file_status: %d\n",owner,file_status);
		return;
	}
	if(file_status == ENUM_FILE_ACTIVE_IN || file_status == ENUM_FILE_ACTIVE_OUT || file_status == ENUM_FILE_ACTIVE_IN_OUT)
	{ // pause in/outbound transfer. Reciever can unpause it.  // Much redundancy in logic applies with file cancel  For group file transfers, like a _PARTIAL, the message is broadcast to everyone.
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
		message_send(n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
		sodium_memzero(checksum,sizeof(checksum));
		process_pause_cancel(n,f,n,ENUM_PROTOCOL_FILE_PAUSE,ENUM_MESSAGE_FAIL);
	}
	else if(file_status == ENUM_FILE_INACTIVE_COMPLETE) // User unpause by re-offering file (safer than setting _ACCEPTED and directly start re-pushing (Section 6RMA8obfs296tlea), even though it could mean some packets / data is sent twice.)
		file_offer_internal(n,n,f,1); // DO NOT CALL process_pause_cancel here, do not set _ACCEPTED ; we wait for peer to accept
	else if(file_status == ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND || file_status == ENUM_FILE_INACTIVE_ACCEPTED)
	{ // Accept, re-accept, or unpause a file
		pthread_rwlock_rdlock(&mutex_global_variable);
		const char *local_download_dir = download_dir;
		pthread_rwlock_unlock(&mutex_global_variable);
		torx_read(n) // 🟧🟧🟧
		const char *file_path = peer[n].file[f].file_path;
		torx_unlock(n) // 🟩🟩🟩
		if(local_download_dir != NULL && file_path == NULL)
		{ // Setting file_path to inside download_dir if existing. Client may have already set .file_path, preventing this from occuring.
			torx_write(n) // 🟥🟥🟥
			pthread_rwlock_rdlock(&mutex_global_variable);
			const size_t allocated_size = strlen(download_dir)+1+strlen(peer[n].file[f].filename)+1;
			peer[n].file[f].file_path = torx_secure_malloc(allocated_size);
			snprintf(peer[n].file[f].file_path,allocated_size,"%s%c%s",download_dir,platform_slash,peer[n].file[f].filename);
			pthread_rwlock_unlock(&mutex_global_variable);
			torx_unlock(n) // 🟩🟩🟩
		}
		else if(local_download_dir == NULL && file_path == NULL)
		{
			error_simple(0,"Cannot accept file. Have not set file path nor download directory.");
			return;
		}
		uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
		torx_read(n) // 🟧🟧🟧
		const unsigned char *split_hashes = peer[n].file[f].split_hashes;
		torx_unlock(n) // 🟩🟩🟩
		if(splits == 0 && split_hashes == NULL)
		{ // set splits to 1 if not already, but not on group files (which will have split_hashes)
			splits = 1; // set default before split_read, which might overwrite it.
			setter(n,INT_MIN,f,offsetof(struct file_list,splits),&splits,sizeof(splits));
		}
		initialize_split_info(n,f); // calls split_read(n,f);
		const uint64_t size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
		if(calculate_transferred_inbound(n,f) < size)
			file_request_internal(n,f,-1);
		else // Complete. Not checking if oversized or wrong hash.
			error_simple(0,"This code should never execute. If it executes, the split file hasn't been deleted but should have been. Report this.");
	}
	else
	{ // NOTE: This is probably a UI error caused by ENUM_FILE_INACTIVE_CANCELLED
		error_printf(0,"Attempted file_accept on file %d with unrecognized file_status: %u. Coding error. Report this.",f,file_status);
		breakpoint();
	}
}

void file_cancel(const int n,const int f)
{ // Much redundancy in logic applies with file pause. For group file transfers, like a _PARTIAL, the message is broadcast to everyone.
	if(n < 0 || f < 0)
		return;
	unsigned char checksum[CHECKSUM_BIN_LEN];
	getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
	message_send(n,ENUM_PROTOCOL_FILE_CANCEL,checksum,CHECKSUM_BIN_LEN);
	sodium_memzero(checksum,sizeof(checksum));
	process_pause_cancel(n,f,n,ENUM_PROTOCOL_FILE_CANCEL,ENUM_MESSAGE_FAIL);
}

unsigned char *file_split_hashes(unsigned char *hash_of_hashes,const char *file_path,const uint8_t splits,const uint64_t size)
{ // Be sure to torx_free. This is for group files.
	if(!file_path)
		return NULL;
	const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
	unsigned char *split_hashes_and_size = torx_secure_malloc(split_hashes_len+sizeof(uint64_t));
	size_t size_total = 0; // sum of sections
	for(int16_t section = 0; section <= splits; section++)
	{ // populate split_hashes
		uint64_t end = 0;
		const uint64_t start = calculate_section_start(&end,size,splits,section);
		const uint64_t len = end - start + 1;
		size_total += b3sum_bin(&split_hashes_and_size[CHECKSUM_BIN_LEN*section],file_path,NULL,start,len);
	//	printf("Checkpoint section=%d start=%lu end=%lu len=%lu total=%lu\n",section,start,end,len,size_total);
	}
	if(size != size_total)
	{
		error_printf(0,"Coding or IO error. File size %zu != %zu sum of sections. Splits=%u",size,size_total,splits);
		torx_free((void*)&split_hashes_and_size);
		return NULL;
	}
	const uint64_t trash = htobe64(size);
	memcpy(&split_hashes_and_size[split_hashes_len],&trash,sizeof(uint64_t));
	if(hash_of_hashes)
		b3sum_bin(hash_of_hashes,NULL,split_hashes_and_size,0,split_hashes_len+sizeof(uint64_t)); // hash of hashes and size
	return split_hashes_and_size;
}

static inline void *file_init(void *arg)
{ // Send File Offer
	struct file_strc *file_strc = (struct file_strc*) arg; // Casting passed struct
	const int n = file_strc->n;
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL); // TODO not utilized. Need to track then pthread_cleanup_push + pop + thread_kill
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	unsigned char checksum[CHECKSUM_BIN_LEN];
	size_t size = 0;
	uint8_t splits = 0;
	unsigned char *split_hashes_and_size = NULL;
//	printf("Checkpoint file_init owner==%u path==%s\n",owner,file_strc->path);
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Determine split count, allocate and populate split_hashes, generate hash of hashes
		splits = UINT8_MAX;
		size = file_strc->size;
		while(splits && size / splits < MINIMUM_SECTION_SIZE)
			splits--;
		split_hashes_and_size = file_split_hashes(checksum,file_strc->path,splits,size);
		if(split_hashes_and_size == NULL)
			goto error;
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
	file_offer_internal(n,n,f,1);
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
	struct stat file_stat = {0};
	if(stat(path, &file_stat) < 0)
	{
		error_simple(0,"File seems to not exist. Cannot send.");
		return -1;
	}
	struct file_strc *file_strc = torx_insecure_malloc(sizeof(struct file_strc));
	file_strc->modified = file_stat.st_mtime;
	file_strc->size = (size_t)file_stat.st_size;
	file_strc->n = n;
	const size_t path_len = strlen(path);
	file_strc->path = torx_secure_malloc(path_len+1);
	snprintf(file_strc->path,path_len+1,"%s",path);
	pthread_t thrd_file_init; // TODO 2024/03/25 track this thread somehow and/or put a mutex inside file_init? both are of questionable utility.
	if(pthread_create(&thrd_file_init,&ATTR_DETACHED,&file_init,(void*)file_strc))
		error_simple(-1,"Failed to create thread6");
	return 0;
}
