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

#include "torx_internal.h"

static inline char *message_prep(uint32_t *message_len_p,const int target_n,const int16_t section,const uint64_t start,const uint64_t end,const int file_n,const int file_f,const int g,const int p_iter,const time_t time,const time_t nstime,const void *arg,const uint32_t base_message_len)
{ // Prepare messages // WARNING: There are no sanity checks. This function can easily de-reference a null pointer if bad/insufficient args are passed.
	#ifndef NO_FILE_TRANSFER
	#else
	(void)section;
	(void)start;
	(void)end;
	(void)file_n;
	(void)file_f;
	#endif // NO_FILE_TRANSFER
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
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
	if(protocol == ENUM_PROTOCOL_GROUP_PEERLIST)
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
		#define obtain_specific_peer /* cannot use do while(0) because we declare a variable here */\
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
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
		memcpy(base_message,group[g].id,GROUP_ID_SIZE); // affix group_id
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
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
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
		memcpy(base_message,group[g].id,GROUP_ID_SIZE);
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
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
	#ifndef NO_FILE_TRANSFER
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{ // CHECKSUM[64] + START[8] + END[8]
		if(section < 0)
			goto error;
		getter_array(base_message,CHECKSUM_BIN_LEN,file_n,INT_MIN,file_f,offsetof(struct file_list,checksum));
	//	error_printf(0,"Checkpoint request n=%d f=%d sec=%d %lu to %lu peer_n=%d",file_n,file_f,section,start,end,target_n);
		uint64_t trash = htobe64(start);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash,sizeof(uint64_t));
		trash = htobe64(end);
		memcpy(&base_message[CHECKSUM_BIN_LEN+sizeof(uint64_t)],&trash,sizeof(uint64_t));
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE)
	{ // CHECKSUM[64] + SIZE[8] + MODIFIED[4] + FILENAME (no null termination)
		getter_array(base_message,CHECKSUM_BIN_LEN,file_n,INT_MIN,file_f,offsetof(struct file_list,checksum));
		const uint64_t file_size = getter_uint64(file_n,INT_MIN,file_f,offsetof(struct file_list,size));
		const uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN],&trash64,sizeof(uint64_t));
		const time_t modified = getter_time(file_n,INT_MIN,file_f,offsetof(struct file_list,modified));
		uint32_t trash32 = htobe32((uint32_t)modified);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
		torx_read(file_n) // 🟧🟧🟧
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],peer[file_n].file[file_f].filename,strlen(peer[file_n].file[file_f].filename)); // second time calling strlen
		torx_unlock(file_n) // 🟩🟩🟩
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
	{ // HashOfHashes + Splits[1] + CHECKSUM_BIN_LEN *(splits + 1)) + SIZE[8] + MODIFIED[4] + FILENAME (no null termination)
		getter_array(base_message,CHECKSUM_BIN_LEN,file_n,INT_MIN,file_f,offsetof(struct file_list,checksum)); // hash of hashes + size, not hash of file
		const uint8_t splits = getter_uint8(file_n,INT_MIN,file_f,offsetof(struct file_list,splits));
		*(uint8_t*)(void*)&base_message[CHECKSUM_BIN_LEN] = splits;
		const size_t split_hashes_len = (size_t)(CHECKSUM_BIN_LEN *(splits + 1));
		torx_read(file_n) // 🟧🟧🟧
		if(peer[file_n].file[file_f].split_hashes) // Necessary sanity check to prevent race conditions
			memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],peer[file_n].file[file_f].split_hashes,split_hashes_len);
		else
		{
			torx_unlock(file_n) // 🟩🟩🟩
			error_simple(0,"split_hashes is NULL. This is unacceptable at this point.");
			breakpoint();
			goto error;
		}
		torx_unlock(file_n) // 🟩🟩🟩
		const uint64_t file_size = getter_uint64(file_n,INT_MIN,file_f,offsetof(struct file_list,size));
		const uint64_t trash64 = htobe64(file_size);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len],&trash64,sizeof(uint64_t));
		const time_t modified = getter_time(file_n,INT_MIN,file_f,offsetof(struct file_list,modified));
		const uint32_t trash32 = htobe32((uint32_t)modified);
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)],&trash32,sizeof(uint32_t));
		torx_read(file_n) // 🟧🟧🟧
		memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t)],peer[file_n].file[file_f].filename,strlen(peer[file_n].file[file_f].filename)); // second time calling strlen
	//	error_printf(3,"Checkpoint message_send group file offer: %lu %s %s\n",file_size,peer[file_n].file[file_f].filename,b64_encode(base_message,CHECKSUM_BIN_LEN));
		torx_unlock(file_n) // 🟩🟩🟩
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
	{ // HashOfHashes + Splits[1] + split_progress[section] *(splits + 1)
		getter_array(base_message,CHECKSUM_BIN_LEN,file_n,INT_MIN,file_f,offsetof(struct file_list,checksum)); // hash of hashes
		const uint8_t splits = getter_uint8(file_n,INT_MIN,file_f,offsetof(struct file_list,splits));
		*(uint8_t*)(void*)&base_message[CHECKSUM_BIN_LEN] = splits;
		torx_read(file_n) // 🟧🟧🟧
		if(peer[file_n].file[file_f].split_progress == NULL) // Necessary sanity check
		{ // If a file path exists, we are the offerer here.
			const uint8_t file_path_exists = peer[file_n].file[file_f].file_path ? 1 : 0;
			torx_unlock(file_n) // 🟩🟩🟩
			const uint64_t size = getter_uint64(file_n,INT_MIN,file_f,offsetof(struct file_list,size));
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
				const uint64_t trash64 = htobe64(peer[file_n].file[file_f].split_progress[section_local]);
				memcpy(&base_message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + sizeof(uint64_t)*(size_t)section_local],&trash64,sizeof(uint64_t));
			}
			torx_unlock(file_n) // 🟩🟩🟩
		}
	}
	#endif // NO_FILE_TRANSFER
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
		// error_printf(0,"Checkpoint message_prep signed owner=%u g=%d",owner_target,g);
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

static inline int message_distribute(const uint8_t skip_prep,const size_t target_count,const int *target_list,const int p_iter,const void *arg,const uint32_t base_message_len,time_t time,time_t nstime)
{ // TODO WARNING: Sanity checks will interfere with message_resend. Message_send + message_distribute + message_prep are highly functional spagetti.
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t stream = protocols[p_iter].stream;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	#ifndef NO_FILE_TRANSFER
	const uint8_t file_offer = protocols[p_iter].file_offer;
	#endif // NO_FILE_TRANSFER
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	int8_t fd_type = -1;
	char *message = NULL; // must initialize as NULL in case of goto error
	uint32_t message_len;
	/* TODO START This block could potentially be moved to message_prep */
	int file_n = -1;
	int file_f = -1;
	#ifndef NO_FILE_TRANSFER
	int16_t section = -1;
	uint64_t start = 0;
	uint64_t end = 0;
	#endif // NO_FILE_TRANSFER
	int relevant_g = -1; // this is either group of offer, or group of peerlist
	if(protocol == ENUM_PROTOCOL_GROUP_PEERLIST || protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
		relevant_g = vptoi(arg);
	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
	{ // Note: The rest of the passed struct is accessed in message_prep
		const struct int_char *int_char = (const struct int_char*) arg; // Casting passed struct
		relevant_g = int_char->i;
	}
	#ifndef NO_FILE_TRANSFER
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST || file_offer)
	{ // NOTE: Any message where arg is expected to be a struct cannot be re-sent
		const struct file_request_strc *file_request_strc = (const struct file_request_strc*) arg; // Casting passed struct
		file_n = file_request_strc->n;
		file_f = file_request_strc->f;
		if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		{
			fd_type = file_request_strc->fd_type;
			section = file_request_strc->section;
			start = file_request_strc->start;
			end = file_request_strc->end;
		}
		else if((protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE) && file_n != target_list[0])
		{ // Could also check that target_list[0] is within the same group as file_n, if target_list[0] != file_n
			error_simple(0,"file_n != target_list[0] when it should be. Coding error. Report this.");
			goto error;
		}
	}
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST && fd_type < 0)
	{
		error_printf(0,"Sanity check failure in message_distribute: FILE_REQUEST fd_type=%d. Coding error. Report this.",fd_type);
		goto error;
	}
	#endif // NO_FILE_TRANSFER
	if((protocol == ENUM_PROTOCOL_PIPE_AUTH || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST) && fd_type == 0)
	{ // The reason is because select_peer MUST have already been called and claimed a specific fd_type. If we err out with fd_type==-1, we'll unclaim all sections (bad).
		error_printf(0,"Sanity check failure in message_distribute: protocol=%u fd_type=%d. Coding error. Report this.",protocol,fd_type);
		goto error;
	}
	/* This block could potentially be moved to message_prep END TODO */
	// XXX Step 4: Set date if unset, and set fd
	if(!time && !nstime)
		set_time(&time,&nstime);
	// XXX Step 5: Build base message
	int group_n = -1;
	int target_g = -1; // necesssary
	int fallback_g = -1; // necesssary
	const uint8_t first_owner = getter_uint8(target_list[0],INT_MIN,-1,offsetof(struct peer_list,owner));
	if(first_owner == ENUM_OWNER_GROUP_PEER && group_msg)
	{
		fallback_g = target_g = set_g(target_list[0],NULL);
		group_n = getter_group_int(target_g,offsetof(struct group_list,n));
	}
	else if(first_owner == ENUM_OWNER_GROUP_PEER)
		fallback_g = set_g(target_list[0],NULL);
	if(skip_prep)
	{ // For re-send only. Warning: Highly experimental. DO NOT USE TORX_COPY because arg may not be TorX allocated.
		message_len = base_message_len;
		message = torx_secure_malloc(message_len);
		memcpy(message,arg,message_len);
	}
	#ifndef NO_FILE_TRANSFER
	else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		message = message_prep(&message_len,target_list[0],section,start,end,file_n,file_f,relevant_g > -1 ? relevant_g : fallback_g,p_iter,time,nstime,arg,base_message_len);
	#endif // NO_FILE_TRANSFER
	else
		message = message_prep(&message_len,group_n > -1 ? group_n : target_list[0],-1,0,0,file_n,file_f,relevant_g > -1 ? relevant_g : fallback_g,p_iter,time,nstime,arg,base_message_len);
	if(message_len < 1/* || message == NULL*/)
	{ // Not necessary to check both
		#ifndef NO_FILE_TRANSFER
		if(protocol != ENUM_PROTOCOL_FILE_REQUEST)
		#endif // NO_FILE_TRANSFER
			error_printf(0,"Checkpoint message_send 0 length. Bailing. fd=%d protocol=%u",fd_type,protocol);
		goto error;
	}
	// XXX Step 6: Iterate message
	const int i = increment_i(group_n > -1 ? group_n : target_list[0],0,time,nstime,ENUM_MESSAGE_FAIL,fd_type,p_iter,message);
	// XXX Step 7: Send_prep as appropriate
	int repeated = 0;
	for(uint32_t cycle = 0; cycle < target_count; cycle++)
	{
		int iiii = i;
		if(target_g > -1) // This is for messages to multiple GROUP_PEER. "Public message"
			iiii = increment_i(target_list[cycle],0,time,nstime,ENUM_MESSAGE_FAIL,fd_type,p_iter,message);
		if(!stream)
		{ // Stream messages, if logged, are logged in packet_removal after they send
			if(cycle == 0)
			{
				if(target_g > -1 || (first_owner == ENUM_OWNER_GROUP_PEER && group_pm))
					repeated = message_insert(fallback_g,group_n > -1 ? group_n : target_list[0],i); // repeated likely means resent message. No print, no insert.
				if(!repeated) // NOT else if, do not eliminate check
				{ // unique same time/nstime, so print and save
					message_new_cb(group_n > -1 ? group_n : target_list[0],i);
					sql_insert_message(group_n > -1 ? group_n : target_list[0],i); // This should go before setting .all_sent = 0, to ensure that it happens before send (which will trigger :sent: write)
				}
			}
			if(!repeated && target_g > -1) // MUST go after the first sql_insert_message call (which saves the message initially to GROUP_CTRL)
				sql_insert_message(target_list[cycle],iiii); // trigger save in each GROUP_PEER
		}
		if(send_prep(target_list[cycle],-1,iiii,p_iter,fd_type) == -1 && stream == ENUM_STREAM_DISCARDABLE) // NOT else if
		{ // delete unsuccessful discardable stream message
			error_printf(4,"Disgarding stream n=%d i=%d fd_type=%d protocol=%u",target_list[cycle],iiii,fd_type,protocol);
			torx_write(target_list[cycle]) // 🟥🟥🟥
			const int shrinkage = zero_i(target_list[cycle],iiii);
			torx_unlock(target_list[cycle]) // 🟩🟩🟩
			if(shrinkage)
				shrinkage_cb(target_list[cycle],shrinkage);
			if(target_g < 0)
				return INT_MIN; // WARNING: do not attempt to free. pointer is already pointing to bunk location after zero_i. will segfault. experimental 2024/03/09
		}
	}
	return i;
	error: {}
	#ifndef NO_FILE_TRANSFER
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
		section_unclaim(file_n,file_f,target_list[0],fd_type);
	#endif // NO_FILE_TRANSFER
	torx_free((void*)&message);
	return INT_MIN;
}

static inline int *generate_target_list(uint32_t *target_count,const int n)
{
	if(!target_count || n < 0)
	{
		error_simple(0,"Sanity check failed in generate_target_list. Coding error. Report this.");
		return NULL;
	}
	int *target_list;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL/* && group_msg*/)
	{
		const int g = set_g(n,NULL);
		if((*target_count = getter_group_uint32(g,offsetof(struct group_list,peercount))) < 1)
		{ // this isn't necessarily an error. this would be an OK place to bail out in some circumstances like broadcast messages
			error_simple(0,"Group has no users. Refusing to queue message. This is fine.");
			breakpoint();
			return NULL;
		}
		target_list = torx_insecure_malloc(sizeof(int)*(*target_count));
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
		for(uint32_t nn = 0; nn < *target_count; nn++)
			target_list[nn] = group[g].peerlist[nn];
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	}
	else
	{
		*target_count = 1;
		target_list = torx_insecure_malloc(sizeof(int)*(*target_count));
		target_list[0] = n;
	}
	return target_list;
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
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const char *name = protocols[p_iter].name;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t socket_swappable = protocols[p_iter].socket_swappable;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(!socket_swappable)
	{ // We shouldn't (and should have no purpose to) re-send non-swappable messages. Seeing this message likely indicates a UI coding error.
		error_printf(0,"message_resend cannot process the following message type because it is non-swappable: %s",name);
		return -1;
	}
	uint32_t target_count;
	int *target_list = generate_target_list(&target_count,n);
	if(!target_list)
		return -1;
	time_t time = 0;
	time_t nstime = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL && date_len && signature_len)
	{ // Keep the existing times (ie, resend only) only if its a group using signed && dated messages (ie private groups)
		torx_read(n) // 🟧🟧🟧
		time = peer[n].message[i].time;
		nstime = peer[n].message[i].nstime;
		torx_unlock(n) // 🟩🟩🟩
	}
	uint32_t message_len;
	char *message = getter_string(&message_len,n,i,-1,offsetof(struct message_list,message));
	message_distribute(1,target_count,target_list,p_iter,message,message_len,time,nstime);
	torx_free((void*)&message);
	torx_free((void*)&target_list);
	return 0;	
}

int message_send_select(const uint32_t target_count,const int *target_list,const uint16_t protocol,const void *arg,const uint32_t base_message_len)
{ // For GROUP_CTRL, it will first generate a peer list. XXX WARNING: if passing a target_count > 1, all targets MUST be GROUP_PEER from the SAME GROUP, or bad things will happen.
	if(!target_count || !target_list)
	{ // No need to goto end because we have no targets
		error_simple(0,"Target count or target list is zero/null. Coding error. Report this.");
		return INT_MIN;
	}
	int p_iter = -1; // must initialize so long as we have the error_printf that could use it
	uint8_t first_owner = 0; // must initialize so long as we have the error_printf that could use it
	if(protocol < 1 || (first_owner = getter_uint8(target_list[0],INT_MIN,-1,offsetof(struct peer_list,owner))) < 1 || (p_iter = protocol_lookup(protocol)) < 0)
	{
		error_printf(0,"message_send failed sanity check: %u %u %u %d. Coding error. Report this.",target_count,protocol,first_owner,p_iter);
		goto error;
	}
	else if(target_count == 1 && first_owner == ENUM_OWNER_GROUP_CTRL)
	{
		uint32_t new_target_count;
		int *new_target_list = generate_target_list(&new_target_count,target_list[0]);
		if(!new_target_list)
			goto error;
		const int ret = message_distribute(0,new_target_count,new_target_list,p_iter,arg,base_message_len,0,0); // i or INT_MIN upon error
		torx_free((void*)&new_target_list);
		return ret;
	}
	else if(target_count > 1)
		for(uint32_t cycle = 0; cycle < target_count; cycle++)
			if(getter_uint8(target_list[cycle],INT_MIN,-1,offsetof(struct peer_list,owner)) != ENUM_OWNER_GROUP_PEER)
			{ // TODO should also check that all peers are from the same group, but that is more expensive
				error_simple(0,"message_send_select was passed a multiple target list containing one or more non-GROUP_PEERs. The calling function should have utilized multiple calls to message_send instead. Coding error. Report this.");
				return INT_MIN;
			}
	return message_distribute(0,target_count,target_list,p_iter,arg,base_message_len,0,0); // i or INT_MIN upon error
	error: {}
	#ifndef NO_FILE_TRANSFER
	if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
	{ // Note: This should not occur, and if it does, it will only with target_count == 1
		const struct file_request_strc *file_request_strc = (const struct file_request_strc*) arg; // Casting passed struct
		section_unclaim(file_request_strc->n,file_request_strc->f,target_list[0],file_request_strc->fd_type);
	}
	#endif // NO_FILE_TRANSFER
	return INT_MIN;
}

int message_send(const int target_n,const uint16_t protocol,const void *arg,const uint32_t base_message_len)
{ // Should accept CTRL, GROUP_PEER, and GROUP_CTRL. To send a message to all members of a group, pass the group_n as target_n. The group_n will store the message but each peer will have copies of the time, protocol, status.
	return message_send_select(1,&target_n,protocol,arg,base_message_len);
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

void *peer_init(void *arg)
{ /* For sending an outgoing friend request */
	const int n = vptoi(arg);
	torx_write(n) // 🟥🟥🟥
	pusher(zero_pthread,(void*)&peer[n].thrd_send)
	torx_unlock(n) // 🟩🟩🟩
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	char suffixonion[56+6+1];
	getter_array(suffixonion,56,n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
	snprintf(&suffixonion[56],6+1,"%6s",".onion");
	const uint16_t vport = INIT_VPORT;
	setter(n,INT_MIN,-1,offsetof(struct peer_list,vport),&vport,sizeof(vport));
	char port_string[21];
	snprintf(port_string,sizeof(port_string),"%d",vport);
	evutil_socket_t proxyfd;
	while((proxyfd = socks_connect(suffixonion,port_string)) < 1) // this is blocking
		sleep(1); // not sure if necessary. could probably be eliminated or reduced without any ill effect
	char fresh_privkey[88+1] = {0};
	char *peernick = getter_string(NULL,n,INT_MIN,-1,offsetof(struct peer_list,peernick));
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
	getter_array(&buffer[2],56,fresh_n,INT_MIN,-1,offsetof(struct peer_list,onion));
	memcpy(&buffer[2+56],ed25519_pk,sizeof(ed25519_pk));
	listen(SOCKET_CAST_OUT proxyfd,1); // Maximum one connect at a time
	const ssize_t s = send(SOCKET_CAST_OUT proxyfd,buffer,sizeof(buffer),0); // this is blocking
	if(s < 0)
		error_simple(0,"Error writing to client socket. should probably try again?");
	else if(s != sizeof(buffer))
		error_printf(0,"Message only partially sent: %ld bytes. This probably means our peer will spoil their onion.",s);
	else // 2+56+32
	{ /* Good send, Expecting response */
		const ssize_t r = recv(SOCKET_CAST_OUT proxyfd,buffer,sizeof(buffer),0); // XXX BLOCKING
		do { // not a real while loop... just avoiding goto
			if(r >= (ssize_t) sizeof(buffer))
			{ // Correct sized reply
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
					char *peernick_fresh_n = getter_string(NULL,fresh_n,INT_MIN,-1,offsetof(struct peer_list,peernick));
					const int peer_index = sql_insert_peer(ENUM_OWNER_CTRL,ENUM_STATUS_FRIEND,fresh_peerversion,fresh_privkey,fresh_peeronion,peernick_fresh_n,0);
					setter(fresh_n,INT_MIN,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
					error_printf(3,"Outbound Handshake occured with %s who has freshonion %s",peernick,fresh_peeronion);
					torx_free((void*)&peernick_fresh_n);
					sodium_memzero(fresh_peeronion,sizeof(fresh_peeronion));
					sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
					sql_update_peer(fresh_n);
					load_onion(fresh_n);
					peer_new_cb(fresh_n);
				}
			}
			else
				error_printf(0,"Wrong sized init reply received from peer of length: %ld after sending length: %ld. Handshake failed.",r,s); //  Could consider deleting peer (no, because their onion could be a mult)
		} while(0);
		const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		takedown_onion(peer_index,1); // delete our PEER XXX after load_onion, otherwise we'll have zeros in our new onion's peernick
	}
	if(evutil_closesocket(proxyfd) < 0)
		error_simple(0,"Failed to close socket in peer_init.");
	torx_free((void*)&peernick);
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	sodium_memzero(buffer,sizeof(buffer));
	sodium_memzero(fresh_privkey,sizeof(fresh_privkey));
	sodium_memzero(suffixonion,sizeof(suffixonion));
	return 0;
}
