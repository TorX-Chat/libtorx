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

/*
	Helper functions for use on peer struct, group struct, packet struct, and child objects, to prevent data races on integers, with return size sanity checking.
*/
void breakpoint(void)
{ // Breakpoint for gdb
}

uint32_t getter_length(const int n,const int i,const int f,const size_t offset)
{ // Designed to be efficient, primarily for the UI to get things like message_len.
	if(n < 0 || (i > INT_MIN && f > -1) || !peer)
	{
		error_printf(-1,"getter_length sanity check failed: n=%d i=%d f=%d offset=%lu",n,i,f,offset);
		return 0;
	}
	uint32_t len = 0;
	torx_read(n) // 🟧🟧🟧
	if(i > INT_MIN)
	{
		if(offset == offsetof(struct message_list,message))
		{
			if(peer[n].message[i].message)
				len = torx_allocation_len(peer[n].message[i].message);
		}
		else
			error_printf(-1,"Invalid offset passed to getter_length1: %lu. Coding error. Report this.",offset);
	}
	else if(f > -1)
	{
		if(offset == offsetof(struct file_list,filename))
		{
			if(peer[n].file[f].filename)
				len = torx_allocation_len(peer[n].file[f].filename);
		}
		else if(offset == offsetof(struct file_list,file_path))
		{
			if(peer[n].file[f].file_path)
				len = torx_allocation_len(peer[n].file[f].file_path);
		}
		else if(offset == offsetof(struct file_list,split_path))
		{
			if(peer[n].file[f].split_path)
				len = torx_allocation_len(peer[n].file[f].split_path);
		}
		else
		{ // Handle arrays or error offsets
			if(offset == offsetof(struct file_list,checksum))
				len = sizeof(peer[n].file[f].checksum);
			else
				error_printf(-1,"Invalid offset passed to getter_length2: %lu. Coding error. Report this.",offset);
		}
	}
	else
	{
		if(offset == offsetof(struct peer_list,peernick))
		{
			if(peer[n].peernick)
				len = torx_allocation_len(peer[n].peernick);
		}
		else
		{ // Handle arrays or error offsets
			if(offset == offsetof(struct peer_list,privkey))
				len = sizeof(peer[n].privkey);
			else if(offset == offsetof(struct peer_list,onion))
				len = sizeof(peer[n].onion);
			else if(offset == offsetof(struct peer_list,torxid))
				len = sizeof(peer[n].torxid);
			else if(offset == offsetof(struct peer_list,peeronion))
				len = sizeof(peer[n].peeronion);
			else
				error_printf(-1,"Invalid offset passed to getter_length3: %lu. Coding error. Report this.",offset);
		}
	}
	torx_unlock(n) // 🟩🟩🟩
	return len;
}

char *getter_string(uint32_t *size,const int n,const int i,const int f,const size_t offset)
{ // XXX BEWARE: Message return is not guaranteed to be a string. Verify independantly (via null_terminated_len) before utilizing. // XXX Don't make use of this in library. This is primarily for use only in UI because it is inefficient (it copies). Be sure to torx_free((void*)&string);
	if(n < 0 || (i > INT_MIN && f > -1) || !peer)
	{
		error_printf(-1,"getter_string sanity check failed: n=%d i=%d f=%d offset=%lu",n,i,f,offset);
		if(size)
			*size = 0;
		return NULL;
	}
	uint32_t len = 0;
	char *string = NULL;
	torx_read(n) // 🟧🟧🟧
	if(i > INT_MIN)
	{
		if(offset == offsetof(struct message_list,message))
		{
			if(peer[n].message[i].message)
				string = torx_copy(&len,peer[n].message[i].message);
		}
		else
			error_printf(-1,"Invalid offset passed to getter_string1: %lu. Coding error. Report this.",offset);
	}
	else if(f > -1)
	{
		if(offset == offsetof(struct file_list,filename))
		{
			if(peer[n].file[f].filename)
				string = torx_copy(&len,peer[n].file[f].filename);
		}
		else if(offset == offsetof(struct file_list,file_path))
		{
			if(peer[n].file[f].file_path)
				string = torx_copy(&len,peer[n].file[f].file_path);
		}
		else if(offset == offsetof(struct file_list,split_path))
		{
			if(peer[n].file[f].split_path)
				string = torx_copy(&len,peer[n].file[f].split_path);
		}
		else
		{ // Handle arrays or error offsets
			if(offset == offsetof(struct file_list,checksum))
				len = sizeof(peer[n].file[f].checksum);
			else
				error_printf(-1,"Invalid offset passed to getter_string2: %lu. Coding error. Report this.",offset);
			string = torx_secure_malloc(len);
			memcpy(string,(char*)&peer[n] + offset,len);
		}
	}
	else
	{
		if(offset == offsetof(struct peer_list,peernick))
		{
			if(peer[n].peernick)
				string = torx_copy(&len,peer[n].peernick);
		}
		else
		{ // Handle arrays or error offsets
			if(offset == offsetof(struct peer_list,privkey))
				len = sizeof(peer[n].privkey);
			else if(offset == offsetof(struct peer_list,onion))
				len = sizeof(peer[n].onion);
			else if(offset == offsetof(struct peer_list,torxid))
				len = sizeof(peer[n].torxid);
			else if(offset == offsetof(struct peer_list,peeronion))
				len = sizeof(peer[n].peeronion);
			else
				error_printf(-1,"Invalid offset passed to getter_string3: %lu. Coding error. Report this.",offset);
			string = torx_secure_malloc(len);
			memcpy(string,(char*)&peer[n] + offset,len);
		}
	}
	torx_unlock(n) // 🟩🟩🟩
	if(size)
		*size = len;
	return string;
}

#define offsize(list,member,name) {offsetof(struct list,member),sizeof(((struct list*)0)->member),name}
struct offsets {
	const size_t offset;
	const size_t size;
	const char *name;
};
// For size of array (number of pages): sizeof(offsets_peer) / sizeof(struct offsets)
struct offsets offsets_peer[] = {
	#ifndef NO_AUDIO_CALL
	offsize(peer_list,audio_cache,"audio_cache"),
	offsize(peer_list,audio_time,"audio_time"),
	offsize(peer_list,audio_nstime,"audio_nstime"),
	offsize(peer_list,audio_last_retrieved_time,"audio_last_retrieved_time"),
	offsize(peer_list,audio_last_retrieved_nstime,"audio_last_retrieved_nstime"),
	offsize(peer_list,cached_recording,"cached_recording"),
	offsize(peer_list,cached_time,"cached_time"),
	offsize(peer_list,cached_nstime,"cached_nstime"),
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	offsize(peer_list,stickers_requested,"stickers_requested"),
	#endif // NO_STICKERS
	offsize(peer_list,owner,"owner"),
	offsize(peer_list,status,"status"),
	offsize(peer_list,privkey,"privkey"),
	offsize(peer_list,peer_index,"peer_index"),
	offsize(peer_list,onion,"onion"),
	offsize(peer_list,torxid,"torxid"),
	offsize(peer_list,peerversion,"peerversion"),
	offsize(peer_list,peeronion,"peeronion"),
	offsize(peer_list,peernick,"peernick"),
	offsize(peer_list,log_messages,"log_messages"),
	offsize(peer_list,last_seen,"last_seen"),
	offsize(peer_list,vport,"vport"),
	offsize(peer_list,tport,"tport"),
	offsize(peer_list,socket_utilized,"socket_utilized"),
	offsize(peer_list,sendfd,"sendfd"),
	offsize(peer_list,recvfd,"recvfd"),
	offsize(peer_list,sendfd_connected,"sendfd_connected"),
	offsize(peer_list,recvfd_connected,"recvfd_connected"),
	offsize(peer_list,bev_send,"bev_send"),
	offsize(peer_list,bev_recv,"bev_recv"),
	offsize(peer_list,max_i,"max_i"),
	offsize(peer_list,min_i,"min_i"),
	offsize(peer_list,sign_sk,"sign_sk"),
	offsize(peer_list,peer_sign_pk,"peer_sign_pk"),
	offsize(peer_list,invitation,"invitation"),
	offsize(peer_list,blacklisted,"blacklisted"),
	offsize(peer_list,broadcasts_inbound,"broadcasts_inbound")
};

struct offsets offsets_message[] = {
	offsize(message_list,time,"time"),
	offsize(message_list,fd_type,"fd_type"),
	offsize(message_list,stat,"stat"),
	offsize(message_list,p_iter,"p_iter"),
	offsize(message_list,message,"message"),
	offsize(message_list,pos,"pos"),
	offsize(message_list,nstime,"nstime")
};

struct offsets offsets_file[] = {
	offsize(file_list,checksum,"checksum"),
	offsize(file_list,filename,"filename"),
	offsize(file_list,file_path,"file_path"),
	offsize(file_list,size,"size"),
	offsize(file_list,modified,"modified"),
	offsize(file_list,splits,"splits"),
	offsize(file_list,split_path,"split_path"),
	offsize(file_list,split_progress,"split_progress"),
	offsize(file_list,split_status_n,"split_status_n"),
	offsize(file_list,split_status_fd,"split_status_fd"),
	offsize(file_list,split_status_req,"split_status_req"),
	offsize(file_list,split_hashes,"split_hashes"),
	offsize(file_list,fd,"fd"),
	offsize(file_list,last_progress_update_time,"last_progress_update_time"),
	offsize(file_list,last_progress_update_nstime,"last_progress_update_nstime"),
	offsize(file_list,bytes_per_second,"bytes_per_second"),
	offsize(file_list,last_transferred,"last_transferred"),
	offsize(file_list,time_left,"time_left"),
	offsize(file_list,speed_iter,"speed_iter"),
	offsize(file_list,last_speeds,"last_speeds")
};

struct offsets offsets_group[] = {
	offsize(group_list,id,"id"),
	offsize(group_list,n,"n"),
	offsize(group_list,hash,"hash"),
	offsize(group_list,peercount,"peercount"),
	offsize(group_list,msg_count,"msg_count"),
	offsize(group_list,peerlist,"peerlist"),
	offsize(group_list,invite_required,"invite_required"),
	offsize(group_list,msg_first,"msg_first"),
	offsize(group_list,msg_last,"msg_last")
};

struct offsets offsets_packet[] = {
	offsize(packet_info,n,"n"),
	offsize(packet_info,f_i,"f_i"),
	offsize(packet_info,packet_len,"packet_len"),
	offsize(packet_info,p_iter,"p_iter"),
	offsize(packet_info,fd_type,"fd_type")
};

struct offsets offsets_protocols[] = {
	offsize(protocol_info,protocol,"protocol"),
	offsize(protocol_info,name,"name"),
	offsize(protocol_info,description,"description"),
	offsize(protocol_info,null_terminated_len,"null_terminated_len"),
	offsize(protocol_info,date_len,"date_len"),
	offsize(protocol_info,signature_len,"signature_len"),
	offsize(protocol_info,logged,"logged"),
	offsize(protocol_info,notifiable,"notifiable"),
	offsize(protocol_info,file_checksum,"file_checksum"),
	offsize(protocol_info,group_pm,"group_pm"),
	offsize(protocol_info,group_msg,"group_msg"),
	offsize(protocol_info,socket_swappable,"socket_swappable"),
	offsize(protocol_info,utf8,"utf8"),
	offsize(protocol_info,file_offer,"file_offer"),
	offsize(protocol_info,group_mechanics,"group_mechanics"),
	offsize(protocol_info,stream,"stream")
};

struct offsets offsets_broadcasts[] = {
	offsize(broadcasts_list,hash,"hash"),
	offsize(broadcasts_list,broadcast,"broadcast"),
	offsize(broadcasts_list,peers,"peers")
};

#ifndef NO_AUDIO_CALL
struct offsets offsets_call[] = {
	offsize(call_list,joined,"joined"),
	offsize(call_list,waiting,"waiting"),
	offsize(call_list,mic_on,"mic_on"),
	offsize(call_list,speaker_on,"speaker_on"),
	offsize(call_list,start_time,"start_time"),
	offsize(call_list,start_nstime,"start_nstime"),
	offsize(call_list,participating,"participating"),
	offsize(call_list,participant_mic,"participant_mic"),
	offsize(call_list,participant_speaker,"participant_speaker")
};
#endif // NO_AUDIO_CALL

#ifndef NO_STICKERS
struct offsets offsets_sticker[] = {
	offsize(sticker_list,checksum,"checksum"),
	offsize(sticker_list,peers,"peers"),
	offsize(sticker_list,data,"data"),
	offsize(sticker_list,saved,"saved")
};
#endif // NO_STICKERS

unsigned char *getter_group_id(const int g)
{
	if(g < 0)
	{
		error_simple(-1,"Negative g passed to getter_group_id. Coding error. Report this.");
		return NULL;
	}
	unsigned char *id = torx_secure_malloc(GROUP_ID_SIZE);
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	memcpy(id,group[g].id,GROUP_ID_SIZE);
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return id;
}

void *group_access(const int g,const size_t offset)
{
	if(g < 0)
	{
		error_simple(-1,"Negative g passed to group_access. Coding error. Report this.");
		return NULL;
	}
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	void *ret = (char*)&group[g] + offset;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return ret;
}

void *group_get_next(int *n,int *i,const void *arg)
{
	if(!n || !i || arg == NULL)
		return NULL;
	const struct msg_list *page = (const struct msg_list *) arg;
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	*n = page->n;
	*i = page->i;
	void *next = page->message_next;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return next;
}

void *group_get_prior(int *n,int *i,const void *arg)
{
	if(!n || !i || arg == NULL)
		return NULL;
	const struct msg_list *page = (const struct msg_list *) arg;
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	*n = page->n;
	*i = page->i;
	void *prior = page->message_prior;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return prior;
}

void group_get_index(int *n,int *i,const int g,const uint32_t index)
{
	if(!n || !i || g < 0)
	{
		error_simple(-1,"group_get_index failed sanity check. Coding error. Report this.");
		return;
	}
	struct msg_list *current_page = NULL;
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	const uint32_t diff_msg_count = (const uint32_t)labs((long int)index - (long int)group[g].msg_count-1);
	const uint32_t diff_msg_index_iter = (const uint32_t)labs((long int)index - (long int)group[g].msg_index_iter);
	if(index <= diff_msg_count && index <= diff_msg_index_iter)
	{ // start from 0 (start from msg_first)
		current_page = group[g].msg_first;
		for(uint32_t iter = 0; current_page && iter != index ; iter++)
			current_page = current_page->message_next;
	}
	else if(diff_msg_count <= diff_msg_index_iter)
	{ // start from group[g].msg_count (start from msg_last)
		current_page = group[g].msg_last;
		for(uint32_t iter = group[g].msg_count-1; current_page && iter != index ; iter--)
			current_page = current_page->message_prior;
	}
	else
	{ // start from group[g].msg_index_iter (start from last lookup, to reduce calculations during scrolling)
		current_page = group[g].msg_index;
		if(index < group[g].msg_index_iter)
			for(uint32_t iter = group[g].msg_index_iter; current_page && iter != index ; iter--)
				current_page = current_page->message_prior;
		else
			for(uint32_t iter = group[g].msg_index_iter; current_page && iter != index ; iter++)
				current_page = current_page->message_next;
	}
	if(current_page)
	{
		*n = current_page->n;
		*i = current_page->i;
	}
	else
	{ // treat failure as non-fatal for now
		error_simple(0,"A non-existant index was requested from group_get_index. Possible coding error. Report this.");
		*n = *i = 0;
	}
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
}

void *protocol_access(const int p_iter,const size_t offset)
{
	if(p_iter < 0)
	{
		error_simple(-1,"Negative p_iter passed to protocol_access. Coding error. Report this.");
		return NULL;
	}
	return (char*)&protocols[p_iter] + offset;
}

#define getter_offset_sanity_check(offsets_struc) /* Cannot be converted to function */ \
{ \
	const size_t pages = sizeof(offsets_struc) / sizeof(struct offsets); \
	while(iter < pages && strcmp(offsets_struc[iter].name,member)) \
		iter++; \
	if(iter == pages) \
		error_printf(-1,"Illegal offset name: %s. Coding error. Report this.",member); \
	if(strcmp(offsets_struc[iter].name,member)) \
		error_printf(-1,"Illegal getter return value for member: %s. Coding error. Report this.",member); \
}

#define getter_offset_return_size(offsets_struc) /* Cannot be converted to function */ \
{ \
	size_t iter = 0; \
	getter_offset_sanity_check(offsets_struc) \
	return offsets_struc[iter].size; \
}

size_t getter_size(const char *parent,const char *member)
{ // Returns size of a member. You may be looking for getter_length instead.
	if(!parent || !member)
	{
		error_simple(-1,"getter_size fail. Coding error. Report this.");
		return 0;
	}
	if(!strcmp(parent,"protocols"))
		getter_offset_return_size(offsets_protocols)
	else if(!strcmp(parent,"peer"))
		getter_offset_return_size(offsets_peer)
	else if(!strcmp(parent,"message"))
		getter_offset_return_size(offsets_message)
	else if(!strcmp(parent,"file"))
		getter_offset_return_size(offsets_file)
	else if(!strcmp(parent,"group"))
		getter_offset_return_size(offsets_group)
	else if(!strcmp(parent,"packet"))
		getter_offset_return_size(offsets_packet)
	else if(!strcmp(parent,"broadcasts"))
		getter_offset_return_size(offsets_broadcasts)
	#ifndef NO_AUDIO_CALL
	else if(!strcmp(parent,"call"))
		getter_offset_return_size(offsets_call)
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	else if(!strcmp(parent,"sticker"))
		getter_offset_return_size(offsets_sticker)
	#endif // NO_STICKERS
	error_printf(-1,"getter_size fail. Coding error. Report this. Parent: %s Member: %s",parent,member);
	return 0;
}

#define getter_offset_return_offset(offsets_struc) /* Cannot be converted to function */ \
{ \
	size_t iter = 0; \
	getter_offset_sanity_check(offsets_struc); \
	return offsets_struc[iter].offset; \
}

size_t getter_offset(const char *parent,const char *member)
{ // Returns offset of a member
	if(!parent || !member)
	{
		error_simple(-1,"getter_offset sanity check fail. Coding error. Report this.");
		return 0;
	}
	if(!strcmp(parent,"protocols"))
		getter_offset_return_offset(offsets_protocols)
	else if(!strcmp(parent,"peer"))
		getter_offset_return_offset(offsets_peer)
	else if(!strcmp(parent,"message"))
		getter_offset_return_offset(offsets_message)
	else if(!strcmp(parent,"file"))
		getter_offset_return_offset(offsets_file)
	else if(!strcmp(parent,"group"))
		getter_offset_return_offset(offsets_group)
	else if(!strcmp(parent,"packet"))
		getter_offset_return_offset(offsets_packet)
	else if(!strcmp(parent,"broadcasts"))
		getter_offset_return_offset(offsets_broadcasts)
	#ifndef NO_AUDIO_CALL
	else if(!strcmp(parent,"call"))
		getter_offset_return_offset(offsets_call)
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	else if(!strcmp(parent,"sticker"))
		getter_offset_return_offset(offsets_sticker)
	#endif // NO_STICKERS
	error_printf(-1,"getter_offset fail. Coding error. Report this. Parent: %s Member: %s",parent,member);
	return 0;
}

char getter_byte(const int n,const int i,const int f,const size_t offset)
{ // WARNING: This gets a single byte, without doing any sanity checks that would occur on an integer. I hate this function, but it serves a purpose.
	char value;
	if(n < 0 || (i > INT_MIN && f > -1))
	{
		error_printf(-1,"getter byte sanity check failed at offset: %lu",offset);
		return 0;
	}
	else if(!peer)
		return 0;
	torx_read(n) // 🟧🟧🟧
	if(i > INT_MIN)
		memcpy(&value,(char*)&peer[n].message[i] + offset,sizeof(value));
	else if(f > -1)
		memcpy(&value,(char*)&peer[n].file[f] + offset,sizeof(value));
	else
		memcpy(&value,(char*)&peer[n] + offset,sizeof(value));
	torx_unlock(n) // 🟩🟩🟩
	return value;
}

#define getter_array_sanity_check(offsets_struc) /* Cannot be converted to function */ \
	const size_t pages = sizeof(offsets_struc) / sizeof(struct offsets);\
	size_t iter = 0;\
	while(iter < pages && offset != offsets_struc[iter].offset)\
		iter++;\
	if(iter == pages)\
		error_printf(-1,"Illegal offset: %lu. Coding error. Report this.2",offset);\
	if(offset == offsetof(struct message_list,message))\
	{\
		const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);\
		if(message_len < size)\
			error_printf(-1,"Illegal getter return value at offset %lu. Coding error. Report this.2 %lu < %lu",offset,offsets_struc[iter].size,size);\
	}\
	else if(offsets_struc[iter].size < size)\
		error_printf(-1,"Illegal getter return value at offset %lu. Coding error. Report this.3 %lu < %lu",offset,offsets_struc[iter].size,size);

void getter_array(void *array,const size_t size,const int n,const int i,const int f,const size_t offset)
{ // Be careful on size. Could actually use this on integers, not just arrays. It needs re-writing and better sanity checks. See getter_string as an example.
	if(n < 0 || (i > INT_MIN && f > -1) || size < 1 || array == NULL)
	{
		if(array)
			sodium_memzero(array,size); // zero the target
		error_printf(-1,"getter_array sanity check failed at offset: %lu",offset);
		return;
	}
	else if(!peer) // can occur during shutdown
		return;
	if(i > INT_MIN)
	{
		getter_array_sanity_check(offsets_message)
		torx_read(n) // 🟧🟧🟧
		if(offset == offsetof(struct message_list,message))
		{
			const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);
			if(message_len < size) // XXX Good example of a sanity check. Need to implement elsewhere in this function, when accessing pointers.
				memcpy(array,peer[n].message[i].message,message_len);
			else
				memcpy(array,peer[n].message[i].message,size);
		}
		else
			memcpy(array,(char*)&peer[n].message[i] + offset,size);
	}
	else if(f > -1)
	{
		getter_array_sanity_check(offsets_file)
		torx_read(n) // 🟧🟧🟧
		if(offset == offsetof(struct file_list,filename)) // TODO This WILL NOT WORK because getter_array_sanity_check will return a maximum size of 8. Need to implement proper length checks.
			memcpy(array,peer[n].file[f].filename,size);
		else if(offset == offsetof(struct file_list,file_path)) // TODO This WILL NOT WORK because getter_array_sanity_check will return a maximum size of 8. Need to implement proper length checks.
			memcpy(array,peer[n].file[f].file_path,size);
		else
			memcpy(array,(char*)&peer[n].file[f] + offset,size);
	}
	else
	{
		getter_array_sanity_check(offsets_peer)
		torx_read(n) // 🟧🟧🟧
		memcpy(array,(char*)&peer[n] + offset,size);
	}
	torx_unlock(n) // 🟩🟩🟩
}

#define getter_sanity_check(offsets_struc) /* Cannot be converted to function */ \
	const size_t pages = sizeof(offsets_struc) / sizeof(struct offsets);\
	size_t iter = 0;\
	while(iter < pages && offset != offsets_struc[iter].offset)\
		iter++;\
	if(iter == pages)\
		error_printf(-1,"Illegal offset. Coding error. Report this.");\
	if(offsets_struc[iter].size != anticipated_size)\
		error_printf(-1,"Illegal getter return value for member: %s. Coding error. Report this. %lu != %lu",offsets_struc[iter].name,offsets_struc[iter].size,anticipated_size);

static inline union types getter_peer_union(const int n,const int i,const int f,const size_t offset,const size_t anticipated_size)
{
	union types value = {0}; // Initialize as 0
	if(n < 0 || (i > INT_MIN && f > -1))
	{
		error_printf(-1,"getter sanity check failed at offset: %lu",offset);
		return value;
	}
	else if(!peer)
		return value;
	if(i > INT_MIN)
	{
		getter_sanity_check(offsets_message)
		torx_read(n)
		memcpy(&value,(char*)&peer[n].message[i] + offset,anticipated_size);
	}
	else if(f > -1)
	{
		getter_sanity_check(offsets_file)
		torx_read(n)
		memcpy(&value,(char*)&peer[n].file[f] + offset,anticipated_size);
	}
	else
	{
		getter_sanity_check(offsets_peer)
		torx_read(n)
		memcpy(&value,(char*)&peer[n] + offset,anticipated_size);
	}
	torx_unlock(n)
	return value;
}

int8_t getter_int8(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int8_t)).int8;
}

int16_t getter_int16(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int16_t)).int16;
}

int32_t getter_int32(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int32_t)).int32;
}

int64_t getter_int64(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int64_t)).int64;
}

uint8_t getter_uint8(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(uint8_t)).uint8;
}

uint16_t getter_uint16(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int16_t)).uint16;
}

uint32_t getter_uint32(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(uint32_t)).uint32;
}

uint64_t getter_uint64(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(uint64_t)).uint64;
}

int getter_int(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(int)).integer;
}

time_t getter_time(const int n,const int i,const int f,const size_t offset)
{
	return getter_peer_union(n,i,f,offset,sizeof(time_t)).time;
}

void setter(const int n,const int i,const int f,const size_t offset,const void *value,const size_t size)
{ /* Suitable for ALL datatypes (string, int, void*, NULL, etc). Note: The (char*) is necessary because otherwise the offset is treated as an addition to the iterator: &peer[n+offset]. https://www.iso-9899.info/n1570.html#6.5.2.1p2
     Integer Usage:
	int8_t value = 69;
	setter(1,INT_MIN,-1,offsetof(struct peer_list,v3auth),&value,sizeof(value));
     Array Usage:
	char onion[56+1] = "hello i am a fish";
	setter(1,INT_MIN,-1,offsetof(struct peer_list,onion),&onion,sizeof(onion));
    Pointer Usage (pointer as argument): XXX do not use & argument is a pointer. THIS ERROR WILL NOT BE DETECTED BY COMPILER.
	char *onion = "hello i am a fish";
	setter(1,INT_MIN,-1,offsetof(struct peer_list,onion),onion,sizeof(onion));
    Pointer Usage (target):
	not utilized so far / not tested / not sure
*/
	if(n < 0 || (i > INT_MIN && f > -1) || size < 1 || value == NULL)
	{
		error_printf(-1,"setter sanity check failed at offset: %lu sanity: %d %d %d",offset,n,i,f);
		return;
	}
	else if(!peer) // can occur during shutdown
		return;
	if(i > INT_MIN)
	{
		getter_array_sanity_check(offsets_message)
		torx_write(n) // 🟥🟥🟥
		memcpy((char*)&peer[n].message[i] + offset,value,size);
	}
	else if(f > -1)
	{
		getter_array_sanity_check(offsets_file)
		torx_write(n) // 🟥🟥🟥
		memcpy((char*)&peer[n].file[f] + offset,value,size);
	}
	else
	{
		getter_array_sanity_check(offsets_peer)
		torx_write(n) // 🟥🟥🟥
		memcpy((char*)&peer[n] + offset,value,size);
	}
	torx_unlock(n) // 🟩🟩🟩
}

/* XXX The following is for group struct only XXX */

static inline union types getter_group_union(const int g,const size_t offset,const size_t anticipated_size)
{
	union types value = {0}; // Initialize as 0
	if(g < 0)
	{
		error_printf(-1,"getter_group sanity check failed at offset: %lu",offset);
		return value;
	}
	else if(!group)
		return value;
	getter_sanity_check(offsets_group)
	pthread_rwlock_rdlock(&mutex_expand_group);
	memcpy(&value,(char*)&group[g] + offset,anticipated_size);
	pthread_rwlock_unlock(&mutex_expand_group);
	return value;
}

int8_t getter_group_int8(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(int8_t)).int8;
}

int16_t getter_group_int16(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(int16_t)).int16;
}

int32_t getter_group_int32(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(int32_t)).int32;
}

int64_t getter_group_int64(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(int64_t)).int64;
}

uint8_t getter_group_uint8(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(uint8_t)).uint8;
}

uint16_t getter_group_uint16(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(uint16_t)).uint16;
}

uint32_t getter_group_uint32(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(uint32_t)).uint32;
}

uint64_t getter_group_uint64(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(uint64_t)).uint64;
}

int getter_group_int(const int g,const size_t offset)
{
	return getter_group_union(g,offset,sizeof(int)).integer;
}

#define getter_group_array_sanity_check(offsets_struc) /* Cannot be converted to function */ \
	const size_t pages = sizeof(offsets_struc) / sizeof(struct offsets);\
	size_t iter = 0;\
	while(iter < pages && offset != offsets_struc[iter].offset)\
		iter++;\
	if(iter == pages)\
		error_printf(-1,"Illegal offset: %lu. Coding error. Report this.6",offset);\
	if(offsets_struc[iter].size < size)\
		error_printf(-1,"Illegal getter return value at offset %lu. Coding error. Report this.7 %lu < %lu",offset,offsets_struc[iter].size,size);

void setter_group(const int g,const size_t offset,const void *value,const size_t size)
{ /* Suitable for ALL datatypes (string, int, void*, NULL, etc). Note: The (char*) is necessary because otherwise the offset is treated as an addition to the iterator: &group[g+offset]. https://www.iso-9899.info/n1570.html#6.5.2.1p2
     Integer Usage:
	uint32_t value = 69;
	setter_group(g,offsetof(struct group_list,n),&value,sizeof(value));
*/
	if(g < 0 || size < 1 || value == NULL)
	{
		error_printf(-1,"setter_group sanity check failed at offset: %lu",offset);
		return;
	}
	else if(!group) // can occur during shutdown
		return;
	getter_group_array_sanity_check(offsets_group)
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	memcpy((char*)&group[g] + offset,value,size);
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
}

/* XXX The following are ONLY SAFE ON packet struct and global variables because of their fixed size / location XXX */

static inline union types getter_global_union(pthread_rwlock_t *mutex,const void *arg,const size_t anticipated_size)
{
	union types value = {0}; // Initialize as 0
	if(!arg || !mutex || !anticipated_size)
	{
		error_simple(-1,"getter_global_union sanity check failed");
		return value;
	}
	pthread_rwlock_rdlock(mutex);
	memcpy(&value, arg, anticipated_size);
	pthread_rwlock_unlock(mutex);
	return value;
}

int8_t threadsafe_read_int8(pthread_rwlock_t *mutex,const int8_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(int8_t)).int8;
}

int16_t threadsafe_read_int16(pthread_rwlock_t *mutex,const int16_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(int16_t)).int16;
}

int32_t threadsafe_read_int32(pthread_rwlock_t *mutex,const int32_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(int32_t)).int32;
}

int64_t threadsafe_read_int64(pthread_rwlock_t *mutex,const int64_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(int64_t)).int64;
}

uint8_t threadsafe_read_uint8(pthread_rwlock_t *mutex,const uint8_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(uint8_t)).uint8;
}

uint16_t threadsafe_read_uint16(pthread_rwlock_t *mutex,const uint16_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(uint16_t)).uint16;
}

uint32_t threadsafe_read_uint32(pthread_rwlock_t *mutex,const uint32_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(uint32_t)).uint32;
}

uint64_t threadsafe_read_uint64(pthread_rwlock_t *mutex,const uint64_t *arg)
{
	return getter_global_union(mutex,arg,sizeof(uint64_t)).uint64;
}

int threadsafe_read_int(pthread_rwlock_t *mutex,const int *arg)
{
	return getter_global_union(mutex,arg,sizeof(int)).integer;
}

void threadsafe_write(pthread_rwlock_t *mutex,void *destination,const void *source,const size_t len)
{
	if(!mutex || !destination || !source || !len)
	{
		error_simple(-1,"threadsafe_write sanity check failed");
		return;
	}
	pthread_rwlock_wrlock(mutex); // 🟥
	memcpy(destination,source,len);
	pthread_rwlock_unlock(mutex); // 🟩
}
