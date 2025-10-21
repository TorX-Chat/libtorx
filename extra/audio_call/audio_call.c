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

void (*initialize_peer_call_registered)(const int call_n,const int call_c) = NULL;
void (*expand_call_struc_registered)(const int call_n,const int call_c) = NULL;
void (*call_update_registered)(const int call_n,const int call_c) = NULL;
void (*audio_cache_add_registered)(const int participant_n) = NULL;

uint8_t default_participant_mic = 1; // default, enabled
uint8_t default_participant_speaker = 1; // default, enabled

void initialize_peer_call_setter(void (*callback)(int,int))
{
	if(initialize_peer_call_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_peer_call_registered = callback;
}
void expand_call_struc_setter(void (*callback)(int,int))
{
	if(expand_call_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_call_struc_registered = callback;
}
void call_update_setter(void (*callback)(int,int))
{
	if(call_update_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		call_update_registered = callback;
}
void audio_cache_add_setter(void (*callback)(int))
{
	if(audio_cache_add_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		audio_cache_add_registered = callback;
}
void initialize_peer_call_cb(const int call_n,const int call_c)
{
	if(initialize_peer_call_registered)
		initialize_peer_call_registered(call_n,call_c);
}
void expand_call_struc_cb(const int call_n,const int call_c)
{
	if(expand_call_struc_registered)
		expand_call_struc_registered(call_n,call_c);
}
void call_update_cb(const int call_n,const int call_c)
{
	if(call_update_registered)
		call_update_registered(call_n,call_c);
}
void audio_cache_add_cb(const int participant_n)
{
	if(audio_cache_add_registered)
		audio_cache_add_registered(participant_n);
}

static inline int8_t call_invalid(const int call_n,const int call_c)
{ // Simply checks whether call_n and call_c are of an existing call. Do not use between locks.
	int8_t ret = 0;
	if(call_n < 0 || call_c < 0)
		ret = -1;
	else
	{
		torx_read(call_n) // 🟧🟧🟧
		if((size_t)call_c >= torx_allocation_len(peer[call_n].call)/sizeof(struct call_list) || (peer[call_n].call[call_c].start_time == 0 && peer[call_n].call[call_c].start_nstime == 0))
			ret = -1; // Do not change order
		torx_unlock(call_n) // 🟩🟩🟩
	}
	if(ret)
		error_printf(-1,"Call sanity check failed. call_n=%d call_c=%d",call_n,call_c);
	return ret;
}

static inline int call_participant_iter_by_n(const int call_n, const int call_c,const int participant_n) // XXX do not put locks in here
{ // XXX WARNING: Returns -1 upon error (participant not in call). Be sure to handle. Mainly used for threadsafe_ functions that rely upon participant_iter.
	size_t iter = 0;
	for( ; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) ; iter++)
		if(peer[call_n].call[call_c].participating[iter] == participant_n)
			break;
	if(iter == torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int))
		return -1; // No such peer in call
	return (int)iter; // Peer is in call
}

static inline union types getter_call_union(const int call_n,const int call_c,const int participant_n,const size_t offset,const size_t anticipated_size)
{ // This can be used directly in C and Dart, but it's safer not to because of potential for errors on return sizes.
	union types types = {0}; // Initialize as 0
	if(call_invalid(call_n,call_c) || (participant_n > -1 && (offset != offsetof(struct call_list,participant_mic) && offset != offsetof(struct call_list,participant_speaker))))
	{
		error_printf(-1,"getter_call_union sanity check failed: call_n=%d call_c=%d participant_n=%d offset=%lu",call_n,call_c,participant_n,offset);
		return types;
	}
	torx_read(call_n) // 🟧🟧🟧
	if(participant_n > -1)
	{
		const int iter = call_participant_iter_by_n(call_n,call_c,participant_n);
		if(iter < 0)
		{ // Necessary sanity check
			torx_unlock(call_n) // 🟩🟩🟩
			error_simple(-1,"getter_call_union sanity check due to negative iter. Coding error. Report this.");
			return types;
		}
		if(offset == offsetof(struct call_list,participant_mic) && sizeof(uint8_t) == anticipated_size)
			types.uint8 = peer[call_n].call[call_c].participant_mic[iter];
		else if(offset == offsetof(struct call_list,participant_speaker) && sizeof(uint8_t) == anticipated_size)
			types.uint8 = peer[call_n].call[call_c].participant_speaker[iter];
	}
	else if(offset == offsetof(struct call_list,joined) && sizeof(uint8_t) == anticipated_size)
		types.uint8 = peer[call_n].call[call_c].joined;
	else if(offset == offsetof(struct call_list,waiting) && sizeof(uint8_t) == anticipated_size)
		types.uint8 = peer[call_n].call[call_c].waiting;
	else if(offset == offsetof(struct call_list,mic_on) && sizeof(uint8_t) == anticipated_size)
		types.uint8 = peer[call_n].call[call_c].mic_on;
	else if(offset == offsetof(struct call_list,speaker_on) && sizeof(uint8_t) == anticipated_size)
		types.uint8 = peer[call_n].call[call_c].speaker_on;
	else if(offset == offsetof(struct call_list,start_time) && sizeof(time_t) == anticipated_size)
		types.time = peer[call_n].call[call_c].start_time;
	else if(offset == offsetof(struct call_list,start_nstime) && sizeof(time_t) == anticipated_size)
		types.time = peer[call_n].call[call_c].start_nstime;
	else
	{
		torx_unlock(call_n) // 🟩🟩🟩
		error_simple(-1,"getter_call_union sanity check due to bad offset. Coding error. Report this.");
		return types;
	}
	torx_unlock(call_n) // 🟩🟩🟩
	return types;
}

uint8_t getter_call_uint8(const int call_n,const int call_c,const int participant_n,const size_t offset)
{
	return getter_call_union(call_n,call_c,participant_n,offset,sizeof(uint8_t)).uint8;
}

time_t getter_call_time(const int call_n,const int call_c,const int participant_n,const size_t offset)
{
	return getter_call_union(call_n,call_c,participant_n,offset,sizeof(time_t)).time;
}

int set_c(const int call_n,const time_t time,const time_t nstime)
{ // XXX -1 is error. Be sure to accomodate.
	if(call_n < 0 || (!time && !nstime))
	{
		error_simple(0,"set_c failed sanity check. Coding error. Report this.");
		return -1;
	}
	int call_c;
	torx_read(call_n) // 🟧🟧🟧
	for(call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
		if(peer[call_n].call[call_c].start_time == time && peer[call_n].call[call_c].start_nstime == nstime)
		{
			torx_unlock(call_n) // 🟩🟩🟩
			return call_c; // found existing match
		}
	for(call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
		if(peer[call_n].call[call_c].start_time == 0 && peer[call_n].call[call_c].start_nstime == 0)
			break; // found an empty slot
	torx_unlock(call_n) // 🟩🟩🟩
	uint8_t expanded = 0;
	torx_write(call_n) // 🟥🟥🟥
	if((size_t)call_c == torx_allocation_len(peer[call_n].call)/sizeof(struct call_list))
	{ // Note: both may be 0
		if(peer[call_n].call)
			peer[call_n].call = torx_realloc(peer[call_n].call, torx_allocation_len(peer[call_n].call) + sizeof(struct call_list));
		else
			peer[call_n].call = torx_insecure_malloc(sizeof(struct call_list));
		initialize_peer_call(call_n,call_c);
		expanded = 1;
	}
	peer[call_n].call[call_c].start_time = time;
	peer[call_n].call[call_c].start_nstime = nstime;
	torx_unlock(call_n) // 🟩🟩🟩
	if(expanded) // must be outside locks
	{
		expand_call_struc_cb(call_n,call_c);
		initialize_peer_call_cb(call_n,call_c);
	}
	return call_c;
}

static inline int *call_refined_list(uint32_t *refined_count,const int call_n,const int call_c,const uint8_t mic_check)
{ // Internal function only. Use call_recipient_list / call_participant_list
	if(call_invalid(call_n,call_c))
	{
		if(refined_count)
			*refined_count = 0;
		return NULL;
	}
	uint32_t count = 0;
	torx_read(call_n) // 🟧🟧🟧
	int tmp_list[torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int)]; // not sensitive
	if(!mic_check || peer[call_n].call[call_c].mic_on)
		for(size_t iter = 0 ; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) ; iter++)
			if(peer[call_n].call[call_c].participating[iter] > -1 && (!mic_check || peer[call_n].call[call_c].participant_mic[iter]))
				tmp_list[count++] = peer[call_n].call[call_c].participating[iter];
	torx_unlock(call_n) // 🟩🟩🟩
	if(refined_count)
		*refined_count = count; // Note: May return 0
	int *final_list = torx_insecure_malloc(count * sizeof(int)); // Note: May return NULL
	if(final_list) // must check
		memcpy(final_list,tmp_list,count * sizeof(int));
	return final_list;
}

int *call_recipient_list(uint32_t *recipient_count,const int call_n,const int call_c)
{ // Returns a refined list which excludes -1 (peers who left) and those with mic off. Mainly for use with message_send_select. Note that the iter will be different than that in ].participating[
	return call_refined_list(recipient_count,call_n,call_c,1);
}

int *call_participant_list(uint32_t *participant_count,const int call_n,const int call_c)
{ // Returns a refined list which excludes -1 (peers who left). Note that the iter will be different than that in ].participating[
	return call_refined_list(participant_count,call_n,call_c,0);
}

void initialize_peer_call(const int call_n,const int call_c) // XXX do not put locks in here
{
	if(call_n < 0 || call_c < 0 || (size_t)call_c >= torx_allocation_len(peer[call_n].call)/sizeof(struct call_list))
	{
		error_simple(0,"Sanity check failed in initialize_peer_call. Coding error. Report this.");
		return;
	}
	peer[call_n].call[call_c].joined = 0;
	peer[call_n].call[call_c].waiting = 0;
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	peer[call_n].call[call_c].mic_on = default_participant_mic;
	peer[call_n].call[call_c].speaker_on = default_participant_speaker;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	peer[call_n].call[call_c].start_time = 0;
	peer[call_n].call[call_c].start_nstime = 0;
	if(peer[call_n].call[call_c].participating == NULL)
	{ // Must malloc otherwise realloc won't know how to handle it
		peer[call_n].call[call_c].participating = torx_insecure_malloc(sizeof(int));
		peer[call_n].call[call_c].participant_mic = torx_insecure_malloc(sizeof(uint8_t));
		peer[call_n].call[call_c].participant_speaker = torx_insecure_malloc(sizeof(uint8_t));
	}
	for(size_t iter = 0 ; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) ; iter++)
	{ // Initialize the participant n and settings
		peer[call_n].call[call_c].participating[iter] = -1;
		peer[call_n].call[call_c].participant_mic[iter] = peer[call_n].call[call_c].mic_on;
		peer[call_n].call[call_c].participant_speaker[iter] = peer[call_n].call[call_c].speaker_on;
	}
}

int call_participant_count(const int call_n,const int call_c)
{
	if(call_invalid(call_n,call_c))
		return 0;
	int participating = 0;
	torx_read(call_n) // 🟧🟧🟧
	for(size_t iter = 0 ; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) ; iter++)
		if(peer[call_n].call[call_c].participating[iter] > -1)
			participating++;
	torx_unlock(call_n) // 🟩🟩🟩
	return participating;
}

int call_start(const int call_n)
{
	const uint8_t owner = getter_uint8(call_n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const uint8_t sendfd_connected = getter_uint8(call_n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
	const uint8_t recvfd_connected = getter_uint8(call_n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
	const uint8_t online = recvfd_connected + sendfd_connected;
	int call_c = -1;
	if(owner == ENUM_OWNER_GROUP_CTRL || online)
	{ // TODO We should either prevent starting calls with no peers, or send offers to peers who come online later? Probably the latter
		time_t time = 0;
		time_t nstime = 0;
		set_time(&time,&nstime);
		if((call_c = set_c(call_n,time,nstime)) > -1)
			call_join(call_n,call_c);
	}
	return call_c;
}

void call_toggle_mic(const int call_n,const int call_c,const int participant_n)
{ // For not a specific participant, pass -1 as participant_iter. Logic is the same as call_toggle_speaker.
	if(call_invalid(call_n,call_c))
		return;
	torx_write(call_n) // 🟥🟥🟥
	if(participant_n > 0)
	{
		const int participant_iter = call_participant_iter_by_n(call_n,call_c,participant_n);
		if(participant_iter > -1)
			toggle_int8(&peer[call_n].call[call_c].participant_mic[participant_iter]); // safe usage
		else // Rare failure
			error_simple(0,"Peer probably left the call before toggle.");
	}
	else
		toggle_int8(&peer[call_n].call[call_c].mic_on); // safe usage
	torx_unlock(call_n) // 🟩🟩🟩
	call_update_cb(call_n,call_c);
}

void call_toggle_speaker(const int call_n,const int call_c,const int participant_n)
{ // For not a specific participant, pass -1 as participant_iter. Logic is the same as call_toggle_mic.
	if(call_invalid(call_n,call_c))
		return;
	torx_write(call_n) // 🟥🟥🟥
	if(participant_n > 0)
	{
		const int participant_iter = call_participant_iter_by_n(call_n,call_c,participant_n);
		if(participant_iter > -1)
			toggle_int8(&peer[call_n].call[call_c].participant_speaker[participant_iter]); // safe usage
		else // Rare failure
			error_simple(0,"Peer probably left the call before toggle.");
	}
	else
		toggle_int8(&peer[call_n].call[call_c].speaker_on); // safe usage
	torx_unlock(call_n) // 🟩🟩🟩
	call_update_cb(call_n,call_c);
}

void call_leave_all_except(const int except_n,const int except_c)
{ // Leave or reject all active calls, except one (or none if -1). To be called primarily when call_join is called, but may also be called for other purposes.
	for(int call_n = 0; getter_byte(call_n,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(call_n,INT_MIN,-1,offsetof(struct peer_list,peer_index)) > -1 ; call_n++)
	{
		torx_read(call_n) // 🟧🟧🟧
		if(peer[call_n].owner == ENUM_OWNER_CTRL || peer[call_n].owner == ENUM_OWNER_GROUP_CTRL || peer[call_n].owner == ENUM_OWNER_GROUP_PEER)
			for(int call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
				if((peer[call_n].call[call_c].joined || peer[call_n].call[call_c].waiting) && (peer[call_n].call[call_c].start_time != 0 || peer[call_n].call[call_c].start_nstime != 0))
					if(call_n != except_n || call_c != except_c)
					{
						torx_unlock(call_n) // 🟩🟩🟩
						call_leave(call_n, call_c);
						torx_read(call_n) // 🟧🟧🟧
					}
		torx_unlock(call_n) // 🟩🟩🟩
	}
}

void call_mute_all_except(const int except_n,const int except_c)
{ // Leave or reject all active calls, except one (or none if -1). To be called primarily when a voice message is being sent, but may also be called for other purposes.
	for(int call_n = 0; getter_byte(call_n,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(call_n,INT_MIN,-1,offsetof(struct peer_list,peer_index)) > -1 ; call_n++)
	{
		torx_read(call_n) // 🟧🟧🟧
		if(peer[call_n].owner == ENUM_OWNER_CTRL || peer[call_n].owner == ENUM_OWNER_GROUP_CTRL || peer[call_n].owner == ENUM_OWNER_GROUP_PEER)
			for(int call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
				if((peer[call_n].call[call_c].joined || peer[call_n].call[call_c].waiting) && (peer[call_n].call[call_c].start_time != 0 || peer[call_n].call[call_c].start_nstime != 0))
					if(call_n != except_n || call_c != except_c)
					{
						uint8_t was_likely_recording = 0;
						uint8_t was_likely_playing = 0;
						if(peer[call_n].call[call_c].joined)
						{
							if(peer[call_n].call[call_c].mic_on)
								was_likely_recording = 1;
							if(peer[call_n].call[call_c].speaker_on)
								was_likely_playing = 1;
						}
						torx_unlock(call_n) // 🟩🟩🟩
						torx_write(call_n) // 🟥🟥🟥
						peer[call_n].call[call_c].mic_on = 0;
						peer[call_n].call[call_c].speaker_on = 0;
						torx_unlock(call_n) // 🟩🟩🟩
						if(was_likely_playing)
							audio_cache_clear_all(call_n,call_c);
						if(was_likely_recording)
							call_update_cb(call_n,call_c); // Stop recording
						torx_read(call_n) // 🟧🟧🟧
					}
		torx_unlock(call_n) // 🟩🟩🟩
	}
}

void call_join(const int call_n,const int call_c)
{ // To start a new call, use call_start not call_join
	if(call_invalid(call_n,call_c))
		return;
	uint16_t protocol;
	unsigned char message[8];
	torx_read(call_n) // 🟧🟧🟧
	if(peer[call_n].owner == ENUM_OWNER_GROUP_PEER)
		protocol = ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE;
	else
		protocol = ENUM_PROTOCOL_AUDIO_STREAM_JOIN;
	uint32_t trash = htobe32((uint32_t)peer[call_n].call[call_c].start_time);
	memcpy(message,&trash,sizeof(trash));
	trash = htobe32((uint32_t)peer[call_n].call[call_c].start_nstime);
	memcpy(&message[4],&trash,sizeof(trash));
	torx_unlock(call_n) // 🟩🟩🟩
	call_leave_all_except(call_n,call_c);
	torx_write(call_n) // 🟥🟥🟥
	peer[call_n].call[call_c].waiting = 0;
	peer[call_n].call[call_c].joined = 1;
	torx_unlock(call_n) // 🟩🟩🟩
	uint32_t participant_count;
	int *participant_list = call_participant_list(&participant_count,call_n,call_c); // All participants, including those with mic off
	if(participant_list)
	{ // Join an existing call
		message_send_select(participant_count,participant_list,protocol,message,sizeof(message));
		torx_free((void*)&participant_list);
	}
	else // Start new call
		message_send(call_n,protocol,message,(uint32_t)sizeof(message));
	sodium_memzero(message,sizeof(message));
	call_update_cb(call_n,call_c);
}

void call_ignore(const int call_n,const int call_c)
{ // Ignore a call we haven't joined yet
	if(call_invalid(call_n,call_c))
		return;
	torx_write(call_n) // 🟥🟥🟥
	peer[call_n].call[call_c].waiting = 0;
	peer[call_n].call[call_c].joined = 0;
	torx_unlock(call_n) // 🟩🟩🟩
	audio_cache_clear_all(call_n,call_c);
	call_update_cb(call_n,call_c);
}

void call_leave(const int call_n,const int call_c)
{
	if(call_invalid(call_n,call_c))
		return;
	uint32_t send_count = 0;
	unsigned char message[8];
	torx_read(call_n) // 🟧🟧🟧
	uint32_t trash = htobe32((uint32_t)peer[call_n].call[call_c].start_time);
	memcpy(message,&trash,sizeof(trash));
	trash = htobe32((uint32_t)peer[call_n].call[call_c].start_nstime);
	memcpy(&message[4],&trash,sizeof(trash));
	const uint8_t owner = peer[call_n].owner;
	const uint8_t joined = peer[call_n].call[call_c].joined;
	torx_unlock(call_n) // 🟩🟩🟩
	if(joined)
	{ // Must verify that we already joined, not just check participant count, before leaving
		uint32_t participant_count = 0;
		int *participant_list = call_participant_list(&participant_count,call_n,call_c); // All participants, including those with mic off
		if(participant_list)
			message_send_select(participant_count,participant_list,ENUM_PROTOCOL_AUDIO_STREAM_LEAVE,message,sizeof(message));
		torx_free((void*)&participant_list);
		send_count += participant_count;
	}
	if(send_count == 0 && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER))
		message_send(call_n,ENUM_PROTOCOL_AUDIO_STREAM_LEAVE,message,sizeof(message)); // Reject a call from a single peer, or cancel an outbound call
	sodium_memzero(message,sizeof(message));
	call_ignore(call_n,call_c);
}

void call_peer_joining(const int call_n,const int call_c,const int participant_n)
{ // One peer is joining an existing call
	if(call_invalid(call_n,call_c))
		return;
	torx_read(call_n) // 🟧🟧🟧
	if(call_participant_iter_by_n(call_n,call_c,participant_n) > -1 || participant_n < 0)
	{
		torx_unlock(call_n) // 🟩🟩🟩
		error_printf(0, "Peer is already part of call or has negative participant_n: %d. Possible coding error. Report this.",participant_n);
		return; // Peer is already in the call
	}
	torx_unlock(call_n) // 🟩🟩🟩
	call_peer_leaving_all_except(participant_n,call_n,call_c);
	const int participants = call_participant_count(call_n,call_c);
	if(participants)
	{ // send a list of peer onions that are already in the call, excluding this peer, if any
		const uint32_t message_len = (uint32_t)(8 + 56 * participants);
		unsigned char message[message_len];
		torx_read(call_n) // 🟧🟧🟧
		uint32_t trash = htobe32((uint32_t)peer[call_n].call[call_c].start_time);
		memcpy(message,&trash,sizeof(trash));
		trash = htobe32((uint32_t)peer[call_n].call[call_c].start_nstime);
		memcpy(&message[4],&trash,sizeof(trash));
		for(size_t iter = 0,count = 0; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) && (int)count < participants; iter++)
			if(peer[call_n].call[call_c].participating[iter] > -1) // BEWARE iter != count
				memcpy(&message[8+count++*56], peer[peer[call_n].call[call_c].participating[iter]].peeronion, 56);
		torx_unlock(call_n) // 🟩🟩🟩
		message_send(participant_n,ENUM_PROTOCOL_AUDIO_STREAM_PEERS,message,message_len);
		sodium_memzero(message,sizeof(message));
	}
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	const uint8_t default_participant_mic_local = default_participant_mic;
	const uint8_t default_participant_speaker_local = default_participant_speaker;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	uint8_t placed = 0;
	torx_write(call_n) // 🟥🟥🟥
	for(size_t iter = 0; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int); iter++)
		if(peer[call_n].call[call_c].participating[iter] == -1)
		{ // Add this peer then break
			peer[call_n].call[call_c].participating[iter] = participant_n;
			peer[call_n].call[call_c].participant_mic[iter] = default_participant_mic_local;
			peer[call_n].call[call_c].participant_speaker[iter] = default_participant_speaker_local;
			placed = 1;
			break;
		}
	if(!placed)
	{ // No empty space (from a peer who already left), need to expand.
		peer[call_n].call[call_c].participating = torx_realloc(peer[call_n].call[call_c].participating,torx_allocation_len(peer[call_n].call[call_c].participating) + sizeof(int));
		peer[call_n].call[call_c].participant_mic = torx_realloc(peer[call_n].call[call_c].participant_mic,torx_allocation_len(peer[call_n].call[call_c].participant_mic) + sizeof(uint8_t));
		peer[call_n].call[call_c].participant_speaker = torx_realloc(peer[call_n].call[call_c].participant_speaker,torx_allocation_len(peer[call_n].call[call_c].participant_speaker) + sizeof(uint8_t));
		const size_t iter = torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) - 1; // newly created slot
		peer[call_n].call[call_c].participating[iter] = participant_n;
		peer[call_n].call[call_c].participant_mic[iter] = default_participant_mic_local;
		peer[call_n].call[call_c].participant_speaker[iter] = default_participant_speaker_local;
	}
	torx_unlock(call_n) // 🟩🟩🟩
	call_update_cb(call_n,call_c);
}

void call_peer_leaving(const int call_n,const int call_c,const int participant_n)
{
	if(call_invalid(call_n,call_c) || participant_n < 0)
		return;
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	const uint8_t default_participant_mic_local = default_participant_mic;
	const uint8_t default_participant_speaker_local = default_participant_speaker;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	torx_write(call_n) // 🟥🟥🟥
	for(size_t iter = 0; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int); iter++)
		if(participant_n == peer[call_n].call[call_c].participating[iter])
		{ // TODO perhaps we should shift all forward, but then using iter outside of locks is very dangerous, so currently we don't.
			peer[call_n].call[call_c].participating[iter] = -1;
			peer[call_n].call[call_c].participant_mic[iter] = default_participant_mic_local;
			peer[call_n].call[call_c].participant_speaker[iter] = default_participant_speaker_local;
			break;
		}
	if((peer[call_n].call[call_c].joined || peer[call_n].call[call_c].waiting) && (peer[call_n].owner == ENUM_OWNER_CTRL || peer[call_n].owner == ENUM_OWNER_GROUP_PEER))
	{ // Ending the call if it is non-group
		peer[call_n].call[call_c].joined = 0;
		peer[call_n].call[call_c].waiting = 0;
	}
	torx_unlock(call_n) // 🟩🟩🟩
	call_update_cb(call_n,call_c);
}

void call_peer_leaving_all_except(const int participant_n,const int except_n,const int except_c)
{ // Peer is leaving all calls (ex: they went offline)
	if(participant_n < 0)
		return; // Sanity check
	const uint8_t owner = getter_uint8(participant_n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_PEER)
	{
		const int g = set_g(participant_n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int call_n = group_n;
		torx_read(call_n) // 🟧🟧🟧
		for(int call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
			if((peer[call_n].call[call_c].joined || peer[call_n].call[call_c].waiting) && (peer[call_n].call[call_c].start_time != 0 || peer[call_n].call[call_c].start_nstime != 0))
				if(call_n != except_n || call_c != except_c)
				{
					torx_unlock(call_n) // 🟩🟩🟩
					call_peer_leaving(call_n, call_c, participant_n);
					torx_read(call_n) // 🟧🟧🟧
				}
		torx_unlock(call_n) // 🟩🟩🟩
	} // NOT ELSE
	const int call_n = participant_n;
	torx_read(call_n) // 🟧🟧🟧
	for(int call_c = 0; (size_t)call_c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); call_c++)
		if((peer[call_n].call[call_c].joined || peer[call_n].call[call_c].waiting) && (peer[call_n].call[call_c].start_time != 0 || peer[call_n].call[call_c].start_nstime != 0))
			if(call_n != except_n || call_c != except_c)
			{
				torx_unlock(call_n) // 🟩🟩🟩
				call_peer_leaving(call_n, call_c, participant_n);
				torx_read(call_n) // 🟧🟧🟧
			}
	torx_unlock(call_n) // 🟩🟩🟩
}

void audio_cache_add(const int participant_n,const time_t time,const time_t nstime,const char *data,const size_t data_len)
{ // Handles ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC data
	if(participant_n < 0 || !data || !data_len)
		return; // Sanity check
	torx_write(participant_n) // 🟥🟥🟥
	if(time < peer[participant_n].audio_last_retrieved_time || (time == peer[participant_n].audio_last_retrieved_time && nstime < peer[participant_n].audio_last_retrieved_nstime))
	{
		torx_unlock(participant_n) // 🟩🟩🟩
		error_simple(0,"Received audio older than last played, or otherwise failed sanity check. Disgarding it. Carry on.");
		return;
	}
	const uint32_t current_allocation_size = torx_allocation_len(peer[participant_n].audio_cache);
	const size_t prior_count = current_allocation_size/sizeof(unsigned char *);
	if(prior_count && (time < peer[participant_n].audio_time[prior_count-1] || (time == peer[participant_n].audio_time[prior_count-1] && nstime < peer[participant_n].audio_nstime[prior_count-1])))
	{ // Received audio is older than something we already have in our struct, so we need to re-order it.
		unsigned char **audio_cache = torx_insecure_malloc((prior_count + 1) * sizeof(unsigned char *));
		time_t *audio_time = torx_insecure_malloc((prior_count + 1) * sizeof(time_t));
		time_t *audio_nstime = torx_insecure_malloc((prior_count + 1) * sizeof(time_t));
		uint8_t already_placed_new_data = 0; // must avoid placing more than once
		for(int old = (int)prior_count-1,new = (int)prior_count; old > -1; new--)
		{
			if(already_placed_new_data || peer[participant_n].audio_time[old] > time || (peer[participant_n].audio_time[old] == time && peer[participant_n].audio_nstime[old] > nstime))
			{ // Existing is newer, place it (may occur many times)
				audio_cache[new] = peer[participant_n].audio_cache[old];
				audio_time[new] = peer[participant_n].audio_time[old];
				audio_nstime[new] = peer[participant_n].audio_nstime[old];
				old--; // only -- when utilizing old data
			}
			else
			{ // Ours is newer, place it (must only occur once)
				audio_cache[new] = torx_secure_malloc(data_len);
				memcpy(audio_cache[new],data,data_len);
				audio_time[new] = time;
				audio_nstime[new] = nstime;
				already_placed_new_data = 1;
			}
		}
		torx_free((void*)&peer[participant_n].audio_cache);
		torx_free((void*)&peer[participant_n].audio_time);
		torx_free((void*)&peer[participant_n].audio_nstime);

		peer[participant_n].audio_cache = audio_cache;
		peer[participant_n].audio_time = audio_time;
		peer[participant_n].audio_nstime = audio_nstime;
	}
	else
	{ // Add the new data at the end because it is newest
		if(peer[participant_n].audio_cache)
		{ // Only checking one for efficiency
			peer[participant_n].audio_cache = torx_realloc(peer[participant_n].audio_cache, (prior_count + 1) * sizeof(unsigned char *));
			peer[participant_n].audio_time = torx_realloc(peer[participant_n].audio_time, (prior_count + 1) * sizeof(time_t));
			peer[participant_n].audio_nstime = torx_realloc(peer[participant_n].audio_nstime, (prior_count + 1) * sizeof(time_t));
		}
		else
		{
			peer[participant_n].audio_cache = torx_insecure_malloc((prior_count + 1) * sizeof(unsigned char *));
			peer[participant_n].audio_time = torx_insecure_malloc((prior_count + 1) * sizeof(time_t));
			peer[participant_n].audio_nstime = torx_insecure_malloc((prior_count + 1) * sizeof(time_t));
		}
		peer[participant_n].audio_cache[prior_count] = torx_secure_malloc(data_len);
		memcpy(peer[participant_n].audio_cache[prior_count],data,data_len);
		peer[participant_n].audio_time[prior_count] = time;
		peer[participant_n].audio_nstime[prior_count] = nstime;
	}
	torx_unlock(participant_n) // 🟩🟩🟩
	audio_cache_add_cb(participant_n);
}

unsigned char *audio_cache_retrieve(time_t *time,time_t *nstime,uint32_t *len,const int participant_n)
{ // Retrieve the oldest section of audio_cache for playback. Do not implement buffering in this function; implement buffering on the sender side. Sender side buffering reduces bandwidth and CPU usage as compared to receiver side.
	unsigned char *data = NULL; // must initialize
	time_t audio_time = 0; // must initialize
	time_t audio_nstime = 0; // must initialize
	if(participant_n > -1)
	{ // Sanity check
		torx_write(participant_n) // 🟥🟥🟥
		const uint32_t count = torx_allocation_len(peer[participant_n].audio_cache)/sizeof(unsigned char *);
		if(count)
		{
			data = peer[participant_n].audio_cache[0];
			audio_time = peer[participant_n].audio_last_retrieved_time = peer[participant_n].audio_time[0]; // Important
			audio_nstime = peer[participant_n].audio_last_retrieved_nstime = peer[participant_n].audio_nstime[0]; // Important

			peer[participant_n].audio_cache = torx_realloc_shift(peer[participant_n].audio_cache,(count - 1) * sizeof(unsigned char *),1); // torx_realloc(
			peer[participant_n].audio_time = torx_realloc_shift(peer[participant_n].audio_time,(count - 1) * sizeof(time_t),1);
			peer[participant_n].audio_nstime = torx_realloc_shift(peer[participant_n].audio_nstime,(count - 1) * sizeof(time_t),1);
		}
		torx_unlock(participant_n) // 🟩🟩🟩
	}
	if(len)
		*len = torx_allocation_len(data); // This is now safe to access outside locks
	if(time)
		*time = audio_time;
	if(nstime)
		*nstime = audio_nstime;
	return data;
}

void audio_cache_clear_participant(const int participant_n)
{
	if(participant_n < 0)
		return; // Sanity check
	torx_write(participant_n) // 🟥🟥🟥
	for(uint32_t count = torx_allocation_len(peer[participant_n].audio_cache)/sizeof(unsigned char *); count ; ) // do not change logic without thinking
		torx_free((void*)&peer[participant_n].audio_cache[--count]); // clear out all unplayed audio data
	torx_free((void*)&peer[participant_n].audio_cache);
	torx_free((void*)&peer[participant_n].audio_time);
	torx_free((void*)&peer[participant_n].audio_nstime);
	peer[participant_n].audio_last_retrieved_time = 0;
	peer[participant_n].audio_last_retrieved_nstime = 0;
	torx_unlock(participant_n) // 🟩🟩🟩
}

void audio_cache_clear_all(const int call_n,const int call_c)
{
	if(call_invalid(call_n,call_c)) // Check is actually unnecessary because it will be checked later by call_participant_list
		return;
	uint32_t participant_count = 0;
	int *participant_list = call_participant_list(&participant_count,call_n,call_c); // All participants, including those with speaker off
	for(uint32_t iter = 0; iter < participant_count; iter++)
		audio_cache_clear_participant(participant_list[iter]);
	torx_free((void*)&participant_list);
}

uint32_t record_cache_clear_nolocks(const int call_n)
{ // No locks, no sanity checks. Must lock and do sanity checks before calling. Internal function ONLY.
	const uint32_t existing_count = torx_allocation_len(peer[call_n].cached_recording)/sizeof(unsigned char *);
	for(uint32_t count = 0; count < existing_count; count++)
		torx_free((void*)&peer[call_n].cached_recording[count]); // clear out all cached recordings
	torx_free((void*)&peer[call_n].cached_recording);
	peer[call_n].cached_time = 0;
	peer[call_n].cached_nstime = 0;
	return existing_count;
}

int record_cache_clear(const int call_n)
{ // Returns amount cleared so that UI can monitor losses
	if(call_n < 0)
		return -1;
	torx_write(call_n) // 🟥🟥🟥
	const uint32_t cleared = record_cache_clear_nolocks(call_n);
	torx_unlock(call_n) // 🟩🟩🟩
	return (int)cleared;
}

int record_cache_add(const int call_n,const int call_c,const uint32_t cache_minimum_size,const uint32_t max_age_in_ms,const unsigned char *data,const uint32_t data_len)
{ // Can pass cache_minimum_size==0 when finishing a recording, to send regardless of length. Do not pass a high number as max_age_in_ms.
	if(call_invalid(call_n,call_c))
		return -1;
	uint32_t recipient_count = 0;
	int *recipient_list = call_recipient_list(&recipient_count,call_n,call_c); // Recipients only; excluding those with mic off
	const uint8_t joined = getter_call_uint8(call_n,call_c,-1,offsetof(struct call_list,joined));
	const uint8_t mic_on = getter_call_uint8(call_n,call_c,-1,offsetof(struct call_list,mic_on));
	if(!recipient_count || !joined || !mic_on) // No one to send to
		return 0;
	time_t current_time = 0;
	time_t current_nstime = 0;
	set_time(&current_time,&current_nstime);
	torx_write(call_n) // 🟥🟥🟥
	uint32_t existing_count = torx_allocation_len(peer[call_n].cached_recording)/sizeof(unsigned char *);
	if(existing_count && ((current_time - peer[call_n].cached_time) * 1000 + (current_nstime - peer[call_n].cached_nstime) / 1000000) > max_age_in_ms)
	{ // Existing cache is too old, discarding it.
		record_cache_clear_nolocks(call_n);
		existing_count = 0; // very important
	}
	size_t current_cache_size = 0;
	for(uint32_t count = 0; count < existing_count; count++)
		current_cache_size += torx_allocation_len(peer[call_n].cached_recording[count]);
	if(current_cache_size + data_len < cache_minimum_size)
	{ // Expand cache to hold new data
		if(existing_count)
			peer[call_n].cached_recording = torx_realloc(peer[call_n].cached_recording,sizeof(unsigned char *) * (existing_count+1));
		else
			peer[call_n].cached_recording = torx_insecure_malloc(sizeof(unsigned char *));
		peer[call_n].cached_recording[existing_count] = torx_secure_malloc(data_len);
		memcpy(peer[call_n].cached_recording[existing_count],data,data_len);
		peer[call_n].cached_time = current_time;
		peer[call_n].cached_nstime = current_nstime;
	}
	else
	{ // Peers to send to
		const uint32_t message_len = (uint32_t)(8 + current_cache_size + data_len);
		unsigned char message[message_len]; // zero'd
		uint32_t trash = htobe32((uint32_t)peer[call_n].call[call_c].start_time);
		memcpy(message,&trash,sizeof(trash));
		trash = htobe32((uint32_t)peer[call_n].call[call_c].start_nstime);
		memcpy(&message[4],&trash,sizeof(trash));
		for(uint32_t count = 0,offset = 0; count < existing_count ; count++) 
		{
			const uint32_t len = torx_allocation_len(peer[call_n].cached_recording[count]);
			memcpy(&message[8 + offset],peer[call_n].cached_recording[count],len);
			offset += len;
		}
		memcpy(&message[8 + current_cache_size],data,data_len);
		torx_unlock(call_n) // 🟩🟩🟩
		message_send_select(recipient_count,recipient_list,ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC,message,message_len);
		torx_write(call_n) // 🟥🟥🟥
		sodium_memzero(message,sizeof(message));
		record_cache_clear_nolocks(call_n);
	}
	torx_unlock(call_n) // 🟩🟩🟩
	torx_free((void*)&recipient_list);
	return (int)recipient_count;
}
