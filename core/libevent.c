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
clear ; gcc /home/user/Code/TorX/src/core/libevent2.c -levent_core -o /tmp/libevent2 && /./tmp/libevent 2

cd /usr/include/event2/ ; grep -a EV_PERSIST *
cd /usr/include/event2/ ; grep -a evbuffer_free *

re: evbuffer_lock "You only need to lock the evbuffer manually when you have more than one operation that need to execute without another thread butting in." https://libevent.org/libevent-book/Ref7_evbuffer.html

XXX	To Do		XXX
	* having functions that read/write file data to disk on the same thread as libevent might be a bottleneck, considering the limited buffer size of sockets
	* test sending the same file to multiple people at once. not sure what will happen. should be OK because they have different .fd
	* delete SING from file without taking down ( takedown_onion(onion,2); ) after receiving connection. Ensures that no funny business can happen. Then takedown_onion(onion,0); after handshake.
	* we noted that some messages get sent on sockets that are in fact down (but tor binary doesn't know it yet)
		if such connections are always going to be reported as successful, then our only option is to require a byte of return receipt.

*/

//TODO: Stop libevent from taking more than the required number of bytes on sing/mult connections. I think it could hypothetically buffer up to 4096 bytes? (hard coded)
// It should break the connection immediately if it receives too many bytes.

//TODO: see "KNOWN BUG:" On a successful sing or MULT, the socket does not close due to the CTRL coming up. It is not the same socket nor the same port. We don't know what is going on.
// Something to do with serv_init being a child process, I think. The socket doesn't close until the child process that called it ends.

static inline struct bufferevent *disconnect(struct event_strc *event_strc)
{ // Internal Function only. For handling or initializing a disconnection
	struct bufferevent *bev;
	torx_write(event_strc->n) // 🟥🟥🟥
	if(event_strc->fd_type == 0)
	{
	//	error_printf(0,"Checkpoint recvfd DISCONNECTED n=%d",event_strc->n);
		peer[event_strc->n].recvfd_connected = 0;
		bev = peer[event_strc->n].bev_recv;
		peer[event_strc->n].bev_recv = NULL;
		const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
		if(event_strc->owner != ENUM_OWNER_CTRL || !local_v3auth_enabled || peer[event_strc->n].peerversion < 2)
			event_strc->authenticated = 0; // must de-authenticate because we have no idea who is connecting in this case
	}
	else /* if(event_strc->fd_type == 1) */
	{
		peer[event_strc->n].sendfd_connected = 0;
		bev = peer[event_strc->n].bev_send;
		peer[event_strc->n].bev_send = NULL;
	}
	torx_unlock(event_strc->n) // 🟩🟩🟩
	if(bev) // Just in case we got here after zero_n for some reason
		bufferevent_free(bev); // Note: Don't call this by itself because it can be subject to double-free issues.
	return bev;
}

static inline void disconnect_forever(struct event_strc *event_strc,const int takedown_delete)
{ // Do NOT call from out of libevent thread.
	struct bufferevent *bev = disconnect(event_strc);
	if(takedown_delete > -1)
	{
		event_strc->killed = 1;
		const int peer_index = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		takedown_onion(peer_index,takedown_delete);
	}
	// error_printf(0,"Checkpoint disconnect_forever n=%d delete=%d killed=%u",event_strc->n,takedown_delete,event_strc->killed);
	if(event_strc->fd_type == 0 && (event_strc->owner == ENUM_OWNER_GROUP_PEER || event_strc->owner == ENUM_OWNER_GROUP_CTRL))
	{ // Necessary because accept_conn creates a copy for each connection
		torx_free((void*)&event_strc->buffer);
		torx_free((void*)&event_strc); // event_strc_unique
	}
	if(bev) // Just in case we got here after zero_n for some reason
		event_base_loopexit(bufferevent_get_base(bev), NULL);
}

static inline void peer_online(struct event_strc *event_strc)
{ // Internal Function only. Use the callback. Note: We store our onion rather than peeronion because this will be checked on initiation where peeronion won't be ready yet.
	if(event_strc->owner != ENUM_OWNER_CTRL && event_strc->owner != ENUM_OWNER_GROUP_PEER)
		return; // not CTRL
	const time_t last_seen = time(NULL); // current time
	setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
	peer_online_cb(event_strc->n);
	if(threadsafe_read_uint8(&mutex_global_variable,&log_last_seen) == 1)
	{
		char p1[21];
		snprintf(p1,sizeof(p1),"%lld",(long long)last_seen);
		const int peer_index = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
	}
	#ifndef NO_FILE_TRANSFER
	if(threadsafe_read_uint8(&mutex_global_variable,&auto_resume_inbound)) // XXX Experimental 2023/10/29: Might need to prevent FILE_REQUEST from being sent when we are potentially already receiving data... not sure if this will be an issue
		for(uint8_t cycle = 0; cycle < 2; cycle++)
		{ // First event_strc->n, then event_strc->group_n if applicable
			if(cycle && event_strc->group_n < 0)
				break;
			int file_n = cycle == 0 ? event_strc->n : event_strc->group_n;
			torx_read(file_n) // 🟧🟧🟧
			for(int f = 0; !is_null(peer[file_n].file[f].checksum,CHECKSUM_BIN_LEN); f++)
			{
				torx_unlock(file_n) // 🟩🟩🟩
				const int file_status = file_status_get(file_n,f);
				if(file_status == ENUM_FILE_INACTIVE_ACCEPTED || file_status == ENUM_FILE_ACTIVE_IN || file_status == ENUM_FILE_ACTIVE_IN_OUT)
					file_request_internal(file_n,f,-1); // re-send request for previously accepted file
				torx_read(file_n) // 🟧🟧🟧
			}
			torx_unlock(file_n) // 🟩🟩🟩
		}
	#endif // NO_FILE_TRANSFER
}

static inline void peer_offline(struct event_strc *event_strc)
{ // Internal Function only. Use the callback. Could combine with peer_online() to be peer_online_change() and peer_online_change_cb()
	if(!event_strc || event_strc->killed) // Sanity check
		return;
	if(event_strc->owner == ENUM_OWNER_GROUP_CTRL)
	{
		error_simple(0,"A group ctrl triggered peer_offline. Coding error. Report this.");
		breakpoint();
	}
	disconnect(event_strc);
	if(event_strc->owner != ENUM_OWNER_CTRL && event_strc->owner != ENUM_OWNER_GROUP_PEER)
		return; // not CTRL
	#ifndef NO_FILE_TRANSFER // was consider_transfers_paused()
	if(event_strc->group_n > -1) // Unclaim any sections on this socket. (should go last)
	{ // TODO Question: we typically call section_unclaim before we call file_remove_request. Is that the ideal order?
		section_unclaim(event_strc->group_n,-1,event_strc->n,event_strc->fd_type); // Pause all inbound Group transfers from this peer
		file_remove_request(event_strc->group_n,-1,event_strc->n,event_strc->fd_type); // Pause all outbound Group transfers to this peer
	}
	section_unclaim(event_strc->n,-1,event_strc->n,event_strc->fd_type); // Pause all inbound PM or P2P transfers from this peer
	file_remove_request(event_strc->n,-1,event_strc->n,event_strc->fd_type); // Pause all outbound PM or P2P transfers to this peer
	#endif // NO_FILE_TRANSFER
	const time_t last_seen = time(NULL); // current time
	setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
	const uint8_t sendfd_connected = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
	const uint8_t recvfd_connected = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
	const uint8_t online = recvfd_connected + sendfd_connected;
	const int peer_index = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	#ifndef NO_AUDIO_CALL
	if(!online || peer_index < 0)
		call_peer_leaving_all_except(event_strc->n,-1,-1);
	#endif // NO_AUDIO_CALL
	peer_offline_cb(event_strc->n); // must be after setting last_seen in memory
	if(peer_index < 0) // Peer has been deleted (and possibly killed)
		return;
	if(threadsafe_read_uint8(&mutex_global_variable,&log_last_seen) == 1)
	{
		char p1[21];
		snprintf(p1,sizeof(p1),"%lld",(long long)last_seen);
		sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
	}
	const int max_i = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(uint8_t cycle = 0; cycle < 2; cycle++)
		for(int i = cycle ? -1 : 0, plus_or_minus = cycle ? -1 : 1; cycle ? i >= min_i : i <= max_i ; i += plus_or_minus) // same as 2j0fj3r202k20f
		{ // Run through messages and clean out stream messages as appropriate. We are deleting and possibly shrinking message struct.
			const int p_iter = getter_int(event_strc->n,i,-1,offsetof(struct message_list,p_iter));
			if(p_iter > -1)
			{
				pthread_rwlock_rdlock(&mutex_protocols); // 🟧
				const uint8_t logged = protocols[p_iter].logged;
				const uint8_t socket_swappable = protocols[p_iter].socket_swappable;
				const uint8_t stream = protocols[p_iter].stream;
				pthread_rwlock_unlock(&mutex_protocols); // 🟩
				if(stream)
				{
					const int8_t fd_type = getter_int8(event_strc->n,i,-1,offsetof(struct message_list,fd_type));
					const uint8_t stat = getter_uint8(event_strc->n,i,-1,offsetof(struct message_list,stat));
					if(((!socket_swappable && fd_type == event_strc->fd_type) || !online) && (stat == ENUM_MESSAGE_FAIL || (stat == ENUM_MESSAGE_SENT && !logged)))
					{ // We don't need to delete them from disk because they aren't saved until sent. We shouldn't actually see any _SENT && !logged here.
						torx_write(event_strc->n) // 🟥🟥🟥
						const int shrinkage = zero_i(event_strc->n,i);
						torx_unlock(event_strc->n) // 🟩🟩🟩
						if(shrinkage)
							shrinkage_cb(event_strc->n,shrinkage);
					}
				}
			}
		}
}

/*void enter_thread_to_disconnect_forever(evutil_socket_t fd,short event,void *ctx)
{
	error_printf(YELLOW"Checkpoint enter_thread_to_disconnect_forever"RESET);
	(void) fd;
	(void) event;
	struct bufferevent *bev_recv = (struct bufferevent*)ctx;
	disconnect_forever(bev_recv,NULL);
}*/

static inline void pipe_auth_and_request_peerlist(struct event_strc *event_strc)
{ // Send ENUM_PROTOCOL_PIPE_AUTH && ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST
	if(event_strc->n < 0)
	{
		error_simple(0,"pipe_auth_and_request_peerlist sanity check failed. Coding error. Report this.");
		return;
	}
	char peeronion[56+1];
	getter_array(&peeronion,sizeof(peeronion),event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
	message_send(event_strc->n,ENUM_PROTOCOL_PIPE_AUTH,peeronion,PIPE_AUTH_LEN);
	sodium_memzero(peeronion,sizeof(peeronion));
	if(event_strc->g > -1 && event_strc->owner == ENUM_OWNER_GROUP_PEER)
	{ // sanity check, more or less.
		const uint32_t peercount = getter_group_uint32(event_strc->g,offsetof(struct group_list,peercount));
		const uint32_t trash = htobe32(peercount);
		message_send(event_strc->n,ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,&trash,sizeof(trash));
	}
}

static inline int pipe_auth_inbound(struct event_strc *event_strc)
{ // Handle Inbound ENUM_PROTOCOL_PIPE_AUTH. Returns n if valid, or -1 if invalid. Relies on message being signed.
	int ret = -1;
	char onion_group_n[56+1];
	getter_array(&onion_group_n,sizeof(onion_group_n),event_strc->n,INT_MIN,-1,offsetof(struct peer_list,onion));
	if(event_strc->fd_type == 0 && torx_allocation_len(event_strc->buffer) >= PIPE_AUTH_LEN + crypto_sign_BYTES && !memcmp(onion_group_n,event_strc->buffer,56)) // 2025/02/21 Using >= because we were getting a few INVALID ENUM_PROTOCOL_PIPE_AUTH for unknown reasons
		ret = event_strc->n;
	sodium_memzero(onion_group_n,sizeof(onion_group_n));
	return ret;
}

static inline void begin_cascade(struct event_strc *event_strc)
{ // Triggers a single unsent message // Note: There is an trivially chance of a race condition (where both sendfd and recvfd connect at the same time), which would cause unsent messages to not send on either fd. However, the alternative is to not do this check and have a far greater risk of having unsent messages going out on either or alternating fd_types, which would be faster but result in messages likely being out of order.
	torx_read(event_strc->n) // 🟧🟧🟧
	const int socket_utilized = peer[event_strc->n].socket_utilized[event_strc->fd_type];
	torx_unlock(event_strc->n) // 🟩🟩🟩
	if(event_strc->authenticated == 0 || socket_utilized > INT_MIN)
	{ // If socket_utilized EVER triggers here, it indicates either that we call begin_cascade somewhere we shouldn't (where a message_send is already called), or otherwise a race condition (where begin_cascade is being called twice).
		error_printf(0,"Sanity check failed in begin_cascade. Possible coding error. Report this. Owner=%u n=%d fd_type=%d utilized=%i authenticated=%u",event_strc->owner,event_strc->n,event_strc->fd_type,socket_utilized,event_strc->authenticated);
		return;
	}
	const int max_i = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(int i = min_i; i <= max_i; i++)
	{
		torx_read(event_strc->n) // 🟧🟧🟧
		const uint8_t stat = peer[event_strc->n].message[i].stat;
		const int8_t fd_type = peer[event_strc->n].message[i].fd_type;
		const int p_iter = peer[event_strc->n].message[i].p_iter;
		const uint32_t pos = peer[event_strc->n].message[i].pos; // TODO This is a GOOD workaround: Socket_utilized is supposed to negate the necessity of this, but doesn't due to races conditions.
		const int utilized_recv = peer[event_strc->n].socket_utilized[0]; // TODO This MIGHT BE a BAD workaround (may lead to stalling).
		const int utilized_send = peer[event_strc->n].socket_utilized[1]; // TODO This MIGHT BE a BAD workaround (may lead to stalling).
		torx_unlock(event_strc->n) // 🟩🟩🟩
		if(stat == ENUM_MESSAGE_FAIL && p_iter > -1 && (fd_type == -1 || fd_type == event_strc->fd_type) && pos == 0 && utilized_recv != i && utilized_send != i)
		{ // important check, to snuff out deleted messages
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint8_t stream = protocols[p_iter].stream;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if(stream != ENUM_STREAM_DISCARDABLE && send_prep(event_strc->n,-1,i,p_iter,event_strc->fd_type) != -1) // Must use event_strc->fd_type, NOT fd_type (which might be -1). Will do nothing if there are no messages to send
				break; // allow cascading effect in packet_removal
		}
	//	else if(stat == ENUM_MESSAGE_FAIL && p_iter > -1 && (fd_type == -1 || fd_type == event_strc->fd_type) && (pos != 0 || utilized_recv == i || utilized_send == i)) // TODO debugging here
	//		error_printf(0,BRIGHT_YELLOW"Checkpoint NO cascade: n=%d fd=%d pos=%u recv=%d send=%d"RESET,event_strc->n,event_strc->fd_type,pos,utilized_recv,utilized_send);
	}
}

// uint64_t total_packets_added = 0; // TODO remove
// uint64_t total_packets_removed = 0; // TODO remove

static inline size_t packet_removal(struct event_strc *event_strc,const size_t drain_len)
{
	size_t drained = 0;
	int packets_to_remove = 1; // 2024/12/24 Very important, do not modify
	pthread_rwlock_wrlock(&mutex_packet); // 🟥
	while(packets_to_remove)
	{
		torx_read(event_strc->n) // 🟧🟧🟧
		const int socket_utilized = peer[event_strc->n].socket_utilized[event_strc->fd_type];
		torx_unlock(event_strc->n) // 🟩🟩🟩
		time_t time_oldest = LONG_MAX; // must initialize as a very high value (some time into the future)
		time_t nstime_oldest = LONG_MAX; // must initialize as a very high value (some time into the future)
		int o_oldest = -1;
		packets_to_remove = 0;
		for(int o = 0 ; o <= threadsafe_read_int(&mutex_global_variable,&highest_ever_o) ; o++)
			if(packet[o].n == event_strc->n && packet[o].fd_type == event_strc->fd_type)
			{
				packets_to_remove++;
				if(time_oldest > packet[o].time || (packet[o].time == time_oldest && nstime_oldest > packet[o].nstime))
				{ // This packet is older than the current oldest.
					time_oldest = packet[o].time;
					nstime_oldest = packet[o].nstime;
					o_oldest = o;
				}
			}
		const int o = o_oldest;
		if(o < 0)
			break; // Done or none
		packets_to_remove--; // Leave here, before the continue
		const int p_iter = packet[o].p_iter;
		if(p_iter < 0) // Should never happen. No good way to handle other than to disconnect and return.
			error_simple(-1,"p_iter is negative in packet_removal. Potentially serious coding error. Report this.");
		const int packet_f_i = packet[o].f_i;
		const uint16_t packet_len = packet[o].packet_len;
		const time_t packet_time = packet[o].time;
		const time_t packet_nstime = packet[o].nstime;
		if(!drain_len && socket_utilized != packet_f_i)
		{ // Supposed to remove a non-file packet, but the socket_utilized doesn't match
			#ifndef NO_FILE_TRANSFER
			if(packet[o].p_iter != file_piece_p_iter)
			{
			#endif // NO_FILE_TRANSFER
				int other_socket_utilized;
				torx_read(event_strc->n) // 🟧🟧🟧
				if(event_strc->fd_type)
					other_socket_utilized = peer[event_strc->n].socket_utilized[0];
				else
					other_socket_utilized = peer[event_strc->n].socket_utilized[1];
				torx_unlock(event_strc->n) // 🟩🟩🟩
				error_printf(0,"Packet removal wrong socket_utilized n=%d fd_type=%d (socket_utilized=%d) != (i=%d). Other socket_utilized=%d. Packet time=%ld nstime=%ld",event_strc->n,event_strc->fd_type,socket_utilized,packet_f_i,other_socket_utilized,packet[o].time,packet[o].nstime);
				break;
			#ifndef NO_FILE_TRANSFER
			}
			#endif // NO_FILE_TRANSFER
		}
		#ifndef NO_FILE_TRANSFER
		const int8_t packet_fd_type = packet[o].fd_type;
		const int packet_file_n = packet[o].file_n;
		packet[o].file_n = -1;
		#endif // NO_FILE_TRANSFER
		packet[o].n = -1; // release it for re-use.
		packet[o].f_i = INT_MIN; // release it for re-use.
		packet[o].packet_len = 0; // release it for re-use.
		packet[o].p_iter = -1; // release it for re-use.
		packet[o].fd_type = -1; // release it for re-use.
		packet[o].time = 0;
		packet[o].nstime = 0;
		pthread_rwlock_unlock(&mutex_packet); // 🟩 // XXX DO NOT continue AFTER THIS XXX
		time_oldest = LONG_MAX; // 2024/12/24 Very important, do not modify
		nstime_oldest = LONG_MAX; // 2024/12/24 Very important, do not modify
		o_oldest = -1;
		drained += packet_len;
	//	total_packets_removed++; // TODO remove
		if(!drain_len)
		{ // For drain_len, we don't do anything except 0 the packets above
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint16_t protocol = protocols[p_iter].protocol;
			const uint8_t stream = protocols[p_iter].stream;
			const char *name = protocols[p_iter].name;
			const uint8_t logged = protocols[p_iter].logged;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			#ifndef NO_FILE_TRANSFER
			if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			{
				const int f = packet_f_i;
				const int r = set_r(packet_file_n,f,event_strc->n);
				if(r > -1)
				{
					torx_write(packet_file_n) // 🟥🟥🟥
					if(peer[packet_file_n].file[f].request)
					{ // Necessary sanity check to prevent race conditions
						peer[packet_file_n].file[f].request[r].transferred[packet_fd_type] += packet_len-16; // const uint64_t this_r =
						const uint64_t current_pos = peer[packet_file_n].file[f].request[r].start[event_strc->fd_type] + peer[packet_file_n].file[f].request[r].transferred[event_strc->fd_type];
						const uint64_t current_end = peer[packet_file_n].file[f].request[r].end[event_strc->fd_type]+1;
						torx_unlock(packet_file_n) // 🟩🟩🟩
					//	error_printf(0,"Checkpoint packet ++=%lu --=%lu highest_ever_o=%d drained=%lu file_n=%d f=%d fd=%d r=%d transferred this_r=%lu total=%lu",total_packets_added,total_packets_removed,highest_ever_o,drained,packet_file_n,f,packet_fd_type,r,this_r,transferred); // TODO remove
						const int file_status = file_status_get(packet_file_n,f);
						if(current_pos == current_end)
						{ // Completed section
							error_printf(0,"Outbound Section Completed file_n=%d f=%d event_strc->n=%d fd_type=%d",packet_file_n,f,event_strc->n,event_strc->fd_type);
							close_sockets(packet_file_n,f)
							transfer_progress(packet_file_n,f);
						}
						else if(file_status == ENUM_FILE_ACTIVE_OUT || file_status == ENUM_FILE_ACTIVE_IN_OUT)
						{
							transfer_progress(packet_file_n,f); // probably best to have this *before* send_prep, but it might not matter
							send_prep(event_strc->n,packet_file_n,f,p_iter,event_strc->fd_type); // sends next packet on same fd, or closes it
						}
						else // Ceasing send due to status change
							error_printf(0,"Ceasing to send file file_n=%d f=%d status=%u",packet_file_n,f,file_status);
					}
					else
						torx_unlock(packet_file_n) // 🟩🟩🟩
				}
			}
			else
			{ // All protocols that contain a message size on the first packet of a message
			#endif // NO_FILE_TRANSFER
				const int i = packet_f_i;
				torx_write(event_strc->n) // 🟥🟥🟥 Warning: don't use getter/setter for ++/+= operations. Increases likelihood of race condition.
				if(peer[event_strc->n].message[i].pos == 0) // first packet of a message, has message_len prefix
					peer[event_strc->n].message[i].pos = packet_len - (2+2+4);
				else // subsequent packet (ie, second or later packet in a message > PACKET_SIZE_MAX)
					peer[event_strc->n].message[i].pos += packet_len - (2+2);
				const uint32_t message_len = torx_allocation_len(peer[event_strc->n].message[i].message);
				const uint32_t pos = peer[event_strc->n].message[i].pos;
				// error_printf(0,"Checkpoint MESSAGE STAT: n=%d i=%d stat=%u",event_strc->n,i,peer[event_strc->n].message[i].stat); // FSojoasfoSO
				torx_unlock(event_strc->n) // 🟩🟩🟩
				if(pos == message_len)
				{ // complete message, complete send
					carry_on_regardless: {}
					if(stream)
					{
						if(logged) // Logged stream messages are only logged after being sent
						{
							const uint8_t stat = ENUM_MESSAGE_SENT;
							setter(event_strc->n,i,-1,offsetof(struct message_list,stat),&stat,sizeof(stat));
							sql_insert_message(event_strc->n,i);
						}
						else
						{ // discard/delete message and attempt rollback
							torx_write(event_strc->n) // 🟥🟥🟥
							const int shrinkage = zero_i(event_strc->n,i);
							torx_unlock(event_strc->n) // 🟩🟩🟩
							if(shrinkage)
								shrinkage_cb(event_strc->n,shrinkage);
						/*	error_printf(0,"Checkpoint actually deleted group_peer's i");
							// TODO we should zero the group_n's message, but we don't know when to do it. Can't do it in message_send, and its hard to do here because we don't know how many group_peers its going out to.
							// TODO give up and hope group_msg and stream rarely go together? lets wait for it to become a real problem. TODO see: sfaoij2309fjfw */
						}
					}
					else if(protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)
					{ // We don't need these messages anymore. They only need to be logged until sent. One day we can perhaps make them stream non-disgardable + !logged?
						if(logged) // yes, it is
						{
							const int peer_index = getter_int(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
							const time_t time = getter_time(event_strc->n,i,-1,offsetof(struct message_list,time));
							const time_t nstime = getter_time(event_strc->n,i,-1,offsetof(struct message_list,nstime));
							sql_delete_message(peer_index,time,nstime);
						}
						torx_write(event_strc->n) // 🟥🟥🟥
						const int shrinkage = zero_i(event_strc->n,i);
						torx_unlock(event_strc->n) // 🟩🟩🟩
						if(shrinkage)
							shrinkage_cb(event_strc->n,shrinkage);
					}
					else
					{
						#ifndef NO_STICKERS
						if(protocol == ENUM_PROTOCOL_STICKER_HASH || protocol == ENUM_PROTOCOL_STICKER_HASH_PRIVATE || protocol == ENUM_PROTOCOL_STICKER_HASH_DATE_SIGNED)
						{ // THE FOLLOWING IS IMPORTANT TO PREVENT FINGERPRINTING BY STICKER WALLET. It has to be upon send instead of earlier to ensure unsent group messages trigger it.
							const int relevent_n = (event_strc->group_n > -1 && protocol != ENUM_PROTOCOL_STICKER_HASH_PRIVATE) ? event_strc->group_n : event_strc->n;
							unsigned char checksum[CHECKSUM_BIN_LEN];
							torx_read(event_strc->n) // 🟧🟧🟧
							memcpy(checksum,peer[event_strc->n].message[i].message,CHECKSUM_BIN_LEN);
							torx_unlock(event_strc->n) // 🟩🟩🟩
							const int s = set_s(checksum);
							sticker_add_peer(s,relevent_n);
							sodium_memzero(checksum,sizeof(checksum));
						}
						#endif // NO_STICKERS
						const uint8_t stat = ENUM_MESSAGE_SENT;
						setter(event_strc->n,i,-1,offsetof(struct message_list,stat),&stat,sizeof(stat));
						sql_update_message(event_strc->n,i);
						message_modified_cb(event_strc->n,i);
						if(protocol == ENUM_PROTOCOL_KILL_CODE)
						{ // Sent Kill Code
							error_simple(1,"Successfully sent a kill code. Deleting peer.");
							disconnect_forever(event_strc,1); // XXX Run last and return immediately after, will exit event base
							return drained; // must return immediately after event_base_loopexit
						}
					}
					error_printf(4,WHITE"packet_removal  peer[%d].socket_utilized[%d] = INT_MIN"RESET,event_strc->n,event_strc->fd_type);
					error_printf(2,CYAN"OUT%d-> %s %u"RESET,event_strc->fd_type,name,message_len);
					torx_write(event_strc->n) // 🟥🟥🟥
					peer[event_strc->n].socket_utilized[event_strc->fd_type] = INT_MIN;
					torx_unlock(event_strc->n) // 🟩🟩🟩
					if(protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
						pipe_auth_and_request_peerlist(event_strc); // this will trigger cascade // send ENUM_PROTOCOL_PIPE_AUTH
					else // Send next message. Necessary.
						begin_cascade(event_strc);
				}
				else if(pos > message_len)
				{ // If this triggers, enable FSojoasfoSO lines for debugging. In the past, it was due to send_prep being called twice on the same n,i pair.
					const uint8_t stat = getter_uint8(event_strc->n,i,-1,offsetof(struct message_list,stat));
					error_printf(0,PINK"packet_removal reported message pos > message_len: %u > %u. n=%d fd_type=%d i=%d stat=%u packet_len=%u time=%ld nstime=%ld protocol: %s. Likely will corrupt message. Coding error. Report this. Printing of packet struct will follow: "RESET,pos,message_len,event_strc->n,event_strc->fd_type,i,stat,packet_len,packet_time,packet_nstime,name);
					pthread_rwlock_rdlock(&mutex_packet); // 🟧
					for(int ooo = 0 ; ooo <= threadsafe_read_int(&mutex_global_variable,&highest_ever_o) ; ooo++)
						if(packet[ooo].p_iter > -1 && packet[ooo].n == event_strc->n && packet[ooo].fd_type == event_strc->fd_type)
						{ // This is important debug info
							pthread_rwlock_rdlock(&mutex_protocols); // 🟧
							const char *o_name = protocols[packet[ooo].p_iter].name;
							pthread_rwlock_unlock(&mutex_protocols); // 🟩
							error_simple(0,"-------------Same n, same fd_type-------------");
							error_printf(0,"Checkpoint packet[%d].name:	%s",ooo,o_name);
							error_printf(0,"Checkpoint packet[%d].n:		%d",ooo,packet[ooo].n);
							#ifndef NO_FILE_TRANSFER
							error_printf(0,"Checkpoint packet[%d].file_n:		%d",ooo,packet[ooo].file_n);
							#endif // NO_FILE_TRANSFER
							error_printf(0,"Checkpoint packet[%d].f_i:		%d",ooo,packet[ooo].f_i);
							error_printf(0,"Checkpoint packet[%d].packet_len:	%u",ooo,packet[ooo].packet_len);
							error_printf(0,"Checkpoint packet[%d].fd_type:		%d",ooo,packet[ooo].fd_type);
							error_printf(0,"Checkpoint packet[%d].time:		%ld",ooo,(long)packet[ooo].time);
							error_printf(0,"Checkpoint packet[%d].nstime:		%ld",ooo,(long)packet[ooo].nstime);
							error_simple(0,"-----------If not _FILE_PIECE, bug!-----------");
							#ifndef NO_FILE_TRANSFER
							if(packet[ooo].p_iter != file_piece_p_iter) // Severe coding error
								error_simple(0,"socket_utilized failed to prevent two non-file packets on the same n+fd_type from getting into our packet struct. Severe coding error. Report this.");
							#endif // NO_FILE_TRANSFER
						}
					pthread_rwlock_unlock(&mutex_packet); // 🟩
					goto carry_on_regardless; // SOMETIMES prevents illegal read in send_prep (beyond message len)
				}
				else // incomplete message, complete send
				{
				//	error_printf(0,"Checkpoint partial message, complete send: n=%d i=%d fd=%d packet_len=%u pos=%u of %u",n,i,event_strc->fd_type,packet_len,pos,message_len); // partial incomplete
				//	error_simple(0,"."); fflush(stdout);
					#ifndef NO_FILE_TRANSFER
					send_prep(event_strc->n,packet_file_n,i,p_iter,event_strc->fd_type); // send next packet on same fd
					#else
					send_prep(event_strc->n,-1,i,p_iter,event_strc->fd_type); // send next packet on same fd
					#endif // NO_FILE_TRANSFER
				}
			#ifndef NO_FILE_TRANSFER
			}
			#endif // NO_FILE_TRANSFER
		}
		pthread_rwlock_wrlock(&mutex_packet); // 🟥
	}
	pthread_rwlock_unlock(&mutex_packet); // 🟩
	if(!drained)
		error_simple(0,"Remove packet failed to remove anything. Coding error. Report this.");
	else if(drain_len && drained != drain_len)
		error_printf(0,"Remove packet drained less than expected: %lu != %lu. Coding error. Report this.",drained,drain_len);
	return drained;
}

static void write_finished(struct bufferevent *bev, void *ctx)
{ /* This write callback is triggered when write buffer has depleted (bufferevent.h) */ // It follows read_conn()
	(void)bev;
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	if(event_strc->owner == ENUM_OWNER_SING || event_strc->owner == ENUM_OWNER_MULT)
	{
		if(event_strc->fresh_n > -1) // sanity check of n returned by load_onion()
		{
			const uint8_t status_fresh = getter_uint8(event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,status));
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
			if(status_fresh == ENUM_STATUS_FRIEND)
				error_printf(3,"Handshake occured. Peer saved as %s on friends list.",peeronion);
			else if(status_fresh == ENUM_STATUS_PENDING)
			{
				error_printf(3,"Handshake occured. Peer saved as %s on pending list.",peeronion);
				incoming_friend_request_cb(event_strc->fresh_n);
			}
			const uint16_t peerversion = getter_uint16(event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
			char privkey[88+1];
			getter_array(&privkey,sizeof(privkey),event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,privkey));
			char *peernick = getter_string(event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,peernick));
			const int peer_index_fresh = sql_insert_peer(ENUM_OWNER_CTRL,status_fresh,peerversion,privkey,peeronion,peernick,0);
			torx_free((void*)&peernick);
			sodium_memzero(peeronion,sizeof(peeronion));
			sodium_memzero(privkey,sizeof(privkey));
			setter(event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,peer_index),&peer_index_fresh,sizeof(peer_index_fresh));
			sql_update_peer(event_strc->fresh_n);
			peer_new_cb(event_strc->fresh_n);
		}
		if(event_strc->owner == ENUM_OWNER_SING)
		{
			error_simple(2,"Disconnecting forever a SING after a write.");
			disconnect_forever(event_strc,1); // XXX Run last and return immediately after, will exit event base
			return;
		}
	}
	else // SING and MULT don't use the packet struct, so there is nothing to remove
		packet_removal(event_strc,0);
/*	const uint8_t status = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{ // Must be after packet_removal
		error_simple(0,"Peer is not a friend. Disconnecting from write_finished.");
		disconnect_forever(event_strc,-1); // XXX Run last and return immediately after, will exit event base
		return;
	} */ // Removing this block because it is redundant, calling disconnect_forever twice on kills. I think it only triggered on kills and we have since otherwise handled that?
}

static void close_conn(struct bufferevent *bev, short events, void *ctx)
{ /* Peer closes connection, or we do. (either of us closes software) */
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	if(event_strc->killed)
		return;
	const uint8_t status = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(events & BEV_EVENT_ERROR)
	{ // 2024/02/20 happened during outbound file transfer when peer (or we) went offline
		error_simple(0,"Error from bufferevent caused connection closure."); // 2023/10/30 occurs when a peer went offline during file transfer
	//	breakpoint(); XXX REMOVING because was_inbound_transferring is typically 0 when we are doing outbound transfer, and this error still occurs XXX
	}
	else if(events & BEV_EVENT_EOF) 
		error_simple(3,"Peer sent EOF, indicating that they closed connection."); // TODO 2022/08/12: "Error caused closed on 0000", after inbound handshake on our sing
	else // not an error but maybe we can use this
		error_simple(2,"Some unknown type of unknown close_conn occured.");
	if(event_strc->owner == ENUM_OWNER_CTRL || event_strc->owner == ENUM_OWNER_GROUP_PEER || event_strc->owner == ENUM_OWNER_MULT) // not GROUP_CTRL because CTRL never goes offline
	{
		error_printf(2,"Connection closed by peer n=%d fd_type=%d owner=%u status=%u",event_strc->n,event_strc->fd_type,event_strc->owner,status);
		peer_offline(event_strc); // internal callback
	}
	else if(event_strc->owner == ENUM_OWNER_SING) // NOTE: this doesnt trigger for successful handshakes because .owner becomes 0000
	{
		error_simple(0,"Spoiled onion due to close.");
		disconnect_forever(event_strc,3); // XXX Run last and return immediately after, will exit event base
		return;
	}
	if(event_strc->fd_type == 1)
	{ // Fix issues caused by unwanted resumption of inbound PM transfers
		struct evbuffer *output = bufferevent_get_output(bev);
		const size_t to_drain = evbuffer_get_length(output);
		if(to_drain)
		{ // Note: there is an infinately small chance of a race condition by calling packet_removal before ev_buffer_drain. Unavoidable unless we use evbuffer locks.
			error_printf(4,"Draining up to n=%d bytes=%zu",event_strc->n,to_drain);
			const size_t to_actually_drain = packet_removal(event_strc,to_drain);
			evbuffer_drain(output,to_actually_drain); // do not pass to_drain because one packet can remain on buffer for ??? reasons
		}
	}
	torx_read(event_strc->n) // 🟧🟧🟧
	const int socket_utilized = peer[event_strc->n].socket_utilized[event_strc->fd_type];
	torx_unlock(event_strc->n) // 🟩🟩🟩
	if(socket_utilized > INT_MIN)
	{
		torx_write(event_strc->n) // 🟥🟥🟥
		peer[event_strc->n].message[socket_utilized].pos = 0;
		peer[event_strc->n].socket_utilized[event_strc->fd_type] = INT_MIN;
		torx_unlock(event_strc->n) // 🟩🟩🟩
		error_printf(0,WHITE"close_conn peer[%d].socket_utilized[%d] = INT_MIN"RESET,event_strc->n,event_strc->fd_type);
	}
	if(event_strc->fd_type == 0 && (event_strc->owner == ENUM_OWNER_GROUP_PEER || event_strc->owner == ENUM_OWNER_GROUP_CTRL))
	{ // Necessary because accept_conn creates a copy for each connection
		torx_free((void*)&event_strc->buffer);
		torx_free((void*)&ctx); // event_strc_unique
	}
}

static void read_conn(struct bufferevent *bev, void *ctx)
{ // Message Received // Followed by write_finished() in the case of incoming friend requests.
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const uint8_t status = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{ // ENUM_STATUS_FRIEND seems to include active SING/MULT
		error_simple(0,"Pending user or blocked user received unexpected message. Disconnecting. Report this."); // TODO 2024/09/28 happens after blocks or deletion, of which the RECV connection stays up because we can't find a threadsafe way to call disconnect_forever from takedown_onion
		disconnect_forever(event_strc,-1); // XXX Run last and return immediately after, will exit event base
		return; // 2024/03/11 hit this after deleting a group. probably didn't takedown the event properly after group delete
	}
	struct evbuffer *input = bufferevent_get_input(bev);
	const int8_t local_debug = torx_debug_level(-1);
	if(event_strc->owner == ENUM_OWNER_CTRL || event_strc->owner == ENUM_OWNER_GROUP_CTRL || event_strc->owner == ENUM_OWNER_GROUP_PEER)
	{ // Bytes to Read on CTRL
		unsigned char read_buffer[PACKET_SIZE_MAX]; // free'd // == "EVBUFFER_MAX_READ_DEFAULT" variable from libevent. could set this to 64kb to be safe, in case libevent increases one day
		int group_peer_n; // DO NOT USE except for signed group messages
		uint8_t continued = 0;
		uint16_t protocol = 0; // NOTE: Until this is set, it could be 0 or the prior packet's protocol
		uint16_t packet_len = 0;
		while(1)
		{ // not a real while loop, just eliminating goto. Do not attempt to eliminate. We use a lot of 'continue' here.
			group_peer_n = -1;
			if(continued == 1)
			{// we came here from continue, so we should flush out whatever complete (but worthless) packet was in the buffer
				sodium_memzero(read_buffer,packet_len);
				#ifndef NO_FILE_TRANSFER
				if(protocol != ENUM_PROTOCOL_FILE_PIECE) // Must not 0 on ENUM_PROTOCOL_FILE_PIECE because it doesn't use buffer. Zeroing will interfere with other protocols which do.
				#endif // NO_FILE_TRANSFER
					torx_free((void*)&event_strc->buffer); // freeing here so we don't have to free before every continue
			}
			else
				continued = 1;
			uint16_t trash_int = 0;
			uint16_t minimum_length = 2+2; // packet length + protocol
			const size_t evbuffer_len = evbuffer_get_length(input);
			if(evbuffer_len < minimum_length || evbuffer_copyout(input,&trash_int,2) != 2)
				return; // too short to get protocol and length
			packet_len = be16toh(trash_int);
			uint16_t cur = 2; // current position, after reading packet len
			if(evbuffer_len < (size_t) packet_len)
				return; // not enough data yet, only partial packet. Minimize CPU cycles and allocations before this. Occurs on about 20% of packets without EV_ET and 25% of packets with EV_ET.
			if(packet_len > PACKET_SIZE_MAX)
			{ // Sanity check
				error_simple(0,"Major unexpected problem, either an invalid packet size or an oversized packet. Packet is being discarded."); // \npacket_len:\t%d\ttrash_int:\t%d\n",packet_len,trash_int);
				break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
			}
			if(evbuffer_remove(input,read_buffer,(size_t)packet_len) != packet_len) // multiples of PACKET_SIZE_MAX, up to 4096 max, otherwise bytes get lost to the ether.
			{ // This is a libevent bug because we already checked length is sufficient.
				error_simple(0,"This should not occur 12873. should never occur under any circumstances. report this.");
				break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
			}
			protocol = be16toh(align_uint16((void*)&read_buffer[cur]));
			cur += 2; // 2 --> 4
			#ifndef NO_FILE_TRANSFER
			if(protocol == ENUM_PROTOCOL_FILE_PIECE)
				minimum_length += 4 + 8; // truncated checksum + start (starting position for file piece)
			else // XXX NOTE: This becomes 'else if' (tested fine with clang/GCC)
			#endif // NO_FILE_TRANSFER
				if(torx_allocation_len(event_strc->buffer) == 0)
				minimum_length += 4; // length of message, if we don't already have a partial message in buffer
			if(packet_len < minimum_length)
			{ // TODO make protocol specific minimum lengths?
				error_simple(0,"Unreasonably small packet received. Peer likely buggy. Report this.");
				break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
			}
			if(event_strc->owner == ENUM_OWNER_CTRL && event_strc->fd_type == 0 && event_strc->authenticated == 0 && (protocol != ENUM_PROTOCOL_PIPE_AUTH && protocol != ENUM_PROTOCOL_PROPOSE_UPGRADE))
			{ // NOTE: Do not ever attempt downgrades here or elsewhere. There are many reasons why it is a bad idea.
				error_printf(0,"Unexpected protocol received on ctrl before PIPE_AUTH: %u. Closing.",protocol);
				break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
			}
			else if(event_strc->owner == ENUM_OWNER_GROUP_CTRL && protocol != ENUM_PROTOCOL_PIPE_AUTH)
			{ // GROUP_CTRL connections are only allowed to authenticate or permit entries
				if((event_strc->invite_required == 1 && protocol != ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
				|| (event_strc->invite_required == 0 && protocol != ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST))
				{
					error_printf(0,"Unexpected protocol received on group ctrl g=%d before PIPE_AUTH: %u. Closing.",event_strc->g,protocol);
					break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
				}
			}
			#ifndef NO_FILE_TRANSFER
			if(protocol == ENUM_PROTOCOL_FILE_PIECE)
			{ // Received Message type: Raw File data // TODO we do too much processing here. this might get CPU intensive.
				int file_n = event_strc->n;
				int f = set_f(file_n,&read_buffer[cur],4);
				if(f < 0 && event_strc->owner == ENUM_OWNER_GROUP_PEER)
				{ // potential group file transfer, non-pm
					file_n = event_strc->group_n;
					f = set_f(file_n,&read_buffer[cur],4);
				}
				if(f < 0) // NOT else if, we set f again above
				{ // TODO should probably send ENUM_PROTOCOL_FILE_PAUSE // TODO consider calling break or blocking peer or something if this triggers. this peer is probably buggy or malicious.
					error_printf(0,"Invalid raw data packet received from owner: %u",event_strc->owner);
					continue;
				}
				cur += 4; // 4 --> 8
				const uint64_t packet_start = be64toh(align_uint64((void*)&read_buffer[cur]));
				cur += 8; // 8 --> 16
				const uint64_t size = getter_uint64(file_n,INT_MIN,f,offsetof(struct file_list,size));
				const uint8_t splits_nn = getter_uint8(file_n,INT_MIN,f,offsetof(struct file_list,splits));
				const int16_t section = section_determination(size,splits_nn,packet_start);
				if(section < 0)
				{ // Very necessary to check
					error_printf(0,"Peer asked us to write beyond file size: %lu. Buggy peer. Bailing.",packet_start);
					continue;
				}
				uint64_t section_end = 0;
				const uint64_t section_start = calculate_section_start(&section_end,size,splits_nn,section);
				torx_read(file_n) // 🟧🟧🟧
				if(peer[file_n].file[f].split_status_n == NULL || peer[file_n].file[f].split_status_fd == NULL || peer[file_n].file[f].split_progress == NULL)
				{ // TODO This triggers upon file completion when we have been offered two identical files with different names, and we selected the second.
					torx_unlock(file_n) // 🟩🟩🟩
					error_simple(0,"Peer asked us to write to a file without calling initialize_split_info, or upon a cancelled file. Coding error. Report this. Bailing.");
					continue; // This could occur if a peer mistakenly sent us a FILE_PIECE of a file we initially offered
				}
				const uint64_t section_info_current = peer[file_n].file[f].split_progress[section];
				const int8_t relevant_split_status_fd = peer[file_n].file[f].split_status_fd[section];
				const int relevant_split_status = peer[file_n].file[f].split_status_n[section];
				torx_unlock(file_n) // 🟩🟩🟩
				if(packet_start + packet_len - cur > section_end + 1)
				{
					error_printf(0,"Peer asked us to write beyond section end: %lu + %lu - %lu > %lu + 1. Buggy peer. Bailing.",packet_start,packet_len,cur,section_end);
					continue;
				}
				else if(packet_start != section_start + section_info_current)
				{
					error_printf(0,"Peer asked us to write non-sequentially: %lu != %lu + %lu. Could be caused by lost packets or pausing/unpausing rapidly before old stream stopped. Bailing.",packet_start,section_start,section_info_current);
					continue;
				}
				else if(relevant_split_status != event_strc->n || relevant_split_status_fd != event_strc->fd_type)
				{ // TODO TODO TODO 2024/02/27 this can result in _FILE_PAUSE reply spam. sending a pause (or thousands) isn't a perfect solution.
					error_simple(0,"Peer asked us to write to an improper section or to a complete file. This can happen if connections break or when a pause is issued."); // No harm if not excessive. Just discard.
					error_printf(0,"Checkpoint improper: n=%d f=%d, section = %d, %d != %d , %d != %d, start position: %lu",event_strc->n,f,section,relevant_split_status,event_strc->n,relevant_split_status_fd,event_strc->fd_type,packet_start);
				//	breakpoint();
				/*	if(!sent_pause++)
					{
						unsigned char checksum[CHECKSUM_BIN_LEN];
						getter_array(&checksum,sizeof(checksum),event_strc->n,INT_MIN,f,offsetof(struct file_list,checksum));
						message_send(event_strc->n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
						sodium_memzero(checksum,sizeof(checksum));
						section_unclaim(event_strc->n,-1); // we dont know precisely what fd the file_pause will go out on, so unclaim all.
					} */
					continue;
				}
				torx_fd_lock(file_n,f) // 🟥🟥🟥🟥
				torx_read(file_n) // 🟧🟧🟧
				FILE *fd_active = peer[file_n].file[f].fd;
				torx_unlock(file_n) // 🟩🟩🟩
				if(fd_active == NULL)
				{
					char *file_path = getter_string(file_n,INT_MIN,f,offsetof(struct file_list,file_path));
					if(!file_path)
					{ // TODO should probably send ENUM_PROTOCOL_FILE_PAUSE
						torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
						error_simple(0,"Incoming file lacks defined path. Coding error. Report this.");
						continue;
					}
					fd_active = fopen(file_path, "a"); // Create file if not existing
					if(fd_active == NULL)
					{ // TODO should probably send ENUM_PROTOCOL_FILE_PAUSE
						torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
						error_printf(0,"Failed to open for writing1: %s",file_path);
						torx_free((void*)&file_path);
						continue;
					}
					close_sockets_nolock(fd_active)
					fd_active = fopen(file_path, "r+"); // Open file for writing
					if(fd_active == NULL)
					{ // TODO should probably send ENUM_PROTOCOL_FILE_PAUSE
						torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
						error_printf(0,"Failed to open for writing2: %s",file_path);
						torx_free((void*)&file_path);
						continue;
					}
					torx_free((void*)&file_path);
				}
				fseek(fd_active,(long int)packet_start,SEEK_SET); // TODO bad to cast here  // TODO 2024/12/20 + 2024/12/28 segfaulted here during group file transfer, on 'local' being null. 2025/01/02 SIGABRT on group file transfer.
				const size_t wrote = fwrite(&read_buffer[cur],1,packet_len-cur,fd_active); // TODO 2024/12/17 segfaulted here during group file transfer
				torx_write(file_n) // 🟥🟥🟥
				peer[file_n].file[f].fd = fd_active;
				torx_unlock(file_n) // 🟩🟩🟩
				torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
				if(wrote == 0)
					error_simple(0,"Failed to write a file packet. Check disk space (this message will repeat for every packet).");
				else if(wrote != (size_t) packet_len-cur) // Should inform user that they are out of disk space, or IO error.
					error_simple(-1,"Failed to write a file packet. Check disk space (this message will NOT repeat).");
				else
				{
					section_update(file_n,f,packet_start,wrote,event_strc->fd_type,section,section_end,event_strc->n);
					transfer_progress(file_n,f); // calling every packet is a bit extreme but necessary. It should handle or we could put an intermediary function.
				}
			}
			else
			{ // Process messages
			#endif // NO_FILE_TRANSFER
				int8_t complete = 0; // if incomplete, do not print it or save it to file yet
				uint32_t buffer_len = torx_allocation_len(event_strc->buffer);
				if(buffer_len == 0)
				{ // this is only on FIRST PACKET of message // protocol check is a sanity check. it is optional.
				//	error_printf(0,"Checkpoint setting event_strc->untrusted_message_len = %u",event_strc->untrusted_message_len);
					event_strc->untrusted_message_len = be32toh(align_uint32((void*)&read_buffer[cur]));
					cur += 4; // 4 --> 8
				}
				if(buffer_len + (packet_len - cur) == event_strc->untrusted_message_len) // 2024/02/16 can be == , >= is to catch excessive, just in case
					complete = 1;
				else if(buffer_len && buffer_len + (packet_len - cur) > event_strc->untrusted_message_len) // Note: buffer_len is required because otherwise this is perhaps 2+ packets.
				{ // XXX Experiemntal XXX 2023/10/24 should disable this, since it generally can't trigger if we have >= above // 2024/06/20 this triggered with all bad info when we were debugging a race condition elsewhere
					error_printf(0,"Disgarding a oversized message of protocol: %u, buffer_len: %u, packet_len: %u, cur: %u, untrusted_message_len: %u. Report this for science.",protocol,buffer_len,packet_len,cur,event_strc->untrusted_message_len);
					break;
				} // XXX 2024/12/25 Disgarding a oversized message of protocol: 56237, buffer_len: 490, packet_len: 409, cur: 4, untrusted_message_len: 0. Report this for science.
				// Allocating only enough space for current packet, not enough for .untrusted_message_len , This is slow but safe... could allocate larger blocks though
				if(event_strc->buffer)
					event_strc->buffer = torx_realloc(event_strc->buffer,buffer_len + (packet_len - cur));
				else
					event_strc->buffer = torx_secure_malloc(packet_len - cur);
				memcpy(&event_strc->buffer[buffer_len],&read_buffer[cur],packet_len - cur);
				buffer_len += packet_len - cur;
				if(complete) // XXX XXX XXX NOTE: All SIGNED messages must be in the COMPLETE area. XXX XXX XXX
				{ // This has to be after the file struct is loaded (? what?)
					const int p_iter = protocol_lookup(protocol);
					if(p_iter < 0)
					{ // NOTE: We can't utilize group_check_sig to determine group_peer_n because we don't know if it is signed.
						error_printf(0,"Unknown protocol message received (%u) on Owner (%u) and n (%d). User should be notified.",protocol,event_strc->owner,event_strc->n);
						unknown_cb(event_strc->n,protocol,event_strc->buffer,buffer_len); // Note: this could include a signature. We don't check.
						event_strc->buffer = NULL; // XXX IMPORTANT: to prevent the message from being torx_free'd when we hit continue;
						continue;
					}
					pthread_rwlock_rdlock(&mutex_protocols); // 🟧
					const uint8_t group_mechanics = protocols[p_iter].group_mechanics;
					const uint32_t date_len = protocols[p_iter].date_len;
					const uint32_t signature_len = protocols[p_iter].signature_len;
					#ifndef NO_FILE_TRANSFER
					const uint8_t file_offer = protocols[p_iter].file_offer;
					#endif // NO_FILE_TRANSFER
					const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
					const uint8_t utf8 = protocols[p_iter].utf8;
					const uint8_t group_pm = protocols[p_iter].group_pm;
					const uint8_t group_msg = protocols[p_iter].group_msg;
					const uint8_t stream = protocols[p_iter].stream;
					const char *name = protocols[p_iter].name;
					pthread_rwlock_unlock(&mutex_protocols); // 🟩
					uint8_t discard_after_processing = 0; // Certain protocols are utilized by library only and do not need to be notified to the UI
					if(buffer_len < null_terminated_len + date_len + signature_len)
					{
						error_printf(0,"Unreasonably short message received from peer. Discarding entire message protocol: %u owner: %u size: %u of reported: %u",protocol,event_strc->owner,buffer_len,event_strc->untrusted_message_len);
						continue;
					}
					else if(event_strc->owner != ENUM_OWNER_GROUP_CTRL && event_strc->owner != ENUM_OWNER_GROUP_PEER && (group_mechanics || group_pm))
					{
						error_simple(0,"Group message received on non-group. Buggy peer or coding error. Report this.");
						continue;
					}
					error_printf(2,CYAN"<--IN%d %s %u"RESET,event_strc->fd_type,name,event_strc->untrusted_message_len);
					if(signature_len)
					{ // XXX Signed and Signed Date messages only
						if(event_strc->owner == ENUM_OWNER_GROUP_CTRL || event_strc->owner == ENUM_OWNER_GROUP_PEER) // XXX adding GROUP_PEER without testing for full duplex
						{ // Check signatures of group messages (unknown sender), then handle any actions that should be taken for specific message types
							group_peer_n = group_check_sig(event_strc->g,event_strc->buffer,buffer_len - signature_len,protocol,(unsigned char *)&event_strc->buffer[buffer_len - crypto_sign_BYTES],NULL);
							if(group_peer_n < 0)
							{ // Disgard if not signed by someone in group TODO notify user? print anonymous message? (no, encourages spam)
								error_simple(0,"Group received an anonymous message. Nothing we can do with it.");
								error_printf(0,PINK"Checkpoint set_g=%d ?= event_strc->g=%d"RESET,set_g(event_strc->n,NULL),event_strc->g); // TODO if different, the bug is set_g / event_strc->g
								break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
							}
							if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
							{ // After receiving this, we should be able to process unsigned messages as having known receiver, on this connection.
								if(event_strc->owner == ENUM_OWNER_GROUP_PEER)
								{ // This connection is already authenticated, no need to re-authenticate it. Not verifying authenticity.
									error_simple(0,"Repeated authentication received on a GROUP_PEER. No issue. Carry on.");
									break;
								}
								else if(pipe_auth_inbound(event_strc) < 0)
								{
									error_printf(0,"Received a INVALID ENUM_PROTOCOL_PIPE_AUTH on GROUP_CTRL: fd_type=%d owner=%u len=%u",event_strc->fd_type,event_strc->owner,buffer_len);
									break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
								}
								// Success. Set recvfd in the appropriate GROUP_PEER to enable full duplex on that GROUP_PEER
								/* TODO If ANY issues EVER arise due to race conditions in this block, replace ALL locks/unlocks with a single pthread_rwlock_wrlock(&mutex_expand); TODO */ 
								torx_read(event_strc->n) // 🟧🟧🟧 Do not mess with this block. (below)
								struct bufferevent *bev_recv = peer[event_strc->n].bev_recv;
								torx_unlock(event_strc->n) // 🟩🟩🟩
								torx_write(group_peer_n) // 🟥🟥🟥
								peer[group_peer_n].bev_recv = bev_recv; // 1st, order important
								torx_unlock(group_peer_n) // 🟩🟩🟩
								torx_write(event_strc->n) // 🟥🟥🟥
								peer[event_strc->n].bev_recv = NULL; // 2nd, order important. do not free.
								torx_unlock(event_strc->n) // 🟩🟩🟩 Do not mess with this block. (above.. also some below. This whole thing is important)
								event_strc->n = group_peer_n; // 3rd, order important. DO NOT PUT SOONER.
								setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd),&event_strc->sockfd,sizeof(event_strc->sockfd)); // important
								const uint8_t recvfd_connected = 1; // important
							//	error_printf(0,"Checkpoint recvfd connected 1 n=%d",event_strc->n);
								setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));
								event_strc->owner = ENUM_OWNER_GROUP_PEER; // important
								event_strc->authenticated = 1;
								/* TODO If ANY issues EVER arise due to race conditions in this block, replace ALL locks/unlocks with a single pthread_rwlock_unlock(&mutex_expand); TODO */ 
								begin_cascade(event_strc);
								peer_online(event_strc);
								discard_after_processing = 1;
							}
							else if(protocol == ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST) // TODO some rate limiting might be prudent
							{
								if(buffer_len != sizeof(uint32_t) + DATE_SIGN_LEN)
								{
									error_simple(0,"Peer sent totally empty REQUEST_PEERLIST. Buggy peer.");
									continue;
								}
								const uint32_t peer_g_peercount = be32toh(align_uint32((void*)event_strc->buffer));
								const uint32_t g_peercount = getter_group_uint32(event_strc->g,offsetof(struct group_list,peercount));
								if(peer_g_peercount < g_peercount)
								{ // Peer has less in their list than us, lets give them our list
									error_printf(2,"Sending peerlist because %u < %u",peer_g_peercount,g_peercount);
									if(event_strc->invite_required)
										message_send(group_peer_n,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(event_strc->g),GROUP_PEERLIST_PRIVATE_LEN);
									else
										message_send(group_peer_n,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(event_strc->g),GROUP_PEERLIST_PUBLIC_LEN);
								}
								else
									error_printf(2,"NOT sending peerlist because %u !< %u\n",peer_g_peercount,g_peercount);
							}
							else if(protocol == ENUM_PROTOCOL_GROUP_PEERLIST)
							{ // Audited 2024/02/16 // Format: g_peercount + onions + ed25519 keys + invitation sigs
								if(buffer_len < sizeof(uint32_t) + DATE_SIGN_LEN)
								{
									error_simple(0,"Peer sent totally empty PEERLIST. Buggy peer.");
									continue;
								}
								const uint32_t g_peercount = be32toh(align_uint32((void*)event_strc->buffer));
								size_t expected_len;
								if(event_strc->invite_required)
									expected_len = GROUP_PEERLIST_PRIVATE_LEN;
								else
									expected_len = GROUP_PEERLIST_PUBLIC_LEN;
								if(!g_peercount || expected_len + DATE_SIGN_LEN != buffer_len)
								{ // Prevent illegal reads from malicious message
									error_printf(0,"Peer sent an invalid sized ENUM_PROTOCOL_GROUP_PEERLIST. Bailing. %u: %zu != %u",g_peercount,expected_len,buffer_len);
									continue;
								}
								int added_one = 1;
								while(added_one)
								{ // need to re-do the whole loop every time one or more is added because it might have invited someone
									for(uint32_t count = 0 ; count < g_peercount ; count++)
									{ // Try each proposed peeronion...
										added_one = 0;
										const char *proposed_peeronion = &event_strc->buffer[sizeof(int32_t)+count*56];
										const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[sizeof(int32_t)+g_peercount*56+count*crypto_sign_PUBLICKEYBYTES];
										int ret;
										if(event_strc->invite_required) // pass inviter's signature
										{
											const unsigned char *group_peer_invitation = (unsigned char *)&event_strc->buffer[sizeof(int32_t)+g_peercount*(56+crypto_sign_PUBLICKEYBYTES)+count*crypto_sign_BYTES];
										//	error_printf(0,"Checkpoint invitation/sig in at %lu of %u: %s",sizeof(int32_t)+g_peercount*(56+crypto_sign_PUBLICKEYBYTES)+count*crypto_sign_BYTES,buffer_len,b64_encode(group_peer_invitation,crypto_sign_BYTES));
											ret = group_add_peer(event_strc->g,proposed_peeronion,NULL,group_peer_ed25519_pk,group_peer_invitation);
										}
										else
											ret = group_add_peer(event_strc->g,proposed_peeronion,NULL,group_peer_ed25519_pk,NULL);
										if(ret == -1)
										{
											error_simple(0,"Incoming peerlist has errors. Bailing.");
											break;
										}
										else if(ret != -2)
										{ // -2 is "already have it"
											added_one++;
											error_simple(0,RED"Checkpoint New group peer! (read_conn 1)"RESET);
											if(event_strc->invite_required)
												message_send(ret,ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST,itovp(event_strc->g),GROUP_PRIVATE_ENTRY_REQUEST_LEN);
											else
											{
												unsigned char ciphertext_new[GROUP_BROADCAST_LEN];
												broadcast_prep(ciphertext_new,event_strc->g);
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
							unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
							getter_array(&peer_sign_pk,sizeof(peer_sign_pk),event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peer_sign_pk));
							char *prefixed_message = affix_protocol_len(protocol,event_strc->buffer,buffer_len - crypto_sign_BYTES);
							if(crypto_sign_verify_detached((unsigned char *)&event_strc->buffer[buffer_len - crypto_sign_BYTES],(unsigned char *)prefixed_message,2+4+buffer_len - crypto_sign_BYTES,peer_sign_pk) != 0)
							{
								sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
								error_printf(0,"Invalid signed (%u) message of len (%u) received from peer.",protocol,buffer_len);
								char *signature_b64 = b64_encode(event_strc->buffer,crypto_sign_BYTES);
								error_printf(3,"Inbound Signature: %s",signature_b64);
								torx_free((void*)&signature_b64);
								torx_free((void*)&prefixed_message);
								continue;
							}
							sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
							torx_free((void*)&prefixed_message);
							if(protocol == ENUM_PROTOCOL_PIPE_AUTH)
							{ // Authenticating a _CTRL, not _GROUP_CTRL
								if(pipe_auth_inbound(event_strc) < 0)
								{
									error_printf(0,"Received a INVALID ENUM_PROTOCOL_PIPE_AUTH on CTRL: fd_type=%d owner=%u len=%u",event_strc->fd_type,event_strc->owner,buffer_len);
									break; // XXX ERROR that indicates corrupt packet, a packet that will corrupt buffer, or a buggy peer ; Disconnect.
								}
								event_strc->authenticated = 1;
								const uint8_t recvfd_connected = 1;
							//	error_printf(0,"Checkpoint recvfd connected 2 n=%d",event_strc->n);
								setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));
								begin_cascade(event_strc); // should go immediately after <fd_type>_connected = 1
								peer_online(event_strc);
								if(threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled) == 1)
								{ // propose upgrade
									error_simple(0,PINK"Checkpoint ENUM_PROTOCOL_PROPOSE_UPGRADE 2"RESET);
									const uint16_t trash_version = htobe16(torx_library_version[0]);
									message_send(event_strc->n,ENUM_PROTOCOL_PROPOSE_UPGRADE,&trash_version,sizeof(trash_version));
								}
								error_simple(0,RED"Checkpoint authed a CTRL"RESET);
							}
						}
					}
					int nn;
					if(group_peer_n > -1)
						nn = group_peer_n; // save message to GROUP_PEER not GROUP_CTRL so that we know who sent it without having to determine it again
					else
						nn = event_strc->n;
					if(protocol == ENUM_PROTOCOL_PROPOSE_UPGRADE)
					{ // Receive Upgrade Proposal // Note: as of current, the effect of this will likely be delayed until next program start
						if(buffer_len != sizeof(uint16_t) + crypto_sign_BYTES)
						{
							error_simple(0,"Propose upgrade of bad size received.");
							continue;
						}
						const uint16_t new_peerversion = be16toh(align_uint16((void*)&event_strc->buffer[0]));
						const uint16_t peerversion = getter_uint16(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
						if(new_peerversion > peerversion)
						{ // Note: currently not facilitating downgrades because we would have to take down sendfd
							error_printf(0,"Received an upgrade proposal: %u > %u",new_peerversion,peerversion);
							setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peerversion),&new_peerversion,sizeof(new_peerversion));
							sql_update_peer(event_strc->n);
						/*	if(event_strc->fd_type == 0 && new_peerversion < 2)
								event_strc->authenticated = 0; */
						}
						discard_after_processing = 1;
					}
					#ifndef NO_FILE_TRANSFER
					else if(file_offer)
					{ // Receive File offer, any type
						if(process_file_offer_inbound(nn,p_iter,event_strc->buffer,buffer_len) == -1)
							continue; // important to discard invalid offer
						if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
							discard_after_processing = 1;
					}
					else if(protocol == ENUM_PROTOCOL_FILE_REQUEST)
					{ // Receive File Request (acceptance) // TODO possible source of race conditions if actively transferring when received? (common scenario, not sure how dangerous)
						if(buffer_len != FILE_REQUEST_LEN)
						{
							error_simple(0,"File request of bad size received.");
							continue;
						}
						int file_n = event_strc->n;
						int f = set_f(file_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
						if(f < 0 && event_strc->owner == ENUM_OWNER_GROUP_PEER)
						{ // potential group file transfer, non-pm
							file_n = event_strc->group_n;
							f = set_f(file_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
						}
						if(f < 0) // NOT else if, we set f again above
						{
							error_simple(0,"Received a request for an unknown file. Bailing out.");
							continue;
						}
						const int file_status = file_status_get(file_n,f);
						if(file_status == ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND || file_status == ENUM_FILE_INACTIVE_CANCELLED)
						{
							error_printf(0,"Peer requested a file that is of a status we're not willing to send: %d",file_status);
							continue;
						}
						const uint64_t size = getter_uint64(file_n,INT_MIN,f,offsetof(struct file_list,size));
						const uint64_t requested_start = be64toh(align_uint64((void*)&event_strc->buffer[CHECKSUM_BIN_LEN]));
						const uint64_t requested_end = be64toh(align_uint64((void*)&event_strc->buffer[CHECKSUM_BIN_LEN+sizeof(uint64_t)]));
						char *file_path = getter_string(file_n,INT_MIN,f,offsetof(struct file_list,file_path));
						if(file_path == NULL || requested_start > size - 1 || requested_end > size - 1)
						{ // Sanity check on request. File might not exist if size is 0
							error_simple(0,"Unknown file or peer requested more data than exists. Bailing. Report this.");
							error_printf(0,"Checkpoint start=%"PRIu64" end=%"PRIu64" size=%"PRIu64"",requested_start,requested_end,size);
							error_printf(0,"Checkpoint path: %s",file_path);
							torx_free((void*)&file_path);
							continue;
						}
						if(file_status == ENUM_FILE_INACTIVE_COMPLETE)
						{ // Verifying that file has not been modified since initially offering it to a peer (or since completing transfer, if a group file)
							struct stat file_stat = {0};
							time_t modified = getter_time(file_n,INT_MIN,f,offsetof(struct file_list,modified));
							const int stat_ret = stat(file_path, &file_stat);
							if(stat_ret)
							{ // File does not exist
								error_simple(0,"Requested file cannot be accessed. Try re-offering it.");
								error_printf(0,"Checkpoint path: %s %ld ?= %ld",file_path,(long)file_stat.st_mtime,(long)modified);
								torx_free((void*)&file_path);
								continue;
							}
							else if(file_stat.st_mtime != modified)
							{ // File cannot be accessed or has an unexpected modification time XXX MUST BE THE SAME AS BELOW torx_fd_lock
								torx_fd_lock(file_n,f) // 🟥🟥🟥🟥 // XXX MUST BE BETWEEN REDUNDANT CHECKS. XXX To prevent two requests that come in at nearly the same time from causing the file to unnecessarily be checksum'd twice.
								if(file_stat.st_mtime != modified)
								{ // Checking again (redundantly) XXX MUST BE THE SAME AS ABOVE torx_fd_lock
									unsigned char checksum[CHECKSUM_BIN_LEN];
									unsigned char checksum_unverified[CHECKSUM_BIN_LEN];
									getter_array(checksum,sizeof(checksum),file_n,INT_MIN,f,offsetof(struct file_list,checksum));
									if(file_n == event_strc->group_n)
									{ // File exists and is group transfer XXX NOTE: If we hit this commonly without modifying file, make sure we are actually setting the modified time when file completes
										error_simple(0,"Re-checking group file because modification time has changed. This is undesirable. Report this.");
										const uint8_t splits = getter_uint8(file_n,INT_MIN,f,offsetof(struct file_list,splits));
										unsigned char *split_hashes_and_size = file_split_hashes(checksum_unverified,file_path,splits,size);
										torx_free((void*)&split_hashes_and_size); // We don't need this, we just need the hash of hashes.
									}
									else
									{ // File exists and is P2P or PM
										error_simple(0,"Re-checking file because modification time has changed. This is undesirable. Report this.");
										b3sum_bin(checksum_unverified,file_path,NULL,0,0);
									}
									const int cmp = memcmp(checksum,checksum_unverified,CHECKSUM_BIN_LEN);
									sodium_memzero(checksum,sizeof(checksum));
									sodium_memzero(checksum_unverified,sizeof(checksum_unverified));
									if(cmp)
									{
										torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
										error_simple(0,"Requested file does not match modification time or hash. It has been modified or corrupted since receiving. You may re-offer the modified file.");
										torx_free((void*)&file_path);
										continue;
									}
									modified = file_stat.st_mtime; // Updating modification time in struct after verifying checksums, and carrying on.
									setter(file_n,INT_MIN,f,offsetof(struct file_list,modified),&modified,sizeof(modified));
								}
								torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
							}
						}
						// XXX NOTICE: For group transfers, the following are in the GROUP_PEER, which lacks filename and path, which only exists in GROUP_CTRL. 
						const int r = set_r(file_n,f,event_strc->n);
						if(r > -1)
						{
							torx_write(file_n) // 🟥🟥🟥
							if(peer[file_n].file[f].request)
							{ // Necessary sanity check to prevent race condition
								peer[file_n].file[f].request[r].start[event_strc->fd_type] = requested_start;
								peer[file_n].file[f].request[r].end[event_strc->fd_type] = requested_end;
								peer[file_n].file[f].request[r].previously_sent += peer[file_n].file[f].request[r].transferred[event_strc->fd_type]; // Need to store the progress before clearing it
								peer[file_n].file[f].request[r].transferred[event_strc->fd_type] = 0;
							}
							torx_unlock(file_n) // 🟩🟩🟩
						}
						// file pipe START (useful for resume) Section 6RMA8obfs296tlea
						torx_free((void*)&file_path);
						error_printf(0,"Checkpoint read_conn sending: from %"PRIu64" to %"PRIu64" on owner=%u peer=%d fd_type=%d",requested_start,requested_end,event_strc->owner,event_strc->n,event_strc->fd_type);
						send_prep(event_strc->n,file_n,f,file_piece_p_iter,event_strc->fd_type); // formerly used protocol_lookup(ENUM_PROTOCOL_FILE_PIECE)
						// file pipe END (useful for resume) Section 6RMA8obfs296tlea
						continue; // because this is now stream
					}
					else if(protocol == ENUM_PROTOCOL_FILE_INFO_REQUEST || protocol == ENUM_PROTOCOL_FILE_PARTIAL_REQUEST || protocol == ENUM_PROTOCOL_FILE_PAUSE || protocol == ENUM_PROTOCOL_FILE_CANCEL)
					{
					//	error_printf(0,"Checkpoint receiving PAUSE or CANCEL is experimental with groups/PM: owner=%d",owner);
						if(buffer_len != CHECKSUM_BIN_LEN)
						{
							error_simple(0,"File pause, cancel, or info request of bad size received.");
							continue;
						}
						int file_n = event_strc->n;
						int f = set_f(file_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
						if(f < 0 && event_strc->owner == ENUM_OWNER_GROUP_PEER)
						{ // potential group file transfer, non-pm
							file_n = event_strc->group_n;
							f = set_f(file_n,(const unsigned char*)event_strc->buffer,CHECKSUM_BIN_LEN-1); // -1 because we need it to be able to return -1
						}
						if(f < 0) // NOT else if, we set f again above
						{
							error_printf(0,"Received %s for an unknown file. Bailing out.",name);
							continue;
						}
						if(protocol == ENUM_PROTOCOL_FILE_INFO_REQUEST)
						{
							file_offer_internal(event_strc->n,file_n,f,0); // Respond with an offer so that the peer can get the info they need
							discard_after_processing = 1;
						}
						else if(protocol == ENUM_PROTOCOL_FILE_PARTIAL_REQUEST)
						{ // Respond with a _PARTIAL if we have the file
							torx_read(file_n) // 🟧🟧🟧
							const uint8_t file_path_exists = peer[file_n].file[f].file_path ? 1 : 0;
							torx_unlock(file_n) // 🟩🟩🟩
							if(file_path_exists)
							{ // We have this file, so respond
								const uint8_t splits = getter_uint8(file_n,INT_MIN,f,offsetof(struct file_list,splits));
								struct file_request_strc file_request_strc = {0};
								file_request_strc.n = file_n;
								file_request_strc.f = f;
								message_send(event_strc->n,ENUM_PROTOCOL_FILE_OFFER_PARTIAL,&file_request_strc,FILE_OFFER_PARTIAL_LEN);
							}
							discard_after_processing = 1;
						}
						else // if(protocol == ENUM_PROTOCOL_FILE_PAUSE || protocol == ENUM_PROTOCOL_FILE_CANCEL)
							process_pause_cancel(event_strc->n,f,event_strc->n,protocol,ENUM_MESSAGE_RECV);
					}
					#endif // NO_FILE_TRANSFER
					else if(protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
					{ // Receive GROUP_OFFER
						if((protocol == ENUM_PROTOCOL_GROUP_OFFER && buffer_len != GROUP_OFFER_LEN) || (protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST && buffer_len != GROUP_OFFER_FIRST_LEN))
						{
							error_simple(0,"Group offer of bad size received.");
							continue;
						}
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
						if((protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT && buffer_len != GROUP_OFFER_ACCEPT_LEN) || (protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST && buffer_len != GROUP_OFFER_ACCEPT_FIRST_LEN) || (protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY && buffer_len != GROUP_OFFER_ACCEPT_REPLY_LEN))
						{
							error_simple(0,"Group offer accept or accept reply of bad size received.");
							break;
						}
						const int g = set_g(-1,event_strc->buffer); // reserved, already existing
						const int group_n = getter_group_int(g,offsetof(struct group_list,n));
						if(group_n < -1)
						{
							error_simple(0,"Sanity check failed on a received Group Offer Accept.");
							break;
						}
						const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
						if(g_invite_required == 0)
						{ // Sanity check continued
							error_simple(0,"Public groups are not accepted in this manner. One client is buggy. Coding error. Report this.");
							break; // 2024/03/11 triggered upon startup after deleting a group that didn't complete handshake
						}
						else
						{
							unsigned char invitation[crypto_sign_BYTES];
							getter_array(&invitation,sizeof(invitation),group_n,INT_MIN,-1,offsetof(struct peer_list,invitation));
							const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[GROUP_ID_SIZE+56];
							pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
							const int *peerlist = group[g].peerlist;
							pthread_rwlock_unlock(&mutex_expand_group); // 🟩
							if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT || protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST)
							{
								if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST && is_null(invitation,crypto_sign_BYTES))
								{ // NOTE: race condition. Once we set the invitation, anyone else who accepts our invite ... umm... lost thought there.
									unsigned char verification_message[56+crypto_sign_PUBLICKEYBYTES];
									getter_array(verification_message,56,group_n,INT_MIN,-1,offsetof(struct peer_list,onion));
									unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
									getter_array(&sign_sk,sizeof(sign_sk),group_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
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
									setter(group_n,INT_MIN,-1,offsetof(struct peer_list,invitation),&invitation,sizeof(invitation));
									sql_update_peer(group_n);
								}
							//	else if(protocol == ENUM_PROTOCOL_GROUP_OFFER_ACCEPT)
							//		message_send(event_strc->n,ENUM_PROTOCOL_GROUP_PEERLIST,itoa(g)); // send a peerlist because this person doesn't have one
							//	group_add_peer(g,group_peeronion,peer[event_strc->n].peernick,group_peer_ed25519_pk,invitation); // note: was in message_send, moving up instead
								if(invitee_remove(g,event_strc->n))
								{
									error_simple(0,"Peer requested invitation into a group we have no record of inviting them into, or requested multiple invites. Refusing.");
									sodium_memzero(invitation,sizeof(invitation));
									continue;
								}
								struct int_char int_char;
								int_char.i = g;
								int_char.p = &event_strc->buffer[GROUP_ID_SIZE]; // group_peeronion;
								int_char.up = group_peer_ed25519_pk;
							//	error_simple(0,"Checkpoint sending ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY. If this was sent as a private message, this needs to be sent to group_peer_n not n"); // TODO delete message if non-applicable
								message_send(event_strc->n,ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY,&int_char,GROUP_OFFER_ACCEPT_REPLY_LEN); // this calls group_add_peer
							}
							else if(peerlist == NULL) // ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY
							{ // If peerlist not NULL, this is a malicious message possibly.
								if(is_null(invitation,crypto_sign_BYTES))
								{ // collect their signature of our group ctrl ( will always be passed, but we don't always need to take it if we already have one )
								// TODO TODO TODO XXX Exploitable??? if this is *always* passed, then malicious actors can switch theirs and change who invited them to the channel??
								// TODO Prevent by not sending ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY unless we already sent them an offer. So, we need to track offers.
									error_simple(2,"Receiving a group invitation signature.");
									memcpy(invitation,&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES],crypto_sign_BYTES);
									setter(group_n,INT_MIN,-1,offsetof(struct peer_list,invitation),&invitation,sizeof(invitation));
									sql_update_peer(group_n);
								}
								unsigned char invitor_invitation[crypto_sign_BYTES];
								memcpy(invitor_invitation,&event_strc->buffer[GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES],crypto_sign_BYTES);
								char *peernick = getter_string(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peernick));
								const int peer_n = group_add_peer(g,&event_strc->buffer[GROUP_ID_SIZE],peernick,group_peer_ed25519_pk,invitor_invitation);
								if(peer_n > -1)
								{
									error_simple(0,RED"Checkpoint New group peer!(read_conn 2)"RESET);
								//	const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
								//	if(peercount == 1) // This only *needs* to run on first connection.... in any other circumstance, new peers should find us.
								//		message_send(peer_n,ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,NULL,0);
								//	else
								//		error_printf(0,"Checkpoint NOT REQUESTING peerlist2. Peercount==%u",peercount);
								}
								torx_free((void*)&peernick);
								sodium_memzero(invitor_invitation,sizeof(invitor_invitation));
							}
							else
								breakpoint();
							sodium_memzero(invitation,sizeof(invitation));
						}
					}
					else if(protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST) // New peer wants to connect to a group we are in.
					{ // Format: their onion + their ed25519_pk + invitation signature of their onion+pk (by someone already in group). Message itself is not signed but the onion+pk they pass is signed
						if(event_strc->owner != ENUM_OWNER_GROUP_CTRL) // should ONLY come in on a GROUP_CTRL
						{
							error_printf(0,"Received private entry request on wrong owner type. Possibly malicious intent or buggy peer: %u",event_strc->owner);
							break;
						}
						const int invitor_n = group_check_sig(event_strc->g,event_strc->buffer,56+crypto_sign_PUBLICKEYBYTES,0,(unsigned char *)&event_strc->buffer[56+crypto_sign_PUBLICKEYBYTES],NULL); // 0 is fine for protocol here because protocol is not signed
						if(invitor_n < 0)// (1) We should verify the signature is from some peer we have
						{ // Disgard if not signed by someone in group
							error_simple(0,"Disregarding a GROUP_PRIVATE_ENTRY_REQUEST from someone.");
							break;
						}
						const char *proposed_peeronion = event_strc->buffer;
						const unsigned char *group_peer_ed25519_pk = (unsigned char *)&event_strc->buffer[56];
						const unsigned char *inviter_signature = (unsigned char *)&event_strc->buffer[56+crypto_sign_PUBLICKEYBYTES];
						const int new_peer = group_add_peer(event_strc->g,proposed_peeronion,NULL,group_peer_ed25519_pk,inviter_signature); // (2) We group_add_peer them.
						if(new_peer == -1)
						{ // Error
							error_simple(0,"New peer is -1 therefore there was an error. Bailing.");
							break;
						}
						else if(new_peer != -2)
						{ // Approved a new peer
							error_simple(0,RED"Checkpoint New group peer! (read_conn 3)"RESET);
					//		error_simple(3,"Received ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST. Responding with peerlist.");
					//		const uint32_t g_peercount = getter_group_uint32(event_strc->g,offsetof(struct group_list,peercount));
					//		message_send(new_peer,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(event_strc->g),GROUP_PEERLIST_PRIVATE_LEN); // (3) respond with peerlist
						}
					}
					else if(protocol == ENUM_PROTOCOL_GROUP_BROADCAST || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)
					{
						if(buffer_len == GROUP_BROADCAST_LEN)
							broadcast_inbound(event_strc->n,(unsigned char *)event_strc->buffer); // this can rebroadcast or handle
						else
						{
							error_printf(0,"Requested rebroadcast of bad broadcast. Bailing. Protocol: %u with an odd lengthed broadcast: %u instead of expected %u.",protocol,buffer_len,GROUP_BROADCAST_LEN);
							breakpoint(); // TODO NOTICE: if this gets hit, its probably due to our DATE_SIGN_LEN. delete it if the math permits.
							continue;
						}
					}
					#ifndef NO_STICKERS
					else if(protocol == ENUM_PROTOCOL_STICKER_REQUEST)
					{ // Recieved sticker request
						if(torx_allocation_len(event_strc->buffer) >= CHECKSUM_BIN_LEN && threadsafe_read_uint8(&mutex_global_variable,&stickers_send_data))
						{
							const int s = set_s((unsigned char*)event_strc->buffer);
							if(s > -1)
							{ // We have this sticker
								int relevant_n = event_strc->n; // For groups, this should be group_n
								for(int cycle = 0; cycle < 2; cycle++)
								{ // Verify that we previously offered this sticker to this peer. First try n, then group_n upon continue.
									const uint8_t owner = getter_uint8(relevant_n,INT_MIN,-1,offsetof(struct peer_list,owner));
									uint32_t iter = 0;
									pthread_rwlock_rdlock(&mutex_sticker); // 🟧
									const size_t peer_count = torx_allocation_len(sticker[s].peers)/sizeof(int);
									while(iter < peer_count && sticker[s].peers[iter] != relevant_n)
										iter++;
									if(iter == peer_count)
									{ // We didn't previously offer this sticker to this peer
										pthread_rwlock_unlock(&mutex_sticker); // 🟩
										if(owner == ENUM_OWNER_GROUP_PEER)
										{ // if not on peer_n(pm), try group_n (public)
											relevant_n = event_strc->group_n;
											continue;
										}
										else
											error_simple(0,"Peer requested a sticker they dont have access to (either they are buggy or malicious). Report this.");
									}
									else
									{ // Peer requested a sticker we have previously offered to them
										pthread_rwlock_unlock(&mutex_sticker); // 🟩
										unsigned char *data = sticker_retrieve_data(NULL,s);
										data = torx_realloc_shift(data,CHECKSUM_BIN_LEN + torx_allocation_len(data),1); // shift forward for checksum
										memcpy(data,event_strc->buffer,CHECKSUM_BIN_LEN); // prefix the checksum
										message_send(event_strc->n,ENUM_PROTOCOL_STICKER_DATA_GIF,data,torx_allocation_len(data)); // note: this is the new length after realloc, do not re-use old value
										torx_free((void*)&data);
									}
									break;
								}
							}
							else
								error_simple(0,"Peer requested sticker we do not have. Maybe we deleted it.");
						}
					}
					else if(protocol == ENUM_PROTOCOL_STICKER_HASH || protocol == ENUM_PROTOCOL_STICKER_HASH_PRIVATE || protocol == ENUM_PROTOCOL_STICKER_HASH_DATE_SIGNED)
					{ // Received sticker
						if(torx_allocation_len(event_strc->buffer) >= CHECKSUM_BIN_LEN && threadsafe_read_uint8(&mutex_global_variable,&stickers_request_data) && (threadsafe_read_uint8(&mutex_global_variable,&stickers_save_all) || !threadsafe_read_uint8(&mutex_global_variable,&stickers_offload_all)))
						{
							const int s = set_s((unsigned char*)event_strc->buffer);
							if(s < 0 || (!sticker_has_peer(s,event_strc->n) && !sticker_has_peer(s,event_strc->group_n)))
							{ // Don't have sticker, or sticker is not on .peer list (redudantly request sticker prevent sticker based identity correlation), consider requesting it
								uint32_t y = 0;
								torx_write(event_strc->n) // 🟥🟥🟥
								while(y < torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *) && memcmp(peer[event_strc->n].stickers_requested[y], event_strc->buffer, CHECKSUM_BIN_LEN))
									y++;
								if(y == torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *))
								{ // We haven't yet requested it. Check for an empty slot otherwise realloc a new slot.
									y = 0; // necessary
									while(y < torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *) && !is_null(peer[event_strc->n].stickers_requested[y],CHECKSUM_BIN_LEN))
										y++;
									if(y == torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *))
									{ // No empty slot available, must realloc
										if(peer[event_strc->n].stickers_requested)
											peer[event_strc->n].stickers_requested = torx_realloc(peer[event_strc->n].stickers_requested,torx_allocation_len(peer[event_strc->n].stickers_requested) + sizeof(unsigned char *));
										else
											peer[event_strc->n].stickers_requested = torx_insecure_malloc(sizeof(unsigned char *));
										peer[event_strc->n].stickers_requested[y] = torx_secure_malloc(CHECKSUM_BIN_LEN);
									}
									memcpy(peer[event_strc->n].stickers_requested[y],event_strc->buffer,CHECKSUM_BIN_LEN);
									torx_unlock(event_strc->n) // 🟩🟩🟩
									message_send(event_strc->n,ENUM_PROTOCOL_STICKER_REQUEST,event_strc->buffer,CHECKSUM_BIN_LEN);
								}
								else // Requested this sticker already. Not requesting again.
									torx_unlock(event_strc->n) // 🟩🟩🟩
							}
						}
					}
					#endif // NO_STICKERS
					else if(null_terminated_len && utf8 && !utf8_valid(event_strc->buffer,buffer_len - (null_terminated_len + date_len + signature_len)))
					{
						error_simple(0,"Non-UTF8 message received. Discarding entire message.");
						continue;
					}
					if(stream)
					{ // certain protocols discarded after processing, others stream_cb to UI
						const uint32_t data_len = buffer_len - (/*null_terminated_len + */date_len + signature_len); // TODO unclear why we don't do this after if(complete) and only do it in if(stream)
						if(!discard_after_processing)
						{ // Further processing or stream_cb
							#ifndef NO_AUDIO_CALL
							if(data_len >= 8 && (protocol == ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC || protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN || protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE || protocol == ENUM_PROTOCOL_AUDIO_STREAM_LEAVE))
							{
								const time_t time = be32toh(align_uint32((void*)event_strc->buffer)); // this is for the CALL, not MESSAGE
								const time_t nstime = be32toh(align_uint32((void*)&event_strc->buffer[4])); // this is for the CALL, not MESSAGE
								if(!time && !nstime)
								{
									error_simple(0,"Received a AUDIO_STREAM protocol with zero times. Disgarding. Peer is buggy.");
									continue;
								}
								int call_n = event_strc->n;
								int call_c = -1;
								int group_n = -1;
								torx_read(call_n) // 🟧🟧🟧
								for(int c = 0; (size_t)c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); c++)
									if(peer[call_n].call[c].start_time == time && peer[call_n].call[c].start_nstime == nstime)
										call_c = c;
								torx_unlock(call_n) // 🟩🟩🟩
								if(call_c == -1 && event_strc->owner == ENUM_OWNER_GROUP_PEER)
								{ // Try group_n instead
									const int g = set_g(event_strc->n, NULL);
									group_n = getter_group_int(g, offsetof(struct group_list, n));
									call_n = group_n;
									torx_read(call_n) // 🟧🟧🟧
									for(int c = 0; (size_t)c < torx_allocation_len(peer[call_n].call)/sizeof(struct call_list); c++)
										if(peer[call_n].call[c].start_time == time && peer[call_n].call[c].start_nstime == nstime)
											call_c = c;
									torx_unlock(call_n) // 🟩🟩🟩
								} // NOT else if
								if(call_c == -1 && (protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN || protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE))
								{ // Received offer to join a new call
									if(protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE)
										call_n = event_strc->n;
									call_c = set_c(call_n,time,nstime); // reserve
									if(call_c > -1)
									{ // This check should be unnecessary
										torx_write(call_n) // 🟥🟥🟥
										peer[call_n].call[call_c].waiting = 1;
										torx_unlock(call_n) // 🟩🟩🟩
										call_peer_joining(call_n, call_c, event_strc->n);
									}
								}
								else if(call_c > -1)
								{ // Existing call
									if(protocol == ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC)
									{
										torx_read(call_n) // 🟧🟧🟧
										size_t iter = 0; // NOTE: copy of call_participant_iter_by_n
										for( ; iter < torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int) ; iter++)
											if(peer[call_n].call[call_c].participating[iter] == event_strc->n)
												break;
										if(iter == torx_allocation_len(peer[call_n].call[call_c].participating)/sizeof(int))
										{ // WARNING: Do not use iter for anything because it might change in call_peer_leaving
											torx_unlock(call_n) // 🟩🟩🟩
											error_simple(0,"Peer mistakenly sending AUDIO before joining or after leaving a call. Coding error. Report this.");
											continue;
										}
										torx_unlock(call_n) // 🟩🟩🟩
										if(getter_call_uint8(call_n,call_c,-1,offsetof(struct call_list,speaker_on)) && getter_call_uint8(call_n,call_c,event_strc->n,offsetof(struct call_list,participant_speaker)))
										{ // We want this audio
											const time_t audio_time = be32toh(align_uint32((void*)&event_strc->buffer[data_len])); // NOTE: this is intentionally reading outside data_len because that is where *message* date/time is stored by library
											const time_t audio_nstime = be32toh(align_uint32((void*)&event_strc->buffer[data_len+sizeof(uint32_t)])); // NOTE: this is intentionally reading outside data_len because that is where *message* date/time is stored by library
											audio_cache_add(event_strc->n,audio_time,audio_nstime,&event_strc->buffer[8],data_len-8);
										}
										else
											error_simple(0,"Checkpoint Disgarding streaming audio because speaker is off");
									}
									else if(protocol == ENUM_PROTOCOL_AUDIO_STREAM_LEAVE)
										call_peer_leaving(call_n, call_c, event_strc->n);
									else // if(protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN || protocol == ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE)
										call_peer_joining(call_n, call_c, event_strc->n);
								}
								else
									error_printf(0, "Received a audio stream related message for an unknown call: %lu %lu",time,nstime); // If DATA, consider sending _LEAVE once. Otherwise it is _LEAVE, so ignore.
							}
							else
							#endif // NO_AUDIO_CALL
							#ifndef NO_STICKERS
							if(data_len >= CHECKSUM_BIN_LEN && protocol == ENUM_PROTOCOL_STICKER_DATA_GIF)
							{
								int s = set_s((unsigned char*)event_strc->buffer);
								if(s > -1)
									error_simple(0,"We already have this sticker data, not registering it again.");
								else
								{ // Fresh sticker data. Save it and print it
									unsigned char checksum[CHECKSUM_BIN_LEN];
									if(b3sum_bin(checksum,NULL,(unsigned char*)&event_strc->buffer[CHECKSUM_BIN_LEN],0,data_len - CHECKSUM_BIN_LEN) != data_len - CHECKSUM_BIN_LEN || memcmp(checksum,event_strc->buffer,sizeof(checksum)))
										error_simple(0,"Received bunk sticker data from peer. Checksum failed. Disgarding sticker.");
									else
									{
										s = sticker_register((unsigned char*)&event_strc->buffer[CHECKSUM_BIN_LEN],data_len - CHECKSUM_BIN_LEN);
										const int relevent_n = (event_strc->group_n > -1) ? event_strc->group_n : event_strc->n; // we don't have a way of determining whether this data was related to a PM or public message, so we register group_n on the principle of "one group, one identity"
										sticker_add_peer(s,relevent_n);
										const uint8_t stickers_save_all_local = threadsafe_read_uint8(&mutex_global_variable,&stickers_save_all);
										const uint8_t stickers_offload_all_local = threadsafe_read_uint8(&mutex_global_variable,&stickers_offload_all);
										if(stickers_save_all_local || !stickers_offload_all_local)
										{ // Be careful if modifying the logic in this block
											pthread_rwlock_wrlock(&mutex_sticker); // 🟥
											sticker[s].data = torx_secure_malloc(data_len - CHECKSUM_BIN_LEN);
											memcpy(sticker[s].data,(unsigned char*)&event_strc->buffer[CHECKSUM_BIN_LEN],data_len - CHECKSUM_BIN_LEN);
											pthread_rwlock_unlock(&mutex_sticker); // 🟩
											if(stickers_save_all_local)
												sticker_save(s);
											if(stickers_offload_all_local)
												sticker_offload(s);
										}
										uint32_t y = 0;
										torx_write(event_strc->n) // 🟥🟥🟥
										while(y < torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *) && memcmp(peer[event_strc->n].stickers_requested[y],checksum,sizeof(checksum)))
											y++;
										if(y < torx_allocation_len(peer[event_strc->n].stickers_requested)/sizeof(unsigned char *))
											sodium_memzero(peer[event_strc->n].stickers_requested[y],CHECKSUM_BIN_LEN);
										torx_unlock(event_strc->n) // 🟩🟩🟩
										torx_read(event_strc->n) // 🟧🟧🟧
										for(int i = peer[event_strc->n].max_i; i > peer[event_strc->n].min_i - 1 ; i--)
										{ // Rebuild any messages that had this sticker
											const int p_iter_local = peer[event_strc->n].message[i].p_iter;
											if(p_iter_local > -1)
											{
												pthread_rwlock_rdlock(&mutex_protocols); // 🟧
												const uint16_t protocol_local = protocols[p_iter_local].protocol;
												pthread_rwlock_unlock(&mutex_protocols); // 🟩
												if((protocol_local == ENUM_PROTOCOL_STICKER_HASH || protocol_local == ENUM_PROTOCOL_STICKER_HASH_DATE_SIGNED || protocol_local == ENUM_PROTOCOL_STICKER_HASH_PRIVATE)
												&& !memcmp(event_strc->buffer,checksum,CHECKSUM_BIN_LEN))
												{ // Rebuild sticker by finding the first relevant message and update it
													torx_unlock(event_strc->n) // 🟩🟩🟩
													message_modified_cb(event_strc->n,i);
													torx_read(event_strc->n) // 🟧🟧🟧
													break;
												}
											}
										}
										torx_unlock(event_strc->n) // 🟩🟩🟩
									}
									sodium_memzero(checksum,sizeof(checksum));
								}
							}
							else
							#endif // NO_STICKERS
								stream_cb(nn,p_iter,event_strc->buffer,data_len);
						}
					}
					else if(protocol == ENUM_PROTOCOL_KILL_CODE)
					{ // Receive Kill Code (note: it is here, not above, because we want the utf8_valid check) NOTE: Will not be saved, like stream.
						sodium_memzero(read_buffer,packet_len);
						if(threadsafe_read_uint8(&mutex_global_variable,&kill_delete))
						{
							error_printf(0,"Received a kill code with reason: %s. Deleting peer.",event_strc->buffer);
							disconnect_forever(event_strc,1); // XXX Run last and return immediately after, will exit event base
						}
						else // just block, dont delete user and history (BAD IDEA)
						{ // Generate fake privkey, onion, peeronion. They look real.
							error_printf(0,"Received a kill code with reason: %s. Generating junk data and blocking peer.",event_strc->buffer);
							char onion[56+1];
							char privkey[88+1];
							char peeronion[56+1];
							generate_onion_simple(onion,privkey);
							generate_onion_simple(peeronion,NULL);
							torx_write(event_strc->n) // 🟥🟥🟥
							memcpy(peer[event_strc->n].onion,onion,sizeof(onion));
							memcpy(peer[event_strc->n].privkey,privkey,sizeof(privkey));
							memcpy(peer[event_strc->n].peeronion,peeronion,sizeof(peeronion));
							torx_unlock(event_strc->n) // 🟩🟩🟩
							sodium_memzero(onion,sizeof(onion));
							sodium_memzero(privkey,sizeof(privkey));
							sodium_memzero(peeronion,sizeof(peeronion));
							if(getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status)) != ENUM_STATUS_BLOCKED) // Note: Checking for safety because block_peer toggles, and we could receive two kill codes.
								block_peer(event_strc->n); // this calls sql_update_peer, so no need to call again.
							disconnect_forever(event_strc,-1); // XXX Run last and return immediately after, will exit event base
						}
						return;
					}
					else
					{
						time_t time = 0;
						time_t nstime = 0;
						if(signature_len && date_len)
						{ // handle messages that come with date (typically any group messages)
							time = (time_t)be32toh(align_uint32((void*)&event_strc->buffer[buffer_len - (2*sizeof(uint32_t) + crypto_sign_BYTES)]));
							nstime = (time_t)be32toh(align_uint32((void*)&event_strc->buffer[buffer_len - (sizeof(uint32_t) + crypto_sign_BYTES)]));
						}
						else
							set_time(&time,&nstime);
						uint8_t stat;
						if(group_peer_n > -1 && group_peer_n == event_strc->group_n) // we received a message that we signed... it was resent to us.
							stat = ENUM_MESSAGE_SENT;
						else
							stat = ENUM_MESSAGE_RECV;
						const int i = increment_i(nn,0,time,nstime,stat,-1,p_iter,event_strc->buffer);
						int repeated = 0; // same time/nstime as another
						if(event_strc->owner == ENUM_OWNER_GROUP_PEER && (group_msg || group_pm)) // Handle group messages
							repeated = message_insert(event_strc->g,nn,i);
						if(repeated)
						{
							torx_write(nn) // 🟥🟥🟥
							const int shrinkage = zero_i(nn,i);
							torx_unlock(nn) // 🟩🟩🟩
							if(shrinkage)
								shrinkage_cb(nn,shrinkage);
						}
						else
						{ // unique same time/nstime
							message_new_cb(nn,i);
							sql_insert_message(nn,i); // DO NOT set these to nn, use n/GROUP_CTRL
						}
					}
					event_strc->buffer = NULL; // XXX IMPORTANT: to prevent the message from being torx_free'd if we hit a continue;
				}
				else
					continued = 0; // important or oversized messages will break
			#ifndef NO_FILE_TRANSFER
			}
			#endif // NO_FILE_TRANSFER
		} // We only leave while() in the event of an error (via break;)
		breakpoint();
		torx_free((void*)&event_strc->buffer); // Necessary because this will be re-used on fd_type = 0
		if(packet_len < sizeof(read_buffer)) // Necessary safety check
			sodium_memzero(read_buffer,packet_len);
		else
			sodium_memzero(read_buffer,sizeof(read_buffer));
		error_printf(2,"Disconnecting n=%d due to error in read_conn",event_strc->n);
		disconnect(event_strc);
	}
	else if(event_strc->owner == ENUM_OWNER_SING || event_strc->owner == ENUM_OWNER_MULT)
	{ // Handle incoming friend request
		char buffer_ln[2+56+crypto_sign_PUBLICKEYBYTES];
		const int len = evbuffer_remove(input,buffer_ln,sizeof(buffer_ln));
		while(len == (int)sizeof(buffer_ln)) // not a real while loop, just to avoid goto
		{ // Generate, send, and save ctrl
			const uint8_t former_owner = event_strc->owner; // use to mitigate race condition caused by deletion of SING
			char fresh_privkey[88+1] = {0};
			char *peernick = getter_string(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peernick));
			event_strc->fresh_n = generate_onion(ENUM_OWNER_CTRL,fresh_privkey,peernick);
			torx_free((void*)&peernick);
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
			char *peernick_fresh_n = getter_string(event_strc->fresh_n,INT_MIN,-1,offsetof(struct peer_list,peernick));
			int fresh_n = -1; // for double chcking
			if(former_owner == ENUM_OWNER_SING || (former_owner == ENUM_OWNER_MULT && threadsafe_read_uint8(&mutex_global_variable,&auto_accept_mult)))
				fresh_n = load_peer_struc(-1,ENUM_OWNER_CTRL,ENUM_STATUS_FRIEND,fresh_privkey,fresh_peerversion,fresh_peeronion,peernick_fresh_n,ed25519_sk,peer_sign_pk,NULL);
			else if	(former_owner == ENUM_OWNER_MULT && !threadsafe_read_uint8(&mutex_global_variable,&auto_accept_mult))
				fresh_n = load_peer_struc(-1,ENUM_OWNER_CTRL,ENUM_STATUS_PENDING,fresh_privkey,fresh_peerversion,fresh_peeronion,peernick_fresh_n,ed25519_sk,peer_sign_pk,NULL);
			else
				error_simple(0,"Coding error 129012. Report this.");
			torx_free((void*)&peernick_fresh_n);
			if(fresh_n == -1 || event_strc->fresh_n != fresh_n)
			{ // Coding error or buggy/malicious peer. TODO Should spoil onion.
				error_printf(0,"Checkpoint FAIL 2323fsadf event_strc->fresh_n == %d,fresh_n==%d",event_strc->fresh_n,fresh_n );
				sodium_memzero(buffer_ln,sizeof(buffer_ln));
				sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
				sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
				sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
				break; // Unable to generate onion. Bail out and spoil or disconnect.
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
			getter_array(&buffer_ln[2],56,fresh_n,INT_MIN,-1,offsetof(struct peer_list,onion));
			memcpy(&buffer_ln[2+56],ed25519_pk,sizeof(ed25519_pk));
			if(local_debug > 2)
				error_printf(3,"Received Version: %u Onion: %s",fresh_peerversion,fresh_peeronion);
			evbuffer_add(bufferevent_get_output(bev), buffer_ln,sizeof(buffer_ln)); // XXX MUST be AFTER load_onion() because it results in write_finished which requires event_strc->fresh_n
			sodium_memzero(fresh_peeronion,sizeof(fresh_peeronion));
			sodium_memzero(buffer_ln,sizeof(buffer_ln));
			sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
			sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
			sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
			return; // All good, bail out (Note: see write_finished() for what happens next)
		}
		if(event_strc->owner == ENUM_OWNER_SING)
		{ // Spoil SING after bad handshake
			error_printf(0,"Wrong size connection attempt of size %lu received. Onion spoiled. Report this.",len);
			disconnect_forever(event_strc,3); // XXX Run last and return immediately after, will exit event base
			return; // redundant, but for safety.
		}
		else if(event_strc->owner == ENUM_OWNER_MULT)
		{ // Disconnect MULT after bad handshake
			error_printf(0,"Invalid attempt of size %lu received on mult. Should notify user of this.",len);
			disconnect(event_strc);
		}
	}
	else
	{ // Should never happen
		error_simple(0,"Received a message on an unexpected owner. Coding error. Report this.");
		breakpoint();
	}
}

static void accept_conn(struct evconnlistener *listener, evutil_socket_t sockfd, struct sockaddr *address, int socklen, void *ctx)
{ /* We got a new inbound connection! Set up a bufferevent for it. */
	(void) listener;
	(void) address; // not using it, this just suppresses -Wextra warning
	(void) socklen; // not using it, this just suppresses -Wextra warning
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	const uint8_t status = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND || event_strc->owner == ENUM_OWNER_PEER || event_strc->owner == ENUM_OWNER_GROUP_PEER) // Disconnect if anything other than status 1
	{
		error_simple(0,"Coding error 32402. Report this.");
		breakpoint();
	//	disconnect_forever(event_strc,-1); // XXX Run last and return immediately after, will exit event base
		return;
	}
	torx_read(event_strc->n) // 🟧🟧🟧
	const uint8_t bev_recv_exists = peer[event_strc->n].bev_recv ? 1 : 0;
	torx_unlock(event_strc->n) // 🟩🟩🟩
	if(bev_recv_exists)
	{
		if(event_strc->owner == ENUM_OWNER_SING)
			return; // We don't want more than one person trying to spoil our onion at a time. It could cause issues when freeing ctx in close_conn.
		error_printf(2,"Disconnecting due to existing bev_recv in accept_conn n=%d",event_strc->n);
		disconnect(event_strc); // Disconnect our existing before handling a new connection.
	}
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev_recv = bufferevent_socket_new(base, sockfd, BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS); // XXX 2023/09 we should probably not just be overwriting bev_recv every time we get a connection?? or we should make it local?? seems we only use it in this function and in send_prep
	evbuffer_enable_locking(bufferevent_get_output(bev_recv),NULL); // 2023/08/11 Necessary for full-duplex. Will lock and unlock automatically, no need to manually evbuffer_lock/evbuffer_unlock.
	if(event_strc->owner == ENUM_OWNER_GROUP_CTRL) // Should never be GROUP_PEER here
	{ // event_strc_unique for use with bufferevent_setcb(), being a total copy of event_strc.
		struct event_strc *event_strc_unique = torx_insecure_malloc(sizeof(struct event_strc));
		memcpy(event_strc_unique,event_strc,sizeof(struct event_strc));
		bufferevent_setcb(bev_recv, read_conn, write_finished, close_conn, event_strc_unique);
	}
	else
		bufferevent_setcb(bev_recv, read_conn, write_finished, close_conn, event_strc);
	bufferevent_enable(bev_recv, EV_READ); // XXX DO NOT ADD EV_WRITE because it triggers write_finished() immediately on connect, which has invalid fresh_n, segfault.
	torx_write(event_strc->n) // 🟥🟥🟥
	peer[event_strc->n].bev_recv = bev_recv; // 2024/07/13 TODO TODO TODO XXX Maybe this should have a null check before we replace bev_recv.
	torx_unlock(event_strc->n) // 🟩🟩🟩

	if(event_strc->authenticated) // This will only trigger on _CTRL, not _GROUP_CTRL or _SING/_MULT
	{ // MUST check if it is authenticated, otherwise we're permitting sends to an unknown peer (relevant to CTRL without v3auth)
		error_printf(2,"Existing peer has connected to us n=%d",event_strc->n);
		const uint8_t recvfd_connected = 1;
		setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected),&recvfd_connected,sizeof(recvfd_connected));
		begin_cascade(event_strc); // should go immediately after <fd_type>_connected = 1
		peer_online(event_strc); // internal callback, keep after peer[n].bev_recv = bev_recv; AND AFTER send_prep
	}
	else if(event_strc->owner == ENUM_OWNER_SING || event_strc->owner == ENUM_OWNER_MULT)
		error_simple(1,"New potential peer has connected.");
}

static void error_conn(struct evconnlistener *listener,void *ctx)
{ // Only used on fd_type==0 // TODO should re-evaluate this. maybe it should do nothing (probably) or maybe it should be == close_conn (not sure)
// TODO March 2 2023 test if this comes up after long term connections (many hours) like it occurs with LCD main.c ( "Too many open files" )
//	struct event_base *base = evconnlistener_get_base(listener);
	(void)listener;
	error_printf(0, "Shutting down event base. Report this. Got the following error from libevent: %s",evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())); // this is const, do not assign and free.
	disconnect_forever(ctx,-1); // XXX Run last and return immediately after, will exit event base
} // TODO TEST: this caused our whole application to shutdown on 2022/07/29 when deleting a peer. Got an error 22 (Invalid argument) on the listener. Shutting down.

void *torx_events(void *ctx)
{ /* Is called ONLY ONCE for .recvfd (which never closes, unless block/delete), but MULTIPLE TIMES for .sendfd (which closes every time there is disconnect) */
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	struct event_strc *event_strc = (struct event_strc*) ctx; // Casting passed struct
	int failed_tor_call = 0; // must initialize as 0
	if(event_strc->fd_type == 0)
	{
		torx_write(event_strc->n) // 🟥🟥🟥
		pusher(zero_pthread,(void*)&peer[event_strc->n].thrd_recv)
		torx_unlock(event_strc->n) // 🟩🟩🟩
		failed_tor_call = add_onion_call(event_strc->n);
	}
	struct event_base *base = event_base_new();
	if(!base)
	{
		error_simple(0,"Couldn't open event base.");
		goto complete_failure;
	}
	while(!failed_tor_call)
	{ // not a real while loop, just to avoid goto
		if(event_strc->fd_type == 0)
		{ /* Exclusively comes here from load_onion */
			struct evconnlistener *listener = evconnlistener_new(base, accept_conn, ctx, LEV_OPT_THREADSAFE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE/*|EVLOOP_ONCE*/, -1, event_strc->sockfd);	// |LEV_OPT_DEFERRED_ACCEPT could cause issues. It is the source of problems if connections fail
			if(!listener)
			{
				error_simple(0,"Couldn't create libevent listener. Report this.");
				break;
			}
			evconnlistener_set_error_cb(listener, error_conn);
		}
		else if(event_strc->fd_type == 1)
		{ /* Exclusively comes here from send_init() */
			struct bufferevent *bev_send = bufferevent_socket_new(base, event_strc->sockfd, BEV_OPT_THREADSAFE|BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
			if(bev_send == NULL) // -1 replacing sockfd for testing
			{
				error_simple(0,"Couldn't create bev_send.");
				break;
			}
			evbuffer_enable_locking(bufferevent_get_output(bev_send),NULL); // 2023/08/11 Necessary for full-duplex. Will lock and unlock automatically, no need to manually evbuffer_lock/evbuffer_unlock.
			bufferevent_setcb(bev_send, read_conn, write_finished, close_conn,ctx);
	//		bufferevent_disable(bev_send,EV_WRITE); // ENABLED BY DEFAULT, TESTING DISABLED
			bufferevent_enable(bev_send, EV_READ/*|EV_ET|EV_PERSIST*/);
			torx_write(event_strc->n) // 🟥🟥🟥
			peer[event_strc->n].bev_send = bev_send;
			torx_unlock(event_strc->n) // 🟩🟩🟩
			// TODO 0u92fj20f230fjw ... to here. TODO
			const uint16_t peerversion = getter_uint16(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
			/// Handle message types that should be in front of the queue
			const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
			const uint8_t sendfd_connected = 1;
			setter(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected),&sendfd_connected,sizeof(sendfd_connected));
			if(event_strc->owner == ENUM_OWNER_CTRL)
			{
				uint8_t have_triggered_cascade = 0;
				if(local_v3auth_enabled == 0 || peerversion < 2)
				{
					pipe_auth_and_request_peerlist(event_strc); // send ENUM_PROTOCOL_PIPE_AUTH
					have_triggered_cascade = 1;
				}
				if(local_v3auth_enabled == 1 && peerversion < torx_library_version[0]) // NOTE: NOT ELSE IF
				{ // propose upgrade (NOTE: this won't catch if they are already > 1, so we also do it elsewhere)
					error_printf(0,PINK"Checkpoint ENUM_PROTOCOL_PROPOSE_UPGRADE 1: %u"RESET,peerversion);
					const uint16_t trash_version = htobe16(torx_library_version[0]);
					message_send(event_strc->n,ENUM_PROTOCOL_PROPOSE_UPGRADE,&trash_version,sizeof(trash_version));
				}
				else if(!have_triggered_cascade)
					begin_cascade(event_strc); // should go immediately after <fd_type>_connected = 1
			}
			else if(event_strc->owner == ENUM_OWNER_GROUP_PEER)
			{ // Put this in front of the queue.
				const uint8_t stat = getter_uint8(event_strc->n,0,-1,offsetof(struct message_list,stat));
				uint8_t first_connect = 0;
				int p_iter;
				if(stat == ENUM_MESSAGE_FAIL && (p_iter = getter_int(event_strc->n,0,-1,offsetof(struct message_list,p_iter))) > -1)
				{ // Put queue skipping protocols first, if unsent, before pipe auth
					pthread_rwlock_rdlock(&mutex_protocols); // 🟧
					const uint16_t protocol = protocols[p_iter].protocol;
					pthread_rwlock_unlock(&mutex_protocols); // 🟩
					if(stat == ENUM_MESSAGE_FAIL && (protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST))
					{
						send_prep(event_strc->n,-1,0,p_iter,1);
						first_connect = 1;
					}
				}
				if(!first_connect) // otherwise wait for successful entry, or messages could end up out of order.
					pipe_auth_and_request_peerlist(event_strc); // send ENUM_PROTOCOL_PIPE_AUTH
			}
			peer_online(event_strc); // internal callback, keep after pipe auth, after peer[n].bev_recv = bev_recv; AND AFTER send_prep
		}
		else
		{
			error_simple(0,"Did not specify socket type (send, recv). Report this.");
			breakpoint();
			break;
		}
		event_base_dispatch(base); // XXX this is the important loop... this is the blocker
		if(!event_strc->killed)
		{
			peer_offline(event_strc);
			const uint8_t status = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,status));
			if(status == ENUM_STATUS_FRIEND && (event_strc->owner == ENUM_OWNER_CTRL || event_strc->owner == ENUM_OWNER_GROUP_CTRL) && event_strc->fd_type == 0) // Its not an error for a 0'd (deleted) onion to get here.
			{
				const uint8_t sendfd_connected = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
				const uint8_t recvfd_connected = getter_uint8(event_strc->n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
				error_printf(0,"Recv ctrl got out of base. It will die but this is unexpected. NOTE: fd_type recv should not get out unless deleted or blocked. sendfd: %d recvfd: %d owner: %u fd_type: %d",sendfd_connected,recvfd_connected,event_strc->owner,event_strc->fd_type); 	// NOTICE: ONLY SING AND PIPEMODE WILL EVER GET OUT OF BASE edit: i think no one gets out
			}
			else
				error_printf(2,"Disconnected in torx_events for reasons other than killcode n=%d",event_strc->n);
		}
		break;
	}
	event_base_free(base);
	complete_failure: {}
	torx_free((void*)&event_strc->buffer);
	torx_free((void*)&ctx);
	return 0;
}
