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

int send_prep(const int n,const int file_n,const int f_i,const int p_iter,int8_t fd_type)
{ // Puts a message into evbuffer and registers the packet info. Should be run in a while loop on startup and reconnections, and once per message_send. Returns -1 on error or peer offline, 0 on success, and -2 on socket utilized (cannot send immediately). We could return 0 instead of -2, but we might use this.
	if(n < 0 || p_iter < 0)
	{
		error_printf(0,"Sanity check failure 1 in send_prep: %d %d %d %d %d. Coding error. Report this.",n,file_n,f_i,p_iter,fd_type);
		return -1;
	}
	int f = -1, i = INT_MIN; // DO NOT INITIALIZE, we want the warnings... but clang is not playing nice so we have to
	uint64_t start = 0;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const char *name = protocols[p_iter].name;
	const uint8_t socket_swappable = protocols[p_iter].socket_swappable;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner != ENUM_OWNER_GROUP_PEER && owner != ENUM_OWNER_CTRL)
	{
		error_printf(0,"Questionable action in send_prep, possibly caused by a protocol being sent to a GROUP_CTRL without being registered as group_msg / ENUM_EXCLUSIVE_GROUP_MSG. Target owner=%u. Coding error. Report this.",owner);
		goto error;
	}
	else if(protocol == ENUM_PROTOCOL_FILE_PIECE)
	{
		f = f_i;
		if(f < 0 || file_n < 0 || fd_type < 0)
		{
			error_printf(0,"Sanity check failure 2 in send_prep: %d %d %d %d %d. Coding error. Report this.",n,file_n,f,p_iter,fd_type);
			goto error;
		}
	}
	else
	{
		i = f_i;
		const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
		if(stat != ENUM_MESSAGE_FAIL)
		{ // Race condition. This can happen where cascade sends off a message before we anticipated.
			error_printf(0,"Send_prep message already sent: n=%d i=%d stat=%u.",n,i,stat);
			goto error;
		}
		const int true_p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
		if(p_iter != true_p_iter) // TODO 2024/03/21 more efficient would be to just *not* pass p_iter as an arg. We just need to pass whether or not its ENUM_PROTOCOL_FILE_PIECE
		{
			if(true_p_iter < 0)
			{
				error_printf(0,"Message deleted: %s. Cannot send_prep. Coding error. Report this.",name);
				goto error;
			}
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const char *true_name = protocols[true_p_iter].name;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			error_printf(-1,"Sanity check fail in send_prep. %s != %s. Coding error. Report this.",name,true_name); // 2024/09/30 Occurred after a possible GTK issue. Sticker Request != Propose Upgrade
		}
		if((start = getter_uint32(n,i,-1,offsetof(struct message_list,pos))) == 0)
		{ // Critically important to ensure we don't swap half-way through a message
			torx_write(n) // 🟥🟥🟥 DO NOT REPLACE WITH torx_read or we could face race conditions
			const int utilized_recv = peer[n].socket_utilized[0];
			const int utilized_send = peer[n].socket_utilized[1];
			if(utilized_recv == i || utilized_send == i)
			{ // Critical mitigation of race condition. DO NOT REMOVE.
				torx_unlock(n) // 🟩🟩🟩
				error_printf(0,PINK"Send_prep failure due to message n=%d i=%d fd_type=%d stat=%u recv=%d send=%d being send_prep'd on this or another socket: %s"RESET,n,i,fd_type,stat,utilized_recv,utilized_send,name);
				return -2; // MUST BE -2 not -1 or we will have big issues in packet_removal
			}
			else if(utilized_recv > INT_MIN && utilized_send > INT_MIN)
			{
				torx_unlock(n) // 🟩🟩🟩
				return -2; // Message will be sent after the current message, even if ENUM_STREAM_DISCARDABLE
			}
			const int recvfd_connected = peer[n].recvfd_connected;
			const int sendfd_connected = peer[n].sendfd_connected;
			if(fd_type < 0)
			{ // There is SOME redundancy here with send_prep's use of socket_swappable, but send_prep's usage is more advanced. This is primitive.
				if(protocol == ENUM_PROTOCOL_PIPE_AUTH || protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
					fd_type = 1; // PIPE_AUTH and ENTRY_REQUEST are exclusively sent out on sendfd
				else if(recvfd_connected && utilized_recv == INT_MIN)
					fd_type = 0; // prefer recvfd for reliability & speed
				else if(sendfd_connected && utilized_send == INT_MIN)
					fd_type = 1;
			}
			if(fd_type < 0 || (utilized_recv > INT_MIN && fd_type == 0) || (utilized_send > INT_MIN && fd_type == 1)) // NOT else if
			{ // Switch sockets
				if(socket_swappable && fd_type == 0)
					fd_type = 1;
				else if(socket_swappable && fd_type == 1)
					fd_type = 0;
				else
				{ // Not swappable, or nothing is on
					torx_unlock(n) // 🟩🟩🟩
					return -2; // Message will be sent after the current message, even if ENUM_STREAM_DISCARDABLE
				}
			}
			if(!socket_swappable) // This is NOT redundant with message_distribute because not every message goes through that stage.
				peer[n].message[i].fd_type = fd_type;
			peer[n].socket_utilized[fd_type] = i; // XXX TODO AFTER THIS POINT, MUST USE goto error
			torx_unlock(n) // 🟩🟩🟩
			error_printf(4,WHITE"send_prep1 peer[%d].socket_utilized[%d] = %d, %s"RESET,n,fd_type,i,name);
		}
		else
		{ // Sanity check for continuing a partially sent message
			torx_read(n) // 🟧🟧🟧
			const int socket_utilized = peer[n].socket_utilized[fd_type];
			torx_unlock(n) // 🟩🟩🟩
			if(socket_utilized != i)
				goto error; // XXX On where pos > 0, socket_utilized must already be set. This is a major coding error.
		}
	}
	torx_read(n) // 🟧🟧🟧
	if(!(fd_type == 0 && peer[n].bev_recv && peer[n].recvfd_connected) && !(fd_type == 1 && peer[n].bev_send && peer[n].sendfd_connected))
	{ // This occurs when message_send is called before torx_events. It sends later when the connection comes up, unless it is ENUM_STREAM_DISCARDABLE.
		torx_unlock(n) // 🟩🟩🟩
		error_printf(2,"Send_prep too early owner=%u n=%d f_i=%d fd=%d: %s",owner,n,f_i,fd_type,name);
		goto error;
	}
	torx_unlock(n) // 🟩🟩🟩
	char send_buffer[PACKET_SIZE_MAX]; // zero'd // NOTE: no need to {0} this, so don't.
	if(getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status)) == ENUM_STATUS_FRIEND)
	{ // TODO 2024/03/24 there can be a race on output. it can be free'd by libevent between earlier check and usage.
		uint16_t packet_len = 0;
		if(protocol == ENUM_PROTOCOL_FILE_PIECE)
		{ // only f is initialized
			const int r = set_r(file_n,f,n);
			if(r < 0) // probably .request is NULL
				goto error;
			uint16_t data_size = PACKET_SIZE_MAX-16;
			torx_fd_lock(file_n,f) // 🟥🟥🟥🟥
			torx_read(file_n) // 🟧🟧🟧
			if(peer[file_n].file[f].request == NULL)
			{ // Necessary sanity check to avoid race conditions
				torx_unlock(file_n) // 🟩🟩🟩
				torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
				error_simple(0,"Send_prep sanity check failure. Something is NULL. File may be cancelled. Possible coding error. Report this.");
				goto error;
			}
			FILE *fd_active = peer[file_n].file[f].fd;
			start = peer[file_n].file[f].request[r].start[fd_type] + peer[file_n].file[f].request[r].transferred[fd_type];
		//	printf("Checkpoint file_n=%d f=%d fd=%d r=%d start=%lu\n",file_n,f,fd_type,r,start); // TODO remove
			if(start + data_size > peer[file_n].file[f].request[r].end[fd_type]) // avoid sending beyond requested amount
				data_size = (uint16_t)(peer[file_n].file[f].request[r].end[fd_type] - start + 1); // hopefully this +1 means "inclusive" because we were losing a byte in the middle
			torx_unlock(file_n) // 🟩🟩🟩
			if(fd_active == NULL)
			{
				char *file_path = getter_string(NULL,file_n,INT_MIN,f,offsetof(struct file_list,file_path));
				if((fd_active = fopen(file_path, "r")) == NULL)
				{
					torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
					error_printf(0,"Cannot open file path %s for sending. Check permissions.",file_path);
					torx_free((void*)&file_path);
					goto error;
				}
				torx_free((void*)&file_path);
			}
			fseek(fd_active,(long int)start,SEEK_SET); // This will be no-op if we only have one section active, which will be rare. Formally, it must trigger: if(peer[n].file[f].request[r].start[fd_type] + peer[n].file[f].request[r].transferred[fd_type] != start)
			const size_t bytes = fread(&send_buffer[16],1,data_size,fd_active);
			torx_write(file_n) // 🟥🟥🟥
			peer[file_n].file[f].fd = fd_active;
			torx_unlock(file_n) // 🟩🟩🟩
			torx_fd_unlock(file_n,f) // 🟩🟩🟩🟩
			if(bytes > 0)
			{ // Handle bytes read from file
				packet_len = 2+2+4+8+(uint16_t)bytes; //  packet len, protocool, truncated file checksum, start position, data itself
				uint16_t trash = htobe16(packet_len);
				memcpy(&send_buffer[0],&trash,sizeof(uint16_t));
				trash = htobe16(protocol);
				memcpy(&send_buffer[2],&trash,sizeof(uint16_t));
				torx_read(file_n) // 🟧🟧🟧
				memcpy(&send_buffer[4],peer[file_n].file[f].checksum,4);
				torx_unlock(file_n) // 🟩🟩🟩
				const uint64_t endian_corrected_start = htobe64(start);
				memcpy(&send_buffer[8],&endian_corrected_start,8);
			}
			else // if(!bytes) // No more to read (legacy complete or IO error)
			{ // File completion is in packet_removal. XXX 2024/12/24 Do not delete this block. It does not necessarily indicate corruption occurred during a transfer.
				error_printf(0,PINK"Read to end of file prematurely at byte: %lu. IO error or coding error. Report this."RESET,start); // could be falsely triggered by file shrinkage
				close_sockets(file_n,f)
				transfer_progress(file_n,f); // XXX This presumably triggers a stall XXX
				sodium_memzero(send_buffer,(size_t)packet_len);
				goto error;
			}
		}
		else
		{ // only i is initialized
			// printf(YELLOW"Checkpoint send_prep: n=%d i=%d\n"RESET,n,i); // FSojoasfoSO
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint8_t group_mechanics = protocols[p_iter].group_mechanics;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if(owner != ENUM_OWNER_GROUP_PEER && group_mechanics)
			{ // these messages can only go out to ENUM_OWNER_GROUP_PEER
				error_simple(0,"owner != ENUM_OWNER_GROUP_PEER && group_mechanics. Coding error. Report this.");
				goto error;
			}
			// All protocols that contain a message size on the first packet of a message // Attempt send of messages marked :fail: or resend
			torx_read(n) // 🟧🟧🟧
			const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);
			torx_unlock(n) // 🟩🟩🟩
			uint32_t prefix_len = 2+2; // packet_len + protocol
			if(start == 0)
			{ // Only place length at the beginning of message, not on every message
				const uint32_t trash = htobe32(message_len);
				memcpy(&send_buffer[prefix_len],&trash,sizeof(uint32_t));
				prefix_len += 4;
			}
			else if(start >= message_len)
			{ // 2024/12/25 This is a serious error but we're not making it fatal because it currently is only triggering on restarts.
				error_printf(0,"Start >= message_len: %u >= %u. n=%d i=%d stat=%u. Coding error. Report this.",start,message_len,n,i,getter_uint8(n,i,-1,offsetof(struct message_list,stat))); // Added check 2024/05/04
				goto error;
			}
			if(prefix_len + message_len - start < PACKET_SIZE_MAX)
				packet_len = (uint16_t)(prefix_len + message_len - start);
			else // oversized message
				packet_len = PACKET_SIZE_MAX;
			if(!packet_len)
			{ // Adding a 0 length packet to packet struct would cause severe issues. Has never happened.
				error_printf(0,"Packet length is zero for n=%d i=%d %s. Coding error. Report this.",n,i,name);
				goto error;
			}
			uint16_t trash = htobe16(packet_len);
			memcpy(&send_buffer[0],&trash,sizeof(uint16_t)); // packet length
			trash = htobe16(protocol);
			memcpy(&send_buffer[2],&trash,sizeof(uint16_t)); // protocol
			/* XXX sanity check start */
			torx_read(n) // 🟧🟧🟧
			const uint32_t allocated = torx_allocation_len(peer[n].message[i].message);
			torx_unlock(n) // 🟩🟩🟩
			const size_t reading = start + (size_t)packet_len - prefix_len;
			if(allocated < reading) // TODO hit on 2024/05/04: 98234 < 98796 (actual message size: 98234)
				error_printf(-1,"Critical error will result in illegal read, msg_len=%u: %lu < (%lu + %lu - %u)",message_len,allocated,start,packet_len,prefix_len);
			/* sanity check end XXX */
			torx_read(n) // 🟧🟧🟧
			memcpy(&send_buffer[prefix_len],&peer[n].message[i].message[start],(size_t)packet_len - prefix_len);
			torx_unlock(n) // 🟩🟩🟩
		}
		struct evbuffer *output = NULL; // XXX If getting issues at bufferevent_get_output in valgrind, it means .bev_recv or .bev_send is not being NULL'd properly in libevent after closing
		struct bufferevent *bev = NULL;
		torx_read(n) // 🟧🟧🟧
		if(fd_type == 0)
			bev = peer[n].bev_recv;
		else if(fd_type == 1)
			bev = peer[n].bev_send;
		torx_unlock(n) // 🟩🟩🟩
		if(bev && (output = bufferevent_get_output(bev))) // TODO perhaps the locks should wrap this line? Should be of minor consequence.
		{
			int o = 0;
			evbuffer_lock(output); // XXX seems to have no beneficial effect. purpose is to prevent mutex_packet lockup
			pthread_rwlock_wrlock(&mutex_packet); // 🟥 // TODO XXX CAN BLOCK in rare circumstances (ex: receiving a bunch of STICKER_REQUEST concurrently), yet... highly necessary to wrap evbuffer_add, do not move, otherwise race condition occurs where packet_removal can (and will on some devices) trigger before we register packet
			while(o < SIZE_PACKET_STRC && packet[o].n != -1) // find first re-usable or empty iter
				o++;
			if(o > threadsafe_read_int(&mutex_global_variable,&highest_ever_o))
			{
				pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
				highest_ever_o = o;
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			}
			if(o >= SIZE_PACKET_STRC)
			{
				pthread_rwlock_unlock(&mutex_packet); // 🟩
				evbuffer_unlock(output); // XXX
				sodium_memzero(send_buffer,(size_t)packet_len);
				error_simple(-1,"Fatal error. Exceeded size of SIZE_PACKET_STRC. Report this.");
			}
			packet[o].n = n; // claim it. set first.
			packet[o].file_n = file_n;
			packet[o].packet_len = packet_len;
			packet[o].fd_type = fd_type;
			packet[o].f_i = f_i;
			packet[o].p_iter = p_iter; // set last, this is what we look for when reading
			set_time(&packet[o].time,&packet[o].nstime); // should probably be here, *after mutex*
			evbuffer_add(
				output,
				send_buffer,
				(size_t)packet_len); // TODO does this have a size limit?
		//	total_packets_added++; // TODO remove
			pthread_rwlock_unlock(&mutex_packet); // 🟩
		//	bufferevent_flush(bev,EV_WRITE,BEV_FLUSH); // TODO 2024/12/30 TESTING
			evbuffer_unlock(output); // XXX
			sodium_memzero(send_buffer,(size_t)packet_len);
			return 0;
		}
		else
			error_simple(0,WHITE"Checkpoint send_prep2 NO AVAILABLE OUTPUT, should -1 next"RESET);
	}
	else
		error_simple(0,"Send prep failed for reasons.");
	error: {}
	if(protocol != ENUM_PROTOCOL_FILE_PIECE && fd_type > -1)
	{
		torx_read(n) // 🟧🟧🟧
		const int socket_utilized = peer[n].socket_utilized[fd_type];
		torx_unlock(n) // 🟩🟩🟩
		if(socket_utilized == i)
		{
			error_printf(4,WHITE"send_prep2 peer[%d].socket_utilized[%d] = INT_MIN"RESET,n,fd_type);
			torx_write(n) // 🟥🟥🟥
			peer[n].socket_utilized[fd_type] = INT_MIN;
			torx_unlock(n) // 🟩🟩🟩
		}
		else
			error_printf(0,PINK"Send_prep4 n=%d fd_type=%d (i=%d) != (socket_utilized=%d) start=%u %s"RESET,n,fd_type,i,socket_utilized,start,name);
		if(start)
		{
			printf(PINK BOLD"Checkpoint setting n=%d i=%d fd=%d pos=%zu to pos=0\n"RESET,n,i,fd_type,start);
			torx_write(n) // 🟥🟥🟥
			peer[n].message[i].pos = 0;
			torx_unlock(n) // 🟩🟩🟩
		}
	}
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
	char apibuffer[512]; // zero'd
	char *p = b64_encode(ed25519_sk,sizeof(ed25519_sk));
	snprintf(apibuffer,sizeof(apibuffer),"ONION_CLIENT_AUTH_ADD %s x25519:%s\n",peeronion,p);
	torx_free((void*)&p);
	char *rbuff = tor_call(apibuffer);
	torx_free((void*)&rbuff);
	sodium_memzero(apibuffer,sizeof(apibuffer));
	if(local_debug > 4)
	{
		error_printf(5,"Outgoing Auth: %s",p=b64_encode(ed25519_sk,32));
		torx_free((void*)&p);
	}
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	return 0;
}

static inline void initialize_event_strc(struct event_strc *event_strc,const int n,const uint8_t owner,const int8_t fd_type,const evutil_socket_t socket)
{
	event_strc->sockfd = socket;
	if(fd_type == 1 || (owner == ENUM_OWNER_CTRL && threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled) && getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,peerversion)) > 1))
		event_strc->authenticated = 1;
	else
		event_strc->authenticated = 0;
	event_strc->fd_type = fd_type;
	if(owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
	{
		event_strc->g = set_g(n,NULL);
		event_strc->invite_required = getter_group_uint8(event_strc->g,offsetof(struct group_list,invite_required));
		if(owner == ENUM_OWNER_GROUP_CTRL)
			event_strc->group_n = n;
		else
			event_strc->group_n = getter_group_int(event_strc->g,offsetof(struct group_list,n));
	}
	else
	{
		event_strc->invite_required = 0;
		event_strc->g = -1;
		event_strc->group_n = -1;
	}
	event_strc->owner = owner;
	event_strc->n = n;
	event_strc->fresh_n = -1;
	event_strc->buffer = NULL;
	event_strc->untrusted_message_len = 0;
	event_strc->killed = 0;
}

static inline void *send_init(void *arg)
{ /* This should be called for every peer on startup and should set the peer [n]. sendfd. */
	const int n = vptoi(arg);
	torx_write(n) // 🟥🟥🟥
	pusher(zero_pthread,(void*)&peer[n].thrd_send)
	torx_unlock(n) // 🟩🟩🟩
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	char peeronion[56+1];
	getter_array(&peeronion,sizeof(peeronion),n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
	uint8_t status; // must constantly re-check
	char suffixonion[56+6+1]; // Correct length to handle the .onion suffix required.
	memcpy(suffixonion,peeronion,56);
	snprintf(&suffixonion[56],sizeof(suffixonion)-56,".onion");
	const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
	const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
	char privkey[88+1];
	getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
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
	const uint16_t vport = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,vport));
	char port_string[21];
	snprintf(port_string,sizeof(port_string),"%u",vport);
	while((status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status))) == ENUM_STATUS_FRIEND)
	{
		const evutil_socket_t socket = socks_connect(suffixonion,port_string);
		if(socket < 1)
		{ // this causes blocking only until connected
			sleep(1); // slow down attempts to reconnect. This is one place we should have sleep. MUST be before the sendfd_connected check to give libevent time to close.
			const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
			if(sendfd_connected) // This used to occur when doing repeated blocks/unblocks of online peer. Unsure of implications. Lots of warnings happened after. 2024/09/28 No longer occurs after moving sleep(1) above instead of below check on sendfd_connected.
				error_printf(0,"Nulling a peer[%d].bev_send here possibly without doing any necessary free in libevent. Coding error. Report this.",n);
		} // TODO 2024/12/25 This happens when restarting Tor. Cannot make this fatal until we resolve it. Perhaps it shouldn't be fatal anyway. This may be a side effect of LEV_OPT_CLOSE_ON_FREE.
		else
		{
			evutil_make_socket_nonblocking(socket); // for libevent
			setter(n,INT_MIN,-1,offsetof(struct peer_list,sendfd),&socket,sizeof(socket));
			error_printf(1,"Connected to existing peer n=%d",n);
			struct event_strc *event_strc = torx_insecure_malloc(sizeof(struct event_strc));
			initialize_event_strc(event_strc,n,owner,1,socket);
			torx_events(event_strc); // NOTE: deleted peers will come out of here with owner "0000"
			// XXX DO NOT ATTEMPT TO CLOSE socket: Causes fsan errors on Android because the socket has already been closed by disconnect() XXX
		}
	}
//	torx_free((void*)&port_string);
	sodium_memzero(suffixonion,sizeof(suffixonion));
	return 0; // peer blocked TODO did we close sockets?
}

static inline char *v3auth_ll(const char *privkey,const uint16_t vport,const uint16_t tport,const int maxstreams,...)
{ // Takes a linked list of v3authkeys and prepares a string for tor_call to apply them to an onion
	char *string = {0};
	char *buffer = torx_secure_malloc(4096); // TODO can eliminate malloc by eliminating this function // TODO could be subject to overflow here, if we used this function with a long linked list. Should keep track to prevent.
	int auths = 0;
	va_list va_args;
	va_start(va_args,maxstreams);
	while(1)
	{
		size_t len = 0;
		if((string = va_arg(va_args,char*)) == NULL || (len = strlen(string)) == 0)
		{ // Must be null terminated
			if(!auths)
				snprintf(buffer,512,"ADD_ONION ED25519-V3:%s Flags=MaxStreamsCloseCircuit MaxStreams=%d Port=%u,%u",privkey,maxstreams,vport,tport);
			strcat(buffer,"\n");
			break; // End of list, none or no more auths to add in LL
		}
		else
		{
			auths++;
			if(len == 56 && string[52] == '=')
				string[52] = '\0';
			else if(len != 52) // We now have tests to prevent this from occuring. It occured ocassionally either for natural reasons, a problem with our x2 conversion, or libsodium issue
				error_printf(0,"Wrong length ClientAuthv3: %lu. This onion will not function.",len);
			if(auths == 1)
				snprintf(buffer,512,"ADD_ONION ED25519-V3:%s Flags=MaxStreamsCloseCircuit,V3Auth MaxStreams=%d Port=%u,%u",privkey,maxstreams,vport,tport);
			strcat(buffer," ClientAuthv3=");
			strcat(buffer,string);
		}
	}
	va_end(va_args);
	return buffer;
}

int add_onion_call(const int n)
{ // PEER / GROUP_PEER doesn't have a listening service nor v3auth. Everything else goes through this, even without v3auth.
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	char incomingauthkey[56+1] = {0}; // zero'd
	if(owner == ENUM_OWNER_CTRL)
	{ // _CTRL is the only type that may have v3auth
		const uint8_t local_v3auth_enabled = threadsafe_read_uint8(&mutex_global_variable,&v3auth_enabled);
		if(local_v3auth_enabled == 1 && getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,peerversion)) > 1)
		{ // V3auth
			unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES]; // zero'd // crypto_sign_ed25519_PUBLICKEYBYTES;
			unsigned char x25519_pk[32] = {0}; // zero'd // crypto_scalarmult_curve25519_BYTES
			char peeronion_uppercase[56+1] = {0};
			baseencode_error_t err = {0}; // for base32
			getter_array(peeronion_uppercase,sizeof(peeronion_uppercase),n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
			xstrupr(peeronion_uppercase);
			unsigned char *p1;
			memcpy(ed25519_pk,p1=base32_decode(peeronion_uppercase,56,&err),sizeof(ed25519_pk));
			sodium_memzero(peeronion_uppercase,sizeof(peeronion_uppercase));
			torx_free((void*)&p1);
			if(crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk) < 0)
			{
				error_simple(0,"Critical public key conversion issue.");
				sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
				return -1;
			}
			sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
			if(base32_encode((unsigned char*)incomingauthkey,x25519_pk,sizeof(ed25519_pk)) != 56)
			{
				error_simple(0,"Serious error in load_onion relating to incoming auth key. Report this");
				sodium_memzero(x25519_pk,sizeof(x25519_pk));
				return -1;
			}
			sodium_memzero(x25519_pk,sizeof(x25519_pk));
			error_printf(5,"Incoming Auth: %s",incomingauthkey);
		}
		else if(local_v3auth_enabled)
			error_simple(0,"Warning: Peer does not support v3auth. Tell peer to upgrade Tor to >0.4.6.1.");
	}
	char privkey[88+1];
	getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
	const uint16_t vport = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,vport));
	const uint16_t tport = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,tport));
	char *apibuffer = v3auth_ll(privkey,vport,tport,owner == ENUM_OWNER_GROUP_CTRL ? MAX_STREAMS_GROUP : MAX_STREAMS_PEER,incomingauthkey,NULL);
	sodium_memzero(privkey,sizeof(privkey));
	sodium_memzero(incomingauthkey,sizeof(incomingauthkey));
	char *rbuff = tor_call(apibuffer);
	torx_free((void*)&apibuffer);
	int failed_tor_call;
	if(rbuff && !strncmp(rbuff,"250",3))
		failed_tor_call = 0;
	else
	{
		error_printf(0,"Received FAILURE code from Tor when calling ADD_ONION. Coding error. Report this.");
		failed_tor_call = 1;
	}
	torx_free((void*)&rbuff);
	return failed_tor_call;
}

void load_onion(const int n)
{ // Not to be called on ENUM_OWNER_PEER
	if(n < 0)
	{
		error_simple(0,"Attempted to load_onion an negative value. Report this.");
		breakpoint();
		return;
	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(status == ENUM_STATUS_PENDING || status == ENUM_STATUS_BLOCKED)
	{
		error_simple(3,"Not loading a pending or blocked onion.");
		return; // do not load unaccepted friend requests
	}
	uint16_t vport;
	if(owner == ENUM_OWNER_CTRL)
		vport = CTRL_VPORT;
	else if(owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
		vport = CTRL_VPORT;
	else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
		vport = INIT_VPORT;
	else
	{
		error_simple(0,"Load_onion attempted to load a PEER. This is wrong, as PEER is not a listening server.");
		return;
	}
	setter(n,INT_MIN,-1,offsetof(struct peer_list,vport),&vport,sizeof(vport));
	const uint16_t tport = randport(0);
	setter(n,INT_MIN,-1,offsetof(struct peer_list,tport),&tport,sizeof(tport));
	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER)
	{
		torx_read(n) // 🟧🟧🟧
		pthread_t *thrd_send = &peer[n].thrd_send;
		torx_unlock(n) // 🟩🟩🟩
		if(pthread_create(thrd_send,&ATTR_DETACHED,&send_init,itovp(n)))
			error_simple(-1,"Failed to create thread1");
	}
	if(owner == ENUM_OWNER_GROUP_PEER)
		return; // done, do not need to load listener because we no sockets to listen on
	else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL)
	{ // Open .recvfd for a SING/MULT/CTRL/GROUP_CTRL onion, then call torx_events() on it
		const evutil_socket_t sock = SOCKET_CAST_IN socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0)
		{
			error_simple(0,"Failed to open socket for recvfd");
			return;
		}
		DisableNagle(sock);
		evutil_make_socket_nonblocking(sock); // for libevent
		struct sockaddr_in serv_addr = {0}; //, cli_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = inet_addr(TOR_CTRL_IP); // IP associated with tport, not necessarily TOR_CTRL_IP
		serv_addr.sin_port = htobe16(tport);
		if(bind(SOCKET_CAST_OUT sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{
			error_simple(0,"Failed to bind. Perhaps the random port is already in use. Coding fail."); //  TODO hit this on 2023/08/11
			if(evutil_closesocket(sock) < 0)
				error_simple(0,"Unlikely socket failed to close error.6");
			return;
		}
		setter(n,INT_MIN,-1,offsetof(struct peer_list,recvfd),&sock,sizeof(sock));
		struct event_strc *event_strc = torx_insecure_malloc(sizeof(struct event_strc));
		initialize_event_strc(event_strc,n,owner,0,sock);
		torx_read(n) // 🟧🟧🟧
		pthread_t *thrd_recv = &peer[n].thrd_recv;
		torx_unlock(n) // 🟩🟩🟩
		if(pthread_create(thrd_recv,&ATTR_DETACHED,&torx_events,(void*)event_strc))
			error_simple(-1,"Failed to create thread from load_onion");
	}
}
