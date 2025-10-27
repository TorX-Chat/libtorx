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

#ifndef TORX_PUBLIC_HEADERS
#define TORX_PUBLIC_HEADERS 1

#include <pthread.h>
#include <libgen.h>	// for dirname / basename
#include <string.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <sodium.h>

#ifdef WIN32
	//#include <winsock2.h>
	//#include <ws2tcpip.h>
	//#include <windows.h>
	//#include <winsock.h>	// for windows. should cover all network related stuff?
	#include <shlobj.h>	// for SHGetKnownFolderPath
	#define SOCKET_CAST_IN (evutil_socket_t)
	#define SOCKET_CAST_OUT (SOCKET)
	#define SOCKET_WRITE_SIZE (int)
	#define pid_t int // currently used for run_binary
	typedef u_short in_port_t;
	#define OPTVAL_CAST (const char *)
	#define pusher(F,A) \
	{ \
		pthread_cleanup_push(F,A); \
		pthread_cleanup_pop(1); \
	}
	#define htobe16(x) _byteswap_ushort((uint16_t)(x))
	#define htobe32(x) _byteswap_ulong((uint32_t)(x))
	#define htobe64(x) _byteswap_uint64((uint64_t)(x))
	#define be16toh(x) htobe16(x)
	#define be32toh(x) htobe32(x)
	#define be64toh(x) htobe64(x)
#else
	#include <sys/wait.h>
	#include <netinet/in.h> 	// required for BSD; not required on linux. throws: scratch_6.c:13: error: storage size of 'serv_addr' isn't known
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netdb.h>		// dns lookup gethostbyname,
	#include <netinet/tcp.h>	// for DisableNagle
	#include <poll.h>		// required by remote_connect.c
	#define SOCKET_CAST_IN
	#define SOCKET_CAST_OUT
	#define SOCKET_WRITE_SIZE
	#define OPTVAL_CAST
	#define pusher(F,A) \
	{ \
		pthread_cleanup_push(F,A) \
		pthread_cleanup_pop(1); \
	}
#endif

#ifdef __ANDROID__
	#define TORX_PHTREAD_CANCEL_TYPE 0 // pthread_cancel / pthread_setcanceltype is not and will not be supported by android
	#define IS_ANDROID 1
#else
	#define TORX_PHTREAD_CANCEL_TYPE PTHREAD_CANCEL_DEFERRED // prior to 2025, was PTHREAD_CANCEL_ASYNCHRONOUS, but we read that's bad (and could cause mutex lockups).
	#define IS_ANDROID 0
#endif

#define RED		"\x1b[31m" // printf( RED "Hello\n" RESET );
#define GREEN		"\x1b[32m"
#define YELLOW		"\x1b[33m"
#define BLUE		"\x1b[34m"
#define MAGENTA		"\x1b[35m"
#define CYAN		"\x1b[36m"
#define WHITE		"\x1b[97m"
#define PINK		"\x1b[38;5;201m" // replace : with ; https://devmemo.io/cheatsheets/terminal_escape_code/
#define BRIGHT_RED	"\x1b[91m"
#define BRIGHT_GREEN	"\x1b[92m"
#define BRIGHT_YELLOW	"\x1b[93m"
#define BRIGHT_TEAL     "\x1b[96m"
#define BOLD		"\x1b[1m" // Usage: printf( BOLD BRIGHT_RED BLINKING "hey\n" RESET );
#define ITALICS		"\x1b[3m"
#define BLINKING	"\x1b[5m"
#define UNDERLINE	"\x1b[4m"
#define HIGHLIGHT	"\x1b[7m"
#define STRIKETHROUGH	"\x1b[9m"
#define RESET		"\x1b[0m"

#define CHECKSUM_BIN_LEN 32
#define GROUP_ID_SIZE crypto_box_SECRETKEYBYTES // 32 
#define MAX_STREAMS_GROUP 500 // Should not need to be >1 except for group chats. If it is too low, it used to break when too many messages come at once.
#define MAX_STREAMS_PEER 10
#define SHIFT 10 // this is for vptoi/itovp. it must be greater than any negative value that we might pass to the functions.
#define PROTOCOL_LIST_SIZE 64
#define SIZE_PACKET_STRC 1024 // Seems to not limit the size of individual outbound messages. One for every packet in outbound buffer. So far single-file outbound transfers show this never gets above 1-2. The space it takes at 10,000 is only ~2mb
#define MAX_INVITEES 4096
#define BROADCAST_QUEUE_SIZE 4096
#define BROADCAST_HISTORY_SIZE BROADCAST_QUEUE_SIZE*2 // should be equal to or larger than queue size
#define BROADCAST_MAX_PEERS 2048 // this can be set to anything. Should be reasonably high because it will be made up of the first loaded N, and they could be old / inactive peers, if you have hundreds or thousands of dead peers.

/* The following DO NOT CONTAIN + '\0' + [Time] + [NSTime] + Protocol + Signature */
#ifndef NO_FILE_TRANSFER
#define FILE_OFFER_LEN			(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t) + filename_len)
#define FILE_REQUEST_LEN		CHECKSUM_BIN_LEN+sizeof(uint64_t)*2
#define FILE_OFFER_GROUP_LEN		(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint8_t) + (uint32_t)CHECKSUM_BIN_LEN *(splits + 1) + sizeof(uint64_t) + sizeof(uint32_t) + filename_len)
#define FILE_OFFER_PARTIAL_LEN		(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint8_t) + sizeof(uint64_t) *(splits + 1))
#endif // NO_FILE_TRANSFER
#define GROUP_OFFER_LEN			GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)
#define GROUP_OFFER_FIRST_LEN		GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t) + 56 + crypto_sign_PUBLICKEYBYTES
#define GROUP_OFFER_ACCEPT_LEN		GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES
#define GROUP_OFFER_ACCEPT_REPLY_LEN	GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES*2
#define GROUP_OFFER_ACCEPT_FIRST_LEN	GROUP_ID_SIZE+56+crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES
#define GROUP_PEERLIST_PUBLIC_LEN	sizeof(int32_t) + g_peercount *(56 + crypto_sign_PUBLICKEYBYTES)
#define GROUP_PEERLIST_PRIVATE_LEN	sizeof(int32_t) + g_peercount *(56 + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES)
#define GROUP_PRIVATE_ENTRY_REQUEST_LEN	56 + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES
#define GROUP_BROADCAST_DECRYPTED_LEN	crypto_pwhash_SALTBYTES+56+crypto_sign_PUBLICKEYBYTES
#define GROUP_BROADCAST_LEN		crypto_box_SEALBYTES+GROUP_BROADCAST_DECRYPTED_LEN
#define PIPE_AUTH_LEN			56
#define DATE_SIGN_LEN			sizeof(uint32_t) + sizeof(uint32_t) + crypto_sign_BYTES // time + nstime + sig

/* Macros for wrapping access to peer struct, especially where not accessing an integer */
#define torx_read(n) \
{ \
	pthread_rwlock_rdlock(&mutex_expand); \
	pthread_rwlock_rdlock(&peer[n].mutex_page); \
}

#define torx_write(n) \
{ \
	pthread_rwlock_rdlock(&mutex_expand); \
	pthread_rwlock_wrlock(&peer[n].mutex_page); \
}

#define torx_unlock(n) \
{ \
	pthread_rwlock_unlock(&peer[n].mutex_page); \
	pthread_rwlock_unlock(&mutex_expand); \
}

/* Note: NOT holding page locks. This is ONLY for disk IO. DO NOT HOLD PAGE LOCKS. XXX Note: Necessary to NOT wrap _mutex_lock in a torx_read because it WILL result in lock-order-inversion */
#ifndef NO_FILE_TRANSFER
#define torx_fd_lock(n,f) \
{ \
	torx_read(n) \
	pthread_mutex_t *mutex = &peer[n].file[f].mutex_file; \
	torx_unlock(n) \
	pthread_mutex_lock(mutex); \
}

#define torx_fd_unlock(n,f) \
{ \
	torx_read(n) \
	pthread_mutex_t *mutex = &peer[n].file[f].mutex_file; \
	torx_unlock(n) \
	pthread_mutex_unlock(mutex); \
}
#endif // NO_FILE_TRANSFER
/* Convenience function for cloning a page */ // WARNING: Do not make a "torx_page_save". That would be a very bad thing because very much could change elsewhere between open and close.
/* Usage example:
	peer[0].owner = 6;
	torx_page_open(0)
	printf("Checkpoint %lu =? %lu\n",sizeof(peer_page),sizeof(peer[0]));
	printf("Checkpoint 6 =? %d\n",peer_page.owner);
	torx_page_close
*/
#define torx_page_open(n) \
{ \
	struct peer_list peer_page; \
	torx_read(n) \
	memcpy(&peer_page,&peer[n],sizeof(peer_page)); \
	torx_unlock(n) \
}

#define torx_page_close \
	sodium_memzero(&peer_page,sizeof(peer_page));


/* Close sockets */
#define close_sockets_nolock(fd) \
{ \
	if(fd) { fclose(fd); fd = NULL; } \
}
/* XXX This is the CORRECT order, do not modify. torx_fd_lock, THEN torx_read, localize, close, torx_write, globalize, torx_fd_unlock, otherwise races could occur. XXX */
#ifndef NO_FILE_TRANSFER
#define close_sockets(n,f) \
{ \
	torx_fd_lock(n,f) \
	torx_read(n) \
	FILE *fd_active_tmp = peer[n].file[f].fd; \
	torx_unlock(n) \
	close_sockets_nolock(fd_active_tmp) \
	torx_write(n) \
	peer[n].file[f].fd = fd_active_tmp; \
	torx_unlock(n) \
	torx_fd_unlock(n,f) \
} // TODO 2025/01/18 There is a possibility that there is a potential for mutex lockup in this function at the torx_write, which can lock up with the torx_read in torx_fd_lock
#endif // NO_FILE_TRANSFER
/* Arrays of Struct that are used globally */ // XXX XXX DO NOT FORGET TO ADD NEW MEMBERS TO torx_lookup()(NOTE: and handle *correctly), intialize_n() and sensitive members to cleanup() XXX XXX
struct peer_list { // "Data type: peer_list"  // Most important is to define onion (required) and fd. We must create an "array of structures"
	uint8_t owner; // XXX buffer overflows will occur if owner is > 9 or negative
	uint8_t status; // 0 blocked, 1 friend, 2 pending acceptance
	char privkey[88+1];
	int peer_index; // For use with SQL functions only
	char onion[56+1]; // our onion derrived from privkey, except for "peer", where it is peeronion, because this must ALWAYS exist
	char torxid[52+1];
	uint16_t peerversion;
	char peeronion[56+1];
	char *peernick;
	int8_t log_messages; // -1 (override global), never log. 0 use global, 1 yes logging (override global)
	time_t last_seen; // time. should be UTC.
	uint16_t vport; // externally visible on onion
	uint16_t tport; // internal
	int socket_utilized[2]; // OUTBOUND ONLY: whether recvfd (0) or sendfd (1) is currently being utilized by send_prep for OUTBOUND message processing. Holds active message_i. XXX NOT relevant to ENUM_PROTOCOL_FILE_PIECE. Held until COMPLETE message sent.
	evutil_socket_t sendfd; // outgoing messages ( XXX NOT currently utilized by ENUM_OWNER_PEER )
	evutil_socket_t recvfd; // incoming messages
	uint8_t sendfd_connected; // This is set to 1 when (bev_send)
	uint8_t recvfd_connected; // This is not set to 1 until a pipe is authenticated, and (bev_recv).
	struct bufferevent *bev_send; // currently only used in libevent.c by libevent thread because libevent is not threadsafe, even with such flags
	struct bufferevent *bev_recv;
//	int8_t oldest_message; // TODO currently unused, should be used. default: 0, this should be set to permit the cycling of messages. when there are too many to fit in the struct, it should start over at 0, overwritting the oldest and moving this start point
	int max_i; // message index number; cap: messages_max. do not depreciate this; it saves cpu cycles and helps reduce chance of race condition when concurrently sending and receiving a message on different threads.
	int min_i;
	struct message_list {
		time_t time; // time since epoch in seconds
		int8_t fd_type; // -1 == swappable, 0 == recvfd, 1 == sendfd
		uint8_t stat;
		int p_iter;
		char *message; // should free on shutdown, in cleanup()
		uint32_t pos; // amount sent TODO utilize for amount received also
		time_t nstime; // nanoseconds (essentially after a decimal point of time)
	} *message; // WARNING: This always points to i=="0", but 0 may not be where the alloc is. Use find_message_struc_pointer to find it.
	#ifndef NO_FILE_TRANSFER
	struct file_list { // XXX Group file transfers are held by GROUP_CTRL, whereas PM transfers are held by GROUP_PEER XXX
		unsigned char checksum[CHECKSUM_BIN_LEN]; // XXX do NOT ever set this BACK to '\0' or it will mess with expand_file_struc. if changing this to *, need to check if null before calling strlen()
		char *filename;
		char *file_path;
		uint64_t size;
		time_t modified; // modification time (UTC, epoch time)
		/* Exclusively Inbound transfer related */
		uint8_t splits; // 0 to max , number of splits (XXX RELEVANT ONLY TO RECEIVER/incoming, and outbound group files)
		char *split_path;
		uint64_t *split_progress; // Contains section info, which is amount transferred in that section (incoming only). NEVER RESET!
		int *split_status_n; // GROUPS NOTE: stores N value, which could be checked upon receiving prior to writing, to ensure that a malicious peer cannot corrupt files
		int8_t *split_status_fd;
		uint64_t *split_status_req; // Contains end byte count of request (incoming only). NOTE: This is unnecessary/unutilized in non-group transfers.
		/* Exclusively Group related */
		unsigned char *split_hashes; // Only relevant to GROUP_CTRL files (group file transfers, non-PM)
		FILE *fd; // Utilized by in and outbound file transfers. Be sure to wrap all usage with torx_fd_lock
		struct offer_list { // XXX DO NOT ACCESS USING SETTER/GETTER FUNCTIONS and ALWAYS verify that .offer is not NULL *WITHIN THE SAME MUTEX* or SEGFAULTS WILL OCCUR XXX
			int offerer_n; // Do not reset to -1
			uint64_t *offer_progress; // == their split_progress. Contains section info that the peer says they have. XXX ALWAYS DO NULL CHECK
		} *offer;
		time_t last_progress_update_time; // last time we updated progress bar
		time_t last_progress_update_nstime; // last time we updated progress bar
		uint64_t bytes_per_second; // larger than necessary but avoids casting when doing calcs
		uint64_t last_transferred; // This is set at the same time as last_progress_update
		time_t time_left; // seconds TODO change integer type to ssize_t,time_t, or uint64_t
		uint8_t speed_iter;
		uint64_t last_speeds[256];
		pthread_mutex_t mutex_file;
		/* Exclusively Outbound transfer related */
		struct request_list { // XXX DO NOT ACCESS USING SETTER/GETTER FUNCTIONS and ALWAYS verify that .request is not NULL *WITHIN THE SAME MUTEX* or SEGFAULTS WILL OCCUR XXX
			int requester_n; // Do not reset to -1
			uint64_t start[2];
			uint64_t end[2];
			uint64_t transferred[2];
			uint64_t previously_sent; // Do not reset to 0. From exhausted requests. This ONLY updated when a request's transferred is reset to 0 (such as when a new request overtakes it on the same socket)
		} *request;
	} *file;
	uint8_t blacklisted; // blacklisted for giving us corrupt file sections in group transfers // note: alternative names:  denylist/disallowed https://web.archive.org/web/20221219160303/https://itcommunity.stanford.edu/ehli
	#endif // NO_FILE_TRANSFER
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES]; // ONLY use for CTRL + GROUP_CTRL, do not use for SING/MULT/PEER (those should only be held locally during handshakes)
	unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES]; // ONLY use for CTRL + GROUP_PEER, do not use for SING/MULT/PEER (those should only be held locally during handshakes)
	unsigned char invitation[crypto_sign_BYTES]; // PRIVATE groups only. ONLY for GROUP_PEER, 64 this the SIGNATURE on our onion, from who invited us, which we will need when connecting to other peers.
	pthread_rwlock_t mutex_page;
	pthread_t thrd_send; // for peer_init / send_init (which calls torx_events (send)
	pthread_t thrd_recv; // for torx_events (recv)
	uint32_t broadcasts_inbound;
	#ifndef NO_AUDIO_CALL
	struct call_list {
		uint8_t joined; // Whether we accepted/joined it
		uint8_t waiting; // Whether it is awaiting an acceptance/join or has been declined/ignored
		uint8_t mic_on;
		uint8_t speaker_on;
		time_t start_time;
		time_t start_nstime;
		int *participating;
		uint8_t *participant_mic;
		uint8_t *participant_speaker;
	} *call;
	/* Playback related */
	unsigned char **audio_cache; // For current call playback cache ( audio_cache_add / audio_cache_retrieve )
	time_t *audio_time; // For current call playback cache ( audio_cache_add / audio_cache_retrieve )
	time_t *audio_nstime; // For current call playback cache ( audio_cache_add / audio_cache_retrieve )
	time_t audio_last_retrieved_time; // For current call playback cache ( audio_cache_add / audio_cache_retrieve )
	time_t audio_last_retrieved_nstime; // For current call playback cache ( audio_cache_add / audio_cache_retrieve )
	/* Recording related */
	unsigned char **cached_recording; // TODO could be held globally, rather than in peer struct?
	time_t cached_time; // time of last modification of cached_recording // TODO could be held globally, rather than in peer struct?
	time_t cached_nstime; // nstime of last modification of cached_recording // TODO could be held globally, rather than in peer struct?
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	unsigned char **stickers_requested;
	#endif // NO_STICKERS
};
extern struct peer_list *peer;

struct group_list { // XXX NOTE: individual peers will be in peer struct but peer[n].owner != CTRL so they won't appear in peer list or show online notifications XXX
	unsigned char id[GROUP_ID_SIZE]; // x25519_sk key, 32 bytes decoded, crypto_scalarmult_base to get _pk. PROBABLY SHOULD NOT CLEAR THIS WHEN DELETING (??? what)
	int n; // n of our GROUP_CTRL
	int invitees[MAX_INVITEES];
	uint32_t hash; // only relevant to groups with 0 peers that we are broadcasting for
	uint32_t peercount; // This is CONFIRMED PEERS, not reported by offers. Does NOT include us. DO NOT SET PEERCOUNT except with ++ or horrible things will happen.
	uint32_t msg_count;
	int *peerlist; // does NOT include us, can be list of onions OR peer_index TODO decide
	uint8_t invite_required; // default 1. 0 is QR compatible. 2 is passed on network only and means that teh group is empty / we need first user to sign our onion
	uint32_t msg_index_iter; // this is for group_get_index
	struct msg_list *msg_index; // no space is allocated, do not free. this is for group_get_index
	struct msg_list *msg_first;
	struct msg_list *msg_last;
}; // NOTE: creator of the group will never ask anyone for peer_list because creator is always on everyone's peer list. Other users can periodically poll people for peer_list.
extern struct group_list *group;

struct protocol_info {
	uint16_t protocol;
	char name[64];
	char description[512]; // Array is preferable than pointer for speed here
	uint32_t null_terminated_len; // 0 or 1, determines whether entirely binary or not // NOTE: Currently doing UTF8 validation on ALL PROTOCOLS UTILIZING .null_terminated_len, which will need to be adjusted if someone implements a non-UTF8 protocol
	uint32_t date_len; // typically 0 or 8, could be just a 'dated' instead
	uint32_t signature_len; // typically 0 or crypto_sign_BYTES
	uint8_t logged;
	uint8_t notifiable; // messages will be printed by UI
	uint8_t file_checksum; // contains CHECKSUM_BIN_LEN prefix compatible with set_f
	uint8_t group_pm; // suitable for private message in public/private groups (uses authenticated pipes)
	uint8_t group_msg; // broadcast multiple times but stored at most once. (outbound public/private group messages, NOT including PMs)
	uint8_t socket_swappable;
	uint8_t utf8;

	// Following are for internal use only, not for UI devs:
	uint8_t file_offer;
	uint8_t group_mechanics;
	uint8_t stream; // TODO should NOT be added to message struct, nor saved to disk, should be provided straight to UI in a stream_cb(n,protocol,void*,len)
};
extern struct protocol_info protocols[PROTOCOL_LIST_SIZE];

/* Struct Models */
union types {
	uint64_t uint64;
	uint32_t uint32;
	uint16_t uint16;
	uint8_t uint8;
	size_t size;
	time_t time;
	int integer;
	int64_t int64;
	int32_t int32;
	int16_t int16;
	int8_t int8;
};

struct msg_list { // This is ONLY to be allocated by message_sort and message_insert
	struct msg_list *message_prior; // if NULL, no prior notifiable message
	int n;
	int i;
	time_t time; // adding time to avoid having to reference peer struct unnecessarily whenever inserting/removing
	time_t nstime;
	struct msg_list *message_next; // if NULL, no next notifiable message
};

enum exclusive_types {
	ENUM_EXCLUSIVE_NONE = 0,
	ENUM_EXCLUSIVE_GROUP_PM = 1,
	ENUM_EXCLUSIVE_GROUP_MSG = 2,
	ENUM_EXCLUSIVE_GROUP_MECHANICS = 3
}; // group_pm, group_msg, file_offer, group_mechanics, utf8, stream);

enum stream_types { // Stream > 0 is not stored in struct longer than necessary. Handed off to UI after sent/recieved and removed from message struct.
	ENUM_NON_STREAM = 0,
	ENUM_STREAM_DISCARDABLE = 1, // Disgard if cannot be sent immediately. Message_send returns -1 if failed to send.
	ENUM_STREAM_NON_DISCARDABLE = 2 // Do not disgard if cannot be sent immediately. No way to check if it ever sent because it is deleted from struct after send.
};

enum protocols { /* TorX Officially Recognized Protocol Identifiers (prefixed upon each message):
		XXX New Method:	echo $(($RANDOM*2-$RANDOM%2)) */
	#ifndef NO_AUDIO_CALL
	ENUM_PROTOCOL_AUDIO_STREAM_JOIN = 65303, // Start Time + nstime // This is also offer
	ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE = 33037, // Start Time + nstime // This is also offer
	ENUM_PROTOCOL_AUDIO_STREAM_PEERS = 16343, // Start Time + nstime + 56*participating
	ENUM_PROTOCOL_AUDIO_STREAM_LEAVE = 23602, // Start Time + nstime
	ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC = 54254, // Start Time + nstime + data (AAC)
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	ENUM_PROTOCOL_STICKER_HASH = 29812,		// Sticker will be sending a sticker hash. If peer doesn't have the sticker, request.
	ENUM_PROTOCOL_STICKER_HASH_PRIVATE = 40505,
	ENUM_PROTOCOL_STICKER_HASH_DATE_SIGNED = 1891,
	ENUM_PROTOCOL_STICKER_REQUEST = 24931,		// hash
	ENUM_PROTOCOL_STICKER_DATA_GIF = 46093,		// hash + data
	#endif // NO_STICKERS
	#ifndef NO_FILE_TRANSFER
/*	ENUM_PROTOCOL_FILE_PREVIEW_PNG = 32343,			// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_PNG_DATE_SIGNED = 17878,	// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_GIF = 54526,			// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_GIF_DATE_SIGNED = 47334,	// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data	*/
	ENUM_PROTOCOL_FILE_OFFER = 44443,
	ENUM_PROTOCOL_FILE_OFFER_PRIVATE = 62747,
	ENUM_PROTOCOL_FILE_OFFER_GROUP = 32918,			// Uses hash of section hashes, not whole file hash, unlike normal file_offer
	ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED = 2125,	// Uses hash of section hashes, not whole file hash, unlike normal file_offer
	ENUM_PROTOCOL_FILE_OFFER_PARTIAL = 64736,		// Uses hash of section hashes, not whole file hash, unlike normal file_offer.
	ENUM_PROTOCOL_FILE_INFO_REQUEST = 63599,		// Uses hash of section hashes. Requests a FILE_OFFER_GROUP or FILE_OFFER_GROUP_DATE_SIGNED.
	ENUM_PROTOCOL_FILE_PARTIAL_REQUEST = 52469,		// Uses hash of section hashes. Requests a ENUM_PROTOCOL_FILE_OFFER_PARTIAL.
	ENUM_PROTOCOL_FILE_PIECE = 7795,			// XXX DOES NOT CARE ABOUT .socket_utilized
	ENUM_PROTOCOL_FILE_REQUEST = 27493,
	ENUM_PROTOCOL_FILE_PAUSE = 38490,
	ENUM_PROTOCOL_FILE_CANCEL = 22461, // cancel or reject
	#endif // NO_FILE_TRANSFER
	ENUM_PROTOCOL_PROPOSE_UPGRADE = 57382, // propose, counter offer, or accept version upgrade TODO implement using change_nick() which has an untested version upgrade functionality
	ENUM_PROTOCOL_KILL_CODE = 41342,
	ENUM_PROTOCOL_UTF8_TEXT = 32896,
//	ENUM_PROTOCOL_UTF8_TEXT_SIGNED = 19150,
	ENUM_PROTOCOL_UTF8_TEXT_DATE_SIGNED = 47208, // Timestamp acts as a salt to prevent relay attacks, Tor project does this with all signed messages.

	ENUM_PROTOCOL_UTF8_TEXT_PRIVATE = 24326, // Private messages cannot be signed or they could be arbitrarily forwarded to non-recipients without any evidence of manupulated destination

	ENUM_PROTOCOL_GROUP_BROADCAST = 13854, // Our onion + PK signed encrypted by GroupID // TODO consider date signing this in groups to prevent spam? or ignoring altogether in groups to prevent DOS attacks by anonymous spammers (could break connections in case of repeated spam of the same message? or ignore for problematic groups)

	/* XXX Out-of-group invitation and handshake XXX */
	ENUM_PROTOCOL_GROUP_OFFER_FIRST = 11919, // (Only used on brand-new invite-only group) includes group_ctrl onion which we need our first oining peer to sign
	ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST = 48942, // (Only used on brand-new invite-only group) includes signature of aforementioned group_ctrl onion
	ENUM_PROTOCOL_GROUP_OFFER = 23579, // ( offer group[g].id ) XXX FOR INVITE-ONLY GROUPS
	ENUM_PROTOCOL_GROUP_OFFER_ACCEPT = 10652, // reply with group[g].id + generated GROUPIE onion
	ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY = 59142, //( sign their GROUPIE onion )

	/* XXX In-group handshake (unsigned messages) XXX */
	ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST = 24335, // same as ENUM_PROTOCOL_GROUP_BROADCAST, just different protocol # to allow logging
	ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST = 13196, //( Our onion signed by the person who invited us + ed25519_pk. NO REPLY EXPECTED. they will add us or drop the connection )

	/* XXX In-group signed messages XXX */
	ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST = 62797, //( Contains only peercount. Response expected if peercount < peercount , do not pass signing key. receiver should have associated group. )
	ENUM_PROTOCOL_GROUP_PEERLIST = 39970, // ( number of peers + onions )

	ENUM_PROTOCOL_PIPE_AUTH = 25078 // sign destination onion. Relevant to groups only. Simply proves who an incoming connection is coming from. Could include a prefix to reduce cpu cycles.
	// Note: "Anonymous Messages" could be sent by not sending ENUM_PROTOCOL_PIPE_AUTH before sending a messages in a public/private group. If choosing to implement, be sure to break connection after sending.
};

enum owners
{ // NOTE: one function is using 20 as "sing spoiled"
	ENUM_OWNER_PEER = 1,
	ENUM_OWNER_SING = 2,
	ENUM_OWNER_MULT = 3,
	ENUM_OWNER_CTRL = 4,
	
	ENUM_OWNER_GROUP_PEER = 5, // outbound unshook + outbound shook, many per group, contains peer names.
	ENUM_OWNER_GROUP_CTRL = 6 // one per group, contains group name. group settings saved with its peer_index.
};

enum peer_statuses
{ // Must not be above 9 or below 1  // formerly 0 blocked, 1 friend, 2 pending acceptance
	ENUM_STATUS_BLOCKED = 1, // includes disabled for SING/MULT
	ENUM_STATUS_FRIEND = 2, // seems to include active SING/MULT
	ENUM_STATUS_PENDING = 3
};

enum recognized_versions
{
	ENUM_VERSION_NOV3AUTH = 1,
	ENUM_VERSION_V3AUTH = 2
};

enum message_statuses
{ // formerly Text: 0 :recv:, 1 :fail:, 2 :sent:, 4 resend-but-dont-save(ex: accept_file upon reload), 5 :done: (file related)
	ENUM_MESSAGE_RECV = 1,
	ENUM_MESSAGE_FAIL = 2,
	ENUM_MESSAGE_SENT = 3
//	ENUM_MESSAGE_RESEND = 4 // resend but do not save, ex: re-accept file upon reload TODO 2023/10/28 seems depreciated
//	ENUM_MESSAGE_DONE = 5 // file related (BAD, too vague)
// TODO these are saved to disk... for file related, we need more than this. We need all file statuses, not just done. Not sure how to implement yet
};/* TODO set other .status, such as finished (ifin,ofin) and paused (ipau,opau) */
#ifndef NO_FILE_TRANSFER
enum file_statuses
{ // NOTE: We don't have a paused status, currently. Paused is ENUM_FILE_INACTIVE_ACCEPTED, which is the default as soon as file_path is set. There is no pause.
	ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND = 0,
	ENUM_FILE_ACTIVE_OUT = 1, // Do not modify
	ENUM_FILE_ACTIVE_IN = 2, // Do not modify
	ENUM_FILE_ACTIVE_IN_OUT = 3, // Do not modify // XXX ENUM value MUST equal ENUM_FILE_ACTIVE_OUT + ENUM_FILE_ACTIVE_IN XXX
	ENUM_FILE_INACTIVE_ACCEPTED = 4, // This must be inbound. For idle outbound, must be ENUM_FILE_INACTIVE_COMPLETE
	ENUM_FILE_INACTIVE_CANCELLED = 5,
	ENUM_FILE_INACTIVE_COMPLETE = 6
};
#endif // NO_FILE_TRANSFER
/* Callbacks */
extern void (*initialize_n_registered)(const int n);
extern void (*initialize_i_registered)(const int n,const int i);
extern void (*initialize_g_registered)(const int g);
extern void (*shrinkage_registered)(const int n,const int shrinkage);
extern void (*expand_message_struc_registered)(const int n,const int i);
extern void (*expand_peer_struc_registered)(const int n);
extern void (*expand_group_struc_registered)(const int g);
extern void (*change_password_registered)(const int value);
extern void (*incoming_friend_request_registered)(const int n);
extern void (*onion_deleted_registered)(const uint8_t owner,const int n);
extern void (*peer_online_registered)(const int n);
extern void (*peer_offline_registered)(const int n);
extern void (*peer_new_registered)(const int n);
extern void (*onion_ready_registered)(const int n);
extern void (*tor_log_registered)(char *message);
extern void (*error_registered)(char *error_message);
extern void (*fatal_registered)(char *error_message);
extern void (*custom_setting_registered)(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext);
extern void (*message_new_registered)(const int n,const int i);
extern void (*message_modified_registered)(const int n,const int i);
extern void (*message_deleted_registered)(const int n,const int i);
extern void (*message_extra_registered)(const int n,const int i,unsigned char *data,const uint32_t data_len);
extern void (*message_more_registered)(const int loaded,int *loaded_array_n,int *loaded_array_i);
extern void (*login_registered)(const int value);
extern void (*peer_loaded_registered)(const int n);
extern void (*cleanup_registered)(const int sig_num); // callback to UI to inform it that we are closing and it should save settings
extern void (*stream_registered)(const int n,const int p_iter,char *data,const uint32_t len);
extern void (*unknown_registered)(const int n,const uint16_t protocol,char *data,const uint32_t len);

/* Callback Setters */
void initialize_n_setter(void (*callback)(int));
void initialize_i_setter(void (*callback)(int,int));
void initialize_g_setter(void (*callback)(int));
void shrinkage_setter(void (*callback)(int,int));
void expand_message_struc_setter(void (*callback)(int,int));
void expand_peer_struc_setter(void (*callback)(int));
void expand_group_struc_setter(void (*callback)(int));
void change_password_setter(void (*callback)(int));
void incoming_friend_request_setter(void (*callback)(int));
void onion_deleted_setter(void (*callback)(uint8_t,int));
void peer_online_setter(void (*callback)(int));
void peer_offline_setter(void (*callback)(int));
void peer_new_setter(void (*callback)(int));
void onion_ready_setter(void (*callback)(int));
void tor_log_setter(void (*callback)(char*));
void error_setter(void (*callback)(char*));
void fatal_setter(void (*callback)(char*));
void custom_setting_setter(void (*callback)(int,char*,char*,size_t,int));
void message_new_setter(void (*callback)(int,int));
void message_modified_setter(void (*callback)(int,int));
void message_deleted_setter(void (*callback)(int,int));
void message_extra_setter(void (*callback)(int,int,unsigned char*,uint32_t));
void message_more_setter(void (*callback)(int,int*,int*));
void login_setter(void (*callback)(int));
void peer_loaded_setter(void (*callback)(int));
void cleanup_setter(void (*callback)(int));
void stream_setter(void (*callback)(int,int,char*,uint32_t));
void unknown_setter(void (*callback)(int,uint16_t,char*,uint32_t));

/* WARNING: All callbacks *must* allocate data for pointers and rely on the receiver to free because the callback may not be triggered syncronously (ex: Flutter) */
void initialize_n_cb(const int n);
void initialize_i_cb(const int n,const int i);
void initialize_g_cb(const int g);
void shrinkage_cb(const int n,const int shrinkage);
void expand_message_struc_cb(const int n,const int i);
void expand_peer_struc_cb(const int n);
void expand_group_struc_cb(const int g);
void change_password_cb(const int value);
void incoming_friend_request_cb(const int n);
void onion_deleted_cb(const uint8_t owner,const int n);
void peer_online_cb(const int n);
void peer_offline_cb(const int n);
void peer_new_cb(const int n);
void onion_ready_cb(const int n);
void tor_log_cb(char *message);
void error_cb(char *error_message);
void fatal_cb(char *error_message);
void custom_setting_cb(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext);
void message_new_cb(const int n,const int i);
void message_modified_cb(const int n,const int i);
void message_deleted_cb(const int n,const int i);
void message_extra_cb(const int n,const int i,unsigned char *data,const uint32_t data_len);
void message_more_cb(const int loaded,int *loaded_array_n,int *loaded_array_i);
void login_cb(const int value);
void peer_loaded_cb(const int n);
void cleanup_cb(const int sig_num);
void stream_cb(const int n,const int p_iter,char *data,const uint32_t len);
void unknown_cb(const int n,const uint16_t protocol,char *data,const uint32_t len);

// XXX TODO FIXME some of these functions might be fun to return const values. Specifically functions that return pointers.

/* thread_safety.c */
/* To prevent data races and race conditions on the peer struct and its members */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-attributes"
void breakpoint(void) __attribute__((optimize("O0")));
#pragma clang diagnostic pop
#pragma GCC diagnostic pop
uint32_t getter_length(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
char *getter_string(uint32_t *size,const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
unsigned char *getter_group_id(const int g)__attribute__((warn_unused_result));
void *group_access(const int g,const size_t offset)__attribute__((warn_unused_result));
void *group_get_next(int *n,int *i,const void *arg)__attribute__((warn_unused_result));
void *group_get_prior(int *n,int *i,const void *arg)__attribute__((warn_unused_result));
void group_get_index(int *n,int *i,const int g,const uint32_t index);
void *protocol_access(const int p_iter,const size_t offset)__attribute__((warn_unused_result));
size_t getter_size(const char *parent,const char *member)__attribute__((warn_unused_result));
size_t getter_offset(const char *parent,const char *member)__attribute__((warn_unused_result));
void setter(const int n,const int i,const int f,const size_t offset,const void *value,const size_t len);
char getter_byte(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
void getter_array(void *array,const size_t size,const int n,const int i,const int f,const size_t offset);
int8_t getter_int8(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
int16_t getter_int16(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
int32_t getter_int32(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
int64_t getter_int64(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
uint8_t getter_uint8(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
uint16_t getter_uint16(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
uint32_t getter_uint32(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
uint64_t getter_uint64(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
int getter_int(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
time_t getter_time(const int n,const int i,const int f,const size_t offset)__attribute__((warn_unused_result));
void setter_group(const int g,const size_t offset,const void *value,const size_t len);
int8_t getter_group_int8(const int g,const size_t offset)__attribute__((warn_unused_result));
int16_t getter_group_int16(const int g,const size_t offset)__attribute__((warn_unused_result));
int32_t getter_group_int32(const int g,const size_t offset)__attribute__((warn_unused_result));
int64_t getter_group_int64(const int g,const size_t offset)__attribute__((warn_unused_result));
uint8_t getter_group_uint8(const int g,const size_t offset)__attribute__((warn_unused_result));
uint16_t getter_group_uint16(const int g,const size_t offset)__attribute__((warn_unused_result));
uint32_t getter_group_uint32(const int g,const size_t offset)__attribute__((warn_unused_result));
uint64_t getter_group_uint64(const int g,const size_t offset)__attribute__((warn_unused_result));
int getter_group_int(const int g,const size_t offset)__attribute__((warn_unused_result));
/* The following are ONLY SAFE ON packet struct or global variables because of their fixed size / location. To prevent data races, not race conditions. */
void threadsafe_write(pthread_rwlock_t *mutex,void *destination,const void *source,const size_t len);
int8_t threadsafe_read_int8(pthread_rwlock_t *mutex,const int8_t *arg)__attribute__((warn_unused_result));
int16_t threadsafe_read_int16(pthread_rwlock_t *mutex,const int16_t *arg)__attribute__((warn_unused_result));
int32_t threadsafe_read_int32(pthread_rwlock_t *mutex,const int32_t *arg)__attribute__((warn_unused_result));
int64_t threadsafe_read_int64(pthread_rwlock_t *mutex,const int64_t *arg)__attribute__((warn_unused_result));
uint8_t threadsafe_read_uint8(pthread_rwlock_t *mutex,const uint8_t *arg)__attribute__((warn_unused_result));
uint16_t threadsafe_read_uint16(pthread_rwlock_t *mutex,const uint16_t *arg)__attribute__((warn_unused_result));
uint32_t threadsafe_read_uint32(pthread_rwlock_t *mutex,const uint32_t *arg)__attribute__((warn_unused_result));
uint64_t threadsafe_read_uint64(pthread_rwlock_t *mutex,const uint64_t *arg)__attribute__((warn_unused_result));
int threadsafe_read_int(pthread_rwlock_t *mutex,const int *arg)__attribute__((warn_unused_result));

/* torx_core.c */
int protocol_lookup(const uint16_t protocol)__attribute__((warn_unused_result));
int protocol_registration(const uint16_t protocol,const char *name,const char *description,const uint8_t null_terminate,const uint8_t date,const uint8_t sign,const uint8_t logged,const uint8_t notifiable,const uint8_t file_checksum,const uint8_t file_offer,const uint8_t exclusive_type,const uint8_t utf8,const uint8_t socket_swappable,const uint8_t stream);
void torx_fn_read(const int n);
void torx_fn_write(const int n);
void torx_fn_unlock(const int n);
void error_printf(const int level,const char *format,...);
void error_simple(const int debug_level,const char *error_message);
unsigned char *read_bytes(size_t *data_len,const char *path)__attribute__((warn_unused_result));
void toggle_int8(void *arg);
void zero_pthread(void *thrd);
void setcanceltype(int type,int *arg);
int8_t torx_debug_level(const int8_t level);
uint16_t align_uint16(const void *ptr)__attribute__((warn_unused_result));
uint32_t align_uint32(const void *ptr)__attribute__((warn_unused_result));
uint64_t align_uint64(const void *ptr)__attribute__((warn_unused_result));
int is_null(const void* arg,const size_t size)__attribute__((warn_unused_result));
void *torx_insecure_malloc(const size_t len)__attribute__((warn_unused_result));
void *torx_secure_malloc(const size_t len)__attribute__((warn_unused_result));
void torx_free_simple(void *p);
void torx_free(void **p);
int message_load_more(const int n);
char *run_binary(pid_t *return_pid,void *fd_stdin,void *fd_stdout,char *const args[],const char *input)__attribute__((warn_unused_result));
void set_time(time_t *time,time_t *nstime);
char *message_time_string(const int n,const int i)__attribute__((warn_unused_result));
int vptoi(const void* arg)__attribute__((warn_unused_result));
void *itovp(const int i)__attribute__((warn_unused_result));
int set_n(const int peer_index,const char *onion)__attribute__((warn_unused_result));
int set_g(const int n,const void *arg)__attribute__((warn_unused_result));
int set_g_from_i(uint32_t *untrusted_peercount,const int n,const int i)__attribute__((warn_unused_result));
void random_string(char *destination,const size_t destination_size);
int pid_kill(const pid_t pid,const int signal);
void torrc_save(const char *torrc_content_local);
char *torrc_verify(const char *torrc_content_local)__attribute__((warn_unused_result));
char *which(const char *binary)__attribute__((warn_unused_result));
uint32_t torx_allocation_len(const void *arg)__attribute__((warn_unused_result));
void *torx_copy(uint32_t *len_p,const void *arg)__attribute__((warn_unused_result));
void *torx_realloc_shift(void *arg,const size_t len_new,const uint8_t shift_data_forwards)__attribute__((warn_unused_result));
void *torx_realloc(void *arg,const size_t len_new)__attribute__((warn_unused_result));
int *refined_list(int *len,const uint8_t owner,const int peer_status,const char *search)__attribute__((warn_unused_result)); // free required
uint16_t randport(const uint16_t arg)__attribute__((warn_unused_result));
void start_tor(void);
size_t b64_decoded_size(const char *in)__attribute__((warn_unused_result));
size_t b64_decode(unsigned char *out,const size_t destination_size,const char *in); // caller must allocate space
char *b64_encode(const void *in,const size_t len)__attribute__((warn_unused_result)); // torx_free required
void initial_keyed(void);
void re_expand_callbacks(void);
int set_last_message(int *last_message_n,const int n,const int count_back)__attribute__((warn_unused_result));
int group_online(const int g)__attribute__((warn_unused_result));
int group_check_sig(const int g,const char *message,const uint32_t message_len,const uint16_t untrusted_protocol,const unsigned char *sig,const char *peeronion_prefix)__attribute__((warn_unused_result));
int group_join(const int inviter_n,const unsigned char *group_id,const char *group_name,const char *creator_onion,const unsigned char *creator_ed25519_pk);
int group_join_from_i(const int n,const int i);
int group_generate(const uint8_t invite_required,const char *name);
void initial(void);
void change_password_start(const char *password_old,const char *password_new,const char *password_verify);
void login_start(const char *password);
void cleanup_lib(const int sig_num);
char *tor_call(const char *msg)__attribute__((warn_unused_result));
void tor_call_async(void (*callback)(char*),const char *msg);
char *onion_from_privkey(const char *privkey)__attribute__((warn_unused_result));
char *torxid_from_onion(const char *onion)__attribute__((warn_unused_result));
char *onion_from_torxid(const char *torxid)__attribute__((warn_unused_result));
int custom_input(const uint8_t owner,const char *identifier,const char *privkey);
int peer_save(const char *unstripped_peerid,const char *peernick);
void peer_accept(const int n);
void change_nick(const int n,const char *freshpeernick);
uint64_t get_file_size(const char *file_path)__attribute__((warn_unused_result));
void destroy_file(const char *file_path); // do not use directly for deleting history
char *custom_input_file(const char *hs_ed25519_secret_key_file)__attribute__((warn_unused_result));
void takedown_onion(const int peer_index,const int delete);
void block_peer(const int n);

/* sql.c */
void message_offload(const int n);
void delete_log(const int n);
int message_edit(const int n,const int i,const char *message);
int sql_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len);
unsigned char *sql_retrieve(size_t *data_len,const int force_plaintext,const char *query)__attribute__((warn_unused_result));
void message_extra(const int n,const int i,const void *data,const uint32_t data_len);
void sql_populate_setting(const int force_plaintext);
int sql_delete_setting(const int force_plaintext,const int peer_index,const char *setting_name);

/* client_init.c */
int message_resend(const int n,const int i);
int message_send_select(const uint32_t target_count,const int *target_list,const uint16_t protocol,const void *arg,const uint32_t base_message_len);
int message_send(const int target_n,const uint16_t protocol,const void *arg,const uint32_t base_message_len);
void kill_code(const int n,const char *explanation); // must accept -1

/* onion_gen.c */
int generate_onion(const uint8_t owner,char *privkey,const char *peernick);

/* cpucount.c */
int cpucount(void)__attribute__((warn_unused_result));

/* utf-validate.c */
uint8_t utf8_valid(const void *const src,const size_t len)__attribute__((warn_unused_result));

#ifdef SECURE_MALLOC	// TODO implement this conditional in library and CMakeLists.txt // https://imtech.imt.fr/en/2019/01/22/stack-canaries-software-protection/
	#define ENABLE_SECURE_MALLOC 1
#else
	#define ENABLE_SECURE_MALLOC 0
#endif

#ifndef NO_QR_GENERATOR
	#include <stdbool.h>
	struct qr_data{
		bool *data;
		size_t height;
		size_t width;
		size_t multiplier;
		size_t size_allocated;
	};
	struct qr_data *qr_bool(const char *text,const size_t multiplier)__attribute__((warn_unused_result));
	char *qr_utf8(const struct qr_data *arg)__attribute__((warn_unused_result));
	void *return_png(size_t *size_ptr,const struct qr_data *arg)__attribute__((warn_unused_result));
	size_t write_bytes(const char *filename,const void *png_data,const size_t length);
#endif // NO_QR_GENERATOR

#ifndef NO_FILE_TRANSFER
extern char *download_dir;
extern char *split_folder;
extern uint8_t auto_resume_inbound;
extern double file_progress_delay;
extern void (*initialize_f_registered)(const int n,const int f);
extern void (*expand_file_struc_registered)(const int n,const int f);
extern void (*transfer_progress_registered)(const int n,const int f,const uint64_t transferred);
void initialize_f_setter(void (*callback)(int,int));
void initialize_f_cb(const int n,const int f);
void expand_file_struc_setter(void (*callback)(int,int));
void expand_file_struc_cb(const int n,const int f);
void transfer_progress_setter(void (*callback)(int, int, uint64_t));
void transfer_progress_cb(const int n,const int f,const uint64_t transferred);
char *file_progress_string(const int n,const int f)__attribute__((warn_unused_result));
uint64_t calculate_transferred_inbound(const int n,const int f)__attribute__((warn_unused_result));
uint64_t calculate_transferred_outbound(const int n,const int f,const int r)__attribute__((warn_unused_result));
uint64_t calculate_transferred(const int n,const int f)__attribute__((warn_unused_result));
int set_f(const int n,const unsigned char *checksum,const size_t checksum_len)__attribute__((warn_unused_result));
int set_f_from_i(int *file_n,const int n,const int i)__attribute__((warn_unused_result));
int set_o(const int n,const int f,const int passed_offerer_n)__attribute__((warn_unused_result));
int set_r(const int n,const int f,const int passed_requester_n)__attribute__((warn_unused_result));
int file_is_active(const int n,const int f)__attribute__((warn_unused_result));
int file_is_cancelled(const int n,const int f)__attribute__((warn_unused_result));
int file_is_complete(const int n,const int f)__attribute__((warn_unused_result));
int file_status_get(const int n,const int f)__attribute__((warn_unused_result));
int file_send(const int n,const char *path);
void file_set_path(const int n,const int f,const char *path);
void file_accept(const int n,const int f);
void file_cancel(const int n,const int f);
#endif // NO_FILE_TRANSFER

#ifndef NO_AUDIO_CALL
extern void (*initialize_peer_call_registered)(const int call_n,const int call_c);
extern void (*expand_call_struc_registered)(const int call_n,const int call_c);
extern void (*call_update_registered)(const int call_n,const int call_c);
extern void (*audio_cache_add_registered)(const int participant_n);
extern uint8_t default_participant_mic;
extern uint8_t default_participant_speaker;
void initialize_peer_call_setter(void (*callback)(int,int));
void expand_call_struc_setter(void (*callback)(int,int));
void call_update_setter(void (*callback)(int,int));
void audio_cache_add_setter(void (*callback)(int));
void initialize_peer_call_cb(const int call_n,const int call_c);
void expand_call_struc_cb(const int call_n,const int call_c);
void call_update_cb(const int call_n,const int call_c);
void audio_cache_add_cb(const int participant_n);
uint8_t getter_call_uint8(const int call_n,const int call_c,const int participant_n,const size_t offset)__attribute__((warn_unused_result));
time_t getter_call_time(const int call_n,const int call_c,const int participant_n,const size_t offset)__attribute__((warn_unused_result));
int *call_recipient_list(uint32_t *recipient_count,const int call_n,const int call_c)__attribute__((warn_unused_result));
int *call_participant_list(uint32_t *participant_count,const int call_n,const int call_c)__attribute__((warn_unused_result));
int call_participant_count(const int call_n, const int call_c)__attribute__((warn_unused_result));
int call_start(const int call_n);
void call_toggle_mic(const int call_n,const int call_c,const int participant_n);
void call_toggle_speaker(const int call_n,const int call_c,const int participant_n);
void call_join(const int call_n,const int call_c);
void call_ignore(const int call_n,const int call_c);
void call_leave(const int call_n,const int call_c);
void call_leave_all_except(const int except_n,const int except_c);
void call_mute_all_except(const int except_n,const int except_c);
unsigned char *audio_cache_retrieve(time_t *time,time_t *nstime,uint32_t *len,const int participant_n)__attribute__((warn_unused_result));
int record_cache_clear(const int call_n);
int record_cache_add(const int call_n,const int call_c,const uint32_t cache_minimum_size,const uint32_t max_age_in_ms,const unsigned char *data,const uint32_t data_len);
#endif // NO_AUDIO_CALL

#ifndef NO_STICKERS
struct sticker_list {
	unsigned char checksum[CHECKSUM_BIN_LEN];
	int *peers; // Only these peers can request data, to prevent fingerprinting by sticker list.
	unsigned char *data; // Cached
	uint8_t saved; // Whether data exists on disk
};
extern struct sticker_list *sticker;
extern uint8_t stickers_save_all;
extern uint8_t stickers_offload_all;
extern uint8_t stickers_request_data;
extern uint8_t stickers_send_data;
int set_s(const unsigned char checksum[CHECKSUM_BIN_LEN])__attribute__((warn_unused_result));
void sticker_save(const int s);
void sticker_delete(const int s);
int sticker_register(const unsigned char *data,const size_t data_len);
uint8_t sticker_retrieve_saved(const int s)__attribute__((warn_unused_result));
char *sticker_retrieve_checksum(const int s)__attribute__((warn_unused_result));
unsigned char *sticker_retrieve_data(size_t *len_p,const int s)__attribute__((warn_unused_result));
uint32_t sticker_retrieve_count(void)__attribute__((warn_unused_result));
void sticker_offload(const int s);
void sticker_offload_saved(void);
#endif // NO_STICKERS

/* Global variables (defined here, declared elsewhere, primarily in torx_core.c) */
extern const uint16_t torx_library_version[4];
extern void *ui_data;
extern char *debug_file;
extern uint8_t reduced_memory;
extern int8_t debug;
extern char *working_dir;
extern char *control_password_clear;
extern char *torrc_content;
extern char *default_peernick;
extern uint16_t tor_socks_port;
extern uint16_t tor_ctrl_port;
extern uint32_t tor_version[4];
extern uint8_t first_run;
extern uint8_t currently_changing_pass;
extern uint8_t destroy_input;
extern uint8_t tor_running;
extern uint8_t using_system_tor;
extern uint8_t lockout;
extern uint8_t keyed;
extern uint8_t messages_loaded;
extern pid_t tor_pid;
extern int max_group;
extern int max_peer;
extern time_t startup_time;
extern const char platform_slash;
extern char *snowflake_location;
extern char *lyrebird_location;
extern char *conjure_location;
extern char *native_library_directory;
extern char *tor_data_directory;
extern char *tor_location;
extern uint32_t sing_expiration_days;
extern uint32_t mult_expiration_days;
extern uint32_t show_log_messages;
extern uint8_t global_log_messages;
extern uint8_t log_last_seen;
extern uint8_t auto_accept_mult;
extern uint8_t shorten_torxids;
extern uint8_t suffix_length;
extern uint32_t global_threads;
extern uint32_t threads_max;
extern uint8_t kill_delete;
extern uint8_t hide_blocked_group_peer_messages;
extern uint8_t log_pm_according_to_group_setting;
extern pthread_attr_t ATTR_DETACHED;
extern pthread_rwlock_t mutex_debug_level;
extern pthread_rwlock_t mutex_global_variable;
extern pthread_rwlock_t mutex_protocols;
extern pthread_rwlock_t mutex_expand;
extern pthread_rwlock_t mutex_expand_group;
extern uint8_t censored_region;

#endif // TORX_PUBLIC_HEADERS
