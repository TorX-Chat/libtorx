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
#define _FILE_OFFSET_BITS 64 // keep this before headers
#include <stdio.h>
#include <stdlib.h> 	// may be redundant. Included in main.h for running external tor binary.
#include <unistd.h> 	// read, etc. Exec ( tor ) XXX does not exist in windows
#include <string.h>
#include <time.h>	// for time in message logs etc
#include <sys/types.h>	// for fork()
#include <sys/stat.h>	// for umask
//#include <stdarg.h>	// for va_list
//#include <ctype.h>	// for "toupper" (we could rewrite the relevant function very easily and remove this)
#include <signal.h>	// for kill signals
//#include <threads.h>	// C11 threads.
#include <pthread.h>
#include <libgen.h>	// used ONLY for "dirname" though we could also get basename from it (rather than the one we use)
#include <utime.h>
#include <inttypes.h>
/* Libevent related */
#include <errno.h>
#include <fcntl.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <sodium.h>			// libsodium
#include <sqlcipher/sqlite3.h>

#ifdef WIN32 // NOTE: This must also be in appindicator.c file
#define SOCKET_CAST_IN (evutil_socket_t)
#define SOCKET_CAST_OUT (SOCKET)
#define SOCKET_WRITE_SIZE (int)
#else
#define SOCKET_CAST_IN
#define SOCKET_CAST_OUT
#define SOCKET_WRITE_SIZE
#endif

#ifdef WIN32 // XXX
#define pid_t int // currently used for run_binary
typedef u_short in_port_t;
//#include <winsock2.h>
//#include <ws2tcpip.h>
//#include <windows.h>
//#include <winsock.h> // for windows. should cover all network related stuff?
#include <shlobj.h> // for SHGetKnownFolderPath
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

#include <sys/wait.h>	// XXX works but not c99
#include <netinet/in.h> // required for BSD; not required on linux. throws: scratch_6.c:13: error: storage size of 'serv_addr' isn't known
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h> 	// dns lookup gethostbyname,
#include <netinet/tcp.h> // for DisableNagle
#include <poll.h>	// required by remote_connect.c
#define OPTVAL_CAST
#define pusher(F,A) \
{ \
	pthread_cleanup_push(F,A) \
	pthread_cleanup_pop(1); \
}

#endif // XXX

#ifdef __ANDROID__
	#define TORX_PHTREAD_CANCEL_TYPE 0 // pthread_cancel / pthread_setcanceltype is not and will not be supported by android
	#define IS_ANDROID 1
#else
	#define TORX_PHTREAD_CANCEL_TYPE PTHREAD_CANCEL_DEFERRED // prior to 2025, was PTHREAD_CANCEL_ASYNCHRONOUS, but we read that's bad (and could cause mutex lockups).
	#define IS_ANDROID 0
#endif

/* 3rd Party Libraries */

//#include <sys/mman.h> // for mlockall(

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

#define ENUM_MALLOC_TYPE_INSECURE INIT_VPORT // number is arbitrary, just don't make it 0/1 as too common
#define ENUM_MALLOC_TYPE_SECURE CTRL_VPORT // number is arbitrary, just don't make it 0/1 as too common
// TODO 2024/03/12 SOCKET_SO_SNDBUF perhaps we make 2048 for libevent's/our library, and 40960 for Tor because its slow?
#define SOCKET_SO_SNDBUF 2048 // By default, use 2048 because 2028*2==4096, which matches libevent's buffer size ; Higher == More speed, Lower == Less delays.
#define SOCKET_SO_RCVBUF 0 // if 0, default: cat /proc/sys/net/core/wmem_default
#define ConstrainedSockSize 0 // not sure if defaulting to system defaults TODO constrain if there are issues with file transfers appearing to send immediately

#define PROTOCOL_LIST_SIZE 64
#define INIT_VPORT 60591 // Tribute to Phil Zimmerman, June 5th 1991, creator of PGP and contributor to ZRTP. https://philzimmermann.com/EN/background/index.html
#define CTRL_VPORT 61912 // Tribute to Julian Assange, June 19th 2012. NOTE: Ports should be listed in LongLivedPorts in torrc.
#define PACKET_SIZE_MAX 498 // (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) = 498 https://github.com/torproject/tor/blob/main/src/core/or/or.h#L489 Appears to be 498 sometimes, 506 other times, but should verify via https://github.com/spring-epfl/tor-cell-dissector
#define SIZE_PACKET_STRC 1024 // Seems to not limit the size of individual outbound messages. One for every packet in outbound buffer. So far single-file outbound transfers show this never gets above 1-2. The space it takes at 10,000 is only ~2mb
#define CHECKSUM_BIN_LEN 32
#define GROUP_ID_SIZE crypto_box_SECRETKEYBYTES // 32 
#define MAX_STREAMS_GROUP 500 // Should not need to be >1 except for group chats. If it is too low, it used to break when too many messages come at once.
#define MAX_STREAMS_PEER 10
#define SHIFT 10 // this is for vptoi/itovp. it must be greater than any negative value that we might pass to the functions.
#define CHECKSUM_ON_COMPLETION 1 // This blocks, so it should be used for debug purposes only
#define MESSAGE_TIMEOUT -1 // should be -1(disabled), but IN THEORY we could be recieving messages but unable to send while waiting for tor's timeout to expire. In practice, -1 has been best. Update: does nothing.
#define AUTOMATICALLY_LOAD_CTRL 1 // 1 yes, 0 no. 1 is effectively default for -q mode. This is not a viable solution because adversaries can still monitor your disconnection times. 
#define TOR_CTRL_IP "127.0.0.1" // note: in *nix, we could use unix sockets.
#define SPLIT_DELAY 1 // 0 is writing checkpoint every packet, 1 is every 120kb, 2 is every 240kb, ... Recommend 1+. XXX 0 may cause divide by zero errors/crash?
#define RETRIES_MAX 300 // Maximum amount of tries for tor_call() (to compensate for slow startups, usually takes only 1 but might take more on slow devices when starting up (up to around 9 on android emulator)
#define MAX_INVITEES 4096
#define MINIMUM_SECTION_SIZE 5*1024*1024 // Bytes. for groups only, currently, because we don't use split files in P2P. Set by the file offerer exlusively.
#define REALISTIC_PEAK_TRANSFER_SPEED 50*1024*1024 // In bytes/s. Throws away bytes_per_second calculations above this level, for the purpose of calculating average transfer speed. It's fine and effective to set this as high as 1024*1024*1024 (1gb/s).

#define BROADCAST_DELAY 1 // seconds, should equal to or lower than BROADCAST_DELAY_SLEEP. To disable broadcasts, set to 0.
#define BROADCAST_DELAY_SLEEP 10 // used if no message was sent last time (sleep mode, save CPU cycles)
#define BROADCAST_MAX_PEERS 2048 // this can be set to anything. Should be reasonably high because it will be made up of the first loaded N, and they could be old / inactive peers, if you have hundreds or thousands of dead peers.
#define BROADCAST_QUEUE_SIZE 4096
#define BROADCAST_HISTORY_SIZE BROADCAST_QUEUE_SIZE*2 // should be equal to or larger than queue size
#define BROADCAST_MAX_INBOUND_PER_PEER BROADCAST_QUEUE_SIZE/16 // Prevent a single peer from filling up our queue with trash. Should be less than BROADCAST_QUEUE_SIZE.

/* The following DO NOT CONTAIN + '\0' + [Time] + [NSTime] + Protocol + Signature */
#define FILE_OFFER_LEN			(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t) + filename_len)
#define FILE_REQUEST_LEN		CHECKSUM_BIN_LEN+sizeof(uint64_t)*2
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
#define FILE_OFFER_GROUP_LEN		(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint8_t) + (uint32_t)CHECKSUM_BIN_LEN *(splits + 1) + sizeof(uint64_t) + sizeof(uint32_t) + filename_len)
#define FILE_OFFER_PARTIAL_LEN		(uint32_t)(CHECKSUM_BIN_LEN + sizeof(uint8_t) + sizeof(uint64_t) *(splits + 1))
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
		uint32_t message_len; // includes (where applicable only) applicable null terminator, date, untrusted protocol, signature
		uint32_t pos; // amount sent TODO utilize for amount received also
		time_t nstime; // nanoseconds (essentially after a decimal point of time)
	} *message; // WARNING: This always points to i=="0", but 0 may not be where the alloc is. Use find_message_struc_pointer to find it.
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
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES]; // ONLY use for CTRL + GROUP_CTRL, do not use for SING/MULT/PEER (those should only be held locally during handshakes)
	unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES]; // ONLY use for CTRL + GROUP_PEER, do not use for SING/MULT/PEER (those should only be held locally during handshakes)
	unsigned char invitation[crypto_sign_BYTES]; // PRIVATE groups only. ONLY for GROUP_PEER, 64 this the SIGNATURE on our onion, from who invited us, which we will need when connecting to other peers.
	uint8_t blacklisted; // blacklisted for giving us corrupt file sections in group transfers // note: alternative names:  denylist/disallowed https://web.archive.org/web/20221219160303/https://itcommunity.stanford.edu/ehli
	pthread_rwlock_t mutex_page;
	pthread_t thrd_send; // for peer_init / send_init (which calls torx_events (send)
	pthread_t thrd_recv; // for torx_events (recv)
	uint32_t broadcasts_inbound;
} *peer;
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
} *group; // NOTE: creator of the group will never ask anyone for peer_list because creator is always on everyone's peer list. Other users can periodically poll people for peer_list.
struct msg_list { // This is ONLY to be allocated by message_sort and message_insert
	struct msg_list *message_prior; // if NULL, no prior notifiable message
	int n;
	int i;
	time_t time; // adding time to avoid having to reference peer struct unnecessarily whenever inserting/removing
	time_t nstime;
	struct msg_list *message_next; // if NULL, no next notifiable message
};

struct packet_info {
	int n; // adding this so we can remove it from peer struct to save HUGE amounts of RAM (confirmed), this was like 80% of our logged in RAM
	int file_n;
	int f_i; // f value or i value, as appropriate? (cannot be required)
	uint16_t packet_len; // size of packet, or unsent size of packet if partial
	int p_iter; // initialize at -1
	int8_t fd_type; // -1 trash (ready for re-use??? but then out of order),0 recv, 1 send
	time_t time; // time added to packet struct
	time_t nstime; // time added to packet struct
} packet[SIZE_PACKET_STRC]; // Should be filled for each packet added to an evbuffer so that we can determine how to make the appropriate :sent: writes 

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
} protocols[PROTOCOL_LIST_SIZE];

struct broadcasts_list {
	uint32_t hash;
	unsigned char broadcast[GROUP_BROADCAST_LEN];
	int peers[BROADCAST_MAX_PEERS]; // initialized as -1
} broadcasts_queued[BROADCAST_QUEUE_SIZE]; // this is queue

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
/*	ENUM_PROTOCOL_FILE_PREVIEW_PNG = 32343,			// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_PNG_DATE_SIGNED = 17878,	// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_GIF = 54526,			// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data
	ENUM_PROTOCOL_FILE_PREVIEW_GIF_DATE_SIGNED = 47334,	// TODO TODO TODO small size preview. associated FILE_HASH + size_of_preview + data	*/
	ENUM_PROTOCOL_UTF8_TEXT = 32896,
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
	ENUM_PROTOCOL_PROPOSE_UPGRADE = 57382, // propose, counter offer, or accept version upgrade TODO implement using change_nick() which has an untested version upgrade functionality
	ENUM_PROTOCOL_KILL_CODE = 41342,
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

/* Struct Models/Types used for passing to specific pthread'd functions */ // Don't forget to initialize = {0} when calling these types.

struct file_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int n;
	char *path;
	time_t modified;
	size_t size;
};
struct pass_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	char *password_old;
	char *password_new;
	char *password_verify;
};
struct event_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	evutil_socket_t sockfd;
	int8_t authenticated; // ONLY relevant to CTRL. For GROUP_PEER, streams are always authenticated. For GROUP_CTRL, streams are shifted to GROUP_PEER immediatly after authentication.
	int8_t fd_type; // 0 recvfd, 1 sendfd
	uint8_t owner;
	uint8_t invite_required;
	int g;
	int group_n;
	int n;
	int fresh_n; // for SING/MULT to pass internally
	char *buffer; // for use with incomplete messages in read_conn.
	uint32_t buffer_len; // current length of .buffer (received so far)
	uint32_t untrusted_message_len; // peer reported length of message currently in .buffer
};
struct int_char { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int i; // cannot make const, not necessary anyway
	const char *p;
	const unsigned char *up;
};

struct file_request_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int n;
	int f;
	int8_t fd_type;
	int16_t section; // must NOT be uint8_t because it MUST be able to reach 256, even though the maximum section number is 0-255; avoid uint8_t overflows in for loops.
	uint64_t start;
	uint64_t end;
};

/* Callbacks */
void (*initialize_n_registered)(int);
void (*initialize_n_registered)(const int n);
void (*initialize_i_registered)(const int n,const int i);
void (*initialize_f_registered)(const int n,const int f);
void (*initialize_g_registered)(const int g);
void (*shrinkage_registered)(const int n,const int shrinkage);
void (*expand_file_struc_registered)(const int n,const int f);
void (*expand_message_struc_registered)(const int n,const int i);
void (*expand_peer_struc_registered)(const int n);
void (*expand_group_struc_registered)(const int g);
void (*transfer_progress_registered)(const int n,const int f,const uint64_t transferred);
void (*change_password_registered)(const int value);
void (*incoming_friend_request_registered)(const int n);
void (*onion_deleted_registered)(const uint8_t owner,const int n);
void (*peer_online_registered)(const int n);
void (*peer_offline_registered)(const int n);
void (*peer_new_registered)(const int n);
void (*onion_ready_registered)(const int n);
void (*tor_log_registered)(char *message);
void (*error_registered)(char *error_message);
void (*fatal_registered)(char *error_message);
void (*custom_setting_registered)(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext);
void (*message_new_registered)(const int n,const int i);
void (*message_modified_registered)(const int n,const int i);
void (*message_deleted_registered)(const int n,const int i);
void (*message_extra_registered)(const int n,const int i,unsigned char *data,const uint32_t data_len);
void (*message_more_registered)(const int loaded,int *loaded_array_n,int *loaded_array_i);
void (*login_registered)(const int value);
void (*peer_loaded_registered)(const int n);
void (*cleanup_registered)(const int sig_num); // callback to UI to inform it that we are closing and it should save settings
void (*stream_registered)(const int n,const int p_iter,char *data,const uint32_t len);
void (*unknown_registered)(const int n,const uint16_t protocol,char *data,const uint32_t len);

/* Callback Setters */
void initialize_n_setter(void (*callback)(int));
void initialize_i_setter(void (*callback)(int,int));
void initialize_f_setter(void (*callback)(int,int));
void initialize_g_setter(void (*callback)(int));
void shrinkage_setter(void (*callback)(int,int));
void expand_file_struc_setter(void (*callback)(int,int));
void expand_message_struc_setter(void (*callback)(int,int));
void expand_peer_struc_setter(void (*callback)(int));
void expand_group_struc_setter(void (*callback)(int));
void transfer_progress_setter(void (*callback)(int, int, uint64_t));
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
void initialize_f_cb(const int n,const int f);
void initialize_g_cb(const int g);
void shrinkage_cb(const int n,const int shrinkage);
void expand_file_struc_cb(const int n,const int f);
void expand_message_struc_cb(const int n,const int i);
void expand_peer_struc_cb(const int n);
void expand_group_struc_cb(const int g);
void transfer_progress_cb(const int n,const int f,const uint64_t transferred);
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

// XXX TODO FIXME some of these functions might be fun to return const values

/* thread_safety.c */
/* To prevent data races and race conditions on the peer struct and its members */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-attributes"
void breakpoint(void) __attribute__((optimize("O0")));
#pragma clang diagnostic pop
#pragma GCC diagnostic pop
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

/* torx_core.c */
int protocol_lookup(const uint16_t protocol)__attribute__((warn_unused_result));
int protocol_registration(const uint16_t protocol,const char *name,const char *description,const uint32_t null_terminated_len,const uint32_t date_len,const uint32_t signature_len,const uint8_t logged,const uint8_t notifiable,const uint8_t file_checksum,const uint8_t file_offer,const uint8_t exclusive_type,const uint8_t utf8,const uint8_t socket_swappable,const uint8_t stream);
void torx_fn_read(const int n);
void torx_fn_write(const int n);
void torx_fn_unlock(const int n);
void error_printf(const int level,const char *format,...);
void error_simple(const int debug_level,const char *error_message);
unsigned char *read_bytes(size_t *data_len,const char *path)__attribute__((warn_unused_result));
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
int message_insert(const int g,const int n,const int i);
void message_remove(const int g,const int n,const int i);
void message_sort(const int g);
time_t message_find_since(const int n)__attribute__((warn_unused_result));
int message_load_more(const int n);
char *run_binary(pid_t *return_pid,void *fd_stdin,void *fd_stdout,char *const args[],const char *input)__attribute__((warn_unused_result));
void set_time(time_t *time,time_t *nstime);
char *message_time_string(const int n,const int i)__attribute__((warn_unused_result));
char *file_progress_string(const int n,const int f)__attribute__((warn_unused_result));
void transfer_progress(const int n,const int f);
char *affix_protocol_len(const uint16_t protocol,const char *total_unsigned,const uint32_t total_unsigned_len)__attribute__((warn_unused_result));
char *message_sign(uint32_t *final_len,const unsigned char *sign_sk,const time_t time,const time_t nstime,const int p_iter,const char *message_unsigned,const uint32_t base_message_len)__attribute__((warn_unused_result));
uint64_t calculate_transferred(const int n,const int f)__attribute__((warn_unused_result));
uint64_t calculate_transferred_inbound(const int n,const int f)__attribute__((warn_unused_result));
uint64_t calculate_transferred_outbound(const int n,const int f,const int r)__attribute__((warn_unused_result));
uint64_t calculate_section_start(uint64_t *end_p,const uint64_t size,const uint8_t splits,const int16_t section); // No need to warn unused because we might just need end
int vptoi(const void* arg)__attribute__((warn_unused_result));
void *itovp(const int i)__attribute__((warn_unused_result));
int set_n(const int peer_index,const char *onion)__attribute__((warn_unused_result));
int set_g(const int n,const void *arg)__attribute__((warn_unused_result));
int set_f(const int n,const unsigned char *checksum,const size_t checksum_len)__attribute__((warn_unused_result));
int set_g_from_i(uint32_t *untrusted_peercount,const int n,const int i)__attribute__((warn_unused_result));
int set_f_from_i(int *file_n,const int n,const int i)__attribute__((warn_unused_result));
int set_o(const int n,const int f,const int passed_offerer_n)__attribute__((warn_unused_result));
int set_r(const int n,const int f,const int passed_requester_n)__attribute__((warn_unused_result));
void random_string(char *destination,const size_t destination_size);
void ed25519_pk_from_onion(unsigned char *ed25519_pk,const char *onion);
char *onion_from_ed25519_pk(const unsigned char *ed25519_pk)__attribute__((warn_unused_result));
int pid_kill(const pid_t pid,const int signal);
void torrc_save(const char *torrc_content_local);
char *torrc_verify(const char *torrc_content_local)__attribute__((warn_unused_result));
char *which(const char *binary)__attribute__((warn_unused_result));
size_t torx_allocation_len(const void *arg)__attribute__((warn_unused_result));
void *torx_realloc_shift(void *arg,const size_t len_new,const uint8_t shift_data_forwards)__attribute__((warn_unused_result));
void *torx_realloc(void *arg,const size_t len_new)__attribute__((warn_unused_result));
void zero_n(const int n);
int zero_i(const int n,const int i);
void zero_g(const int g);
void invitee_add(const int g,const int n);
int invitee_remove(const int g,const int n);
char *mit_strcasestr(char *dumpster,const char *diver)__attribute__((warn_unused_result));
int *refined_list(int *len,const uint8_t owner,const int peer_status,const char *search)__attribute__((warn_unused_result)); // free required
size_t stripbuffer(char *buffer);
uint16_t randport(const uint16_t arg)__attribute__((warn_unused_result));
char *replace_substring(const char *source,const char *search,const char *replace)__attribute__((warn_unused_result));
void start_tor(void);
size_t b64_decoded_size(const char *in)__attribute__((warn_unused_result));
size_t b64_decode(unsigned char *out,const size_t destination_size,const char *in); // caller must allocate space
char *b64_encode(const void *in,const size_t len)__attribute__((warn_unused_result)); // torx_free required
void initial_keyed(void);
void re_expand_callbacks(void);
void expand_message_struc(const int n,const int i); // must be called from within locks
void expand_message_struc_followup(const int n,const int i); // must be called after expand_message_struc, after unlock
int increment_i(const int n,const int offset,const time_t time,const time_t nstime,const uint8_t stat,const int8_t fd_type,const int p_iter,char *message,const uint32_t message_len)__attribute__((warn_unused_result));
int set_last_message(int *last_message_n,const int n,const int count_back)__attribute__((warn_unused_result));
int group_online(const int g)__attribute__((warn_unused_result));
int group_check_sig(const int g,const char *message,const uint32_t message_len,const uint16_t untrusted_protocol,const unsigned char *sig,const char *peeronion_prefix)__attribute__((warn_unused_result));
int group_add_peer(const int g,const char *group_peeronion,const char *group_peernick,const unsigned char *group_peer_ed25519_pk,const unsigned char *inviter_signature);
int group_join(const int inviter_n,const unsigned char *group_id,const char *group_name,const char *creator_onion,const unsigned char *creator_ed25519_pk);
int group_join_from_i(const int n,const int i);
int group_generate(const uint8_t invite_required,const char *name);
void initial(void);
void change_password_start(const char *password_old,const char *password_new,const char *password_verify);
void login_start(const char *password);
void cleanup_lib(const int sig_num);
void xstrupr(char *string);
void xstrlwr(char *string);
void load_onion_events(const int n);
int tor_call(void (*callback)(int),const int n,const char *msg);
char *onion_from_privkey(const char *privkey)__attribute__((warn_unused_result));
char *torxid_from_onion(const char *onion)__attribute__((warn_unused_result));
char *onion_from_torxid(const char *torxid)__attribute__((warn_unused_result));
int custom_input(const uint8_t owner,const char *identifier,const char *privkey);

/* broadcast.c */
void broadcast_add(const int origin_n,const unsigned char broadcast[GROUP_BROADCAST_LEN]);
void broadcast_prep(unsigned char ciphertext[GROUP_BROADCAST_LEN],const int g);
void broadcast_inbound(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN]);
void broadcast_start(void);

/* sql.c */
int load_peer_struc(const int peer_index,const uint8_t owner,const uint8_t status,const char *privkey,const uint16_t peerversion,const char *peeronion,const char *peernick,const unsigned char *sign_sk,const unsigned char *peer_sign_pk,const unsigned char *invitation);
void load_onion(const int n);
void message_offload(const int n);
void delete_log(const int n);
int message_edit(const int n,const int i,const char *message);
int sql_exec(sqlite3** db,const char *command,const char *setting_value,const size_t setting_value_len);
int sql_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len);
int sql_insert_message(const int n,const int i);
int sql_update_message(const int n,const int i);
int sql_insert_peer(const uint8_t owner,const uint8_t status,const uint16_t peerversion,const char *privkey,const char *peeronion,const char *peernick,const int expiration);
int sql_update_peer(const int n);
int sql_populate_message(const int peer_index,const uint32_t days,const uint32_t messages,const time_t since);
void message_extra(const int n,const int i,const void *data,const uint32_t data_len);
int sql_populate_peer(void);
unsigned char *sql_retrieve(size_t *data_len,const int force_plaintext,const char *query)__attribute__((warn_unused_result));
void sql_populate_setting(const int force_plaintext);
int sql_delete_message(const int peer_index,const time_t time,const time_t nstime);
int sql_delete_history(const int peer_index);
int sql_delete_setting(const int force_plaintext,const int peer_index,const char *setting_name);
int sql_delete_peer(const int peer_index);

/* file_magic.c */
int file_is_active(const int n,const int f)__attribute__((warn_unused_result));
int file_is_cancelled(const int n,const int f)__attribute__((warn_unused_result));
int file_is_complete(const int n,const int f)__attribute__((warn_unused_result));
int file_status_get(const int n,const int f)__attribute__((warn_unused_result));
void process_pause_cancel(const int n,const int f,const int peer_n,const uint16_t protocol,const uint8_t message_stat);
int process_file_offer_outbound(const int n,const unsigned char *checksum,const uint8_t splits,const unsigned char *split_hashes_and_size,const uint64_t size,const time_t modified,const char *file_path);
int process_file_offer_inbound(const int n,const int p_iter,const char *message,const uint32_t message_len);
int peer_save(const char *unstripped_peerid,const char *peernick);
void peer_accept(const int n);
void change_nick(const int n,const char *freshpeernick);
uint64_t get_file_size(const char *file_path)__attribute__((warn_unused_result));
void destroy_file(const char *file_path); // do not use directly for deleting history
int initialize_split_info(const int n,const int f);
void section_update(const int n,const int f,const uint64_t packet_start,const size_t wrote,const int8_t fd_type,const int16_t section,const uint64_t section_end,const int peer_n);
size_t b3sum_bin(unsigned char checksum[CHECKSUM_BIN_LEN],const char *file_path,const unsigned char *data,const uint64_t start,const uint64_t len);
char *custom_input_file(const char *hs_ed25519_secret_key_file)__attribute__((warn_unused_result));
void takedown_onion(const int peer_index,const int delete);
void block_peer(const int n);

/* client_init.c */
void DisableNagle(const evutil_socket_t sendfd);
int file_remove_offer(const int file_n,const int f,const int peer_n);
int file_remove_request(const int file_n,const int f,const int peer_n,const int8_t fd_type);
int section_unclaim(const int n,const int f,const int peer_n,const int8_t fd_type);
int message_resend(const int n,const int i);
int message_send(const int target_n,const uint16_t protocol,const void *arg,const uint32_t base_message_len);
void kill_code(const int n,const char *explanation); // must accept -1
void file_request_internal(const int n,const int f,const int8_t fd_type);
void file_offer_internal(const int target_n,const int file_n,const int f,const uint8_t send_partial);
void file_set_path(const int n,const int f,const char *path);
void file_accept(const int n,const int f);
void file_cancel(const int n,const int f);
unsigned char *file_split_hashes(unsigned char *hash_of_hashes,const char *file_path,const uint8_t splits,const uint64_t size)__attribute__((warn_unused_result));
int file_send(const int n,const char *path);

/* serv_init.c */
int send_prep(const int n,const int file_n,const int f_i,const int p_iter,int8_t fd_type);

/* libevent.c */
void *torx_events(void *arg);

/* onion_gen.c */
void generate_onion_simple(char onion[56+1],char privkey[88+1]);
void gen_truncated_sha3(unsigned char *truncated_checksum,unsigned char *ed25519_pk);
int generate_onion(const uint8_t owner,char *privkey,const char *peernick);

/* socks.c */
evutil_socket_t remote_connect(const char *host, const char *port, struct addrinfo hints)__attribute__((warn_unused_result));
evutil_socket_t socks_connect(const char *host, const char *port)__attribute__((warn_unused_result));

/* cpucount.c */
int cpucount(void)__attribute__((warn_unused_result));

/* sha3.c */
#define DIGEST 32 // 256-bit digest in bytes.
void sha3_hash(uint8_t digest[DIGEST], const uint64_t len, const uint8_t data[len]);

/* utf-validate.c */
uint8_t utf8_valid(const void *const src,const size_t len)__attribute__((warn_unused_result));

/* base32.c */
typedef enum _baseencode_errno {
	SUCCESS = 0,
	INVALID_INPUT = 1,
	EMPTY_STRING = 2,
	INPUT_TOO_BIG = 3,
	INVALID_B32_DATA = 4,
	INVALID_B64_DATA = 5,
	MEMORY_ALLOCATION = 6,
} baseencode_error_t;
size_t base32_encode(unsigned char *encoded_data,const unsigned char *user_data,const size_t data_len);
unsigned char *base32_decode(const char *user_data_untrimmed,size_t data_len,baseencode_error_t *err)__attribute__((warn_unused_result));

#ifdef SECURE_MALLOC	// TODO implement this conditional in library and CMakeLists.txt // https://imtech.imt.fr/en/2019/01/22/stack-canaries-software-protection/
	#define ENABLE_SECURE_MALLOC 1
#else
	#define ENABLE_SECURE_MALLOC 0
#endif

#ifdef QR_GENERATOR	// TODO implement this conditional in library and CMakeLists.txt
	#include <png.h>
	#include "../qrcodegen.h"
	#include "../qrcodegen.c"
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
	#include "../torx_qr.c"
#endif

/* TorX function files */
#include "../core/utf8/utf8-validate.c"
#include "../core/blake3-tiny/blake3.c"
#include "../core/sha3-256/sha3.c"		// for onion_gen.c and for verifying checksums from https://github.com/euugenechou/sha3-256
#include "../core/mkp224o/cpucount.c"
#include "../core/torx_core.c"
#include "../core/thread_safety.c"
#include "../core/libbaseencode/base32.c"	// from libbaseencode. Issue: it sometimes outputs short output due to requiring null input.
#include "../core/netcat-openbsd/socks.c"		// openbsd socks 
#include "../core/netcat-openbsd/remote_connect.c"	// openbsd socks
#include "../core/broadcast.c"
#include "../core/libevent.c"			/* Libevent testing file */
#include "../core/onion_gen.c"
#include "../core/file_magic.c"
#include "../core/sql.c"
#include "../core/serv_init.c"
#include "../core/client_init.c"
