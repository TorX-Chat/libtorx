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

#ifndef TORX_PRIVATE_HEADERS
#define TORX_PRIVATE_HEADERS 1

#define _FILE_OFFSET_BITS 64 // keep this before headers

#include <stdio.h>
#include <stdlib.h> 	// may be redundant. Included in main.h for running external tor binary.
#include <unistd.h> 	// read, etc. Exec ( tor ) XXX does not exist in windows
#include <time.h>	// for time in message logs etc
#include <sys/types.h>	// for fork()
#include <sys/stat.h>	// for umask
#include <signal.h>	// for kill signals
#include <utime.h>
#include <inttypes.h>
/* Libevent related */
#include <errno.h>
#include <fcntl.h>

#include <sqlcipher/sqlite3.h>

#include <torx.h>

#define ENUM_MALLOC_TYPE_INSECURE INIT_VPORT // number is arbitrary, just don't make it 0/1 as too common
#define ENUM_MALLOC_TYPE_SECURE CTRL_VPORT // number is arbitrary, just don't make it 0/1 as too common
// TODO 2024/03/12 SOCKET_SO_SNDBUF perhaps we make 2048 for libevent's/our library, and 40960 for Tor because its slow?
#define SOCKET_SO_SNDBUF 2048 // By default, use 2048 because 2028*2==4096, which matches libevent's buffer size ; Higher == More speed, Lower == Less delays.
#define SOCKET_SO_RCVBUF 0 // if 0, default: cat /proc/sys/net/core/wmem_default
#define ConstrainedSockSize 0 // not sure if defaulting to system defaults TODO constrain if there are issues with file transfers appearing to send immediately
#define INIT_VPORT 60591 // Tribute to Phil Zimmerman, June 5th 1991, creator of PGP and contributor to ZRTP. https://philzimmermann.com/EN/background/index.html
#define CTRL_VPORT 61912 // Tribute to Julian Assange, June 19th 2012. NOTE: Ports should be listed in LongLivedPorts in torrc.
#define PORT_DEFAULT_SOCKS 9050
#define PORT_DEFAULT_CONTROL 9051
#define PACKET_SIZE_MAX 498 // (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) = 498 https://github.com/torproject/tor/blob/main/src/core/or/or.h#L489 Appears to be 498 sometimes, 506 other times, but should verify via https://github.com/spring-epfl/tor-cell-dissector
#define CHECKSUM_ON_COMPLETION 1 // This blocks, so it should be used for debug purposes only
#define MESSAGE_TIMEOUT -1 // should be -1(disabled), but IN THEORY we could be recieving messages but unable to send while waiting for tor's timeout to expire. In practice, -1 has been best. Update: does nothing.
#define AUTOMATICALLY_LOAD_CTRL 1 // 1 yes, 0 no. 1 is effectively default for -q mode. This is not a viable solution because adversaries can still monitor your disconnection times. 
#define TOR_CTRL_IP "127.0.0.1" // Allowing this to be set by UI would be incredibly dangerous because users could set it to remote and expose their keys to unencrypted networks. Note: in *nix, we could use unix sockets.
#define TOR_SOCKS_IP "127.0.0.1" // See above. If system tor is not using this IP for their socks port, we won't be able to connect because extract_port doesn't account for it.
#define RETRIES_MAX 300 // Maximum amount of tries for tor_call() (to compensate for slow startups, usually takes only 1 but might take more on slow devices when starting up (up to around 9 on android emulator)
#define BROADCAST_DELAY 1 // seconds, should equal to or lower than BROADCAST_DELAY_SLEEP. To disable broadcasts, set to 0.
#define BROADCAST_DELAY_SLEEP 10 // used if no message was sent last time (sleep mode, save CPU cycles)
#define BROADCAST_MAX_INBOUND_PER_PEER (BROADCAST_QUEUE_SIZE/16) // Prevent a single peer from filling up our queue with trash. Should be less than BROADCAST_QUEUE_SIZE.

struct packet_info {
	int n; // adding this so we can remove it from peer struct to save HUGE amounts of RAM (confirmed), this was like 80% of our logged in RAM
	#ifndef NO_FILE_TRANSFER
	int file_n;
	#endif // NO_FILE_TRANSFER
	int f_i; // f value or i value, as appropriate? (cannot be required)
	uint16_t packet_len; // size of packet, or unsent size of packet if partial
	int p_iter; // initialize at -1
	int8_t fd_type; // -1 trash (ready for re-use??? but then out of order),0 recv, 1 send
	time_t time; // time added to packet struct
	time_t nstime; // time added to packet struct
}; // Should be filled for each packet added to an evbuffer so that we can determine how to make the appropriate :sent: writes 
extern struct packet_info packet[SIZE_PACKET_STRC];

struct broadcasts_list {
	uint32_t hash;
	unsigned char broadcast[GROUP_BROADCAST_LEN];
	int peers[BROADCAST_MAX_PEERS]; // initialized as -1
}; // this is queue
extern struct broadcasts_list broadcasts_queued[BROADCAST_QUEUE_SIZE];

/* Internal Use Struct Models used for passing to specific pthread'd functions */ // Don't forget to initialize = {0} when calling these types.
struct blake3 {
	unsigned char input[64];	/* current input bytes */
	uint32_t bytes;			/* bytes in current input block */
	unsigned block;			/* block index in chunk */
	uint64_t chunk;			/* chunk index */
	uint32_t *cv, cv_buf[54 * 8];	/* chain value stack */
};
struct tor_call_strc {
	pthread_t thrd;
	void (*callback)(char*);
	char *msg;
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
	uint32_t untrusted_message_len; // peer reported length of message currently in .buffer
	uint8_t killed;
};
struct int_char { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int i; // cannot make const, not necessary anyway
	const char *p;
	const unsigned char *up;
};
#ifndef NO_FILE_TRANSFER
struct file_request_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int n;
	int f;
	int8_t fd_type;
	int16_t section; // must NOT be uint8_t because it MUST be able to reach 256, even though the maximum section number is 0-255; avoid uint8_t overflows in for loops.
	uint64_t start;
	uint64_t end;
};
#endif // NO_FILE_TRANSFER

/* torx_core.c */
int message_insert(const int g,const int n,const int i);
void message_remove(const int g,const int n,const int i);
void message_sort(const int g);
time_t message_find_since(const int n)__attribute__((warn_unused_result));
char *affix_protocol_len(const uint16_t protocol,const char *total_unsigned,const uint32_t total_unsigned_len)__attribute__((warn_unused_result));
char *message_sign(const unsigned char *sign_sk,const time_t time,const time_t nstime,const int p_iter,const char *message_unsigned,const uint32_t base_message_len)__attribute__((warn_unused_result));
void ed25519_pk_from_onion(unsigned char *ed25519_pk,const char *onion);
char *onion_from_ed25519_pk(const unsigned char *ed25519_pk)__attribute__((warn_unused_result));
void zero_n(const int n); // must be called from within locks
int zero_i(const int n,const int i); // must be called from within locks
void zero_g(const int g);
void invitee_add(const int g,const int n);
int invitee_remove(const int g,const int n);
char *mit_strcasestr(char *dumpster,const char *diver)__attribute__((warn_unused_result));
size_t stripbuffer(char *buffer);
char *replace_substring(const char *source,const char *search,const char *replace)__attribute__((warn_unused_result));
void expand_message_struc(const int n,const int i); // must be called from within locks
void expand_message_struc_followup(const int n,const int i);
int increment_i(const int n,const int offset,const time_t time,const time_t nstime,const uint8_t stat,const int8_t fd_type,const int p_iter,char *message)__attribute__((warn_unused_result));
int group_add_peer(const int g,const char *group_peeronion,const char *group_peernick,const unsigned char *group_peer_ed25519_pk,const unsigned char *inviter_signature);
void xstrupr(char *string);
void xstrlwr(char *string);

/* broadcast.c */
void broadcast_prep(unsigned char ciphertext[GROUP_BROADCAST_LEN],const int g);
void broadcast_inbound(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN]);
void broadcast_start(void);
void broadcast_add(const int origin_n,const unsigned char broadcast[GROUP_BROADCAST_LEN]);
void broadcast_remove(const int g);

/* sql.c */
int load_peer_struc(const int peer_index,const uint8_t owner,const uint8_t status,const char *privkey,const uint16_t peerversion,const char *peeronion,const char *peernick,const unsigned char *sign_sk,const unsigned char *peer_sign_pk,const unsigned char *invitation);
int sql_exec(sqlite3** db,const char *command,...);
unsigned char *sql_retrieve_setting(const int force_plaintext,const char *setting_name)__attribute__((warn_unused_result));
int sql_insert_message(const int n,const int i);
int sql_update_message(const int n,const int i);
int sql_insert_peer(const uint8_t owner,const uint8_t status,const uint16_t peerversion,const char *privkey,const char *peeronion,const char *peernick,const int expiration);
int sql_update_peer(const int n);
int sql_populate_message(const int peer_index,const uint32_t days,const uint32_t messages,const time_t since);
int sql_populate_peer(void);
int sql_delete_message(const int peer_index,const time_t time,const time_t nstime);
int sql_delete_history(const int peer_index);
int sql_delete_peer(const int peer_index);

/* client_init.c */
void *peer_init(void *arg);

/* serv_init.c */
int send_prep(const int n,const int file_n,const int f_i,const int p_iter,int8_t fd_type);
int add_onion_call(const int n);
void load_onion(const int n);

/* libevent.c */
void *torx_events(void *ctx);

/* onion_gen.c */
void generate_onion_simple(char onion[56+1],char privkey[88+1]);
void gen_truncated_sha3(unsigned char *truncated_checksum,unsigned char *ed25519_pk);

/* socks.c */
void DisableNagle(const evutil_socket_t sendfd);
evutil_socket_t socks_connect(const char *host, const char *port)__attribute__((warn_unused_result));

/* sha3.c */
#define DIGEST 32 // 256-bit digest in bytes.
void sha3_hash(uint8_t digest[DIGEST], const uint64_t len, const uint8_t data[len]);

/* blake3.c */
void blake3_init(struct blake3 *);
void blake3_update(struct blake3 *, const void *, size_t);
void blake3_out(struct blake3 *, unsigned char *restrict, size_t);
size_t b3sum_bin(unsigned char checksum[CHECKSUM_BIN_LEN],const char *file_path,const unsigned char *data,const uint64_t start,const uint64_t len);

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

#ifndef NO_FILE_TRANSFER
extern int file_piece_p_iter;
void initialize_f(const int n,const int f);
void zero_o(const int n,const int f,const int o);
void zero_r(const int n,const int f,const int r);
void zero_f(const int n,const int f);
void transfer_progress(const int n,const int f);
uint64_t calculate_section_start(uint64_t *end_p,const uint64_t size,const uint8_t splits,const int16_t section); // No need to warn unused because we might just need end
void process_pause_cancel(const int n,const int f,const int peer_n,const uint16_t protocol,const uint8_t message_stat);
int process_file_offer_outbound(const int n,const unsigned char *checksum,const uint8_t splits,const unsigned char *split_hashes_and_size,const uint64_t size,const time_t modified,const char *file_path);
int process_file_offer_inbound(const int n,const int p_iter,const char *message,const uint32_t message_len);
int initialize_split_info(const int n,const int f);
int16_t section_determination(const uint64_t size,const uint8_t splits,const uint64_t packet_start)__attribute__((warn_unused_result));
void section_update(const int n,const int f,const uint64_t packet_start,const size_t wrote,const int8_t fd_type,const int16_t section,const uint64_t section_end,const int peer_n);
int calculate_file_request_start_end(uint64_t *start,uint64_t *end,const int n,const int f,const int o,const int16_t section)__attribute__((warn_unused_result));
int file_remove_offer(const int file_n,const int f,const int peer_n);
int file_remove_request(const int file_n,const int f,const int peer_n,const int8_t fd_type);
int section_unclaim(const int n,const int f,const int peer_n,const int8_t fd_type);
void file_request_internal(const int n,const int f,const int8_t fd_type);
void file_offer_internal(const int target_n,const int file_n,const int f,const uint8_t send_partial);
unsigned char *file_split_hashes(unsigned char *hash_of_hashes,const char *file_path,const uint8_t splits,const uint64_t size)__attribute__((warn_unused_result));
#endif // NO_FILE_TRANSFER

#ifndef NO_AUDIO_CALL
int set_c(const int call_n,const time_t time,const time_t nstime)__attribute__((warn_unused_result));
void initialize_peer_call(const int call_n,const int call_c);
void call_peer_joining(const int call_n,const int call_c,const int participant_n);
void call_peer_leaving(const int call_n,const int call_c,const int participant_n);
void call_peer_leaving_all_except(const int participant_n,const int except_n,const int except_c);
void audio_cache_add(const int participant_n,const time_t time,const time_t nstime,const char *data,const size_t data_len);
void audio_cache_clear_participant(const int participant_n);
void audio_cache_clear_all(const int call_n,const int call_c);
uint32_t record_cache_clear_nolocks(const int call_n);
#endif // NO_AUDIO_CALL

#ifndef NO_STICKERS
void sticker_add_peer(const int s,const int n);
uint8_t sticker_has_peer(const int s,const int n)__attribute__((warn_unused_result));
void sticker_remove_peer(const int s,const int n);
void sticker_remove_peer_from_all(const int n);
#endif // NO_STICKERS

/* Global variables (defined here, declared elsewhere, primarily in torx_core.c) */
extern uint8_t v3auth_enabled;
extern size_t tor_calls;
extern long long unsigned int crypto_pwhash_OPSLIMIT;
extern size_t crypto_pwhash_MEMLIMIT;
extern int crypto_pwhash_ALG;
extern char saltbuffer[crypto_pwhash_SALTBYTES];
extern char *file_db_plaintext;
extern char *file_db_encrypted;
extern char *file_db_messages;
extern char *file_tor_pid;
extern char control_password_hash[61+1];
extern evutil_socket_t tor_ctrl_socket;
extern uint8_t sodium_initialized;
extern int highest_ever_o;
extern unsigned char decryption_key[crypto_box_SEEDBYTES];
extern uint32_t broadcast_history[BROADCAST_HISTORY_SIZE];
extern pthread_rwlock_t mutex_packet;
extern pthread_rwlock_t mutex_broadcast;
#ifndef NO_STICKERS
extern pthread_rwlock_t mutex_sticker;
#endif // NO_STICKERS
extern pthread_t thrd_tor_log_reader;
extern pthread_t thrd_start_tor;
extern pthread_t thrd_broadcast;
extern pthread_t thrd_change_password;
extern pthread_t thrd_login;
extern pthread_mutex_t mutex_socket_rand;
extern pthread_mutex_t mutex_clock;
extern pthread_mutex_t mutex_sql_plaintext;
extern pthread_mutex_t mutex_sql_encrypted;
extern pthread_mutex_t mutex_sql_messages;
extern pthread_mutex_t mutex_group_peer_add;
extern pthread_mutex_t mutex_group_join;
extern pthread_mutex_t mutex_onion;
extern pthread_mutex_t mutex_closing;
extern pthread_mutex_t mutex_tor_pipe;
extern pthread_mutex_t mutex_message_loading;
extern pthread_mutex_t mutex_tor_ctrl;
extern sqlite3 *db_plaintext;
extern sqlite3 *db_encrypted;
extern sqlite3 *db_messages;

#endif // TORX_PRIVATE_HEADERS
