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

/*	This file will contain most core functions. There will be no "main" because core is a library.	*/

/*
	Regarding the MitM potential:
	* we could concat the onion & peeronion, make a hash, and then people should compare the hash outside? The value of this is low however and it is stupidly complex for normies to understand.
		- (strings would have to be a particular order(abc..129?).... otherwise the hash would be different)

TODO FIXME XXX Notes:
	* Do not use: strcpy, strncpy, strcat, strncat, strcmp, scanf, itoa (strncmp is ok)
	* %m (allocation related) must be avoided because it is normal malloc and therefore incompatible with torx_free((void*)&)
	* sleep() should be used carefully because sleep() on android is not accurately one second. Commonly speed up by several times for unknown reasons.
	* AUTOMATICALLY_LOAD_CTRL = 0 is not viable because adversaries can monitor disconnection times
	* having connections break after every message (preventing online status checks) is not really viable because an adversary can still do a HSDir lookup to find you status, without ever making a TCP connection to you
*/

/* Globally defined variables follow */ // XXX BE SURE TO UPDATE CMakeLists.txt VERSION XXX
const uint16_t torx_library_version[4] = { 2 , 0 , 35 , 0 }; // https://semver.org [0]++ breaks protocol, [1]++ breaks databases, [2]++ breaks api, [3]++ breaks nothing. SEMANTIC VERSIONING.
// XXX NOTE: UI versioning should mirror the first 3 and then go wild on the last. XXX BE SURE TO UPDATE CMakeLists.txt VERSION XXX

/* Configurable Options */ // Note: Some don't need rwlock because they are modified only once at startup
void *ui_data = NULL; // XXX UI devs may put a struct on this to store data within the C backend, to avoid being lost during UI disposal. The library must NOT use it. XXX
char *debug_file = {0}; // This is ONLY FOR DEVELOPMENT USE. Set to a filename to enable
uint8_t v3auth_enabled = 1; // global default // 0 (off), 1 (BEST: derived from onion). NOT user toggleable. For discussion on the safety of using onion derived ed25519 keys and converting to x25519: https://crypto.stackexchange.com/questions/3260/using-same-keypair-for-diffie-hellman-and-signing/3311#3311
uint8_t reduced_memory = 0; // NOTE: increasing decreases RAM requirements *and* CPU cycles. 0 = 1024mb, 1 = 256mb, 2 = 64mb. More ram allocated will make startup ever-so-slightly slower, but significantly increase security against bruteforcing. Recommended to leave as default (0, 1024mb), but could crash some devices.
int8_t debug = 0; //"0-5" default verbosity. Ensure that privacy related info is not printed before level 3.
long long unsigned int crypto_pwhash_OPSLIMIT = 0;
size_t crypto_pwhash_MEMLIMIT = 0;
size_t tor_calls = 0; // This is part of a work-around for a bug
int crypto_pwhash_ALG = 0;
char saltbuffer[crypto_pwhash_SALTBYTES]; // 16
char *working_dir = {0}; // directory for containing .db and .pid files
char *file_db_plaintext = {0}; // "plaintext.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_db_encrypted = {0}; // "encrypted.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_db_messages = {0}; // "messages.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_tor_pid = {0}; // "tor.pid";
char *control_password_clear = {0};
char control_password_hash[61+1] = {0}; // MUST be \0 initialized. // does not need rwlock because only modified once // correct length.  Is cleared on shutdown in case it was set by UI to something custom.
char *torrc_content = {0}; // default is set in initial() or after initial() by UI
char *default_peernick = {0}; // default is set in initial() or after initial() by UI. Do not null.
evutil_socket_t tor_ctrl_socket = {0}; // for tor_call()
uint16_t tor_socks_port = 0; // Must initialize to 0 rather than PORT_DEFAULT_SOCKS to allow setting by UI for system tor usage
uint16_t tor_ctrl_port = 0; // Must initialize to 0 rather than PORT_DEFAULT_CONTROL to allow setting by UI for system tor usage
uint32_t tor_version[4] = {0};
uint8_t sodium_initialized = 0; // Do not add a rwlock. Must be fast. Added to prevent SEVERE memory errors that are incredibly difficult to diagnose.
uint8_t currently_changing_pass = 0; // TODO consider using mutex_sql_encrypted instead
uint8_t first_run = 0; // TODO use for setting default torrc (ie, ask user). do not manually change this. This works and can be used as the basis for stuff (ex: an introduction or opening help in a GUI client)
uint8_t destroy_input = 0; // 0 no, 1 yes. Destroy custom input file.
uint8_t tor_running = 0; // For UI, it's probably better to use bootstrapping % to determine. This is for library usage to determine if Tor is responsive.
uint8_t using_system_tor = 0; // Trigger this by setting a tor_ctrl_port to a valid control port and optionally set control_password_clear
uint8_t lockout = 0;
uint8_t keyed = 0; // whether initial_keyed has run. better than checking !torrc_content or !tor_ctrl_port
pid_t tor_pid = 0; // Do not use this to check if Tor is running because this is not set when using system tor. Use tor_running.
int highest_ever_o = 0;
uint8_t messages_loaded = 0; // easy way to check whether messages are already loaded, to prevent re-loading when re-running "load_onions" on restarting tor
unsigned char decryption_key[crypto_box_SEEDBYTES] = {0}; // 32 *must* be intialized as zero to permit passwordless login
int max_group = 0; // Should not be used except to constrain expand_message_struc
int max_peer = 0; // Should not be used except to constrain expand_peer_struc
time_t startup_time = 0;
#ifdef WIN32
const char platform_slash = '\\';
#else
const char platform_slash = '/';
#endif

/* User configurable options that will automatically be checked by initial() */
char *snowflake_location = {0}; // UI should set this
char *lyrebird_location = {0}; // UI should set this
char *conjure_location = {0}; // UI should set this
char *native_library_directory = {0}; // UI should set this (Android-only)
char *tor_data_directory = {0}; // UI can set this as a fixed path (relative paths produce warnings) within working_dir. This will override any path set in torrc.
char *tor_location = {0}; // $PATH will be used if this is not set. Must be set on android/windows.
uint32_t sing_expiration_days = 30; // default 30 days, is deleted after. 0 should be no expiration.
uint32_t mult_expiration_days = 365; // default 1 year, is deleted after. 0 should be no expiration.
uint32_t show_log_messages = 500; // TODO For production, set this to a high number (hundreds or thousands) to avoid causing issues with file transfers. For testing/debugging, set this to something low (like 25 to 205) and ensure it works. Note: Needs to be above what could be reasonably shown on any size of large screen. Needs also to consider that file related messages are included yet invisible.
uint8_t global_log_messages = 1; // 0 no, 1 encrypted, 2 plaintext (depreciated, no longer exists). This is the "global default" which can be overridden per-peer.
uint8_t log_last_seen = 1;
uint8_t auto_accept_mult = 0; // 1 is yes, 0 is no. Yes is not good. Using mults in general is not good. We should rate limit them or have them only come on line for 1 minute every 30 minutes (randomly) and accept 1 connect.
uint8_t shorten_torxids = 1; // 1 is on, 0 is off. Cuts off the version byte, the checksum, and a prefix
uint8_t suffix_length = 4; // 4 is a reasonable default for suffix at this time (or 3 for prefix). Up to 7 has been confirmed possible (45 length torxid).
uint32_t global_threads = 1; // for onion_gen(), cpu threads.
uint32_t threads_max = 0; // max as detected by cpu_count()
uint8_t kill_delete = 1; // delete peer and history when receiving kill code (if zero, just block and keep history). This can be set by UI.
uint8_t hide_blocked_group_peer_messages = 0; // Note: blocking would require re-sorting, if hide is toggled
uint8_t log_pm_according_to_group_setting = 1; // toggles whether or not PM logging should follow the logging settings of the group (useful to UI devs who might want to control group PM logging per-peer)
uint8_t censored_region = 0;
uint32_t broadcast_history[BROADCAST_HISTORY_SIZE] = {0}; // NOTE: this is sent OR queued

struct peer_list *peer = {0};
struct group_list *group = {0};
struct packet_info packet[SIZE_PACKET_STRC] = {0};
struct protocol_info protocols[PROTOCOL_LIST_SIZE] = {0};
struct broadcasts_list broadcasts_queued[BROADCAST_QUEUE_SIZE] = {0};

void (*initialize_n_registered)(int) = NULL;
void (*initialize_i_registered)(const int n,const int i) = NULL;
void (*initialize_g_registered)(const int g) = NULL;
void (*shrinkage_registered)(const int n,const int shrinkage) = NULL;
void (*expand_message_struc_registered)(const int n,const int i) = NULL;
void (*expand_peer_struc_registered)(const int n) = NULL;
void (*expand_group_struc_registered)(const int g) = NULL;
void (*change_password_registered)(const int value) = NULL;
void (*incoming_friend_request_registered)(const int n) = NULL;
void (*onion_deleted_registered)(const uint8_t owner,const int n) = NULL;
void (*peer_online_registered)(const int n) = NULL;
void (*peer_offline_registered)(const int n) = NULL;
void (*peer_new_registered)(const int n) = NULL;
void (*onion_ready_registered)(const int n) = NULL;
void (*tor_log_registered)(char *message) = NULL;
void (*error_registered)(char *error_message) = NULL;
void (*fatal_registered)(char *error_message) = NULL;
void (*custom_setting_registered)(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext) = NULL;
void (*message_new_registered)(const int n,const int i) = NULL;
void (*message_modified_registered)(const int n,const int i) = NULL;
void (*message_deleted_registered)(const int n,const int i) = NULL;
void (*message_extra_registered)(const int n,const int i,unsigned char *data,const uint32_t data_len) = NULL;
void (*message_more_registered)(const int loaded,int *loaded_array_n,int *loaded_array_i) = NULL;
void (*login_registered)(const int value) = NULL;
void (*peer_loaded_registered)(const int n) = NULL;
void (*cleanup_registered)(const int sig_num) = NULL; // callback to UI to inform it that we are closing and it should save settings
void (*stream_registered)(const int n,const int p_iter,char *data,const uint32_t len) = NULL;
void (*unknown_registered)(const int n,const uint16_t protocol,char *data,const uint32_t len) = NULL;

static char *read_tor_pipe_cache = NULL; // cache it hits a newline, without blocking

pthread_attr_t ATTR_DETACHED; // Note: must be initialized by initial before use. Replaces pthread_detach to prevent data race in calls to pusher/zero_pthread.

pthread_t thrd_tor_log_reader = {0};
pthread_t thrd_start_tor = {0}; // start_tor_threaded (starting tor and calling sql_populate_peer)
pthread_t thrd_broadcast = {0}; // for broadcast_threaded
pthread_t thrd_change_password = {0}; // for change_password_threaded
pthread_t thrd_login = {0}; // for login_threaded

pthread_mutex_t mutex_socket_rand = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_clock = PTHREAD_MUTEX_INITIALIZER; // to ensure unique message times.
pthread_mutex_t mutex_sql_plaintext = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_sql_encrypted = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_sql_messages = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_group_peer_add = PTHREAD_MUTEX_INITIALIZER; // is necessary to avoid race condition, do not eliminate
pthread_mutex_t mutex_group_join = PTHREAD_MUTEX_INITIALIZER; // is necessary to avoid race condition, do not eliminate
pthread_mutex_t mutex_onion = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_closing = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_tor_pipe = PTHREAD_MUTEX_INITIALIZER; // prevents rapid restarts of Tor from causing issues with reading Tor's STDOUT
pthread_mutex_t mutex_message_loading = PTHREAD_MUTEX_INITIALIZER; // may be necessary in rare cases where Tor for some reason restarts on startup; related to messages_loaded
pthread_mutex_t mutex_tor_ctrl = PTHREAD_MUTEX_INITIALIZER; // prevents multiple concurrent Tor calls (since we need to recv respones before sending new commands)

/* 2024 rwmutex */
pthread_rwlock_t mutex_debug_level = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_global_variable = PTHREAD_RWLOCK_INITIALIZER; // do not use for debug variable
pthread_rwlock_t mutex_protocols = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_expand = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_expand_group = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_packet = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_broadcast = PTHREAD_RWLOCK_INITIALIZER;

sqlite3 *db_plaintext = {0};
sqlite3 *db_encrypted = {0};
sqlite3 *db_messages = {0};

const char *tor_log_removed_suffixes[] = {". Giving up. (waiting for circuit)\n", "New control connection opened from 127.0.0.1.\n", ". Giving up. (waiting for rendezvous desc)\n", "].onion for reason resolve failed. Fetch status: No more HSDir available to query.\n"};

const char *torrc_content_default = "\
## Contents of this file are encrypted\n\
# Socks5Proxy 127.0.0.1:PORT\n\
# LogTimeGranularity 1\n\
# SafeLogging 0\n\
# Log debug file tor-debug.log\n\
## CircuitsAvailableTimeout 86400\n\
## ConnectionPadding auto\n\
## ReducedConnectionPadding 0\n\
## DormantTimeoutDisabledByIdleStreams 1\n\
## KeepalivePeriod 300\n\
## DormantClientTimeout 1000 week\n\
## MaxCircuitDirtiness 1000 week\n\
## FetchUselessDescriptors 1\n\
"; // This default this all will be replaced by initial_keyed() if user has set something, or UI defaults
const char *torrc_content_default_censored_region_part1 = "\
## Contents of this file are encrypted\n\
## CircuitsAvailableTimeout 86400\n\
## ConnectionPadding auto\n\
## ReducedConnectionPadding 0\n\
## DormantTimeoutDisabledByIdleStreams 1\n\
## KeepalivePeriod 300\n\
## DormantClientTimeout 1000 week\n\
## MaxCircuitDirtiness 1000 week\n\
## FetchUselessDescriptors 1\n\
UseBridges 1\n\
UpdateBridgesFromAuthority 1\n\
ClientTransportPlugin snowflake exec ";
const char *torrc_content_default_censored_region_part2 = "\n\
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn\n\
Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn\n\
";
// For updated bridges: https://github.com/net4people/bbs/issues/338 https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/raw/main/projects/tor-expert-bundle/pt_config.json
const char *table_peer = \
	"CREATE TABLE IF NOT EXISTS peer (\
		peer_index	INTEGER	PRIMARY KEY AUTOINCREMENT,\
		owner		INT	STRICT NOT NULL,\
		status		INT	STRICT NOT NULL,\
		peerversion	INT	STRICT NOT NULL,\
		privkey		TEXT	STRICT NOT NULL UNIQUE CHECK (length(privkey) == 88),\
		peeronion	TEXT	STRICT NOT NULL UNIQUE CHECK (length(peeronion) == 56),\
		peernick	TEXT	STRICT NOT NULL,\
		peer_sign_pk	BLOB,\
		sign_sk		BLOB,\
		invitation	BLOB,\
		expiration	INT\
	);";
const char *table_setting_clear = \
	"CREATE TABLE IF NOT EXISTS setting_clear (\
		setting_index	INTEGER	PRIMARY KEY AUTOINCREMENT,\
		setting_name	TEXT	STRICT UNIQUE NOT NULL,\
		setting_value   BLOB\
	);";
const char *table_setting_global = \
	"CREATE TABLE IF NOT EXISTS setting_global (\
		setting_index	INTEGER	PRIMARY KEY AUTOINCREMENT,\
		setting_name	TEXT	STRICT UNIQUE NOT NULL,\
		setting_value   BLOB\
	);";
const char *table_setting_peer = \
	"CREATE TABLE IF NOT EXISTS setting_peer (\
		setting_index	INTEGER	PRIMARY KEY AUTOINCREMENT,\
		peer_index	INT	STRICT,\
		setting_name	TEXT	STRICT NOT NULL,\
		setting_value   BLOB\
	);"; // REFERENCES peer(peer_index) ON DELETE CASCADE
const char *table_message = /* Messages can be null (ex: GROUP_PEER). Message must be text-only for full-text search support*/\
	"CREATE TABLE IF NOT EXISTS message (\
		time		INT	STRICT NOT NULL,\
		nstime		INT	STRICT NOT NULL,\
		peer_index	INT 	STRICT NOT NULL,\
		stat		INT	STRICT NOT NULL,\
		protocol	INT	STRICT NOT NULL,\
		message_txt	TEXT	STRICT,\
		message_bin	BLOB,\
		signature	BLOB,\
		extraneous	BLOB,\
		PRIMARY KEY	(peer_index, time, nstime)\
	) WITHOUT ROWID;"; // REFERENCES peer(peer_index) ON DELETE CASCADE

int protocol_lookup(const uint16_t protocol)
{ // Check if a protocol is within an array, return p_iter
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧 // this operates recursively, is typically redundant. Just leave it as redundant.
	for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE; p_iter++)
		if(protocols[p_iter].protocol == protocol)
		{
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			return p_iter;
		}
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
//	error_printf(0,"Protocol not found: %u. Be sure to catch this.",protocol);
	return -1; // protocol not found. be sure to catch this.
}

int protocol_registration(const uint16_t protocol,const char *name,const char *description,const uint8_t null_terminate,const uint8_t date,const uint8_t sign,const uint8_t logged,const uint8_t notifiable,const uint8_t file_checksum,const uint8_t file_offer,const uint8_t exclusive_type,const uint8_t utf8,const uint8_t socket_swappable,const uint8_t stream)
{ // Register a custom protocol // TODO probbaly passing a struct + protocol is more rational than this massive amount of args
	if(protocol_lookup(protocol) != -1)
	{ // TODO more sanity checks
		error_printf(0,"Protocol already exists or sanity check failed. Cannot register: %u %u %s",logged,stream,name);
		return -1; // invalid args or protocol exists already
	}
	uint8_t group_pm = 0;
	uint8_t group_msg = 0;
	uint8_t group_mechanics = 0;
	if(exclusive_type == ENUM_EXCLUSIVE_GROUP_PM)
		group_pm = 1;
	else if(exclusive_type == ENUM_EXCLUSIVE_GROUP_MSG)
		group_msg = 1;
	else if(exclusive_type == ENUM_EXCLUSIVE_GROUP_MECHANICS)
		group_mechanics = 1;
	pthread_rwlock_wrlock(&mutex_protocols); // 🟥
	for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE; p_iter++)
		if(protocols[p_iter].protocol == 0)
		{ // set stuff in an unused p_iter
			protocols[p_iter].protocol = protocol;
			if(name)
				snprintf(protocols[p_iter].name,sizeof(protocols[p_iter].name),"%s",name);
			if(description)
				snprintf(protocols[p_iter].description,sizeof(protocols[p_iter].description),"%s",description);
			protocols[p_iter].null_terminated_len = null_terminate;
			protocols[p_iter].date_len = date ? 2*sizeof(uint32_t) : 0;
			protocols[p_iter].signature_len = sign ? crypto_sign_BYTES : 0;
			protocols[p_iter].logged = logged;
			protocols[p_iter].notifiable = notifiable;
			protocols[p_iter].file_checksum = file_checksum;
			protocols[p_iter].group_pm = group_pm;
			protocols[p_iter].group_msg = group_msg;
			protocols[p_iter].file_offer = file_offer;
			protocols[p_iter].group_mechanics = group_mechanics;
			protocols[p_iter].utf8 = utf8;
			protocols[p_iter].socket_swappable = socket_swappable;
			protocols[p_iter].stream = stream;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			return p_iter;
		}
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	error_simple(0,"Cannot register protocol. Hit PROTOCOL_LIST_SIZE."); // so increase it!
	breakpoint();
	return -1;
}

void torx_fn_read(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read prevented. Coding error. Report this.");
	torx_read(n) // 🟧🟧🟧
}
void torx_fn_write(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read prevented. Coding error. Report this.");
	torx_write(n) // 🟥🟥🟥
}
void torx_fn_unlock(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read occurred. Coding error. Report this.");
	torx_unlock(n) // 🟩🟩🟩
}

static inline int torx_close_socket(pthread_rwlock_t *mutex,evutil_socket_t *socket)
{ // Only useful for global variables. NOTE: For file descriptors, use close_sockets_nolock and close_sockets macros.
	if(!socket)
		return -1; // Sanity check
	if(mutex)
		pthread_rwlock_wrlock(mutex); // 🟥
	int ret = 0;
	if(*socket > 0 && (ret = evutil_closesocket(*socket)) < 0)
	{
		error_simple(0,"Failed to close socket.");
		breakpoint();
	}
	*socket = 0;
	if(mutex)
		pthread_rwlock_unlock(mutex); // 🟩
	return ret; // 0 on success or non-op
}

static inline void write_debug_file(const char *message)
{
	if(!message || !strlen(message))
		return;
	FILE *file = fopen(debug_file, "a+");
	if(file == NULL)
		return;
	fputs(message,file); // No point to check return here
	close_sockets_nolock(file)
}

static inline void error_allocated_already(const int debug_level,char *do_not_free_message)
{ // INTERNAL FUNCTION ONLY. No sanity checks, do_not_free_message must be already allocated by torx_secure_malloc.
	if(debug_file)
		write_debug_file(do_not_free_message);
	if(debug_level < 0)
	{
		breakpoint();
		fatal_cb(do_not_free_message); // must free.
		cleanup_cb(debug_level);
	}
	else
		error_cb(do_not_free_message); // must free. Could also return level and length. Custom levels could be used to make a popup notification, etc.
// Ideally we would free in this function and all the _cb should be const char, but in reality we can't do that because callbacks may occur asyncronously
}

void error_simple(const int debug_level,const char *error_message)
{ // Adds newline if one does not exist
	if(!error_message || debug_level > torx_debug_level(-1))
		return;
	const size_t length = strlen(error_message);
	uint8_t has_newline = 0;
	if(error_message[length-1] == '\n')
		has_newline = 1;
	char *do_not_free_message = torx_secure_malloc(length + 2 - has_newline);
	if(has_newline)
		snprintf(do_not_free_message,length+1,"%s",error_message);
	else
		snprintf(do_not_free_message,length+2,"%s\n",error_message);
	error_allocated_already(debug_level,do_not_free_message);
}

void error_printf(const int debug_level,const char *format,...)
{ // Adds newline if one does not exist (either in format or final string)
	if(!format || debug_level > torx_debug_level(-1))
		return;
	va_list args, copy;
	va_start(args, format);
	va_copy(copy, args);
	uint8_t has_newline = 0;
	if(format[strlen(format)-1] == '\n')
		has_newline = 1;
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wunknown-pragmas"
	#pragma clang diagnostic push
	#pragma clang diagnostic ignored "-Wformat-nonliteral"
	const int length = vsnprintf(NULL, 0, format, copy);
	va_end(copy);
	if(length > 0)
	{
		char *do_not_free_message = torx_secure_malloc((size_t)length + 2 - has_newline);
		if(has_newline)
			vsnprintf(do_not_free_message, (size_t)length + 1, format, args);
		else
		{
			vsnprintf(do_not_free_message, (size_t)length + 1, format, args);
			if(do_not_free_message[length-1] != '\n')
			{ // one last check, to see if a potential %c or %s (etc) added a newline
				do_not_free_message[length] = '\n';
				do_not_free_message[length+1] = '\0';
			}
		}
		error_allocated_already(debug_level,do_not_free_message);
	}
	else
		error_simple(0,"Invalid format or zero length passed to error_printf");
    	va_end(args);
	#pragma clang diagnostic pop
	#pragma GCC diagnostic pop
}

void initialize_n_cb(const int n)
{
	if(initialize_n_registered)
		initialize_n_registered(n);
}
void initialize_i_cb(const int n,const int i)
{
	if(initialize_i_registered)
		initialize_i_registered(n,i);
}
void initialize_g_cb(const int g)
{
	if(initialize_g_registered)
		initialize_g_registered(g);
}
void shrinkage_cb(const int n,const int shrinkage)
{
	if(shrinkage_registered)
		shrinkage_registered(n,shrinkage);
}
void expand_message_struc_cb(const int n,const int i)
{
	if(expand_message_struc_registered)
		expand_message_struc_registered(n,i);
}
void expand_peer_struc_cb(const int n)
{
	if(expand_peer_struc_registered)
		expand_peer_struc_registered(n);
}
void expand_group_struc_cb(const int g)
{
	if(expand_group_struc_registered)
		expand_group_struc_registered(g);
}

void change_password_cb(const int value)
{
	if(change_password_registered)
		change_password_registered(value);
}
void incoming_friend_request_cb(const int n)
{
	if(incoming_friend_request_registered)
		incoming_friend_request_registered(n);
}
void onion_deleted_cb(const uint8_t owner,const int n)
{
	if(onion_deleted_registered)
		onion_deleted_registered(owner,n);
}
void peer_online_cb(const int n)
{
	if(peer_online_registered)
		peer_online_registered(n);
}
void peer_offline_cb(const int n)
{
	if(peer_offline_registered)
		peer_offline_registered(n);
}
void peer_new_cb(const int n)
{
	if(peer_new_registered)
		peer_new_registered(n);
}
void onion_ready_cb(const int n)
{
	if(onion_ready_registered)
		onion_ready_registered(n);
}
void tor_log_cb(char *message)
{
	if(tor_log_registered)
		tor_log_registered(message);
	else
		torx_free((void*)&message);
}
void error_cb(char *error_message)
{
	if(error_registered)
		error_registered(error_message);
	else
		torx_free((void*)&error_message);
}
void fatal_cb(char *error_message)
{
	if(fatal_registered)
		fatal_registered(error_message);
	else
		torx_free((void*)&error_message);
}
void custom_setting_cb(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext)
{
	if(custom_setting_registered)
		custom_setting_registered(n,setting_name,setting_value,setting_value_len,plaintext);
	else
	{
		torx_free((void*)&setting_name);
		torx_free((void*)&setting_value);
	}
}
void message_new_cb(const int n,const int i)
{
	if(message_new_registered)
		message_new_registered(n,i);
}
void message_modified_cb(const int n,const int i)
{
	if(message_modified_registered)
		message_modified_registered(n,i);
}
void message_deleted_cb(const int n,const int i)
{ // XXX WARNING: DO NOT ACCESS .message STRUCT due to shrinkage possibly having occurred
	if(message_deleted_registered)
		message_deleted_registered(n,i);
}
void message_extra_cb(const int n,const int i,unsigned char *data,const uint32_t data_len)
{
	if(message_extra_registered)
		message_extra_registered(n,i,data,data_len);
	else
		torx_free((void*)&data);
}
void message_more_cb(const int loaded,int *loaded_array_n,int *loaded_array_i)
{
	if(message_more_registered)
		message_more_registered(loaded,loaded_array_n,loaded_array_i);
	else
	{
		torx_free((void*)&loaded_array_n);
		torx_free((void*)&loaded_array_i);
	}
}
void login_cb(const int value)
{
	if(login_registered)
		login_registered(value);
}
void peer_loaded_cb(const int n)
{
	if(peer_loaded_registered)
		peer_loaded_registered(n);
}
void cleanup_cb(const int sig_num)
{
	if(cleanup_registered)
		cleanup_registered(sig_num);
}
void stream_cb(const int n,const int p_iter,char *data,const uint32_t len)
{
	if(stream_registered)
		stream_registered(n,p_iter,data,len);
	else
		torx_free((void*)&data);
}
void unknown_cb(const int n,const uint16_t protocol,char *data,const uint32_t len)
{
	if(unknown_registered)
		unknown_registered(n,protocol,data,len);
	else
		torx_free((void*)&data);
}

void initialize_n_setter(void (*callback)(int))
{
	if(initialize_n_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_n_registered = callback;
}

void initialize_i_setter(void (*callback)(int,int))
{
	if(initialize_i_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_i_registered = callback;
}

void initialize_g_setter(void (*callback)(int))
{
	if(initialize_g_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_g_registered = callback;
}

void shrinkage_setter(void (*callback)(int,int))
{
	if(shrinkage_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		shrinkage_registered = callback;
}

void expand_message_struc_setter(void (*callback)(int,int))
{
	if(expand_message_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_message_struc_registered = callback;
}

void expand_peer_struc_setter(void (*callback)(int))
{
	if(expand_peer_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_peer_struc_registered = callback;
}

void expand_group_struc_setter(void (*callback)(int))
{
	if(expand_group_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_group_struc_registered = callback;
}

void change_password_setter(void (*callback)(int))
{
	if(change_password_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		change_password_registered = callback;
}

void incoming_friend_request_setter(void (*callback)(int))
{
	if(incoming_friend_request_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		incoming_friend_request_registered = callback;
}

void onion_deleted_setter(void (*callback)(uint8_t,int))
{
	if(onion_deleted_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		onion_deleted_registered = callback;
}

void peer_online_setter(void (*callback)(int))
{
	if(peer_online_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		peer_online_registered = callback;
}

void peer_offline_setter(void (*callback)(int))
{
	if(peer_offline_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		peer_offline_registered = callback;
}

void peer_new_setter(void (*callback)(int))
{
	if(peer_new_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		peer_new_registered = callback;
}

void onion_ready_setter(void (*callback)(int))
{
	if(onion_ready_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		onion_ready_registered = callback;
}

void tor_log_setter(void (*callback)(char*))
{
	if(tor_log_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		tor_log_registered = callback;
}

void error_setter(void (*callback)(char*))
{
	if(error_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		error_registered = callback;
}

void fatal_setter(void (*callback)(char*))
{
	if(fatal_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		fatal_registered = callback;
}

void custom_setting_setter(void (*callback)(int,char*,char*,size_t,int))
{
	if(custom_setting_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		custom_setting_registered = callback;
}

void message_new_setter(void (*callback)(int,int))
{
	if(message_new_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		message_new_registered = callback;
}

void message_modified_setter(void (*callback)(int,int))
{
	if(message_modified_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		message_modified_registered = callback;
}

void message_deleted_setter(void (*callback)(int,int))
{
	if(message_deleted_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		message_deleted_registered = callback;
}

void message_extra_setter(void (*callback)(int,int,unsigned char*,uint32_t))
{
	if(message_extra_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		message_extra_registered = callback;
}

void message_more_setter(void (*callback)(int,int*,int*))
{
	if(message_more_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		message_more_registered = callback;
}

void login_setter(void (*callback)(int))
{
	if(login_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		login_registered = callback;
}

void peer_loaded_setter(void (*callback)(int))
{
	if(peer_loaded_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		peer_loaded_registered = callback;
}

void cleanup_setter(void (*callback)(int))
{
	if(cleanup_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		cleanup_registered = callback;
}

void stream_setter(void (*callback)(int,int,char*,uint32_t))
{
	if(stream_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		stream_registered = callback;
}

void unknown_setter(void (*callback)(int,uint16_t,char*,uint32_t))
{
	if(unknown_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		unknown_registered = callback;
}

unsigned char *read_bytes(size_t *data_len,const char *path)
{ // Read a file entirely into an torx_insecure_malloc. Return data and set data_len
	unsigned char *data = NULL;
	size_t allocated = 0;
	FILE *fp;
	if(path && (fp = fopen(path, "r")))
	{
		fseek(fp, 0L, SEEK_END);
		allocated = (size_t)ftell(fp);
		data = torx_insecure_malloc(allocated);
		fseek(fp, 0L, SEEK_SET);
		if(fread(data,1,allocated,fp) != allocated)
			error_simple(0,"Read less than expected amount of data. Uncaught bug.");
		close_sockets_nolock(fp)
	}
	else
		error_simple(0,"Could not open file. Check permissions. Bailing out.");
	if(data_len)
		*data_len = allocated;
	return data;
}

void toggle_int8(void *arg)
{ // Works for int8_t and uint8_t // XXX DO NOT USE WITH g_signal_connect / g_signal_connect_swapped / any async usage requiring "&" prefix
	if(*(uint8_t *)arg)
		*(uint8_t *)arg = 0;
	else
		*(uint8_t *)arg = 1;
}

void zero_pthread(void *thrd)
{ // Implement inside thread via pthread_cleanup_push(zero_pthread,(void*)&) in all threads that could be thread_kill'd
	pthread_t *thread = (pthread_t *)thrd;
	*thread = 0;
}

static inline void thread_kill(pthread_t pthread)
{ /* man pthread_cleanup_push / pthread_cleanup_pop / Disabled because calling _join on an inactive thread causes bad times. TODO need to track "active" https://stackoverflow.com/questions/2156353/how-do-you-query-a-pthread-to-see-if-it-is-still-running */
	#ifndef __ANDROID__
	{
		if(pthread)
		{
			pthread_cancel(pthread);
			pthread_join(pthread,NULL);
		}
	}
	#endif
	(void) pthread;
}

void setcanceltype(int type,int *arg)
{
	#ifndef __ANDROID__
	{
		pthread_setcanceltype(type,arg);
	}
	#endif
	(void) type;
	(void) arg;
}

int8_t torx_debug_level(const int8_t level)
{ // sets or gets (-1)
	if(level > -1)
	{ // set
		pthread_rwlock_wrlock(&mutex_debug_level); // 🟥
		debug = level;
		pthread_rwlock_unlock(&mutex_debug_level); // 🟩
		return level;
	}
	else
	{ // get
		pthread_rwlock_rdlock(&mutex_debug_level); // 🟧
		const int8_t current_level = debug;
		pthread_rwlock_unlock(&mutex_debug_level); // 🟩
		return current_level;
	}
}

uint16_t align_uint16(const void *ptr)
{ // to satisfy -fsanitize=address load of misaligned address
	uint16_t value;
	memcpy(&value, ptr, sizeof(value));
	return value;
}

uint32_t align_uint32(const void *ptr)
{ // to satisfy -fsanitize=address load of misaligned address
	uint32_t value;
	memcpy(&value, ptr, sizeof(value));
	return value;
}

uint64_t align_uint64(const void *ptr)
{ // to satisfy -fsanitize=address load of misaligned address
	uint64_t value;
	memcpy(&value, ptr, sizeof(value));
	return value;
}

int is_null(const void* arg,const size_t size)
{ // Returns TRUE if array is null. Signed or Unsigned arrays. XXX USE THIS instead of checking first value in arrays (***except on strings***, where it is less efficient)
	const unsigned char *array = arg;
	for(size_t i = 0; i < size; i++)
		if(array[i] != '\0')
			return 0; // FALSE. Found value, not NULL
    	return 1; // TRUE. No values found, is NULL
}

void *torx_insecure_malloc(const size_t len)
{
	if(len < 1)
		return NULL; // avoids some occassional very small memory leaks
	void *allocation = malloc(len+4+4);
	if(allocation == NULL)
	{
		error_simple(-1,"Insecure allocation failure.");
		return NULL;
	}
	sodium_memzero(((char*)allocation + 4 + 4),len); // Zero the allocation, which is what sodium_malloc does.
	*((uint32_t *)allocation) = (uint32_t) len; // ONLY THE REAL DATA LENGTH, not including prefix bytes or padding
	*((uint32_t *)allocation+1) = ENUM_MALLOC_TYPE_INSECURE;
	return ((char*)allocation + 4 + 4);
}

void *torx_secure_malloc(const size_t len)
{
	if(len < 1)
		return NULL; // avoids some occassional very small memory leaks
	else if(!sodium_initialized)
	{ // Implemented to prevent SEVERE errors
		if(sodium_init() < 0)
		{
			fprintf(stderr,"Error initializing LibSodium library. Be sure to compile with -lsodium flag\n"); // must be fprintf. This error is fatal.
			exit(-1);
		}
		sodium_initialized = 1;
		error_simple(0,"TorX function called before initial. Coding error. Report this.");
		breakpoint();
	}
	size_t allocation_len;
	void *allocation;
	if(ENABLE_SECURE_MALLOC)
	{
		allocation_len = (len + 4 + 4 + 63) & ~((size_t)63); // round up to nearest multiple of 8 because sodium_malloc doesn't guarantee alignment otherwise (NOTE: docs in 2015 said 64)
		allocation = sodium_malloc(allocation_len);
	}
	else
	{
		allocation_len = (len + 4 + 4);
		allocation = malloc(allocation_len);
	}
	if(allocation == NULL)
	{
		error_simple(-1,"Secure allocation failure.");
		return NULL;
	}
	if(!ENABLE_SECURE_MALLOC)
		sodium_memzero(((char*)allocation + 4 + 4),len); // Zero the allocation, which is what sodium_malloc does.
	*((uint32_t *)allocation) = (uint32_t) len; // ONLY THE REAL DATA LENGTH, not including prefix bytes or padding
	*((uint32_t *)allocation+1) = ENUM_MALLOC_TYPE_SECURE;
	return ((char*)allocation + 4 + 4);
}

uint32_t torx_allocation_len(const void *arg)
{ // Convenience function for running safety checks before read/write to a pointer of unknown allocation. Returns length including/AFTER virtual pointer, not including prefix bytes or padding before the pointer.
	uint32_t len = 0;
	if(arg)
	{
		const void *real_ptr = (const char *)arg - 8;
		const uint32_t type = *((const uint32_t *)real_ptr+1);
		if(type != ENUM_MALLOC_TYPE_SECURE && type != ENUM_MALLOC_TYPE_INSECURE)
		{
			error_simple(0,"Called torx_allocation_len on a non-TorX malloc, resulting in an illegal read and failure.");
			breakpoint();
		}
		else // NOTE: Must obtain len *after* verifying type, otherwise we increase illegal read potential by four bytes
			len = *((const uint32_t *)real_ptr);
	}
	return len;
}

void *torx_copy(uint32_t *len_p,const void *arg)
{ // Convenience function; typically used where a mutex is involved. DO NOT USE WHERE THE ARGUMENT COULD BE A NON-TORX ALLOCATION.
	if(arg)
	{
		const void *real_ptr = (const char *)arg - 8;
		const uint32_t type = *((const uint32_t *)real_ptr+1);
		if(type != ENUM_MALLOC_TYPE_SECURE && type != ENUM_MALLOC_TYPE_INSECURE)
		{
			error_simple(0,"Called torx_copy on a non-TorX malloc, resulting in an illegal read and failure.");
			breakpoint();
		}
		else
		{ // NOTE: Must obtain len *after* verifying type, otherwise we increase illegal read potential by four bytes
			const uint32_t len = *((const uint32_t *)real_ptr);
			void *allocation = type == ENUM_MALLOC_TYPE_SECURE ? torx_secure_malloc(len) : torx_insecure_malloc(len);
			memcpy(allocation,arg,len);
			if(len_p)
				*len_p = len;
			return allocation;
		}
	}
	if(len_p)
		*len_p = 0;
	return NULL;
}

void *torx_realloc_shift(void *arg,const size_t len_new,const uint8_t shift_data_forwards)
{ // Pass 0 as shift_data_forwards for normal operation
	void *allocation = NULL;
	if(arg)
	{
		if(len_new)
		{
			void *real_ptr = (char *)arg - 8;
			const size_t len_old = *((uint32_t *)real_ptr);
			if(len_old == len_new)
			{ // Not an error, just dumb coding resulted in non-op. Should avoid, but not at all harmful.
				error_simple(4,"Called torx_realloc with an unchanged length. Non-op occured. Carry on.");
				return arg;
			}
			const uint32_t type = *((uint32_t *)real_ptr+1);
			if(type == ENUM_MALLOC_TYPE_SECURE)
				allocation = torx_secure_malloc(len_new);
			else if(type == ENUM_MALLOC_TYPE_INSECURE)
				allocation = torx_insecure_malloc(len_new);
			else
			{
				error_simple(0,"Called torx_realloc on a non-TorX malloc, resulting in an illegal read and failure.");
				breakpoint();
				return NULL;
			}
			const size_t diff = len_old > len_new ? len_old-len_new : len_new-len_old; // note: always positive
			if(len_new < len_old)
			{ // Shrink
				error_printf(2,"Reducing size in torx_realloc. %lu < %lu",len_new,len_old);
				if(shift_data_forwards) // Cause loss of start data, instead of end data.
					memcpy(allocation,(char*)arg + diff,len_new);
				else
					memcpy(allocation,arg,len_new);
			}
			else
			{ // Expand
				if(shift_data_forwards) // Leaves uninitialized data at the start, instead of the end
					memcpy((char*)allocation + diff,arg,len_old);
				else
					memcpy(allocation,arg,len_old);
			}
		} // If zero is passed, simply free without complaining
		torx_free(&arg);
	}
	else
	{ // Standard realloc functionality is to function even if arg is null. We should not facilitate this, but to prevent issues, we are.
		error_simple(0,"Pointer was not previously allocated, so we don't know how to expand it. We're assuming secure allocation. Coding error. Report this.");
		breakpoint();
		allocation = torx_secure_malloc(len_new);
	}
	return allocation;
}

void *torx_realloc(void *arg,const size_t len_new)
{
	return torx_realloc_shift(arg,len_new,0);
}

void torx_free(void **p)
{ // XXX Usage: torx_free((void*)&pointer)
	if(*p == NULL)
		return;
	void *real_ptr = (char *)(*p) - 8;
	const uint32_t size = *((uint32_t *)real_ptr);
	const uint32_t type = *((uint32_t *)real_ptr+1);
	*((uint32_t *)real_ptr+1) = 1234567890; // Destroying the type. Note: This probably will never serve a useful purpose (of preventing double-free).
	if(type == ENUM_MALLOC_TYPE_SECURE && ENABLE_SECURE_MALLOC)
		sodium_free(real_ptr);
	else if(type == ENUM_MALLOC_TYPE_SECURE)
	{
		sodium_memzero(*p,size);
		free(real_ptr);
	}
	else if(type == ENUM_MALLOC_TYPE_INSECURE)
		free(real_ptr);
	else
	{
		error_simple(0,"Called torx_free on a non-TorX malloc, resulting in an illegal read and failure to free.");
		breakpoint();
		return;
	}
	*p = NULL;
}

void torx_free_simple(void *p)
{ // For stupid UI languages (like Flutter/Dart)
	torx_free((void*)&p);
}

int message_insert(const int g,const int n,const int i)
{ // Insert a message between two messages in our linked list
	if(g < 0 || n < 0)
	{
		error_simple(0,"Message_insert sanity check failed.");
		breakpoint();
		return -1;
	}
	torx_read(n) // 🟧🟧🟧
	const time_t time = peer[n].message[i].time;
	const time_t nstime = peer[n].message[i].nstime;
	torx_unlock(n) // 🟩🟩🟩
	struct msg_list *page = torx_insecure_malloc(sizeof(struct msg_list));
	if(!page)
		return -1;
	page->n = n;
	page->i = i;
	page->time = time;
	page->nstime = nstime;
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	struct msg_list *current_page = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(current_page)
	{ // Not first message
		while(current_page->time < time || (current_page->time == time && current_page->nstime < nstime))
		{ // Our message is newer, keep moving forward
			if(current_page->message_next == NULL)
				break;
			current_page = current_page->message_next;
		} // Breaks if we hit the end of the messages or if our message finds a newer message than ours
		if(current_page->time == time && current_page->nstime == nstime)
		{ // CAUSES: Chance, someone re-sent our date-signed message (private group), or malicious (someone wants to prevent others from receiving a message)
			error_simple(0,"Time and nstime are the same as existing message.");
			torx_free((void*)&page);
			return -1; // We could utilize this return to update the message (scroll = 3), but we'd have to update sql too. This would facilitate recalls/changes... but only group messages, its dumb. don't pursue.
		}
		if(current_page->message_next == NULL && (current_page->time < time || (current_page->time == time && current_page->nstime < nstime)))
		{ // End of messages, ours is newest, insert infront
			page->message_prior = current_page;
			page->message_next = NULL;
			pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
			group[g].msg_last = current_page->message_next = page;
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		}
		else
		{ // Current_page is newer than ours, insert behind
			page->message_prior = current_page->message_prior;
			page->message_next = current_page;
			if(current_page->message_prior) // if current page isn't the very first message, ie there are others before it
				current_page->message_prior->message_next = page;
			else
			{
				pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
				group[g].msg_first = page;
				pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			}
			current_page->message_prior = page; // do last
		}
	}
	else
	{ // First message
		page->message_prior = NULL;
		page->message_next = NULL;
		pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
		group[g].msg_last = group[g].msg_first = page;
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	}
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	group[g].msg_count++;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return 0;
}

void message_remove(const int g,const int n,const int i)
{ // Remove message between two messages in our linked list
	if(g < 0 || n < 0)
		error_simple(-1,"Message_remove sanity check failed.");
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	struct msg_list *current_page = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	while(current_page && (n != current_page->n || i != current_page->i))
		current_page = current_page->message_next;
	if(current_page && n == current_page->n && i == current_page->i)
	{
		if(current_page->message_prior) // not removing first
			current_page->message_prior->message_next = current_page->message_next; // might be NULL, is fine
		else
		{ // removing first
			pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
			group[g].msg_first = current_page->message_next; // might be NULL, is fine
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		}
		if(current_page->message_next) // removing non-latest
			current_page->message_next->message_prior = current_page->message_prior; // might be NULL, is fine
		else
		{ // removing latest
			pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
			group[g].msg_last = current_page->message_prior; // might be NULL, is fine
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		}
		pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
		if(current_page == group[g].msg_index)
		{ // MUST NULL msg_index if it is message_remove'd, to prevent undefined behaviour
			group[g].msg_index = NULL;
			group[g].msg_index_iter = 0;
		}
		group[g].msg_count--;
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		torx_free((void*)&current_page);
	}
	else
	{ // TODO 2024/02/24 unable to discern why some fail and some don't. (ie why some are in struct and others aren't -- review message_insert, message_sort)
		const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
		if(p_iter < 0)
			error_printf(0,"Sanity message_remove called on non-existant message. Coding error. Report this.");
		else
		{
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const char *name = protocols[p_iter].name;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			error_printf(0,"Sanity message_remove called on non-existant message of protocol: %s. Coding error. Report this.",name);
		}
	//	breakpoint();
		return;
	}
}

void message_sort(const int g)
{ // Sort group messages into a list of msg.
	if(g < 0)
		error_simple(-1,"Message_sort sanity check failed.");
	const uint8_t hide_blocked_group_peer_messages_local = threadsafe_read_uint8(&mutex_global_variable,&hide_blocked_group_peer_messages);
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	const int group_n = group[g].n;
	const uint32_t peercount = group[g].peercount;
	const int *peerlist = group[g].peerlist;
	struct msg_list *msg_list = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(msg_list != NULL || group_n < 0)
	{ // Do not check peercount >0 because we might have messages to no-one on a new group (which are pointless but nevertheless permitted)
		error_printf(0,"Message_sort has been called twice (please use message_insert instead) or upon a deleted group: %d",group_n);
	//	breakpoint();
		return;
	}
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	group[g].msg_count = 0;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	struct msg_list *message_prior = NULL; // NOTE: this will change
	const int group_n_max_i = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	time_t time_last = 0;
	time_t nstime_last = 0;
	const int group_n_min_i = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(int i = group_n_min_i; i < group_n_max_i + 1; i++)
	{ // Do outbound messages on group_n. NOTE: For speed of insertion, we assume they are sequential. If that assumption is wrong, *MUST USE* message_insert instead.
		torx_read(group_n) // 🟧🟧🟧
		const uint8_t stat = peer[group_n].message[i].stat;
		const time_t time = peer[group_n].message[i].time;
		const time_t nstime = peer[group_n].message[i].nstime;
		const int p_iter = peer[group_n].message[i].p_iter;
		torx_unlock(group_n) // 🟩🟩🟩
		if(p_iter > -1)
		{
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint16_t protocol = protocols[p_iter].protocol;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if(stat == ENUM_MESSAGE_FAIL || stat == ENUM_MESSAGE_SENT)
			{ // Do outbound messages on group_n. NOTE: For speed of insertion, since this is the first N, it should be in order and therefore there is no need to check time/nstime, we assume they are sequential.
				if(time_last < time || (time_last == time && nstime_last < nstime))
				{ // Indeed sequential
					struct msg_list *page = torx_insecure_malloc(sizeof(struct msg_list));
					if(!page)
						return;
					page->message_prior = message_prior;
					page->n = group_n;
					page->i = i;
					page->time = time;
					page->nstime = nstime;
					page->message_next = NULL;
					if(message_prior) // Not first message
						message_prior->message_next = page;
					else
					{ // First message
						pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
						group[g].msg_first = page;
						pthread_rwlock_unlock(&mutex_expand_group); // 🟩
					}
					if(i == group_n_max_i)
					{ // Potentiallly last (can be overruled by message_insert later)
						pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
						group[g].msg_last = page;
						pthread_rwlock_unlock(&mutex_expand_group); // 🟩
					}
					else
						message_prior = page; // for the next one
					time_last = time;
					nstime_last = nstime;
					pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
					group[g].msg_count++;
					pthread_rwlock_unlock(&mutex_expand_group); // 🟩
				}
				else // If that assumption is wrong, *MUST USE* message_insert instead.
					message_insert(g,group_n,i);
			}
			else if(protocol != ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST && protocol != ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)
			{
				error_printf(0,"Checkpoint message_sort unexpected stat: %d %u",stat,protocol);
				breakpoint(); // shouldn't happen, just checking. If this doesn't trigger, can potentially remove stat check
			}
		}
		else // TODO eliminate error message if this causes no issues
			error_simple(0,"Message_sort called on a message with p_iter < 0. Carry on.");
	}
	if(peerlist && peercount > 0)
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{ // Warning: use peer_n not nn
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			torx_read(peer_n) // 🟧🟧🟧
			const uint8_t status = peer[peer_n].status;
			const int max_i = peer[peer_n].max_i;
			const int min_i = peer[peer_n].min_i;
			torx_unlock(peer_n) // 🟩🟩🟩
			if(hide_blocked_group_peer_messages_local && status == ENUM_STATUS_BLOCKED)
				continue; // skip if appropriate
			for(int i = min_i; i <= max_i; i++)
			{ // Do inbound messages && outbound private messages on peers
				torx_read(peer_n) // 🟧🟧🟧
				const int p_iter = peer[peer_n].message[i].p_iter;
				const uint8_t stat =  peer[peer_n].message[i].stat;
				torx_unlock(peer_n) // 🟩🟩🟩
				if(p_iter > -1)
				{
					pthread_rwlock_rdlock(&mutex_protocols); // 🟧
					const uint8_t group_pm = protocols[p_iter].group_pm;
					pthread_rwlock_unlock(&mutex_protocols); // 🟩
					if(stat == ENUM_MESSAGE_RECV || group_pm)
						message_insert(g,peer_n,i);
				}
			}
		}
}

time_t message_find_since(const int n)
{ // Helper function to get approximate age (for calling sql_populate_message with `since` arg) for group_pm (if GROUP_PEER) or group_msg (if GROUP_CTRL) messages of show_log_messages distance
	const uint32_t local_show_log_messages = threadsafe_read_uint32(&mutex_global_variable,&show_log_messages);
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	char command_supplement[4096] = {0}; // size is somewhat arbitrary
	time_t earliest_time = 0;
	time_t earliest_nstime = 0;
	if(owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL)
	{
		torx_read(n) // 🟧🟧🟧
		for(int tmp_i = peer[n].min_i ; tmp_i < peer[n].max_i ; tmp_i++)
		{
			const int p_iter = peer[n].message[tmp_i].p_iter;
			if(p_iter < 0)
				continue;
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint8_t group_pm = protocols[p_iter].group_pm;
			const uint8_t group_msg = protocols[p_iter].group_msg;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if((owner == ENUM_OWNER_GROUP_PEER && group_pm) || (owner == ENUM_OWNER_GROUP_CTRL && group_msg))
			{
				earliest_time = peer[n].message[tmp_i].time;
				earliest_nstime = peer[n].message[tmp_i].nstime;
				break;
			}
		}
		torx_unlock(n) // 🟩🟩🟩
		size_t pos = 0;
		int group_pm_count = 0,group_msg_count = 0;
		for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE; p_iter++)
		{
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint8_t group_pm = protocols[p_iter].group_pm;
			const uint8_t group_msg = protocols[p_iter].group_msg;
			const uint16_t protocol = protocols[p_iter].protocol;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if((owner == ENUM_OWNER_GROUP_PEER && group_pm) || (owner == ENUM_OWNER_GROUP_CTRL && group_msg))
			{
				if((owner == ENUM_OWNER_GROUP_PEER && !group_pm_count) || (owner == ENUM_OWNER_GROUP_CTRL && !group_msg_count))
					pos += (size_t) snprintf(command_supplement,sizeof(command_supplement)," AND protocol IN (");
				pos += (size_t) snprintf(&command_supplement[pos],sizeof(command_supplement)-pos,"%u,",protocol);
				owner == ENUM_OWNER_GROUP_PEER ? group_pm_count++ : group_msg_count++;
			}
		}
		if((owner == ENUM_OWNER_GROUP_PEER && group_pm_count) || (owner == ENUM_OWNER_GROUP_CTRL && group_msg_count))
		{
			if(command_supplement[pos-1] == ',')
				pos--;
			command_supplement[pos-3] = ')';
			command_supplement[pos-2] = ' ';
			command_supplement[pos-1] = '\0';
		}
	}
	sqlite3_stmt *stmt;
	char command[4096]; // size is somewhat arbitrary
	int len = 0; // clang thinks this should be initialized, but I disagree.
	if(!messages_loaded)
		len = snprintf(command,sizeof(command),"SELECT time FROM ( SELECT *FROM message WHERE peer_index = %d %s ORDER BY time DESC,nstime DESC LIMIT %u ) ORDER BY time ASC,nstime ASC;",peer_index,command_supplement,local_show_log_messages);
	else
		len = snprintf(command,sizeof(command),"SELECT time FROM message WHERE ( peer_index = %d AND time < %lld OR peer_index = %d AND time = %lld AND nstime < %lld ) %s ORDER BY time DESC,nstime DESC LIMIT %u;",peer_index,(long long)earliest_time,peer_index,(long long)earliest_time,(long long)earliest_nstime,command_supplement,local_show_log_messages);
	int val = sqlite3_prepare_v2(db_messages,command, len, &stmt, NULL); // XXX passing length + null terminator for testing because sqlite is weird
	sodium_memzero(command,sizeof(command));
	if(val != SQLITE_OK)
	{
		error_printf(0, "Can't prepare message statement: %s. Not loading messages. Report this.",sqlite3_errmsg(db_messages));
		return 0;
	}
	int count = 0;
	time_t oldest_time = 0; // yes, must initialize to 0
	while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const time_t time = (time_t)sqlite3_column_int(stmt, 0);
		if(!count++ || time < oldest_time)
			oldest_time = time;
	}
	if(val != SQLITE_DONE)
		error_printf(0, "Can't retrieve data: %s",sqlite3_errmsg(db_messages));
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	return oldest_time;
}

static inline void sort_load_more(int *loaded_array_n,int *loaded_array_i,const int array_len)
{ // Sorted list for message_load_more, specifically for groups. Not necessary except in groups.
	if(!loaded_array_n || !loaded_array_i || !array_len)
		return;
	int tmp_array_n[array_len];
	int tmp_array_i[array_len];
	for(int outer = 0 ; outer < array_len ; outer++)
	{
		time_t highest_time = 0;
		time_t highest_nstime = 0;
		int current_winner_iter = 0;
		for(int inner = 0 ; inner < array_len ; inner++)
		{
			const int n = loaded_array_n[inner];
			if(n > -1)
			{
				const int i = loaded_array_i[inner];
				const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
				const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
				if(time > highest_time || (time == highest_time && nstime > highest_nstime))
				{
					highest_time = time;
					highest_nstime = nstime;
					current_winner_iter = inner;
					tmp_array_n[outer] = n; // yes, outer
					tmp_array_i[outer] = i; // yes, outer
				}
			}
		}
		loaded_array_n[current_winner_iter] = -1; // destroy it to avoid using twice
	}
	memcpy(loaded_array_n,tmp_array_n,sizeof(tmp_array_n));
	memcpy(loaded_array_i,tmp_array_i,sizeof(tmp_array_i));
}

static inline int inline_load_array(const int g,const int n,int *loaded_array_n,int *loaded_array_i,const int loaded,const int freshly_loaded)
{
	const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	int discovered = 0;
	for(int i = min_i; discovered < freshly_loaded ; i++)
	{
		const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
		if(p_iter > -1)
		{
			const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner)); // do not pass this without thinking
			const uint8_t message_stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			const uint8_t group_msg = protocols[p_iter].group_msg;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
			if(!(message_stat != ENUM_MESSAGE_RECV && group_msg && owner == ENUM_OWNER_GROUP_PEER))
			{ // XXX j2fjq0fiofg WARNING: This MUST be the same as in sql_populate_message
				loaded_array_n[loaded + discovered] = n;
				loaded_array_i[loaded + discovered++] = i;
				if(g > -1)
					message_insert(g,n,i);
			}
		}
	}
	return discovered;
}

int message_load_more(const int n)
{ // Load show_log_messages more messages for the given peer
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	int loaded = 0; // must initialize as 0
	int *loaded_array_n = NULL; // must initialize as NULL
	int *loaded_array_i = NULL; // must initialize as NULL
	if(owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL)
	{ // need to use helper function to get since rather than guessing with exponential growth, then call sql_populate_message with since
		const time_t since = message_find_since(n); // YES, use n not group_n here because we respect what our caller is looking for
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int group_n_peer_index = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		loaded_array_n = torx_insecure_malloc(1); // DO NOT REMOVE. THIS IS TO ALLOW REALLOC TO FUNCTION properly in case the group_n loads none.
		loaded_array_i = torx_insecure_malloc(1); // DO NOT REMOVE. THIS IS TO ALLOW REALLOC TO FUNCTION properly in case the group_n loads none.
		int freshly_loaded;
		if((freshly_loaded = sql_populate_message(group_n_peer_index,0,0,since)))
		{ // Do GROUP CTRL first
			loaded_array_n = torx_realloc(loaded_array_n,(size_t)(loaded + freshly_loaded) * sizeof(int));
			loaded_array_i = torx_realloc(loaded_array_i,(size_t)(loaded + freshly_loaded) * sizeof(int));
			inline_load_array(g,group_n,loaded_array_n,loaded_array_i,loaded,freshly_loaded);
			loaded += freshly_loaded;
		}
	//	printf("Checkpoint loaded group_n=%d count=%d\n",group_n,freshly_loaded);
		const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			const int peer_n_peer_index = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			if((freshly_loaded = sql_populate_message(peer_n_peer_index,0,0,since)))
			{ // Do each GROUP_PEER
				loaded_array_n = torx_realloc(loaded_array_n,(size_t)(loaded + freshly_loaded) * sizeof(int));
				loaded_array_i = torx_realloc(loaded_array_i,(size_t)(loaded + freshly_loaded) * sizeof(int));
				inline_load_array(g,peer_n,loaded_array_n,loaded_array_i,loaded,freshly_loaded);
				loaded += freshly_loaded;
			//	printf("Checkpoint loaded peer_n=%d count=%d\n",peer_n,freshly_loaded);
			}
		}
		sort_load_more(loaded_array_n,loaded_array_i,loaded);
	}
	else if(owner == ENUM_OWNER_CTRL)
	{
		const uint32_t local_show_log_messages = threadsafe_read_uint32(&mutex_global_variable,&show_log_messages);
		if((loaded = sql_populate_message(peer_index,0,local_show_log_messages,0)))
		{
			loaded_array_n = torx_insecure_malloc((size_t)loaded * sizeof(int));
			loaded_array_i = torx_insecure_malloc((size_t)loaded * sizeof(int));
			inline_load_array(-1,n,loaded_array_n,loaded_array_i,0,loaded);
			int inverted_n[loaded];
			int inverted_i[loaded];
			for(int increase = 0,decrease = loaded-1; increase < loaded ; increase++,decrease--)
			{ // Change order (this is a bit faster than sort_load_more, but either can be used)
				inverted_n[increase] = loaded_array_n[decrease];
				inverted_i[increase] = loaded_array_i[decrease];
			}
			memcpy(loaded_array_n,inverted_n,sizeof(inverted_n));
			memcpy(loaded_array_i,inverted_i,sizeof(inverted_i));
		}
	}
	if(loaded)
		message_more_cb(loaded,loaded_array_n,loaded_array_i);
	return loaded;
}

char *run_binary(pid_t *return_pid,void *fd_stdin,void *fd_stdout,char *const args[],const char *input)
{ // Check return_pid > -1 to verify successful run of binary. Note: in Unix, fd_stdin/out is int, and in Windows it is HANDLE (void*). NOTE: The reason this returns char* and needs to be torx_free'd instead of returning pid is because double pointers are annoying in some languages and this is UI exposed.
// XXX LIMITATION / WARNING ON LINUX: If fd_stdout is passed, *return_pid WILL BE > 0, even in case of failure.
// XXX LIMITATION / WARNING: If fd_stdout is NOT passed, and the successfully running binary does NOT close, it WILL hang forever. (Win + Linux)
// There are workarounds to the second limitation, but they could result in false positives, so we have not implemented them. Ex: if(output[len-1] == '\n') break;
#ifdef WIN32
	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	SECURITY_ATTRIBUTES saAttr;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 

	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		error_simple(-1,"CreatePipe failure");
	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		error_simple(-1,"CreatePipe failure");

	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		error_simple(-1,"SetHandleInformation failure");
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		error_simple(-1,"SetHandleInformation failure");

	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
//	siStartInfo.hStdError = g_hChildStd_OUT_Wr; // we don't want stderr
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

/*	const char prefix[] = "cmd.exe /c ";
	size_t len = sizeof(prefix)-1;
	char *cmd = torx_malloc(sizeof(prefix));
	memcpy(cmd,prefix,sizeof(prefix)); */
	size_t len = 0;
	char *cmd = {0};
	size_t counter = 0;
	for(char *arg; (arg = args[counter]) != NULL; counter++)
	{
		const size_t bytesRead = strlen(arg);
		size_t excess = 1; // for space
		if(counter)
			excess += 2; // for ""
		if(cmd)
			cmd = torx_realloc(cmd, len + (size_t)bytesRead + excess + 1); // we +1 for the null pointer we'll add at the end
		else
			cmd = torx_secure_malloc(len + (size_t)bytesRead + excess + 1); // we +1 for the null pointer we'll add at the end
		if(counter)
		{
			cmd[len] = '"';
			memcpy(cmd + len + 1, arg, (size_t)bytesRead);
		}
		else
			memcpy(cmd + len, arg, (size_t)bytesRead);
		len += (size_t)bytesRead + excess;
		if(counter)
			cmd[len-2] = '"';
		cmd[len-1] = ' ';
	}
	if(cmd)
		cmd[len] = '\0';
	if (!CreateProcess(NULL,cmd,NULL,NULL,TRUE,0,NULL,NULL,&siStartInfo,&piProcInfo)) // this is just a bool
	{
		if(return_pid)
			*return_pid = -1;
		if(fd_stdin)
			fd_stdin = NULL;
		if(fd_stdout)
			*(HANDLE*)fd_stdout = NULL;
	}
	else
	{
		if(return_pid)
			*(DWORD*)return_pid = piProcInfo.dwProcessId;
		if(input)
		{
			DWORD written;
			WriteFile(g_hChildStd_IN_Wr, input, (DWORD)strlen(input), &written, NULL);
		}
		if(fd_stdin)
			fd_stdin = g_hChildStd_IN_Wr;
		else
			CloseHandle(g_hChildStd_IN_Wr);
	//	WaitForSingleObject(piProcInfo.hProcess, INFINITE); // This would cause waiting for binary to exit, which we have no need for
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
	}
	CloseHandle(g_hChildStd_IN_Rd);
	CloseHandle(g_hChildStd_OUT_Wr);
	torx_free((void*)&cmd);
	char *output = {0};
	if(fd_stdout)
		*(HANDLE*)fd_stdout = g_hChildStd_OUT_Rd;
	else
	{ // Handle stdout, if directed to
		len = 0;
		char buffer[4096];
		DWORD bytesRead;
		while(ReadFile(g_hChildStd_OUT_Rd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead)
		{ // TODO WARNING: Will hang forever if no STDOUT. See limitations.
			if(output)
				output = torx_realloc(output, len + (size_t)bytesRead + 1); // we +1 for the null pointer we'll add at the end
			else
				output = torx_secure_malloc(len + (size_t)bytesRead + 1); // we +1 for the null pointer we'll add at the end
			memcpy(output + len, buffer, (size_t)bytesRead);
			len += (size_t)bytesRead;
		}
		CloseHandle(g_hChildStd_OUT_Rd);
		if(len > sizeof(buffer))
			sodium_memzero(buffer,sizeof(buffer));
		else
			sodium_memzero(buffer,len);
		if(output)
		{ // Strip trailing newline, if applicable, otherwise null terminate
			if(output[len-1] == '\n')
			{
				output[len-1] = '\0';
				if(output[len-2] == '\r') // This came up on Windows. Carriage Return.
					output[len-2] = '\0';
			}
			else
				output[len] = '\0';
		}
	}
	return output;
#else
	#define FAILURE_STRING "0559d5fbba2cc6b32f91a1da10dd6dd275a635bcb959a8dc2a291a91d237e2d1" // Is currently: `echo -n LuigiMangioneDidNothingWrong#FreeLuigi#JuryNullification | sha256sum` ; can be anything not reasonably likely to be returned by a binary.
	int link1[2];
	int link2[2];
	if(pipe(link1) == -1)
		error_simple(-1,"Pipe failure 1 in run_binary");
	if(pipe(link2) == -1)
		error_simple(-1,"Pipe failure 2 in run_binary");
	pid_t pid;
	if((pid = fork()) == -1)
		error_simple(-1,"Fork failure in run_binary");
	if(pid == 0)
	{ // Child process
		close(link1[0]); // read end
		dup2(link1[1], STDOUT_FILENO); // Stdout for logging
		close(link1[1]); // write end
		close(link2[1]); // write end
		dup2(link2[0], STDIN_FILENO); // Stdin for torrc feeding
		close(link2[0]); // read end
		if(execvp(args[0], (char *const *) args)) // Execute the binary
			printf(FAILURE_STRING);
		exit(0);
	}
	close(link1[1]);
	close(link2[0]);
	if(input)
	{
		FILE *pipewrite = fdopen(link2[1],"w");
		fputs(input,pipewrite);
		close_sockets_nolock(pipewrite)
	}
	if(fd_stdin)
		*(int*)fd_stdin = link2[1];
	else
		close(link2[1]);
	char *output = {0};
	if(fd_stdout)
		*(int*)fd_stdout = link1[0];
	else
	{ // Handle stdout, if directed to
		char buffer[4096];
		size_t len = 0;
		ssize_t bytesRead;
		while((bytesRead = read(link1[0], buffer, sizeof(buffer) - 1)) > 0)
		{ // TODO WARNING: Will hang forever if no STDOUT. See limitations.
			if(output)
				output = torx_realloc(output, len + (size_t)bytesRead + 1); // we +1 for the null pointer we'll add at the end
			else
				output = torx_secure_malloc(len + (size_t)bytesRead + 1); // we +1 for the null pointer we'll add at the end
			memcpy(output + len, buffer, (size_t)bytesRead);
			len += (size_t)bytesRead;
		}
		close(link1[0]); // reading end
		if(len > sizeof(buffer))
			sodium_memzero(buffer,sizeof(buffer));
		else
			sodium_memzero(buffer,len);
		if(bytesRead < 0 || (len == sizeof(FAILURE_STRING)-1 && !memcmp(output,FAILURE_STRING,sizeof(FAILURE_STRING)-1)))
		{ // Pipe fail or (more likely) failed to execute the binary for some reason (such as wrong path)
			if(bytesRead < 0)
				error_simple(0,"Reading pipe fail in run_binary");
			torx_free((void*)&output);
			if(fd_stdin)
				*(int*)fd_stdin = -1;
			if(fd_stdout)
				*(int*)fd_stdout = -1;
			if(return_pid)
				*return_pid = -1;
			return NULL;
		}
		if(output)
		{ // Strip trailing newline, if applicable, otherwise null terminate
			if(output[len-1] == '\n')
				output[len-1] = '\0';
			else
				output[len] = '\0';
		}
	}
	if(return_pid)
		*(pid_t*)return_pid = pid;
	return output;
#endif
}

void set_time(time_t *time,time_t *nstime)
{ // Sets .time and .nstime for a given message, to current time. Should be unique even when threaded.
	if(!time || !nstime || *time != 0 || *nstime != 0)
	{ // This is a coding error. Sanity check.
		error_simple(0,"set_time called on a message that already has time set. Coding errror. Report this.");
		breakpoint();
		return;
	}
	struct timespec ts;
	pthread_mutex_lock(&mutex_clock); // 🟥🟥
	clock_gettime(CLOCK_REALTIME, &ts);
	pthread_mutex_unlock(&mutex_clock); // 🟩🟩
	*time = ts.tv_sec;
	*nstime = ts.tv_nsec;
}

char *message_time_string(const int n,const int i)
{ // Helper function available to UI devs (but no requirement to use)
	if(n < 0)
		return NULL;
	// Convert Epoch Time to Human Readable
	const time_t rawtime = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t diff = time(NULL) - rawtime; // comparing both in UTC
	struct tm *info = localtime(&rawtime);
	char *timebuffer = torx_insecure_malloc(20); // not sure whether there is value in having this secure. going to venture to say no.
	if(diff >= 0 && diff < 86400) // 24 hours
		strftime(timebuffer,20,"%H:%M:%S",info);
	else
		strftime(timebuffer,20,"%Y/%m/%d %H:%M:%S",info);
	return timebuffer;
}

char *affix_protocol_len(const uint16_t protocol,const char *total_unsigned,const uint32_t total_unsigned_len)
{ // For use with crypto_sign_detached / crypto_sign_verify_detached. TODO This copy-op's cost can be eliminated if we use it to store protocol + date behind .message pointer. However, we also need to do the same for unsigned messages, otherwise free called on messages will depend on whether signed or not, which is unnecessarily complex and risky.
	const uint16_t trash = htobe16(protocol);
	char *prefixed_message = torx_secure_malloc(sizeof(uint16_t) + sizeof(uint32_t) + total_unsigned_len);
	memcpy(&prefixed_message[0],&trash,sizeof(trash));
	const uint32_t trash2 = htobe32(total_unsigned_len);
	memcpy(&prefixed_message[2],&trash2,sizeof(trash2));
	memcpy(&prefixed_message[2+4],total_unsigned,sizeof(total_unsigned_len));
	return prefixed_message;
}

char *message_sign(uint32_t *final_len,const unsigned char *sign_sk,const time_t time,const time_t nstime,const int p_iter,const char *message_unsigned,const uint32_t base_message_len)
{ // Audited 2024/02/18 // Message + '\0' + [Time] + [NSTime] + Protocol + Signature Note: should theoretically work with unsigned too (but no value in using it as such)
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(!protocol || (signature_len && sign_sk == NULL) || (date_len && time == 0) || (message_unsigned && base_message_len == 0) || (message_unsigned == NULL && base_message_len))
	{ // Note: we don't sanity check message_unsigned or base_message_len because they could be NULL/0 for some protocols.
		error_simple(0,"Failure of sanity check in message_sign.");
		goto fail; 
	}
	const uint32_t allocation = base_message_len + null_terminated_len + date_len + signature_len;
//	printf("Checkpoint message_sign %u: %u %u %u %u %u\n",protocol,allocation,base_message_len,null_terminated_len,date_len,signature_len);
	char *message_prepared = torx_secure_malloc(allocation);
	if(message_unsigned)
		memcpy(message_prepared,message_unsigned,base_message_len);
	if(null_terminated_len)
		message_prepared[base_message_len] = '\0';
	if(date_len)
	{
	//	if(!signature_len)
	//		error_simple(0,"You are trying to date a message without signing it. This is pointless.");
		uint32_t trash = htobe32((uint32_t)time);
		memcpy(&message_prepared[base_message_len + null_terminated_len],&trash,sizeof(trash));
		trash = htobe32((uint32_t)nstime);
		memcpy(&message_prepared[base_message_len + null_terminated_len + sizeof(trash)],&trash,sizeof(trash));
	}
	long long unsigned int sig_len = 0; // discard
	const uint32_t total_unsigned_len = allocation - signature_len;
	if(signature_len)
	{ // affix protocol, if this is a 'message' and not just 'other stuff'... for other stuff, don't use this function. use crypto_sign*
		char *prefixed_message = affix_protocol_len(protocol,message_prepared,total_unsigned_len);
		if(crypto_sign_detached((unsigned char *)&message_prepared[total_unsigned_len],&sig_len,(unsigned char *)prefixed_message,2+4+total_unsigned_len,sign_sk) != 0)
		{
			error_simple(0,"Failure in message_sign at crypto_sign_detached.");
			torx_free((void*)&prefixed_message);
			torx_free((void*)&message_prepared);
			goto fail;
		}
		torx_free((void*)&prefixed_message);
	}
	if(final_len)
		*final_len = allocation;
	return message_prepared;
	fail:
	breakpoint();
	if(final_len)
		*final_len = 0;
	return NULL;
}

int vptoi(const void* arg)
{
	int val = (int)(int64_t)arg;
	return val-SHIFT;
}

void *itovp(const int i)
{
	if(i+SHIFT == 0)
	{
		error_printf(0,"Shift is insufficient. Must increase it or determine source of error. Coding error. Report this. %d",i);
		breakpoint();
	}
	return (void*)(intptr_t)(i+SHIFT);
}

void random_string(char *destination,const size_t destination_size)
{ // Puts length + '\0' in destination // NOTE: srand() must be properly seeded (not with time()) or rand() will produce non-unique results if called more than once a second
	if(!destination || destination_size < 2)
	{
		error_simple(0,"Random_string failed sanity check. Coding error. Report this.");
		return;
	}
	const char alphanumeric[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	destination[destination_size-1] = '\0';
	for(size_t iter = 0; iter < destination_size - 1; iter++)
		destination[iter] = *(alphanumeric + (randombytes_random() % 62));
}

void ed25519_pk_from_onion(unsigned char *ed25519_pk,const char *onion)
{ // Caller must allocate 32 bytes. TODO make more extensive use of this function?
	if(onion == NULL || !utf8_valid(onion,56))
	{
		error_simple(0,"ed25519_pk_from_onion passed a null or invalid length onion. Report this.");
		breakpoint();
		return;
	}
	char onion_uppercase[56+1]; // zero'd
	memcpy(onion_uppercase,onion,56);
	onion_uppercase[56] = '\0';
	xstrupr(onion_uppercase);
	baseencode_error_t err = {0}; // for base32
	unsigned char *p = base32_decode(onion_uppercase,56,&err);
	sodium_memzero(onion_uppercase,sizeof(onion_uppercase));
	if(err != 0)
	{
		error_simple(0,"Uncaught error in onion_to_ed25519_pk. Report this.");
		torx_free((void*)&p);
		breakpoint();
		return;
	}
	memcpy(ed25519_pk,p,crypto_sign_PUBLICKEYBYTES);
	torx_free((void*)&p);
}

char *onion_from_ed25519_pk(const unsigned char *ed25519_pk)
{ // Remember to torx_free
	unsigned char onion_decoded[35]; // zero'd
	memcpy(onion_decoded,ed25519_pk,crypto_sign_PUBLICKEYBYTES);
	gen_truncated_sha3(&onion_decoded[crypto_sign_PUBLICKEYBYTES],onion_decoded);
	onion_decoded[34] = 0x03; // adds version byte
	char onion[56+1];
	const size_t len = base32_encode((unsigned char*)onion,onion_decoded,sizeof(onion_decoded));
	sodium_memzero(onion_decoded,sizeof(onion_decoded));
	if(len == 56)
	{
		xstrlwr(onion);
		char *onion_pointer = torx_secure_malloc(sizeof(onion));
		snprintf(onion_pointer,sizeof(onion),"%s",onion);
		sodium_memzero(onion,sizeof(onion));
		return onion_pointer;
	}
	else
	{
		error_simple(0,"Failed to generate onion in onion_from_ed25519_pk. Report this.");
		breakpoint();
		return NULL;
	}
}

int pid_kill(const pid_t pid,const int signal)
{
	#ifdef WIN32
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE,(DWORD)pid);
	if(hProcess == NULL)
	{
		error_printf(0,"Failed to open process. Error code: %lu\n", GetLastError());
		return -1;
	}
	BOOL result = TerminateProcess(hProcess,(UINT)signal);
	if(result == 0)
	{
		error_printf(0,"Failed to terminate process. Error code: %lu\n", GetLastError());
		CloseHandle(hProcess);
		return -1;
	}
	CloseHandle(hProcess);
	return 0; // Success
	#else
	return kill(pid,signal);
	#endif
}

static int pid_write(const int pid)
{ // Write Tor's PID to file
	FILE *fp;
	if((fp = fopen(file_tor_pid, "w+")) == NULL)
	{
		error_simple(0,"Failed to write PID file to disk.");
		return -1; // error
	}
	char p1[21];
	snprintf(p1,sizeof(p1),"%d",pid);
	fputs(p1,fp);
	close_sockets_nolock(fp) // close append mode
	return 0;
}

static inline int pid_read(void)
{ // Read Tor's PID from file (used for killing an orphaned process after a crash or improper shutdown)
	int pid = 0;
	FILE *fp;
	if((fp = fopen(file_tor_pid, "r")))
	{
		char pid_string[21] = {0};
		if(fgets(pid_string,sizeof(pid_string)-1,fp))
			pid = (int)strtoll(pid_string, NULL, 10);
		close_sockets_nolock(fp) // close append mode
	}
	return pid;
}

void torrc_save(const char *torrc_content_local)
{ // Pass null or "" to reset defaults
	if(threadsafe_read_uint8(&mutex_global_variable,&using_system_tor))
	{ // In *theory* we could check config-can-saveconf and then make saveconf calls for every setting, but that's out of scope.
		error_simple(0,"Cannot save torrc while using system Tor.");
		return;
	}
	size_t len;
	char *torrc_content_final;
	uint8_t set_default = 0;
	if(!torrc_content_local || (len = strlen(torrc_content_local)) == 0)
	{ // Setting to defaults
		set_default = 1;
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
		if(censored_region == 1 && snowflake_location)
		{
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			const size_t len_part1 = strlen(torrc_content_default_censored_region_part1);
			const size_t len_snowflake = strlen(snowflake_location);
			const size_t len_part2 = strlen(torrc_content_default_censored_region_part2);
			len = len_part1 + len_snowflake + len_part2;
			torrc_content_final = torx_secure_malloc(len + 1);
			snprintf(torrc_content_final,len + 1,"%s%s%s",torrc_content_default_censored_region_part1,snowflake_location,torrc_content_default_censored_region_part2);
		}
		else
		{
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			len = strlen(torrc_content_default); // 22 is for ConstrainedSockSize + newline
			torrc_content_final = torx_secure_malloc(len + 1);
			snprintf(torrc_content_final,len + 1,"%s",torrc_content_default);
		}
	}
	else
	{ // Setting to passed
		torrc_content_final = torx_secure_malloc(len+1);
		memcpy(torrc_content_final,torrc_content_local,len+1);
	}
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	torx_free((void*)&torrc_content);
	torrc_content = torrc_content_final;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(threadsafe_read_uint8(&mutex_global_variable,&keyed))
	{ // checking if this was called as startup (unkeyed) or manually (keyed)
		if(set_default)
			sql_delete_setting(0,-1,"torrc");
		else
			sql_setting(0,-1,"torrc",torrc_content_final,len); // using local to avoid needing locks
		start_tor(); // do not check if running first, as it may have crashed due to user error and we want to be able to allow recovery
	}
}

char *torrc_verify(const char *torrc_content_local)
{ // Returns null if passed torrc_content_local has no errors. Otherwise returns errors. Remember to free if there are errors.
// TODO 2024 WARNING: This function does not take into account our command line hard-coded options, which could conflict with something that passes this function.
	char arg1[] = "--verify-config";
	char arg2[] = "--hush";
	char arg3[] = "-f";
	char arg4[] = "-";
	char arg5[] = "--DataDirectory"; // tor_data_directory
	char tor_location_local[PATH_MAX];
	char tor_data_directory_local[PATH_MAX];
	int tdd_len = 0;
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	snprintf(tor_location_local,sizeof(tor_location_local),"%s",tor_location);
	if(tor_data_directory)
		tdd_len = snprintf(tor_data_directory_local,sizeof(tor_data_directory_local),"%s",tor_data_directory);
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(tdd_len)
	{
		char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,arg4,arg5,tor_data_directory_local,NULL};
		return run_binary(NULL,NULL,NULL,args_cmd,torrc_content_local);
	}
	else
	{
		char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,arg4,NULL};
		return run_binary(NULL,NULL,NULL,args_cmd,torrc_content_local);
	}
}

char *which(const char *binary) 
{ // Locates a binary from PATH and returns the path, falls back to check current directory, or a NULL pointer if it does not exist in path/current directory.
	if(!binary)
		return NULL;
	#ifdef WIN32
	char searcher[] = "where"; // NOTE: Unnecessary to affix .exe
	#else
	char searcher[] = "which";
	#endif
	char binary_array[PATH_MAX];
	snprintf(binary_array,sizeof(binary_array),"%s",binary);
	char* const args_cmd[] = {searcher,binary_array,NULL};
	char *location;
	if((location = run_binary(NULL,NULL,NULL,args_cmd,NULL)))
		return location;
	#ifdef WIN32
	const size_t initial_len = strlen(binary_array);
	if(initial_len > 4 && memcmp(&binary_array[initial_len-4],".exe",4) && memcmp(&binary_array[initial_len-4],".EXE",4))
		snprintf(&binary_array[initial_len],sizeof(binary_array)-initial_len,".exe"); // affix .exe where it doesn't exist
	#endif
	if(get_file_size(binary_array) > 0)
	{ // Not in path, so checking current directory.
		char path[PATH_MAX];
		if(getcwd(path,PATH_MAX))
		{ // if we can get cwd, get its path and prefix it
			size_t len = strlen(path);
			snprintf(&path[len],PATH_MAX-len,"%c%s",platform_slash,binary_array);
			len = strlen(path);
			char *full_path = torx_insecure_malloc(len+1);
			memcpy(full_path,path,len+1);
			return full_path;
		}
		const size_t len = strlen(binary_array);
		char *relative_path = torx_insecure_malloc(len+1);
		memcpy(relative_path,binary_array,len+1);
		return relative_path;
	}
	return NULL;
}

static inline int find_message_struc_pointer(const int min_i)
{ // Note: returns negative. Min_i must be <=0, which it should be.
	const int multiple_of_10 = (min_i / 10) * 10; // XXX DO NOT MODIFY THIS MATH. This is C math, not regular math!!!
	if (min_i <= multiple_of_10)
		return multiple_of_10 - 10;
	return -10;
}

int zero_i(const int n,const int i) // XXX do not put locks in here (except mutex_global_variable + mutex_protocols)
{ // GROUP_PEER looks hacky because we should maybe use ** but we don't (note: hacky here simplifies a lot of things elsewhere)
	if(peer[n].message[i].p_iter == -1)
		return 0; // already deleted
	const int p_iter = peer[n].message[i].p_iter;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint8_t group_msg = protocols[p_iter].group_msg;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(group_msg && peer[n].owner == ENUM_OWNER_GROUP_PEER)
		peer[n].message[i].message = NULL; // will be freed in group CTRL
	else
		torx_free((void*)&peer[n].message[i].message);
	peer[n].message[i].p_iter = -1; // must be -1
	peer[n].message[i].stat = 0;
	peer[n].message[i].pos = 0;
	peer[n].message[i].fd_type = -1;
	peer[n].message[i].time = 0;
	peer[n].message[i].nstime = 0;
	// ROLLBACK FUNCTIONALITY (utilized primarily on streams, when clearing history, and when deleting peers to try to reduce burden on our struct). In the future, will facilitate message offloading.
	int shrinkage = 0; // Mandatory shrinkage
	const int pointer_location = find_message_struc_pointer(peer[n].min_i); // XXX DO NOT MOVE THIS. It must use min_i from *before* we shrink.
	if(peer[n].max_i == i)
		while(peer[n].message[peer[n].max_i].p_iter == -1 && peer[n].max_i > -1)
		{
			if(peer[n].max_i && peer[n].max_i % 10 == 0)
				shrinkage -= 10;
			peer[n].max_i--;
		}
	else if(peer[n].min_i == i)
		while(peer[n].message[peer[n].min_i].p_iter == -1 && peer[n].min_i < 0)
		{
			if(peer[n].min_i && peer[n].min_i % 10 == 0)
				shrinkage += 10;
			peer[n].min_i++;
		}
	if(shrinkage)
	{ // TODO Maybe have this not occur on shutdown (BUT, it should happen when calling zero_n, to allow for a re-initialized n suitable for re-use)
		const uint32_t current_allocation_size = torx_allocation_len(peer[n].message + pointer_location);
		const size_t current_shift = (size_t)abs(shrinkage);
		error_printf(2,"Experimental rollback functionality occuring! n=%d min_i=%d max_i=%d pointer_location=%d shrinkage=%d\n",n,peer[n].min_i,peer[n].max_i,pointer_location,shrinkage);
		if(shrinkage > 0) // We shift everything forward
			peer[n].message = (struct message_list*)torx_realloc_shift(peer[n].message + pointer_location, current_allocation_size - sizeof(struct message_list) *current_shift,1) - pointer_location - current_shift;
		else
			peer[n].message = (struct message_list*)torx_realloc(peer[n].message + pointer_location, current_allocation_size - sizeof(struct message_list) *current_shift) - pointer_location;
	}
	return shrinkage;
}

void zero_n(const int n) // XXX do not put locks in here. XXX DO NOT dispose of the mutex
{ // DO NOT SET THESE TO \0 as then the strlen will be different. We presume these are already properly null terminated.
	for(int i = 0 ; i <= peer[n].max_i ; i++) // must go before .owner = 0, for variations in zero_i
		zero_i(n,i);  // same as 2j0fj3r202k20f
	for(int i = -1 ; i >= peer[n].min_i ; i--) // we seperate this out for more efficient zero_i rollback
		zero_i(n,i); // same as 2j0fj3r202k20f
	#ifndef NO_FILE_TRANSFER
	for(int f = 0 ; !is_null(peer[n].file[f].checksum,CHECKSUM_BIN_LEN) ; f++)
		zero_f(n,f);
	peer[n].blacklisted = 0;
	#endif // NO_FILE_TRANSFER
//	torx_free((void*)&peer[n].message); // **cannot** be here but needs to be elsewhere, at least on cleanup. NOTE: 0 may not be where the alloc is. Use find_message_struc_pointer to find it.
//	peer[n].max_i = -1; // should now be handled by zero_i/shrinkage
//	peer[n].min_i = 0; // should now be handled by zero_i/shrinkage
	peer[n].owner = 0;
	peer[n].status = 0;
	memset(peer[n].privkey,'0',sizeof(peer[n].privkey)-1); // DO NOT REPLACE WITH SODIUM MEMZERO as we currently expect these to be 0'd not \0'd
	peer[n].peer_index = -2; // MUST be lower than -1 to properly error by sql_setting if unset
	memset(peer[n].onion,'0',sizeof(peer[n].onion)-1);
	memset(peer[n].torxid,'0',sizeof(peer[n].torxid)-1);
	peer[n].peerversion = 0;
	memset(peer[n].peeronion,'0',sizeof(peer[n].peeronion)-1);
	torx_free((void*)&peer[n].peernick);
	peer[n].log_messages = 0;
	peer[n].last_seen = 0;
	peer[n].vport = 0;
	peer[n].tport = 0;
	peer[n].socket_utilized[0] = INT_MIN;
	peer[n].socket_utilized[1] = INT_MIN;
	torx_close_socket(NULL,&peer[n].sendfd);
	torx_close_socket(NULL,&peer[n].recvfd);
	peer[n].sendfd_connected = 0;
	peer[n].recvfd_connected = 0;
	peer[n].bev_send = NULL; // TODO ensure its leaving event loop?
	peer[n].bev_recv = NULL;
	sodium_memzero(peer[n].sign_sk,crypto_sign_SECRETKEYBYTES);
	sodium_memzero(peer[n].peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	sodium_memzero(peer[n].invitation,crypto_sign_BYTES);
	peer[n].thrd_send = 0; // thread_kill(peer[n].thrd_send); // NO. will result in deadlocks.
	peer[n].thrd_recv = 0; // thread_kill(peer[n].thrd_recv); // NO. will result in deadlocks.
	peer[n].broadcasts_inbound = 0;
	#ifndef NO_AUDIO_CALL
	for (size_t c = 0; c < torx_allocation_len(peer[n].call)/sizeof(struct call_list); c++)
	{
		torx_free((void*)&peer[n].call[c].participating);
		torx_free((void*)&peer[n].call[c].participant_mic);
		torx_free((void*)&peer[n].call[c].participant_speaker);
	}
	torx_free((void*)&peer[n].call);
	for(uint32_t count = torx_allocation_len(peer[n].audio_cache)/sizeof(unsigned char *); count ; ) // do not change logic without thinking
		torx_free((void*)&peer[n].audio_cache[--count]); // clear out all unplayed audio data
	torx_free((void*)&peer[n].audio_cache);
	torx_free((void*)&peer[n].audio_time);
	torx_free((void*)&peer[n].audio_nstime);
	peer[n].audio_last_retrieved_time = 0;
	peer[n].audio_last_retrieved_nstime = 0;
	record_cache_clear_nolocks(n);
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	for (size_t y = 0; y < torx_allocation_len(peer[n].stickers_requested)/sizeof(unsigned char *); y++)
		torx_free((void*)&peer[n].stickers_requested[y]);
	torx_free((void*)&peer[n].stickers_requested);
	#endif // NO_STICKERS
// TODO probably need a callback to UI (to zero the UI struct)
}

void zero_g(const int g)
{ // DO NOT SET THESE TO \0 as then the strlen will be different. We presume these are already properly null terminated.
//	printf("Checkpoint zeroing g==%d\n",g);
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	memset(group[g].id,'0',GROUP_ID_SIZE);
	group[g].n = -1;
	for(int invitee = 0; invitee < MAX_INVITEES; invitee++)
		group[g].invitees[invitee] = -2; // please don't initialize as 0/-1
	group[g].hash = 0; // please don't initialize as -1
	group[g].peercount = 0; // please don't initialize as -1
	group[g].msg_count = 0; // please don't initialize as -1
	torx_free((void*)&group[g].peerlist);
	group[g].invite_required = 0;
	group[g].msg_index_iter = 0; // please don't initialize as -1
	group[g].msg_index = NULL; // do not free, there is no space allocated
	struct msg_list *page = group[g].msg_first;
	while(page)
	{ // This is essentially a waste of CPU cycles
		if(page->message_next)
		{
			page = page->message_next;
			torx_free((void*)&page->message_prior); // TODO 2024/06/19 Bug on shutdown after deleting group. Unknown origin.
		}
		else
			torx_free((void*)&page); // TODO 2024/06/19 Bug on shutdownafter deleting group. Unknown origin.
	}
	group[g].msg_first = NULL; // this is necessary, but using torx_free would be redundant and lead to errors
	group[g].msg_last = NULL; // this is necessary, but using torx_free would be redundant and lead to errors
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
// TODO probably need a callback to UI ( for what ? )
}

static inline void sort_n(int sorted_n[],const int size)
{ // Produces an array of N index values that will order our peer[n]. struct from newest to oldest message, without regard to online status or owner (ie, not just CTRL)
	if(!sorted_n || size < 0)
		error_simple(-1,"Sanity check failed in sort_n. Coding error. Report this.");
	time_t last_time[size]; // things get moved around in here (will contain sorted selection)
	for(int nn = 0; nn < size; nn++)
	{
		const uint8_t owner = getter_uint8(nn,INT_MIN,-1,offsetof(struct peer_list,owner));
		if(owner == ENUM_OWNER_GROUP_CTRL)
		{
			const int g = set_g(nn,NULL);
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			struct msg_list *page = group[g].msg_last;
			if(page)
				last_time[nn] = group[g].msg_last->time;
			else
				last_time[nn] = 0;
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		}
		/* else if(owner == ENUM_OWNER_GROUP_PEER) */
			// TODO Consider: If GROUP_PEER, we should sort by last private message time. This would add (potentially lots of) CPU cycles though and would only be useful if we have a UI developer who wants to seperate private chats into a seperate sorted list.
		else
		{
			const int max_i = getter_int(nn,INT_MIN,-1,offsetof(struct peer_list,max_i));
			if(max_i > INT_MIN)
				last_time[nn] = getter_time(nn,max_i,-1,offsetof(struct message_list,time)); // last message time
			else
				last_time[nn] = 0;
		}
		sorted_n[nn] = nn; // true N value
	}
	for(int remaining = size; remaining > 1; remaining--)
	{
		time_t highest_time = 0;
		int highest_n = 0;
		int highIndex = 0;
		for(int j = 0 ; j < remaining ; j++)
		{
			if(last_time[j] >= highest_time)
			{
				highest_time = last_time[j];
				highest_n = sorted_n[j];
				highIndex = j;
			}
		}
		time_t temp_time = last_time[remaining-1];
		last_time[remaining-1] = highest_time;
		last_time[highIndex] = temp_time;			
		int temp_n = sorted_n[remaining-1];
		sorted_n[remaining-1] = highest_n;
		sorted_n[highIndex] = temp_n;
	}
}

void invitee_add(const int g,const int n)
{
	int invitee = 0;
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	for(int first_negative_one = -1; invitee < MAX_INVITEES ; invitee++)
	{
		if(group[g].invitees[invitee] == -1 && first_negative_one < 0)
			first_negative_one = invitee;
		else if(group[g].invitees[invitee] == n)
			break; // Already added
		else if(group[g].invitees[invitee] == -2)
		{ // Not in list
			if(first_negative_one > -1) // Fill a gap
				group[g].invitees[first_negative_one] = n;
			else
				group[g].invitees[invitee] = n;
			break;
		}
	}
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(invitee == MAX_INVITEES)
		error_simple(0,"Hit MAX_INVITEES in invitee_add. Report this.");
}

int invitee_remove(const int g,const int n)
{
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	for(int invitee = 0; invitee < MAX_INVITEES && group[g].invitees[invitee] != -2 ; invitee++)
		if(group[g].invitees[invitee] == n)
		{
			group[g].invitees[invitee] = -1;
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			return 0;
		}
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return -1;
}

char *mit_strcasestr(char *dumpster,const char *diver)
{ // written without reviewing source of GNU strcasestr to avoid its restrictive license. Should be efficient.
	if(!dumpster || !diver)
		return dumpster;
	const size_t dumpster_len = strlen(dumpster);
	const size_t diver_len = strlen(diver);
	if(!diver_len)
		return dumpster;
	if(!dumpster_len || diver_len > dumpster_len)
		return NULL;
	for(size_t iter = 0; iter + diver_len <= dumpster_len; iter++)
		if(!strncasecmp(&dumpster[iter],diver,diver_len)) // Note: after reviewing source code of strncasecmp, its use is not inefficient.
			return &dumpster[iter];
	return NULL;
}

int *refined_list(int *len,const uint8_t owner,const int peer_status,const char *search)
{ // Must allocate space for len and free both return and len after
  // XXX NOTE: for GROUP_PEER owner, must pass G as peer_status
	int nn = 0;
	int g = -1;
	if(owner == ENUM_OWNER_GROUP_PEER && peer_status > -1)
		g = peer_status;
	while(getter_byte(nn,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(nn,INT_MIN,-1,offsetof(struct peer_list,peer_index)) > -1) // find number of onions / array size
		nn++;
	if(nn == 0)
	{ // 2023/10/16 added this... not sure if necessary
		if(len)
			*len = 0;
		return NULL;
	}
	int *array = torx_insecure_malloc(sizeof(int)*(size_t)nn);
	int relevant = 0;
	if((owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL) || (owner == ENUM_OWNER_CTRL && (peer_status == ENUM_STATUS_BLOCKED || peer_status == ENUM_STATUS_FRIEND || peer_status == ENUM_STATUS_PENDING)))
	{
		int sorted_n[nn];
		sort_n(sorted_n,nn);
		if(owner == ENUM_OWNER_GROUP_PEER || (owner == ENUM_OWNER_CTRL && peer_status == ENUM_STATUS_FRIEND))
		{
			for(int z = 0; z < 4; z++)
			{ // Z relates to colors (online status). It puts the online peers first and the offline peers last.
				int max = nn;
				while(max--)
				{
					const int n = sorted_n[max];
					const uint8_t local_owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
					const uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
					if(local_owner == owner && ((owner == ENUM_OWNER_CTRL && status == peer_status) || (owner == ENUM_OWNER_GROUP_PEER && (g == set_g(n,NULL)))))
					{
						const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
						const uint8_t recvfd_connected = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
						char *peernick = getter_string(NULL,n,INT_MIN,-1,offsetof(struct peer_list,peernick));
						if((search == NULL || mit_strcasestr(peernick,search) != NULL)\
						&& ((z == 0 && (sendfd_connected > 0 && recvfd_connected > 0)) /* green */\
						|| (z == 1 && (sendfd_connected < 1 && recvfd_connected > 0)) /* orange */\
						|| (z == 2 && (sendfd_connected > 0 && recvfd_connected < 1)) /* yellow */\
						|| (z == 3 && (sendfd_connected < 1 && recvfd_connected < 1)) /* grey */))
						{
							array[relevant] = n;
							relevant++;
						//	if(owner == ENUM_OWNER_GROUP_PEER)
						//		printf("Checkpoint refined_list owner==%d g==%d n==%u\n",owner,g,n);
						}
						torx_free((void*)&peernick);
					}
				}
			}
		}
		else
		{ // Pending or blocked CTRL (not sorting)
			int max = nn;
			while(max--)
			{
				const int n = sorted_n[max];
				const uint8_t local_owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
				const uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
				char *peernick = getter_string(NULL,n,INT_MIN,-1,offsetof(struct peer_list,peernick));
				if(local_owner == owner && status == peer_status && (search == NULL || mit_strcasestr(peernick,search) != NULL))
				{
					array[relevant] = n;
					relevant++;
				}
				torx_free((void*)&peernick);
			}
		}
	}
	else if(owner == ENUM_OWNER_PEER || owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
	{ // note: ignores peer_status, does not sort
		int max = nn;
		while(max--)
		{ // effectively newest first order
			const uint8_t owner_max = getter_uint8(max,INT_MIN,-1,offsetof(struct peer_list,owner));
			char *peernick = getter_string(NULL,max,INT_MIN,-1,offsetof(struct peer_list,peernick));
			if(owner_max == owner && (search == NULL || mit_strcasestr(peernick,search) != NULL))
			{
				array[relevant] = max;
				relevant++;
			}
			torx_free((void*)&peernick);
		}
	}
	else
	{
		error_printf(0,"Coding error passed to refined_list. Report this. Owner=%u",owner);
		breakpoint();
	}
//	array[relevant] = '\0'; //INVALID WRITE, DO NOT USE so we can eliminate *len. recommended however not to until we beat this checkpoint below.
	if(len)
		*len = relevant;
	return array;
}

size_t stripbuffer(char *buffer)
{ // For handshakes and general use. This function strips anything other than 0-9 and a-zA-Z.
	size_t j = 1; // necessary to initialize as 1 in case of 0 length
	for(size_t i = 0; buffer[i] != '\0'; ++i) 
		while(!(buffer[i] >= 'a' && buffer[i] <= 'z') && !(buffer[i] >= 'A' && buffer[i] <= 'Z') && !(buffer[i] >= '0' && buffer[i] <= '9') && !(buffer[i] == '\0')) 
		{
			for(j = i; buffer[j] != '\0'; ++j) 
				buffer[j] = buffer[j + 1];
			buffer[j] = '\0';
		}
	if(j - 1 == 0 && buffer != NULL) // workaround for case where no modifications need to be done to string
		j = j + strlen(buffer);
	return j - 1; // return length of new modified string
}

static inline int hash_password_internal(const char *password)
{ // Hashes the Tor control port password by making a call to the Tor binary
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	const char *tor_location_local_pointer = tor_location;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(!tor_location_local_pointer || !password)
		return 0;
	char arg1[] = "--quiet";
	char arg2[] = "--DataDirectory";
	char arg3[64];
	random_string(arg3,sizeof(arg3)); // generate a random data directory to avoid errors on certain platforms
	char arg4[] = "--hash-password";
//	char arg5[] = "-"; // cannot, does not work TODO talk to #tor
	const size_t password_len = strlen(password);
	char *arg5 = torx_secure_malloc(password_len+1);
	memcpy(arg5,password,password_len+1);
	char tor_location_local[PATH_MAX];
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	snprintf(tor_location_local,sizeof(tor_location_local),"%s",tor_location);
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,arg4,arg5,NULL};
	char *ret = run_binary(NULL,NULL,NULL,args_cmd,NULL);
	torx_free((void*)&arg5);
	size_t len = 0;
	if(ret)
		len = strlen(ret);
	if(len == 61)
	{
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		memcpy(control_password_hash,ret,sizeof(control_password_hash));
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		error_printf(3,"Actual Tor Control Password: %s",password);
		error_printf(3,"Hashed Tor Control Password: %s",ret);
	}
	else
		error_printf(0,"Improper length hashed Tor Control Password. Possibly Tor location incorrect? Length: %zu Output: %s",len,ret);
	torx_free((void*)&ret);
	return (int)len;
}

static inline void hash_password(void)
{ // Generate Tor Control Password, if not already existing. Do not overwrite.
	if(threadsafe_read_uint8(&mutex_global_variable,&using_system_tor))
	{ // Sanity check
		error_simple(0,"Hash password cannot be called while running system Tor because it could overwrite a control_password_clear. Coding error. Report this.");
		return;
	}
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	if(is_null(control_password_hash,sizeof(control_password_hash)))
	{
		if(!control_password_clear) // avoid overwriting if it has been set for some reason (ex: by UI)
		{
			control_password_clear = torx_secure_malloc(32+1);
			random_string(control_password_clear,32+1);
		}
		const size_t current_len = strlen(control_password_clear);
		char control_password_clear_local[current_len+1];
		memcpy(control_password_clear_local,control_password_clear,sizeof(control_password_clear_local));
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		if(hash_password_internal(control_password_clear_local) != 61)
		{
			pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
			torx_free((void*)&tor_location);
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		}
		sodium_memzero(control_password_clear_local,sizeof(control_password_clear_local));
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	}
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
}

static inline int extract_version(uint32_t output[4],const char *input)
{ // Extract version number from any null terminated string
	if(!input || !output)
		return -1;
	for(const char *p = input; *p; p++)
		if(*p >= '0' && *p <= '9')
		{
			uint32_t one,two,three,four;
			if(sscanf(p,"%u.%u.%u.%u",&one,&two,&three,&four) == 4)
			{ // Success
				output[0] = one;
				output[1] = two;
				output[2] = three;
				output[3] = four;
				return 0;
			}
		}
	return -1; // Not found
}

static inline int get_tor_version(void)
{ // Sets the tor_version, decides v3auth_enabled. Utilizes run_binary or tor_call, as appropriate.
	char *ret = NULL;
	char tor_location_local[PATH_MAX]; // not sensitive
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	snprintf(tor_location_local,sizeof(tor_location_local),"%s",tor_location);
	uint8_t using_system_tor_local = (tor_ctrl_port && !tor_pid);
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(using_system_tor_local)
		ret = tor_call("getinfo version\n");
	if(!ret && tor_location_local[0] != '\0') // NOT else
	{ // Unless using system Tor, prefer to make a binary call if the binary is available so that this function can be called successfully before Tor is started.
		if(using_system_tor_local)
		{
			error_simple(0,"System Tor is not working, despite being configured. Falling back to binary.");
			using_system_tor_local = 0;
		}
		char arg1[] = "--quiet";
		char arg2[] = "--version";
		char* const args_cmd[] = {tor_location_local,arg1,arg2,NULL};
		ret = run_binary(NULL,NULL,NULL,args_cmd,NULL);
	}
	else if(!ret)
	{
		error_simple(0,"No system Tor functioning and no binary available.");
		return -1;
	}
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	using_system_tor = using_system_tor_local;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	const int failed = extract_version(tor_version,ret);
	torx_free((void*)&ret);
	if(failed)
	{
		if(!using_system_tor_local && tor_location_local[0] != '\0')
		{
			error_printf(0,"Tor failed to return version. Check binary location and integrity: %s",tor_location_local);
			pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
			torx_free((void*)&tor_location);
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		}
	}
	else
	{
		error_printf(0,"Tor Version: %u.%u.%u.%u",tor_version[0],tor_version[1],tor_version[2],tor_version[3]);
		uint8_t local_v3auth_enabled;
		if((tor_version[0] > 0 || tor_version[1] > 4 ) || (tor_version[1] == 4 && tor_version[2] > 6) || (tor_version[1] == 4 && tor_version[2] == 6 && tor_version[3] > 0 ))
			local_v3auth_enabled = 1; // tor version >0.4.6.0
		else // Disable v3auth if tor version <0.4.6.1
			local_v3auth_enabled = 0;
		error_simple(0,local_v3auth_enabled ? "V3Auth is enabled by default." : "V3Auth is disabled by default. Recommended to upgrade Tor to a version >0.4.6.1");
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		v3auth_enabled = local_v3auth_enabled;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
	return failed;
}

uint16_t randport(const uint16_t arg) // Passing arg tests whether the port is available (currently unused functionality, but works)
{ // Returns an available random port above at 10,000. Mutex used here to prevent race condition when calling randport() concurrently on different threads (which we do)
	uint16_t port = 0;
	evutil_socket_t socket_rand;
	struct sockaddr_in serv_addr = {0};
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	pthread_mutex_lock(&mutex_socket_rand); // 🟥🟥
	while(1)
	{
		if(arg)
			port = arg;
		else
			port = (uint16_t)(randombytes_random() % (65536 - 10000 + 1)) + 10000; // keeping it over 10000 to keep byte length consistent (5 bytes)
		if((socket_rand = SOCKET_CAST_IN socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{ // Unlikely to occur. Could be fatal but shouldnt happen.
			error_simple(0,"Unlikely socket creation error");
			continue;
		}
		serv_addr.sin_port = htobe16(port);
		if(bind(SOCKET_CAST_OUT socket_rand,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0)
		{
			if(evutil_closesocket(socket_rand) < 0)
			{
				error_simple(0,"Unlikely socket failed to close error.1");
				continue;
			}
			break;
		}
		else if(arg)
		{ // passed port not available
			port = 0;
			error_printf(5,"Port %u not available. Returning port %u (error).",arg,port);
			if(evutil_closesocket(socket_rand) < 0)
				error_simple(0,"Unlikely socket failed to close error.2");
			break;
		}
		else // port in use
		{
			error_simple(0,"Port already in use. Will try another. Carry on."); // XXX can remove this, or set it to level 4+
			if(evutil_closesocket(socket_rand) < 0)
				error_simple(0,"Unlikely socket failed to close error.3");
		}
	}
	pthread_mutex_unlock(&mutex_socket_rand); // 🟩🟩
	return port;
}

static inline void remove_lines_with_suffix(char *input)
{ // We remove these lines because they are excessively common and provide no added value to us. Note: if line doesn't end in newline, it is not removed (as it is incomplete). This means some lines could sneak through, which is OK.
	size_t total_len; // so far unused
	if(!input || !(total_len = strlen(input)))
		return;
	const int num_suffixes = sizeof(tor_log_removed_suffixes)/sizeof(char *);
	for (char *start = input,*end = NULL; (end = strchr(start, '\n')) != NULL; ) // Move past the newline character
	{
		const size_t line_len = (size_t)(end - start + 1);
		uint8_t should_remove = 0;
		for (int i = 0; i < num_suffixes; i++)
		{
			const size_t suffix_len = strlen(tor_log_removed_suffixes[i]);
			if((should_remove = (line_len >= suffix_len && !strncmp(start + line_len - suffix_len, tor_log_removed_suffixes[i],suffix_len))))
				break;
		}
		if(should_remove)
		{
			total_len -= line_len; // so far unused
			size_t iter = 0;
			for(; (end+1)[iter] != '\0'; iter++)
				start[iter] = (end+1)[iter];
			start[iter] = '\0';
		}
		else
			start = end + 1;
	}
}

static inline void *tor_log_reader(void *arg)
{
	pusher(zero_pthread,(void*)&thrd_tor_log_reader)
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	char data[40960]; // should be big
	#ifdef WIN32
	HANDLE fd_stdout = arg;
	DWORD len;
	#define handling_pipe ReadFile(fd_stdout, data, sizeof(data), &len, NULL) && len > 0
	#else
	const int fd_stdout = vptoi(arg);
	ssize_t len;
	#define handling_pipe (len = read(fd_stdout,data,sizeof(data)-1)) > 0
	#endif
	while(handling_pipe)
	{ // Casting as size_t is safe because > 0
		data[len] = '\0'; // Ensure null termination. This is necessary. If issues continue, utilize utf8_valid too.
		char *msg = NULL;
		pthread_mutex_lock(&mutex_tor_pipe); // 🟥🟥
		if(read_tor_pipe_cache)
		{
			const uint32_t current_size = torx_allocation_len(read_tor_pipe_cache);
			read_tor_pipe_cache = torx_realloc(read_tor_pipe_cache,current_size+(size_t)len);
			memcpy(&read_tor_pipe_cache[current_size-1],data,(size_t)len+1);
		}
		if(data[(size_t)len-1] == '\n')
		{ // complete
			if(read_tor_pipe_cache)
			{
				msg = read_tor_pipe_cache;
				read_tor_pipe_cache = NULL; // Very important!
			}
			else
			{
				msg = torx_secure_malloc((size_t)len+1);
				memcpy(msg,data,(size_t)len+1); // includes copying null terminator
			}
			remove_lines_with_suffix(msg);
			pthread_mutex_unlock(&mutex_tor_pipe); // 🟩🟩
			const size_t remaining_len = strlen(msg);
			if(remaining_len && utf8_valid(msg,remaining_len))
				tor_log_cb(msg);
			else
			{
				if(remaining_len) // 2024/12/25 This can occur when restarting Tor
					error_simple(0,"Disgarding a Tor log message due to failure of utf8_valid check.");
				torx_free((void*)&msg);
			}
		}
		else if(read_tor_pipe_cache == NULL)
		{ // incomplete, no existing cache
			read_tor_pipe_cache = torx_secure_malloc((size_t)len+1);
			memcpy(read_tor_pipe_cache,data,(size_t)len+1); // includes copying null terminator
			pthread_mutex_unlock(&mutex_tor_pipe); // 🟩🟩
		}
		else // incomplete, existing cache
			pthread_mutex_unlock(&mutex_tor_pipe); // 🟩🟩
		sodium_memzero(data,(size_t)len);
	}
	#ifdef WIN32
	CloseHandle(fd_stdout);
	#else
	close(fd_stdout);
	#endif
	error_simple(0,"Exiting Tor log reader, probably because Tor died or was restarted. Is Tor already running?");
	return 0;
}

char *replace_substring(const char *source,const char *search,const char *replace)
{ // Non-destructive, returns allocated string if it finds and replaces substring, otherwise returns NULL. Do not modify this function.
	char *pos;
	if (!source || !search || !replace || !(pos = strstr(source, search)))
		return NULL;
	const size_t source_len = strlen(source);
	const size_t search_len = strlen(search);
	const size_t replace_len = strlen(replace);
	const size_t final_len = source_len - search_len + replace_len;
	char *new = torx_secure_malloc(final_len + 1);
	const size_t prefix_len = (size_t)(pos - source);
	const size_t suffix_len = final_len - prefix_len - replace_len;
	memcpy(new, source, prefix_len); // add prefix
	memcpy(new + prefix_len, replace, replace_len); // add replace
	memcpy(new + prefix_len + replace_len, pos + search_len, suffix_len); // add suffix
	new[final_len] = '\0';
	return new;
}

static inline uint16_t extract_port(const char *input,const char *type)
{ // Get a port from getinfo config-text. Ex: SocksPort, DNSPort, TransPort, etc. TODO Does not account for the possibility that the first port we find may be listening on non-localhost.
	if(!input || !type)
		return 0;
	const size_t type_len = strlen(type);
	const char *p = input;
	while(*p)
	{
		if(!strncmp(p,type,type_len) && p[type_len] == ' ')
		{
			uint16_t last_num = 0;
			const char *line_end = p;
			while (*line_end && *line_end != '\n')
				line_end++; // Find end of this line
			for(const char *scan = p ; scan < line_end ; )
			{ // Scan for numbers within this line. Skip non-digit characters.
				while (scan < line_end && !(*scan >= '0' && *scan <= '9'))
					scan++;
				if (scan >= line_end)
					break;
				int num = 0;
				while (scan < line_end && (*scan >= '0' && *scan <= '9'))
				{ // Parse numbers out
					num = num * 10 + (*scan - '0');
					scan++;
				}
				if (num >= 0 && num <= 65535)
					last_num = (uint16_t)num;
			}
			return last_num;
		}
		while(*p && *p != '\n')
			p++;
		if(*p == '\n')
			p++; // Move to next line
		else // End of input
			return 0;
	}
	return 0; // Not found
}

static inline void unlock(void)
{
	if(threadsafe_read_uint8(&mutex_global_variable,&lockout))
	{
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		lockout = 0;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		login_cb(0);
	}
}

static inline void kill_tor(const uint8_t wait_to_reap)
{ // XXX Note: should be called from within mutex_tor_pipe locks XXX
	if(tor_pid > 0) // Necessary sanity check
	{
		if(tor_ctrl_socket < 1)
		{ // tor_ctrl_socket could be 0 because we could be killing an orphaned Tor from a pid file
			#ifdef WIN32
			(void) wait_to_reap;
			pid_kill(tor_pid,SIGTERM);
			#else
			signal(SIGCHLD, SIG_DFL); // XXX allow zombies to be reaped by wait()
			if(!kill(tor_pid,SIGTERM) && wait_to_reap && threadsafe_read_uint8(&mutex_global_variable,&tor_running)) // DO NOT MODIFY: wait() must NOT be called if !tor_running or issues on startup occur.
				wait(NULL); // TODO before we wait() forever, we should probably also check that this PID is owned by the same user, and/or wait for a limited number of seconds
			signal(SIGCHLD, SIG_IGN); // XXX prevent zombies again
			#endif
		}
		else
		{
			pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
			const uint8_t already_using_system_tor = using_system_tor;
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			if(!already_using_system_tor)
			{ // Must only request shutdown on binary Tor
				char *ret = tor_call("signal shutdown\n"); // Request a clean shutdown (cleaner than TAKEOWNERSHIP or kill() invoked)
				torx_free((void*)&ret);
			} // Not else if
			if(torx_close_socket(&mutex_global_variable,&tor_ctrl_socket)) // This takes advantage of TAKEOWNERSHIP. Note: cannot wait() here
				error_simple(0,"Tor is probably already dead.");
		}
	//	while(!randport(tor_ctrl_port) || !randport(tor_socks_port)) // does not work because tor is not deregistering these ports properly on shutdown, it seems.
	//		fprintf(stderr,"not ready yet. TODO REMOVE???\n");
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		tor_running = 0;
		tor_pid = 0;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		pid_write(tor_pid);
	}
}

static inline void *start_tor_threaded(void *arg)
{ /* Start or Restart Tor and pipe stdout to pipe_tor */ // TODO have a tor_failed global variable that can be somehow set by errors here
	(void) arg;
	pusher(zero_pthread,(void*)&thrd_start_tor)
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	uint16_t tor_ctrl_port_local = tor_ctrl_port;
	uint16_t tor_socks_port_local = tor_socks_port;
	const uint8_t already_using_system_tor = using_system_tor;
	const uint8_t already_running = tor_running;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(already_running && already_using_system_tor) // Must do this before calling get_tor_version in case we are changing tor_ctrl_port
		torx_close_socket(&mutex_global_variable,&tor_ctrl_socket);
	if(get_tor_version())
		error_simple(0,"Cannot start Tor without a functional binary or control port.");
	else if(threadsafe_read_uint8(&mutex_global_variable,&using_system_tor))
	{ // System Tor is to be utilized
		if(already_running && !already_using_system_tor)
		{
			pthread_mutex_lock(&mutex_tor_pipe); // 🟥🟥
			kill_tor(1);
			pthread_mutex_unlock(&mutex_tor_pipe); // 🟩🟩
		}
		char *ret = tor_call("getinfo config-text\n");
		if(tor_socks_port_local || (tor_socks_port_local = extract_port(ret,"SocksPort")))
		{
			error_simple(2,"Running system Tor.");
			char *system_tor_torrc_content;
			size_t ret_len;
			const char expected_prefix[]= "250+config-text=\n";
			const char expected_suffix[]= "\n.\n250 OK\n";
			if(ret && (ret_len = strlen(ret)) > sizeof(expected_prefix) + sizeof(expected_suffix))
			{ // Stripping prefix and suffix
				system_tor_torrc_content = torx_secure_malloc(ret_len + 1 - sizeof(expected_prefix) - sizeof(expected_suffix));
				memcpy(system_tor_torrc_content,&ret[sizeof(expected_prefix)],ret_len + 1 - sizeof(expected_prefix) - sizeof(expected_suffix));
				system_tor_torrc_content[ret_len - sizeof(expected_prefix) - sizeof(expected_suffix)] = '\0'; // Very necessary
			}
			else
				system_tor_torrc_content = NULL;
			pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
			tor_socks_port = tor_socks_port_local;
			torx_free((void*)&torrc_content);
			torrc_content = system_tor_torrc_content;
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			sql_populate_peer();
		}
		else // Bad password or bad control port
			error_simple(0,"System Tor has no functional SOCKS port.");
		torx_free((void*)&ret);
	}
	else
	{ // Binary Tor is to be utilized
		error_simple(2,"Running binary Tor.");
		pthread_mutex_lock(&mutex_tor_pipe); // 🟥🟥
		if(!tor_pid) // If Tor is not running in this runtime, check for an abandoned Tor progess.
			tor_pid = pid_read();
		hash_password(); // MUST NOT TRIGGER IF USING SYSTEM TOR because system Tor allows empty control_password_clear
		if(tor_pid > 0) // NOT ELSE: This must be evaluated AFTER pid_read.
		{ // Restart an existing Tor process
			error_simple(0,"Tor is being restarted, or a PID file was found."); // XXX might need to re-randomize socksport and ctrlport, though hopefully not considering wait()
			kill_tor(1);
		}
		if(!tor_socks_port_local)
		{ // Only set if UI didn't set it, then try defaults first
			if((tor_socks_port_local = randport(PORT_DEFAULT_SOCKS)) || (tor_socks_port_local = randport(0)))
			{ // This WILL succeed
				pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
				tor_socks_port = tor_socks_port_local;
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			}
		}
		else if(!randport(tor_socks_port_local))
		{
			tor_socks_port_local = randport(0);
			error_printf(0,"Changing Tor Socks Port to %u",tor_socks_port_local);
			pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
			tor_socks_port = tor_socks_port_local;
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		}
		if(!tor_ctrl_port_local)
		{ // Only set if UI didn't set it, then try defaults first
			if((tor_ctrl_port_local = randport(PORT_DEFAULT_CONTROL)) || (tor_ctrl_port_local = randport(0)))
			{ // This WILL succeed
				pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
				tor_ctrl_port = tor_ctrl_port_local;
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			}
		}
		else if(!randport(tor_ctrl_port_local))
		{
			tor_ctrl_port_local = randport(0);
			error_printf(0,"Changing Tor Control Port to %u",tor_ctrl_port_local);
			pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
			tor_ctrl_port = tor_ctrl_port_local;
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		}
		#ifdef WIN32
		HANDLE fd_stdout = {0};
		#else
		int fd_stdout = -1;
		#endif
		pid_t pid;
		char arg1[] = "-f";
		char arg2[] = "-";
		char arg3[] = "--SocksPort"; // p1
		char arg4[] = "--ControlPort"; // p2
		char arg5[] = "--HashedControlPassword"; // control_password_hash
		char arg6[] = "--ConstrainedSockets";
		char arg7[] = "1";
		char arg8[] = "--ConstrainedSockSize"; // p3
		char arg9[] = "--LongLivedPorts"; // p4
		char arg10[] = "--DataDirectory"; // tor_data_directory
		char p1[21],p2[21],p3[21],p4[21];
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
		snprintf(p1,sizeof(p1),"%u",tor_socks_port_local);
		snprintf(p2,sizeof(p2),"%u",tor_ctrl_port_local);
		snprintf(p3,sizeof(p3),"%d",ConstrainedSockSize);
		snprintf(p4,sizeof(p4),"%d, %d",INIT_VPORT,CTRL_VPORT);
		char *torrc_content_local = replace_substring(torrc_content,"nativeLibraryDir",native_library_directory);
		if(!torrc_content_local && torrc_content) // Do unnecessary copy operation to allow consistant freeing of torrc_content_local
			torrc_content_local = torx_copy(NULL,torrc_content);
		char tor_location_local[PATH_MAX]; // not sensitive
		snprintf(tor_location_local,sizeof(tor_location_local),"%s",tor_location);
		char *ret;
		if(ConstrainedSockSize)
		{
			if(tor_data_directory)
			{
				char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg6,arg7,arg8,p3,arg9,p4,arg10,tor_data_directory,NULL};
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
				ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			}
			else
			{
				char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg6,arg7,arg8,p3,arg9,p4,NULL};
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
				ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			}
		}
		else
		{
			if(tor_data_directory)
			{
				char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg9,p4,arg10,tor_data_directory,NULL};
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
				ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			}
			else
			{
				char* const args_cmd[] = {tor_location_local,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg9,p4,NULL};
				pthread_rwlock_unlock(&mutex_global_variable); // 🟩
				ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			}
		}
		torx_free((void*)&ret); // we don't use this and it should be null anyway
		torx_free((void*)&torrc_content_local);
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		tor_pid = pid;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		pthread_mutex_unlock(&mutex_tor_pipe); // 🟩🟩
		ret = tor_call("TAKEOWNERSHIP\n"); // We place this here rather than after authenticating in tor_call because we do need to run sql_populate_peer again
		torx_free((void*)&ret);
		pid_write(pid);
		#ifdef WIN32
		if(pthread_create(&thrd_tor_log_reader,&ATTR_DETACHED,&tor_log_reader,fd_stdout))
			error_simple(-1,"Failed to create thread");
		#else
		if(pthread_create(&thrd_tor_log_reader,&ATTR_DETACHED,&tor_log_reader,itovp(fd_stdout)))
			error_simple(-1,"Failed to create thread");
		#endif
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
		error_printf(1,"Tor PID: %d",tor_pid);
		error_printf(1,"Tor SOCKS Port: %u",tor_socks_port_local);
		error_printf(3,"Tor Control Port: %u",tor_ctrl_port_local);
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		sql_populate_peer();
	}
	unlock(); // We allow login even in the event of connection failure because it may need to be fixed in UI
	return 0;
}

void start_tor(void)
{
	if(pthread_create(&thrd_start_tor,&ATTR_DETACHED,&start_tor_threaded,NULL))
		error_simple(-1,"Failed to create thread");
}

static inline int b64_isvalidchar(const char c) {
	if(c >= '0' && c <= '9')
		return 1;
	if(c >= 'A' && c <= 'Z')
		return 1;
	if(c >= 'a' && c <= 'z')
		return 1;
	if(c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}
size_t b64_decoded_size(const char *in)
{ /* Now newline safe. This function alone can determine whether a base64 privkey is superficially valid (returns 64) */
	if(in == NULL)
		return 0;
	size_t len = strlen(in);
	if(in[len-1] == '\n')
		len--;
	size_t ret = len / 4 *3;
	for(size_t i = len; i --> 0; )
	{
		if(in[i] == '=')
			ret--;
		else
			break;
	}
	return ret;
}
size_t b64_decode(unsigned char *out,const size_t destination_size,const char *in)
{ // Now newline safe. XXX WILL THROW ERROR IF *OUT IS NOT MALLOC()'d or an array[]. 2023/10/17 changed this to return 0 on error so can use size_t
	if(out == NULL)
	{
		error_simple(0,"b64_decode output location is likely a pointer that is not malloc'd");
		return 0;
	}
	out[0] = '\0'; // this is for safety, leave it
	if(in == NULL)
	{
		error_simple(0,"b64_decode input is null");
		return 0;
	}
	int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
		59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
		29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
		43, 44, 45, 46, 47, 48, 49, 50, 51 };
	const size_t outlen = b64_decoded_size(in);
	if(outlen > destination_size)
	{ // avoid illegal writes
		error_simple(0,"b64_decode destination is too small");
		return 0;
	}
	size_t len = strlen(in);
	if(in[len-1] == '\n')
		len--;
	if(len % 4 != 0)
		return 0;
	for(size_t i = 0; i < len; i++)
		if(!b64_isvalidchar(in[i]))
			return 0;
	int v;
	for(size_t i = 0, j = 0; i < len; i += 4, j += 3)
	{
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];
		out[j] = (unsigned char)((v >> 16) & 0xFF);
		if(in[i+2] != '=')
			out[j+1] = (unsigned char)((v >> 8) & 0xFF);
		if(in[i+3] != '=')
			out[j+2] = (unsigned char)(v & 0xFF);
	}
	if(outlen > SSIZE_MAX)
		return 0; // practically speaking will never occur
	return outlen;
}

static inline size_t b64_encoded_size(const size_t inlen)
{ // Required for b64_encode()
	size_t ret = inlen;
	if(inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;
	return ret;
}
char *b64_encode(const void *in_arg,const size_t len)
{ // remember to torx_free((void*)&)
	const unsigned char *in = in_arg;
	const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t elen,i,j,v;
	if(in == NULL || len == 0)
		return NULL;
	elen = b64_encoded_size(len);
	char *out = torx_secure_malloc(elen+1);
	for(i=0, j=0; i<len; i+=3, j+=4) 
	{
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;
		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if(i+1 < len)
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		else
			out[j+2] = '=';
		if(i+2 < len)
			out[j+3] = b64chars[v & 0x3F];
		else
			out[j+3] = '=';
	}
	out[elen] = '\0';
	return out;
}

void initial_keyed(void)
{ // Read in settings from file. Can also be used by clients for their settings. XXX Do not *need* locks. Unnecessary. Runs before most threads (except UI) start.
//	mlockall(MCL_FUTURE); // TODO TODO TODO this causes pthread_create to fail on some systems
	if(torrc_content == NULL) // making sure UI dev didn't set it already
		torrc_save(NULL);
//error	sql_exec(0,"PRAGMA journal_mode = WAL;",NULL);
//error	sql_exec(0,"PRAGMA locking_mode = NORMAL;",NULL);
//error	sql_exec(0,"PRAGMA secure_delete = ON;",NULL); // TODO "Cannot execute statement: unknown error"
	sql_exec(&db_messages,"PRAGMA synchronous = NORMAL;",NULL,0);
	sql_exec(&db_messages,"PRAGMA cipher_memory_security = ON;",NULL,0);
	sql_exec(&db_messages,"PRAGMA foreign_keys = ON;",NULL,0); // might be necessary for successful cascading delete since we reference entries in other table (peer)?
	sql_exec(&db_encrypted,"PRAGMA synchronous = NORMAL;",NULL,0);
	sql_exec(&db_encrypted,"PRAGMA cipher_memory_security = ON;",NULL,0);
	sql_exec(&db_encrypted,"PRAGMA foreign_keys = ON;",NULL,0); // might be necessary for successful cascading delete since we reference entries in other table (peer)?
	if(!first_run)
		sql_populate_setting(0); // encrypted settings
	else // if(first_run)
	{
		sql_exec(&db_encrypted,table_setting_global,NULL,0);
		sql_exec(&db_encrypted,table_peer,NULL,0);
		sql_exec(&db_encrypted,table_setting_peer,NULL,0);
	}
	if(get_file_size(file_db_messages) == 0) // permit recovery after deletion of messages database
		sql_exec(&db_messages,table_message,NULL,0);
	start_tor(); // XXX NOTE: might need to make this independently called by UI because on mobile it might be a problem to exec binaries within native code
	sodium_memzero(broadcasts_queued,sizeof(broadcasts_queued));
	for(int iter_queue = 0; iter_queue < BROADCAST_QUEUE_SIZE; iter_queue++)
		for(int iter_peer = 0; iter_peer < BROADCAST_MAX_PEERS; iter_peer++)
			broadcasts_queued[iter_queue].peers[iter_peer] = -1;
	broadcast_start();
	keyed = 1; // KEEP THIS AT THE END, after start_tor, etc.
}

static void initialize_i(const int n,const int i) // XXX do not put locks in here
{ // initalize an iter of the messages struc
	peer[n].message[i].time = 0;
	peer[n].message[i].fd_type = -1;
	peer[n].message[i].stat = 0;
	peer[n].message[i].p_iter = -1;
	peer[n].message[i].message = NULL;
	peer[n].message[i].pos = 0;
	peer[n].message[i].nstime = 0;
//	note: our max is message_n which is handled elsewhere
}

static void initialize_n(const int n) // XXX do not put locks in here
{ // initalize an iter of the peer struc XXX ONLY used when expanding. Don't forget to also update zero_n(). TODO consider calling zero_n() here?
	peer[n].owner = 0;
	peer[n].status = 0;
	sodium_memzero(peer[n].privkey,sizeof(peer[n].privkey)); // peer[n].privkey[0] = '\0';
	peer[n].peer_index = -2; // MUST be lower than -1 to properly error by sql_setting if unset
	sodium_memzero(peer[n].onion,sizeof(peer[n].onion)); // peer[n].onion[0] = '\0';
	sodium_memzero(peer[n].torxid,sizeof(peer[n].torxid));
	peer[n].peerversion = 0;
	sodium_memzero(peer[n].peeronion,sizeof(peer[n].peeronion)); // peer[n].peeronion[0] = '\0';
	peer[n].peernick = NULL;
	peer[n].log_messages = 0;
	peer[n].last_seen = 0;
	peer[n].vport = 0;
	peer[n].tport = 0;
	peer[n].socket_utilized[0] = INT_MIN;
	peer[n].socket_utilized[1] = INT_MIN;
	peer[n].sendfd = 0;
	peer[n].recvfd = 0;
	peer[n].sendfd_connected = 0;
	peer[n].recvfd_connected = 0;
	peer[n].bev_send = NULL;
	peer[n].bev_recv = NULL;
	peer[n].max_i = -1;
	peer[n].min_i = 0;
	sodium_memzero(peer[n].sign_sk,crypto_sign_SECRETKEYBYTES);
	sodium_memzero(peer[n].peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	sodium_memzero(peer[n].invitation,crypto_sign_BYTES);
	pthread_rwlock_init(&peer[n].mutex_page,NULL);
	peer[n].thrd_send = 0;
	peer[n].thrd_recv = 0;
	peer[n].broadcasts_inbound = 0;
	#ifndef NO_AUDIO_CALL
	peer[n].audio_cache = NULL;
	peer[n].audio_time = NULL;
	peer[n].audio_nstime = NULL;
	peer[n].audio_last_retrieved_time = 0;
	peer[n].audio_last_retrieved_nstime = 0;
	peer[n].cached_recording = NULL;
	peer[n].cached_time = 0;
	peer[n].cached_nstime = 0;
	peer[n].call = NULL; // Will be further initialized by set_c
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	peer[n].stickers_requested = NULL;
	#endif // NO_STICKERS
	peer[n].message = (struct message_list *)torx_secure_malloc(sizeof(struct message_list) *21) + 10; // XXX Note the +10
	for(int j = -10; j < 11; j++)
		initialize_i(n,j);
	#ifndef NO_FILE_TRANSFER
	peer[n].blacklisted = 0;
	peer[n].file = torx_secure_malloc(sizeof(struct file_list) *11);
	for(int j = 0; j < 11; j++)
		initialize_f(n,j);
	#endif // NO_FILE_TRANSFER
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	max_peer++;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
//	initialize_o(n); // depreciate, do not place here
}

static void initialize_g(const int g) // XXX do not put locks in here
{ // initalize an iter of the group struc
	sodium_memzero(group[g].id,GROUP_ID_SIZE);
	group[g].n = -1;
	for(int invitee = 0; invitee < MAX_INVITEES; invitee++)
		group[g].invitees[invitee] = -2; // please don't initialize as 0/-1
	group[g].hash = 0; // please don't initialize as -1
	group[g].peercount = 0; // please don't initialize as -1
	group[g].msg_count = 0; // please don't initialize as -1
	group[g].peerlist = NULL;
	group[g].invite_required = 0;
	group[g].msg_index_iter = 0;
	group[g].msg_index = NULL;
	group[g].msg_first = NULL;
	group[g].msg_last = NULL;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩 // XXX DANGER, WE ASSUME LOCKS XXX
	initialize_g_cb(g);
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥 // XXX DANGER, WE ASSUME LOCKS XXX
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	max_group++;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
}

void re_expand_callbacks(void)
{ // UI helper function for re-calling the expand struct callbacks (useful when UI is disposed) // WARNING: if conditions must be equal to those in expand_*_struct functions
	for(int n = 10; n + 10 <= threadsafe_read_int(&mutex_global_variable,&max_peer) ; n += 10)
	{ // starting at 10 because 0-10 should be initialized
		expand_peer_struc_cb(n);
		for(int nn = n + 10; nn > n; nn--)
		{
			initialize_n_cb(nn);
			const int max_i = getter_int(nn,INT_MIN,-1,offsetof(struct peer_list,max_i));
			const int min_i = getter_int(nn,INT_MIN,-1,offsetof(struct peer_list,min_i));
			for(int i = min_i; i <= max_i ; i++)
			{ // Note: min_i is not necessarily a multiple of -10/10
				if(i && i % 10 == 0)
				{
					expand_message_struc_cb(nn,i);
					if(i < 0) // Expanding down
						for(int j = i - 10; j < i; j++)
							initialize_i_cb(nn,j);
					else // Expanding up
						for(int j = i + 10; j > i; j--)
							initialize_i_cb(nn,j);
				}
			}
			#ifndef NO_FILE_TRANSFER
			unsigned char checksum[CHECKSUM_BIN_LEN];
			for(int f = 10; ; f += 10)
			{ // starting at 10 because 0-10 should be initialized
				getter_array(&checksum,sizeof(checksum),nn,INT_MIN,f,offsetof(struct file_list,checksum));
				if(is_null(checksum,CHECKSUM_BIN_LEN))
					break;
				expand_file_struc_cb(nn,f);
				for(int j = f + 10; j > f; j--)
					initialize_f_cb(nn,j);
			}
			#endif // NO_FILE_TRANSFER
			#ifndef NO_AUDIO_CALL
			torx_read(nn) // 🟧🟧🟧
			const size_t count = torx_allocation_len(peer[nn].call)/sizeof(struct call_list);
			torx_unlock(nn) // 🟩🟩🟩
			for(int call_c = 0; (size_t)call_c < count ; call_c++)
			{
				expand_call_struc_cb(nn,call_c);
				initialize_peer_call_cb(nn,call_c);
			}
			#endif // NO_AUDIO_CALL
		}
	}
	for(int g = 10; g + 10 <= threadsafe_read_int(&mutex_global_variable,&max_group) ; g += 10)
	{ // starting at 10 because 0-10 should be initialized
		expand_group_struc_cb(g);
		for(int j = g + 10; j > g; j--)
			initialize_g_cb(j);
	}

}

void expand_message_struc(const int n,const int i) // XXX do not put locks in here
{ /* Expand messages struct if our current i is unused && divisible by 10 */
	if(n < 0)
	{
		error_simple(0,"expand_message_struc failed sanity check. Coding error. Report this.");
		return;
	}
	const int max_i = peer[n].max_i;
	const int min_i = peer[n].min_i;
	const int p_iter = peer[n].message[i].p_iter;
	if(p_iter == -1 && i && i % 10 == 0 && (i + 10 > max_i + 1 || i - 10 < min_i - 1)) // NOTE: same as joafdoiwfoefjioasdf
	{ // NOTE: This is only a redundant sanity check. It should already have been checked by the calling function.
		int pointer_location;
		int current_shift = 0;
		if(i < 0)
		{
			current_shift = -10;
			pointer_location = i; // Note: should already be the same as find_message_struc_pointer(min_i)
		}
		else
			pointer_location = find_message_struc_pointer(min_i); // Note: returns negative
		const uint32_t current_allocation_size = torx_allocation_len(peer[n].message + pointer_location);
		if(i < 0)
			peer[n].message = (struct message_list*)torx_realloc_shift(peer[n].message + pointer_location, current_allocation_size + sizeof(struct message_list) *10,1) - pointer_location - current_shift;
		else
			peer[n].message = (struct message_list*)torx_realloc(peer[n].message + pointer_location, current_allocation_size + sizeof(struct message_list) *10) - pointer_location;
	}
	else
		error_simple(-1,"Sanity check failure in expand_message_struc");
}

static inline void expand_peer_struc(const int n)
{ /* Expand peer struct if our current n is unused && divisible by 10 */
	if(n < 0)
	{
		error_simple(0,"expand_peer_struc failed sanity check. Coding error. Report this.");
		return;
	}
	char onion = '\0';
	getter_array(&onion,1,n,INT_MIN,-1,offsetof(struct peer_list,onion));
	if(onion == '\0' && getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index)) < 0 && n && n % 10 == 0 && n + 10 > threadsafe_read_int(&mutex_global_variable,&max_peer))
	{ // Safe to cast n as size_t because > -1
		pthread_rwlock_wrlock(&mutex_expand); // 🟥
		const uint32_t current_allocation_size = torx_allocation_len(peer);
		peer = torx_realloc(peer,current_allocation_size + sizeof(struct peer_list) *10);
		for(int j = n + 10; j > n; j--)
			initialize_n(j);
		pthread_rwlock_unlock(&mutex_expand); // 🟩
		expand_peer_struc_cb(n);
		for(int j = n + 10; j > n; j--)
		{
			initialize_n_cb(j);
			for(int jj = -10; jj < 11; jj++)
				initialize_i_cb(j,jj);
			#ifndef NO_FILE_TRANSFER
			for(int jj = 0; jj < 11; jj++)
				initialize_f_cb(j,jj);
			#endif // NO_FILE_TRANSFER
		}
	}
}

static inline void expand_group_struc(const int g) // XXX do not put locks in here
{ /* Expand group struct if our current n is unused && divisible by 10 */
//	printf("Checkpoint expand_group_struct called on g==%d\n",g);
	if(g < 0)
	{
		error_simple(0,"expand_group_struc failed sanity check. Coding error. Report this.");
		return;
	}
	if(g % 10 == 0 && g && g + 10 > threadsafe_read_int(&mutex_global_variable,&max_group) && is_null(group[g].id,GROUP_ID_SIZE))
	{ // Safe to cast g as size_t because > -1
		const uint32_t current_allocation_size = torx_allocation_len(group);
		group = torx_realloc(group,current_allocation_size + sizeof(struct group_list) *10);
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩 // XXX DANGER, WE ASSUME LOCKS XXX
		expand_group_struc_cb(g);
		pthread_rwlock_wrlock(&mutex_expand_group); // 🟥 // XXX DANGER, WE ASSUME LOCKS XXX
		for(int j = g + 10; j > g; j--)
			initialize_g(j);
	}
}

void expand_message_struc_followup(const int n,const int i)
{ // must be called after expand_message_struc, after unlock
	if(n < 0 || i == 0 || i % 10) // i must not be 0, must be divisible by 10
		error_simple(-1,"expand_message_struc_followup sanity check failed");
	expand_message_struc_cb(n,i);
	torx_write(n) // 🟥🟥🟥
	if(i < 0) // Expanding down
		for(int j = i - 10; j < i; j++)
			initialize_i(n,j);
	else // Expanding up
		for(int j = i + 10; j > i; j--)
			initialize_i(n,j);
	torx_unlock(n) // 🟩🟩🟩
	if(i < 0) // Expanding down
		for(int j = i - 10; j < i; j++)
			initialize_i_cb(n,j);
	else // Expanding up
		for(int j = i + 10; j > i; j--)
			initialize_i_cb(n,j);
}

int increment_i(const int n,const int offset,const time_t time,const time_t nstime,const uint8_t stat,const int8_t fd_type,const int p_iter,char *message)
{
	if(n < 0)
		error_simple(-1,"increment_i sanity check failed");
	uint8_t expanded = 0;
	int i;
	torx_write(n) // 🟥🟥🟥
	if(offset < 0)
		i = peer[n].min_i - offset -1;
	else
		i = peer[n].max_i + 1;
	if(!offset)
	{ // In the case of offset, we must have already expanded the struct in sql_populate_message
		if(peer[n].message[i].p_iter == -1 && i && i % 10 == 0 && (i + 10 > peer[n].max_i + 1 || i - 10 < peer[n].min_i - 1))
		{ // NOTE: same as joafdoiwfoefjioasdf
			expand_message_struc(n,i);
			expanded = 1;
		}
		peer[n].max_i++;
	}
	//printf("Checkpoint increment_i n=%d i=%d max_i=%d min_i=%d\n",n,i,peer[n].max_i,peer[n].min_i);
	peer[n].message[i].time = time;
	peer[n].message[i].nstime = nstime;
	peer[n].message[i].fd_type = fd_type;
	peer[n].message[i].stat = stat;
	peer[n].message[i].p_iter = p_iter;
	peer[n].message[i].message = message;
	torx_unlock(n) // 🟩🟩🟩
	if(expanded)
		expand_message_struc_followup(n,i);
	return i;
}

int set_last_message(int *last_message_n,const int n,const int count_back)
{ /* Helper to determine the last message worth displaying in peer list. UI can use this or an alternative. */ // WARNING: May return INT_MIN;
	int finalized_count_back = count_back;
	int current_count_back = 0;
	if(finalized_count_back < 1) // non-fatal sanity check
		finalized_count_back = 0;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Last message for a group
		if(!last_message_n)
		{
			error_simple(0,"Set_last_message: last_message_n must not be NULL. Coding error. Report this.");
			return INT_MIN;
		}
		const int g = set_g(n,NULL);
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
		struct msg_list *page = group[g].msg_last;
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		while(page)
		{
			const int p_iter = getter_int(page->n,page->i,-1,offsetof(struct message_list,p_iter));
			if(p_iter > -1 && threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) && current_count_back++ == finalized_count_back)
			{
				*last_message_n = page->n;
				return page->i;
			}
			page = page->message_prior;
		}
		*last_message_n = n;
		return INT_MIN;
	}
	else
	{ // Last message for non-group
		const int max_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,max_i));
		const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
		int i = max_i;
		if(i >= min_i)
		{ // Critical check
		//	for(int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter)); threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) == 0 ; p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter)))
		//		if(--i == -1) // do NOT modify. this should be --i, not i++
		//			break;
			while(1)
			{ // DO NOT CHANGE ORDER OR LOGIC. The logic is complex
				const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
				if(p_iter > -1 && threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) && current_count_back++ == finalized_count_back)
					break;
				else if(--i < min_i)
				{
					i = INT_MIN;
					break;
				}
			}
		}
		else
			i = INT_MIN;
		if(last_message_n)
			*last_message_n = n;
		return i;
	}
}

int set_n(const int peer_index,const char *onion)
{ // Finds appropriate peer struct N value or gets an empty one. IMPORTANT: Prioritizes peer_index over onion if both passed. Do not modify without extensive testing. Any changes might need to be reflected in expand_peer_struc too.
  // Onion MUST be null terminated, and may be partial length
	int n = 0;
	uint8_t onion_check = 0;
	while(1)
	{ // not real while loop, just to avoid goto
		if(onion_check || peer_index == -1)
		{ // Traditional set_n
			torx_read(n) // 🟧🟧🟧
			if(onion) // search by onion
				while((peer[n].onion[0] != '\0' || peer[n].peer_index > -1) && strncmp(peer[n].onion,onion,56))
				{
					torx_unlock(n++) // 🟩🟩🟩
					torx_read(n) // 🟧🟧🟧
				}
			else // find next blank
				while(peer[n].onion[0] != '\0' || peer[n].peer_index > -1)
				{
					torx_unlock(n++) // 🟩🟩🟩
					torx_read(n) // 🟧🟧🟧
				}
			torx_unlock(n) // 🟩🟩🟩
		}
		else if(peer_index > -1)
		{ // set n from peer_index (sql related)
			torx_read(n) // 🟧🟧🟧
			while(peer[n].peer_index != peer_index && (peer[n].onion[0] != '\0' || peer[n].peer_index > -1))
			{
				torx_unlock(n++) // 🟩🟩🟩
				torx_read(n) // 🟧🟧🟧
			}
			if(peer[n].peer_index != peer_index && onion != NULL)
			{// Blank, go to onion check. IMPORTANT for NAA1AmTDLE: instead of exclusively prioritizing peer_index if both are passed, peer_index is checked first and then .onion is checked, before settling on blank.
				torx_unlock(n) // 🟩🟩🟩
				n = 0;
				onion_check = 1;
				continue;
			}
			torx_unlock(n) // 🟩🟩🟩
	//		if(peer[n].peer_index == peer_index)
	//			printf("Checkpoint BINGO %d == %d\n",peer[n].peer_index,peer_index);
	//		else
	//			printf("Checkpoint NO MATCHES, utilizing blank n=%d\n",n);
		}
		else
		{ // -2 means uninitialized (confirm in initialize_n)
			error_printf(0,"Invalid peer_index passed to set_n: %d. Coding error. Report this.",peer_index);
			breakpoint();
			return -1;
		}
		break;
	}
	expand_peer_struc(n); // Expand struct if necessary
	// TODO if desired, reserve here. DO NOT RESERVE BEFORE EXPAND_ or it will be lost
	if(peer_index > -1)
		setter(n,INT_MIN,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
	if(onion) // do NOT put 'else if'
		setter(n,INT_MIN,-1,offsetof(struct peer_list,onion),onion,strlen(onion)); // source is pointer. NOTE: strlen looks odd but it is in case we are looking up with only a partial
	return n;
}

int set_g(const int n,const void *arg)
{ // prioritizes N over group_id, if both provided. XXX WILL NEVER RETURN NEGATIVE.
// NOTE: This uses N instead of peer_index. That only works so long as the structure of our database doesn't change. if setting "group_id" isn't loaded first, then our group structure will fall apart.
// We could fix this by using peer_index but then we'd have to set_n every time we needed N, and that is undesirable.
// TODO to save CPU (especially when printing/loading group chats in UI), should have a peer[n].associated_group and have set_g check it before checking every group's peerlist TODO
	const unsigned char *group_id = arg; // allows passing of char or unsigned char
	unsigned char zero_array[GROUP_ID_SIZE];// = "00000000000000000000000000000000"; XXX do NOT eliminate. '0' != '\0'
	memset(zero_array,'0',sizeof(zero_array)); // does not need null termination
	int8_t error = 0;
	int g = 0;
	uint8_t owner = 0; // initializing for clang. doesnt need to be.
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	if(n > -1)
	{
		owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
		if(owner == ENUM_OWNER_GROUP_CTRL) // search for a GROUP_CTRL by n
		{
			while((group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE)) && group[g].n != n)
				g++;
			if(group[g].n != n && !arg && group[g-1].n == -1) // We didn't find the group
				g--; // Roll-back in certain limited circumstances (such as when creating a group with group_generate) // TODO EXPERIMENTAL 2024/11/27 and subject to rare possibility of race condition (specifically if analyzing a group offer at the same moment as generating a group... there could be two most-recent groups that both have no group_n yet)
		}
		else if(owner == ENUM_OWNER_GROUP_PEER) // search for a GROUP_PEER by n
			while(group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE))
			{ // XXX EXPERIMENTAL
				uint32_t gg = 0;
				while(gg < group[g].peercount && group[g].peerlist[gg] != n)
					gg++;
				if(gg == group[g].peercount)
					g++; // was not in this group
				else
					break; // winner! set peer[n].associated_group here so that it only need be set once
			}
		else
		{ // MUST BE FATAL or it will cause weird problems. Don't call set_g on non-group peer types.
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			error_simple(-1,"set_g called on a non-group peer. Coding error. Report this. (include backtrace in report)"); // NOTE: Highly likely a UI dev error. Get a backtrace.
		}
	}
	else if(group_id)// search by group_id
		while((group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE)) && memcmp(group[g].id,group_id,GROUP_ID_SIZE))
			g++;
	else // find next blank, allow re-use
		while(group[g].n > -1 || (!is_null(group[g].id,GROUP_ID_SIZE) && memcmp(group[g].id,zero_array,GROUP_ID_SIZE)))
			g++; // TODO potential uninitialized soething (seems to be a bug on re-use... so it doesn't occur on first-run, just after crap is deleted)
/* // Useful but valgrind gets upset. Disabled 2024/03/24.
	if(owner == ENUM_OWNER_GROUP_PEER && n > -1 && g > -1 && group[g].n < 0 && (is_null(group[g].id,GROUP_ID_SIZE) || !memcmp(group[g].id,zero_array,GROUP_ID_SIZE)))
	{
		if(arg)
			printf("Checkpoint arg exists\n");
		else
			printf("Checkpoint arg is NULL\n");
		printf("Checkpoint is_null %d\n",is_null(group[g].id,GROUP_ID_SIZE));
		printf("Checkpoint memcmp %d\n",!memcmp(group[g].id,zero_array,GROUP_ID_SIZE));
		printf("Checkpoint group_n %d\n",group[g].n);
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		error_printf(-1,"Set_g landed on a blank group g==%d ENUM_OWNER_GROUP_PEER. Report this.",g); // TODO 2024/02/24 happened in a private group when clicking peerlist. Same group has allowed PMing wrong person
		error = 1;
	} */
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	expand_group_struc(g); // Expand struct if necessary
	if(!error && n > -1)
		if(owner == ENUM_OWNER_GROUP_CTRL) // necessary check, to ensure we're not setting group_n to GROUP_PEER
			group[g].n = n;
	if(group_id) // do NOT set 'else if'
		memcpy(group[g].id,group_id,GROUP_ID_SIZE);
/*	if(owner == ENUM_OWNER_GROUP_PEER && is_null(group[g].id,GROUP_ID_SIZE))
	{ // This will probably lead to severe bugs elsewhere, so we should detect it. TODO note: its not triggering, so this can't be the issue. DEBUGGING 2024/11/15 REMOVE
		error_simple(0,"Returning a g with a null ID. Likely coding error. Report this.");
		breakpoint();
	} */
//	error_printf(0,PINK"Checkpoint set_g = %d n=%d arg=%s"RESET,g,n,arg?b64_encode(arg,GROUP_ID_SIZE):"NULL"); // TODO NOTE: SHOULD NOT BE >0 when there is only one group. XXX XXX XXX
//	if(group_id)
//		printf("Checkpoint GID: %s\n",b64_encode(group_id,GROUP_ID_SIZE));
/*	if(n > -1)
		printf("Checkpoint set_g by n, n==%d g==%d\n",n,g);
	else if(arg)
		printf("Checkpoint set_g by hash\n");
	else
		printf("Checkpoint set_g by fresh g==%d\n",g); */
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	return g;
}

int set_g_from_i(uint32_t *untrusted_peercount,const int n,const int i)
{ // Returns -1 if message protocol isn't group offer. Helper function to be used on Group Offers.
	if(n < 0)
		return -1;
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
		return -1;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(protocol != ENUM_PROTOCOL_GROUP_OFFER && protocol != ENUM_PROTOCOL_GROUP_OFFER_FIRST)
		return -1;
	torx_read(n) // 🟧🟧🟧
	const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);
	torx_unlock(n) // 🟩🟩🟩
	if((protocol == ENUM_PROTOCOL_GROUP_OFFER && message_len < GROUP_OFFER_LEN) || (protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST && message_len < GROUP_OFFER_FIRST_LEN))
		return -1;
	char tmp_message[GROUP_ID_SIZE + sizeof(uint32_t)];
	torx_read(n) // 🟧🟧🟧
	memcpy(tmp_message,peer[n].message[i].message,sizeof(tmp_message));
	torx_unlock(n) // 🟩🟩🟩
	const int g = set_g(-1,tmp_message);
	if(untrusted_peercount)
		*untrusted_peercount = be32toh(align_uint32((void*)&tmp_message[GROUP_ID_SIZE]));
	sodium_memzero(tmp_message,sizeof(tmp_message));
	return g;
}

int group_online(const int g)
{ // Returns number of online peers
	int online = 0;
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(peerlist != NULL)
	{
		const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			const uint8_t sendfd_connected = getter_uint8(peer_n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
			const uint8_t recvfd_connected = getter_uint8(peer_n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
			if(sendfd_connected > 0 || recvfd_connected > 0)
				online++;
		}
	}
	return online;
}

int group_check_sig(const int g,const char *message,const uint32_t message_len,const uint16_t untrusted_protocol,const unsigned char *sig,const char *peeronion_prefix)
{ // This function checks signatures of messages sent to a GROUP_CTRL and returns who sent them.
// Any length of prefix can be passed, NULL / 0-56. If there are multiple matches (ex: short prefix), each will be tried.
//TODO This could be a burden on file transfers and it might be worthwhile in the future to assign peers to a specific port or otherwise authenticate sockets/streams instead.
	const int group_n = getter_group_int(g,offsetof(struct group_list,n));
	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	size_t peeronion_len = 0;
	if(peeronion_prefix)
		peeronion_len = strlen(peeronion_prefix);
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(g < 0 || sig == NULL || peeronion_len > 56 || message == NULL || message_len < 1)
	{
		if(message == NULL || message_len < 1)
			error_simple(0,"Failure of sanity check in group_check_sig: Message is NULL or of bad length.");
		else if(g < 0)
			error_simple(0,"Failure of sanity check in group_check_sig: Invalid G value.");
		else if(sig == NULL)
			error_simple(0,"Failure of sanity check in group_check_sig: No signature passed.");
		else if(peeronion_len > 56)
			error_simple(0,"Failure of sanity check in group_check_sig: Peeronion is of invalid length. Report this.");
		breakpoint();
		return -1;
	}
	char *prefixed_message = NULL;
	size_t prefix_length = 0;
	if(untrusted_protocol)
	{
		prefixed_message = affix_protocol_len(untrusted_protocol,message, message_len);
		prefix_length = 2+4;
	}
	if(peerlist) // NOTE: peerlist is null when adding first peer, so we skip and check for self-sign
		for(uint32_t nn = 0; nn != g_peercount; nn++)
		{
			pthread_rwlock_wrlock(&mutex_expand_group); // 🟥 // YES this is wrlock TODO why did we insist on it being wrlock???
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),peer_n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
			unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
			getter_array(&peer_sign_pk,sizeof(peer_sign_pk),peer_n,INT_MIN,-1,offsetof(struct peer_list,peer_sign_pk));
			if((peeronion_len == 0 || !memcmp(peeronion,peeronion_prefix,peeronion_len)) && crypto_sign_verify_detached(sig,(const unsigned char *)(untrusted_protocol ? prefixed_message : message), prefix_length + message_len, peer_sign_pk) == 0)
			{
				sodium_memzero(peeronion,sizeof(peeronion));
				sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
				error_simple(4,"Success of group_check_sig: Signed by a peer.");
				torx_free((void*)&prefixed_message);
				return peer_n;
			}
			sodium_memzero(peeronion,sizeof(peeronion));
			sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
		}
	if(peeronion_len)
	{ // do not continue if prefix was passed and no more peers
		error_simple(4,"Failure of group_check_sig. Prefix doesn't match any peeronions in group.");
		torx_free((void*)&prefixed_message);
		return -1;
	}
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES]; // TODO could just store this in group_ctrl's peer_sign_pk, since it isn't being used
	getter_array(&sign_sk,sizeof(sign_sk),group_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
	crypto_sign_ed25519_sk_to_pk(ed25519_pk,sign_sk);
	sodium_memzero(sign_sk,sizeof(sign_sk));
	if(crypto_sign_verify_detached(sig,(const unsigned char *)(untrusted_protocol ? prefixed_message : message), prefix_length + message_len, ed25519_pk) == 0)
	{ // Signed by us! (only applicable in the case that this message is an invitation_signature)
		error_simple(4,"Success of group_check_sig: Signed by group_n (us).");
	//	printf("Checkpoint SUCCESS of GROUP self-sign: %u\n",untrusted_protocol);
		sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
		torx_free((void*)&prefixed_message);
		return group_n;
	}
	else if(peerlist)
	{ // Failure here IS failure
		error_printf(0,"Failure of group_check_sig. Unknown signer or bad signature. Protocol: %u",untrusted_protocol); // Unknown signer (bug, malicious peer, blocked peer, deleted peer)
		error_printf(3,MAGENTA"Checkpoint failed signature: %s"RESET,b64_encode(sig,crypto_sign_BYTES));
		error_printf(3,MAGENTA"Checkpoint failed signing pk key: %s"RESET,b64_encode(ed25519_pk,sizeof(ed25519_pk)));
		error_printf(3,MAGENTA"Checkpoint failed message(b64) of len %lu: %s"RESET,message_len,b64_encode(message, message_len));
	//	breakpoint();
	}
	else if(g_peercount != 0)
	{
		error_simple(0,"Failure of sanity check in group_check_sig: Peerlist is null while peercount is not 0. Coding error. Report this.");
		breakpoint();
	}
	else
		error_printf(0,"Group=%d has no peerlist and peercount=%d. group_check_sig had nothing to check against except our own signature.",g,g_peercount);
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	torx_free((void*)&prefixed_message);
	return -1;
}

int group_add_peer(const int g,const char *group_peeronion,const char *group_peernick,const unsigned char *group_peer_ed25519_pk,const unsigned char *inviter_signature) // peer's inviter_signature
{ // TODO Triggered upon SENDING and upon RECEIVING message type ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY, as well as (multiple times) upon receiving ENUM_PROTOCOL_GROUP_PEERLIST TODO
  // XXX NOTE: Group_peeronion is NOT treated as a string. Group_peernick IS treated as a string but if NULL will be set to group_peeronion. // TODO if desired, could check group_peeronion for 56 characters of base32.
	if(group_peeronion == NULL || g < 0)
	{ // TODO Could also verify that group is not null.
		error_simple(0,"Group_peeronion is null or group is invalid. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	const int group_n = getter_group_int(g,offsetof(struct group_list,n));
	char local_group_peeronion[56+1]; // WARNING: group_peeronion is NOT GUARANTEED TO BE A STRING, use local_group_peeronion
	memcpy(local_group_peeronion,group_peeronion,56);
	local_group_peeronion[56] = '\0';
	pthread_mutex_lock(&mutex_group_peer_add); // 🟥🟥
	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	if(peerlist)
	{
		char onion_group_n[56+1];
		getter_array(&onion_group_n,sizeof(onion_group_n),group_n,INT_MIN,-1,offsetof(struct peer_list,onion));
		for(uint32_t nn = 0 ; nn < g_peercount ; nn++) // check for existing before adding
		{
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),peer_n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
			const int ret = memcmp(peeronion,local_group_peeronion,56);
			sodium_memzero(peeronion,sizeof(peeronion));
			if(!ret || !memcmp(onion_group_n,local_group_peeronion,56))
			{
				pthread_mutex_unlock(&mutex_group_peer_add); // 🟩🟩
				error_simple(2,"Peer already exists in peerlist or as group_n. Not adding."); // was level 4
				sodium_memzero(local_group_peeronion,sizeof(local_group_peeronion));
				return -2;
			}
		}
		sodium_memzero(onion_group_n,sizeof(onion_group_n));
	}
	if(g_invite_required)
	{
		if(group_peer_ed25519_pk == NULL || inviter_signature == NULL)
		{
			pthread_mutex_unlock(&mutex_group_peer_add); // 🟩🟩
			error_simple(0,"Group is invite_required but something is null.");
			sodium_memzero(local_group_peeronion,sizeof(local_group_peeronion));
			return -1;
		}
		char peer_invite[56+crypto_sign_PUBLICKEYBYTES]; // TODO rename variable logically
		memcpy(peer_invite,local_group_peeronion,56);
		memcpy(&peer_invite[56],group_peer_ed25519_pk,crypto_sign_PUBLICKEYBYTES);
		if(group_check_sig(g,peer_invite,sizeof(peer_invite),0,inviter_signature,NULL) < 0)
		{ // XXX for testing, allowing pass upon failure if there are no peers (presumably we just got invited) TODO this could have unintended consequences on group creator's side
			if(peerlist != NULL)
			{ // Bail out if there is a peerlist with no keys matching sig
				pthread_mutex_unlock(&mutex_group_peer_add); // 🟩🟩
				error_simple(0,"Group requires invite but peer failed signature check.");
				sodium_memzero(peer_invite,sizeof(peer_invite));
				sodium_memzero(local_group_peeronion,sizeof(local_group_peeronion));
				return -1;
			}
		}
		sodium_memzero(peer_invite,sizeof(peer_invite));
	}
	const char *local_group_peernick;
	char nick_array[56+1];
	if(group_peernick && strlen(group_peernick) > 0)
		local_group_peernick = group_peernick;
	else
	{ // use torxid instead of // local_group_peernick = local_group_peeronion;
		char *torxid = torxid_from_onion(local_group_peeronion);
		snprintf(nick_array,sizeof(nick_array),"%s",torxid);
		torx_free((void*)&torxid);
		local_group_peernick = nick_array;
	}
	char fake_privkey[88+1];
	random_string(fake_privkey,sizeof(fake_privkey));
	const int peer_index = sql_insert_peer(ENUM_OWNER_GROUP_PEER,ENUM_STATUS_FRIEND,99,fake_privkey,local_group_peeronion,local_group_peernick,0);
	int n;
	if(g_invite_required)
		n = load_peer_struc(peer_index,ENUM_OWNER_GROUP_PEER,ENUM_STATUS_FRIEND,fake_privkey,99,local_group_peeronion,local_group_peernick,NULL/*SK*/,group_peer_ed25519_pk,inviter_signature);
	else
		n = load_peer_struc(peer_index,ENUM_OWNER_GROUP_PEER,ENUM_STATUS_FRIEND,fake_privkey,99,local_group_peeronion,local_group_peernick,NULL/*SK*/,group_peer_ed25519_pk,NULL);
	sodium_memzero(local_group_peeronion,sizeof(local_group_peeronion));
	sodium_memzero(nick_array,sizeof(nick_array));
	if(n < 0)
	{
		pthread_mutex_unlock(&mutex_group_peer_add); // 🟩🟩
		error_simple(0,"Coding error 57518. Report this.");
		breakpoint();	
		return -1;
	}
	sql_update_peer(n); // saves group_peer_ed25519_pk
	// Associate it with a group, save setting
//	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	char setting_name[64]; // arbitrary size
	snprintf(setting_name,sizeof(setting_name),"group_peer%d",peer_index); // "group_peer" + peer_index, for uniqueness. might make deleting complex.
	const int peer_index_group = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	sql_setting(0,peer_index_group,setting_name,"",0);
	// Add it to our peerlist
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
	if(group[g].peerlist)
		group[g].peerlist = torx_realloc(group[g].peerlist,((size_t)g_peercount+1)*sizeof(int));
	else
		group[g].peerlist = torx_insecure_malloc(((size_t)g_peercount+1)*sizeof(int));
	group[g].peerlist[group[g].peercount] = n;
	group[g].peercount++;
//	printf("Checkpoint group_add_peer g==%d peercount==%u\n",g,group[g].peercount);
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	pthread_mutex_unlock(&mutex_group_peer_add); // 🟩🟩
	load_onion(n); // connect to their onion with our signed onion, also in sql_populate_peer()
	peer_new_cb(n);
	return n;
}

int group_join(const int inviter_n,const unsigned char *group_id,const char *group_name,const char *creator_onion,const unsigned char *creator_ed25519_pk)
{ // Audited 2024/02/17 // NOTE: if group is public (not invite-only), pass -1 as inviter_n // Note: Cannot assume null terminated creator_onion // TODO Note: might be better to pass n,i of the offer instead of creator_onion and creator_ed25519_pk, to prevent rare potential read race
	if(group_id == NULL || (inviter_n > -1 && ((creator_onion && !creator_ed25519_pk) || (!creator_onion && creator_ed25519_pk) || (creator_onion && creator_ed25519_pk && !utf8_valid(creator_onion,56)))))
	{
		error_simple(0,"Group join sanity check failed. Coding error or invalid creator onion passed from peer. Report this.");
		breakpoint();
		return -1;
	}
	const int g = set_g(-1,group_id); // reserving
	uint8_t g_invite_required = 0;
	pthread_mutex_lock(&mutex_group_join); // 🟥🟥
	int group_n = getter_group_int(g,offsetof(struct group_list,n));
	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount)); // this is CONFIRMED PEERS, not unconfirmed/reported on offer
	uint8_t responding_to_first_offer = 0;
	if(inviter_n > -1)
	{ // Invite-Only group
		g_invite_required = 1;
		if(creator_onion != NULL && creator_ed25519_pk != NULL)
			responding_to_first_offer = 1;
	}
	setter_group(g,offsetof(struct group_list,invite_required),&g_invite_required,sizeof(g_invite_required)); // MUST be before generate_onion
	if(group_n > -1 && (g_peercount > 0 || inviter_n < 0)) // DO NOT change this logic. its important to prevent trying to join our own public group or invite-only groups with peers already
	{ // Adding peercount check to enable multiple attempts, as otherwise invite-only group could be unjoinable if a message gets lost
		pthread_mutex_unlock(&mutex_group_join); // 🟩🟩
		error_simple(0,"Have already attempted to join or joined this group. Bailing out.");
		return g;
	}
	else if(group_n < 0)
	{ // Brand new group, first attempt, need to create CTRL
		if(group_name == NULL || strlen(group_name) < 1)
		{ // No name passed, so use encoded group ID
			char *local_group_name = b64_encode(group_id,GROUP_ID_SIZE);
			group_n = generate_onion(ENUM_OWNER_GROUP_CTRL,NULL,local_group_name);
			torx_free((void*)&local_group_name);
		}
		else
			group_n = generate_onion(ENUM_OWNER_GROUP_CTRL,NULL,group_name); // load, save
		setter_group(g,offsetof(struct group_list,n),&group_n,sizeof(group_n));
	}
	pthread_mutex_unlock(&mutex_group_join); // 🟩🟩
	const int peer_index = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	sql_setting(0,peer_index,"group_id",(const char*)group_id,GROUP_ID_SIZE); // IMPORTANT: This MUST be the FIRST setting saved because it will also be the first loaded.
	char p1[21];
	snprintf(p1,sizeof(p1),"%d",g_invite_required);
	sql_setting(0,peer_index,"invite_required",p1,strlen(p1));
	if(responding_to_first_offer)
	{ // Responding to a ENUM_PROTOCOL_GROUP_OFFER_FIRST. Need to sign invitor's creator_onion.
		struct int_char int_char;
		int_char.i = g;
		int_char.p = creator_onion;
		int_char.up = creator_ed25519_pk;
		message_send(inviter_n,ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST,&int_char,GROUP_OFFER_ACCEPT_FIRST_LEN);
	}
	else if(g_invite_required) // responding to a ENUM_PROTOCOL_GROUP_OFFER (already populated group), not newly created. no need to sign our inviter's onion.
		message_send(inviter_n,ENUM_PROTOCOL_GROUP_OFFER_ACCEPT,itovp(g),GROUP_OFFER_ACCEPT_LEN);
	else
	{ // Public Group. Broadcast a GROUP_JOIN message ( crypto_box_SEALBYTES + 16(salt) +  56 + crypto_sign_PUBLICKEYBYTES ) (48 + 16 + 56 + 32)... to join a public group. 
	// Broadcast to everyone, including members of groups. Check if we own the requesting onion before processing. In groups, do not rebroadcast received messages. Also no need to sign.
		unsigned char ciphertext[GROUP_BROADCAST_LEN];
		broadcast_prep(ciphertext,g);
		broadcast_add(-1,ciphertext);
		sodium_memzero(ciphertext,sizeof(ciphertext));
	}
	return g; // now it waits for a our signed ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY
}

int group_join_from_i(const int n,const int i)
{
	if(n < 0)
		return -1;
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
		return -1;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(protocol != ENUM_PROTOCOL_GROUP_OFFER_FIRST && protocol != ENUM_PROTOCOL_GROUP_OFFER)
		return -1;
	int g;
	unsigned char id[GROUP_ID_SIZE];
	torx_read(n) // 🟧🟧🟧
	memcpy(id,peer[n].message[i].message,sizeof(id));
	torx_unlock(n) // 🟩🟩🟩
	if(protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
	{
		char creator_onion[56+1];
		unsigned char creator_ed25519_pk[crypto_sign_PUBLICKEYBYTES];
		torx_read(n) // 🟧🟧🟧
		memcpy(creator_onion,&peer[n].message[i].message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)],56);
		memcpy(creator_ed25519_pk,&peer[n].message[i].message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)+56],sizeof(creator_ed25519_pk));
		torx_unlock(n) // 🟩🟩🟩
		creator_onion[56] = '\0';
		g = group_join(n,id,NULL,creator_onion,creator_ed25519_pk);
		sodium_memzero(creator_onion,sizeof(creator_onion));
		sodium_memzero(creator_ed25519_pk,sizeof(creator_ed25519_pk));
	}
	else/* if(protocol == ENUM_PROTOCOL_GROUP_OFFER) */
		g = group_join(n,id,NULL,NULL,NULL);
	sodium_memzero(id,sizeof(id));
	return g;
}

int group_generate(const uint8_t invite_required,const char *name)
{ // Audited 2024/02/15 // NOTE: if group is public (not invite-only) then the .id can be shared as a QR/otherwise which new users will use to sign their onion and pass around the network until they get in
	if(name == NULL || strlen(name) == 0)
	{
		error_simple(0,"Cannot generate a group with 0 length name.");
		return -1;
	}
	unsigned char x25519_pk[crypto_box_PUBLICKEYBYTES]; // 32
	unsigned char x25519_sk[crypto_box_SECRETKEYBYTES]; // 32 the group_id
	crypto_box_keypair(x25519_pk,x25519_sk);
	const int g = set_g(-1,x25519_sk); // get a blank g, reserves the group. DO NOT generate_onion before reserving and setting .invite_required
	setter_group(g,offsetof(struct group_list,invite_required),&invite_required,sizeof(invite_required));
	const int group_n = generate_onion(ENUM_OWNER_GROUP_CTRL,NULL,name); // must do this AFTER reserving group and setting invite_required
	setter_group(g,offsetof(struct group_list,n),&group_n,sizeof(group_n));
	const int peer_index = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	sql_setting(0,peer_index,"group_id",(char*)x25519_sk,sizeof(x25519_sk)); // IMPORTANT: This MUST be the FIRST setting saved because it will also be the first loaded.
	sodium_memzero(x25519_pk,sizeof(x25519_pk));
	sodium_memzero(x25519_sk,sizeof(x25519_sk));
	char p1[21];
	snprintf(p1,sizeof(p1),"%u",invite_required);
	sql_setting(0,peer_index,"invite_required",p1,strlen(p1));
	return g;
}

void initial(void)
{ /* Note: Creates ~/.config/torx/ and all files will be created there by default (as it becomes current dir) */
/* Preferred if this can remain safe to run multiple times so that it can be used to, for example, load the theme/language login page several times without logging in */
	if(sodium_init() < 0)
	{ // XXX WARNING DO NOT PUT ANY ERROR_* BEFORE THIS OR IT WILL LEAD TO SEVERE MEMORY ERRORS AND CRASHES ON ANDROID XXX
		fprintf(stderr,"Error initializing LibSodium library. Be sure to compile with -lsodium flag\n"); // must be fprintf. This error is fatal.
		exit(-1);
	}
	sodium_initialized = 1;
	srand(randombytes_random()); // seed rand() with libsodium, in case we use rand() somewhere, Do not use rand() for sensitive operations. Use randombytes_random(). Note: rand() is terrible on Windows.
	umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // umask 600 equivalent. man 2 umask
	if(debug_file)
	{ // If a debug file is enabled, write the fact and current time to it. NOTE: Debug file could be enabled later by UI, skipping this.
		time_t now;
		time(&now);
		struct tm *utc_time = gmtime(&now);
		char timebuffer[20];
		strftime(timebuffer,20,"%Y/%m/%d %H:%M:%S",utc_time);
		error_printf(0,"Warning: Starting up TorX with debug file enabled at %s. Current time: %s UTC",debug_file,timebuffer);
	}
	#ifdef WIN32
		evthread_use_windows_threads();
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
			error_simple(-1,"WSAStartup failed");
	#else
		evthread_use_pthreads();
		signal(SIGBUS, cleanup_cb);
		signal(SIGSYS, cleanup_cb);
		signal(SIGPIPE, cleanup_cb);
		signal(SIGALRM, cleanup_cb);
		signal(SIGHUP, cleanup_cb);
		signal(SIGUSR1, cleanup_cb);
		signal(SIGUSR2, cleanup_cb);
		signal(SIGCHLD, SIG_IGN); // XXX prevent zombies
	#endif
	signal(SIGINT, cleanup_cb);
	signal(SIGABRT, cleanup_cb);
	signal(SIGTERM, cleanup_cb);
	signal(SIGSEGV, cleanup_cb);
	signal(SIGILL, cleanup_cb);
	signal(SIGFPE, cleanup_cb);

	pthread_attr_init(&ATTR_DETACHED); // must be triggered before any use
	pthread_attr_setdetachstate(&ATTR_DETACHED, PTHREAD_CREATE_DETACHED); // must be triggered before any use

	error_printf(0,"TorX Library Version: %u.%u.%u.%u",torx_library_version[0],torx_library_version[1],torx_library_version[2],torx_library_version[3]);
	error_simple(0,ENABLE_SECURE_MALLOC ? "Compiled with ENABLE_SECURE_MALLOC" : "Compiled without ENABLE_SECURE_MALLOC");

	sodium_memzero(protocols,sizeof(protocols)); // XXX initialize protocols struct XXX

	// protocol, name, description,	null_terminated_len, date_len, signature_len, logged, notifiable, file_checksum, file_offer, exclusive_type, utf8, socket_swappable, stream XXX NOTE: cannot depreciate group mechanics, as stream is not suitable (stream deletes upon fail)
	#ifndef NO_FILE_TRANSFER
	file_piece_p_iter = protocol_registration(ENUM_PROTOCOL_FILE_PIECE,"File Piece","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,0,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_GROUP,"File Offer Group","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,"File Offer Group Date Signed","",0,1,1,1,1,1,1,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_PARTIAL,"File Offer Partial","",0,0,0,0,0,1,1,ENUM_EXCLUSIVE_GROUP_MSG,0,1,ENUM_STREAM_NON_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_FILE_INFO_REQUEST,"File Info Request","",0,0,0,0,0,1,0,ENUM_EXCLUSIVE_NONE,0,1,ENUM_STREAM_NON_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_FILE_PARTIAL_REQUEST,"File Partial Request","",0,0,0,0,0,1,0,ENUM_EXCLUSIVE_GROUP_MSG,0,1,ENUM_STREAM_NON_DISCARDABLE);
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_PNG TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_PNG TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_GIF TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_GIF TODO
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER,"File Offer","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_NONE,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_PRIVATE,"File Offer Private","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_GROUP_PM,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_REQUEST,"File Request","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,0,ENUM_STREAM_NON_DISCARDABLE); // TODO we store file path here, so if it doesn't save, we can't resume. This means accepting a file while a peer is offline is meaningless if they don't come online before we restart our client.
	protocol_registration(ENUM_PROTOCOL_FILE_PAUSE,"File Pause","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_CANCEL,"File Cancel","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	#endif // NO_FILE_TRANSFER
	protocol_registration(ENUM_PROTOCOL_PROPOSE_UPGRADE,"Propose Upgrade","",0,0,1,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,ENUM_STREAM_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_KILL_CODE,"Kill Code","",1,1,1,1,0,0,0,ENUM_EXCLUSIVE_NONE,1,1,0);
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT,"UTF8 Text","",1,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
//	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_SIGNED,"UTF8 Text Signed","",1,0,1,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0); // not in use
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_DATE_SIGNED,"UTF8 Text Date Signed","",1,1,1,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_PRIVATE,"UTF8 Text Private","",1,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_PM,1,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_BROADCAST,"Group Broadcast","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MSG,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_FIRST,"Group Offer First","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER,"Group Offer","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST,"Group Offer Accept First","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT,"Group Offer Accept","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY,"Group Offer Accept Reply","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,"Group Public Entry Request","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,0,0); // group_mechanics, must be logged until sent
	protocol_registration(ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST,"Group Private Entry Request","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,0,0); // group_mechanics, must be logged until sent
	protocol_registration(ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,"Group Request Peerlist","",0,1,1,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,1,0); // group_mechanics // XXX 2024/06/20 making this swappable reveals a bad race condition caused by multiple cascades, which can only be fixed by having a 4th "_QUEUED" stat that is the equivalent of _FAIL that has been send_prep'd into the packet struct
	protocol_registration(ENUM_PROTOCOL_GROUP_PEERLIST,"Group Peerlist","",0,1,1,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,1,0); // group_mechanics
	protocol_registration(ENUM_PROTOCOL_PIPE_AUTH,"Pipe Authentication","",0,0,1,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,0,ENUM_STREAM_DISCARDABLE);
	#ifndef NO_AUDIO_CALL
	protocol_registration(ENUM_PROTOCOL_AUDIO_STREAM_JOIN, "Audio Stream Join", "", 0, 0, 0, 0, 1, 0, 0, ENUM_EXCLUSIVE_GROUP_MSG, 0, 1, ENUM_STREAM_NON_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_AUDIO_STREAM_JOIN_PRIVATE, "Audio Stream Join Private", "", 0, 0, 0, 0, 1, 0, 0, ENUM_EXCLUSIVE_GROUP_PM, 0, 1, ENUM_STREAM_NON_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_AUDIO_STREAM_PEERS, "Audio Stream Peers", "", 0, 0, 0, 0, 0, 0, 0, ENUM_EXCLUSIVE_NONE, 0, 1, ENUM_STREAM_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_AUDIO_STREAM_LEAVE, "Audio Stream Leave", "", 0, 0, 0, 0, 1, 0, 0, ENUM_EXCLUSIVE_NONE, 0, 1, ENUM_STREAM_NON_DISCARDABLE);
	protocol_registration(ENUM_PROTOCOL_AUDIO_STREAM_DATA_DATE_AAC, "Audio Data Date AAC", "", 0, 1, 0, 0, 0, 0, 0, ENUM_EXCLUSIVE_NONE, 0, 1, ENUM_STREAM_DISCARDABLE);
	#endif // NO_AUDIO_CALL
	#ifndef NO_STICKERS
	protocol_registration(ENUM_PROTOCOL_STICKER_HASH,"Sticker","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,0,1,0);
	protocol_registration(ENUM_PROTOCOL_STICKER_HASH_DATE_SIGNED,"Sticker Date Signed","",0,1,1,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,0,1,0);
	protocol_registration(ENUM_PROTOCOL_STICKER_HASH_PRIVATE,"Sticker Private","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_PM,0,1,0);
	protocol_registration(ENUM_PROTOCOL_STICKER_REQUEST,"Sticker Request","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_STICKER_DATA_GIF,"Sticker data","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,ENUM_STREAM_NON_DISCARDABLE); // NOTE: if making !stream, need to move related handler
	#endif // NO_STICKERS
	size_t len;
	if(file_db_plaintext == NULL)
	{
		len = sizeof("plaintext.db"); // includes null terminator
		file_db_plaintext = torx_secure_malloc(len); // "plaintext.db";
		snprintf(file_db_plaintext,len,"plaintext.db");
	}
	if(file_db_encrypted == NULL)
	{
		len = sizeof("encrypted.db"); // includes null terminator
		file_db_encrypted = torx_secure_malloc(len); // "encrypted.db";
		snprintf(file_db_encrypted,len,"encrypted.db");
	}
	if(file_db_messages == NULL)
	{
		len = sizeof("messages.db"); // includes null terminator
		file_db_messages = torx_secure_malloc(len); // "messages.db";
		snprintf(file_db_messages,len,"messages.db");
	}
	if(file_tor_pid == NULL)
	{
		len = sizeof("tor.pid"); // includes null terminator
		file_tor_pid = torx_secure_malloc(len); // "tor.pid";
		snprintf(file_tor_pid,len,"tor.pid");
	}

	/* Create config directory */
	if(working_dir == NULL)
	{
		#ifdef WIN32 // XXX
		PWSTR basePath = NULL;
		if(SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &basePath)))
		{ // Get AppData path
			wchar_t appdata_path[MAX_PATH];
			swprintf(appdata_path,sizeof(appdata_path),L"%s\\TorX",basePath);
		//	if(SUCCEEDED(StringCchCopyW(appdata_path, MAX_PATH, basePath)) && SUCCEEDED(StringCchCatW(appdata_path, MAX_PATH, L"\\TorX")))
			if((GetFileAttributesW(appdata_path) == INVALID_FILE_ATTRIBUTES && CreateDirectoryW(appdata_path, NULL)) || GetLastError() == ERROR_ALREADY_EXISTS)
				SetCurrentDirectoryW(appdata_path);
			CoTaskMemFree(basePath); // Free the memory allocated by SHGetKnownFolderPath
		}
		#else
		if(chdir(getenv("HOME")) == 0)
		{
			mkdir(".config",0700);
			if(chdir(".config") == 0)
			{
				mkdir("torx",0700);
				if(chdir("torx") == 0)
					error_simple(4,"Navigated to proper directory.");
			}
		}
		#endif
	}
	else if(chdir(working_dir) == 0)
		error_simple(4,"Navigated to proper directory.");
	else
		error_simple(0,"Failed to navigate to desired directory. Will fallback to current directory.");

	// XXX Cannot move to initial_keyed because we need this info to build the initial UI (whether to display switch). For this reason, if we store this in a database, it'll have to be in cleartext. XXX
	// Note: Will be over-written by stored settings, if applicable.
	// Note: We intentionally placed this after chdir because which looks in current dir not where our running binary exists.
	if(tor_location == NULL)
		tor_location = which("tor");
	if(snowflake_location == NULL)
		snowflake_location = which("snowflake-client");
	if(lyrebird_location == NULL)
		lyrebird_location = which("lyrebird");
	if(conjure_location == NULL)
		conjure_location = which("conjure");

	if(default_peernick == NULL)
	{
		const char defname[8+1] = "Nameless";
		default_peernick = torx_secure_malloc(sizeof(defname));
		snprintf(default_peernick,sizeof(defname),"%s",defname);
	}

	if(get_file_size(file_db_plaintext) == 0)
		first_run = 1; // first point to set (1 of 2)

	if(peer == NULL)
	{ // make safe for repeated calls of initial, in case UI is buggy // XXX 2024 this check is safe because variables declared in .h are zero initialized https://en.wikipedia.org/wiki/.bss
		startup_time = time(NULL);
		if(!file_db_plaintext || sqlite3_open(file_db_plaintext, &db_plaintext) != SQLITE_OK)
		{
			error_printf(0, "Cannot open database: %s", sqlite3_errmsg(db_plaintext));
			sqlite3_close(db_plaintext);
			return;
		}
		if(!file_db_encrypted || sqlite3_open(file_db_encrypted, &db_encrypted) != SQLITE_OK)
		{
			error_printf(0,"Cannot open database: %s", sqlite3_errmsg(db_encrypted));
			sqlite3_close(db_encrypted);
			return;
		}
		if(!file_db_messages || sqlite3_open(file_db_messages, &db_messages) != SQLITE_OK)
		{
			error_printf(0,"Cannot open database: %s", sqlite3_errmsg(db_messages));
			sqlite3_close(db_messages);
			return;
		}
	//sqlite3_exec(db, "PRAGMA journal_mode = WAL; PRAGMA locking_mode = NORMAL; PRAGMA synchronous = NORMAL;", NULL, NULL, NULL);
	//	sql_exec(1,"PRAGMA journal_mode = WAL;",NULL);
	//	sql_exec(1,"PRAGMA locking_mode = NORMAL;",NULL);
	//	sql_exec(1,"PRAGMA secure_delete = ON;",NULL); // TODO "Cannot execute statement: unknown error"
		sql_exec(&db_plaintext,"PRAGMA synchronous = NORMAL;",NULL,0);
		sql_exec(&db_plaintext,"PRAGMA cipher_memory_security = ON;",NULL,0);
		sql_exec(&db_plaintext,"PRAGMA foreign_keys = ON;",NULL,0); // might be necessary for successful cascading delete since we reference entries in other table (peer)?
		if(first_run)
			sql_exec(&db_plaintext,table_setting_clear,NULL,0);
		/* Initialize peer struct */
		pthread_rwlock_wrlock(&mutex_expand); // 🟥
		peer = torx_secure_malloc(sizeof(struct peer_list) *11);
		for(int j = 0; j < 11; j++)
			initialize_n(j);
		pthread_rwlock_unlock(&mutex_expand); // 🟩
		for(int j = 0; j < 11; j++)
		{
			initialize_n_cb(j);
			for(int jj = -10; jj < 11; jj++)
				initialize_i_cb(j,jj);
			#ifndef NO_FILE_TRANSFER
			for(int jj = 0; jj < 11; jj++)
				initialize_f_cb(j,jj);
			#endif // NO_FILE_TRANSFER
		}
		/* Initialize group struct */
		pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
		group = torx_secure_malloc(sizeof(struct group_list) *11);
		for(int j = 0; j < 11; j++)
			initialize_g(j);
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		/* Initalize the packet struc */
		for(int o = 0; o < SIZE_PACKET_STRC; o++)
		{
			pthread_rwlock_wrlock(&mutex_packet); // 🟥
			packet[o].n = -1;
			#ifndef NO_FILE_TRANSFER
			packet[o].file_n = -1;
			#endif // NO_FILE_TRANSFER
			packet[o].f_i = INT_MIN;
			packet[o].packet_len = 0;
			packet[o].p_iter = -1;
			packet[o].fd_type = -1;
			packet[o].time = 0;
			packet[o].nstime = 0;
			pthread_rwlock_unlock(&mutex_packet); // 🟩
		}
		const uint32_t count = (uint32_t)cpucount();
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		threads_max = count;
		if(threads_max > 256 || threads_max < 1) // Triggered if cpucount() returns an obviously bad value, which could occur on mobile or obscure platforms
			threads_max = 8; // error_simple(0,"Failed to detect CPU count automatically. Defaulting to 8 threads.");
		global_threads = threads_max; // (can be overwritten by any settings loaded from file subsequently)
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
	if(!first_run)
		sql_populate_setting(1); // plaintext settings
}

static inline int password_verify(const char *password)
{ // Check if a password is indeed correct (ie, for before we allow changing)
	if(!password)
		return -1;
	sqlite3 *db_tmp = {0};
	if(sqlite3_open(file_db_encrypted, &db_tmp) != SQLITE_OK)
	{
		error_simple(0,"Checkpoint password_verify failed to open db");
		return -1;
	}
	unsigned char testing_decryption_key[crypto_box_SEEDBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES]; // MUST be declared before goto
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	memcpy(salt,saltbuffer,sizeof(salt));
	const long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	const size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	const int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(crypto_pwhash(testing_decryption_key,sizeof(testing_decryption_key),password,strlen(password),salt,local_crypto_pwhash_OPSLIMIT,local_crypto_pwhash_MEMLIMIT,local_crypto_pwhash_ALG) != 0)
	{ // XXX if it crashes due to lack of memory, the password might not be removed
		sodium_memzero(salt,sizeof(salt)); // not important
		sqlite3_close(db_tmp);
		error_simple(-1,"Ran out of memory.");
		return -1;
	}
	sodium_memzero(salt,sizeof(salt)); // not important
	sqlite3_key(db_tmp, testing_decryption_key, sizeof(testing_decryption_key));
	sodium_memzero(testing_decryption_key,sizeof(testing_decryption_key));
	const int ret = sqlite3_exec(db_tmp, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);// official recommended way to test if password is good
	sqlite3_close(db_tmp);
	if(ret == SQLITE_OK)
		return 0; // Correct
	return -1; // Incorrect
}

static inline void *change_password_threaded(void *arg)
{ // NOTE: do not change salt, do not change iter, just generate a new password hash and use it. This will be critical for later when we gerryrig a resume function utilizing cipher_integrity_check and some internal functions i guess.
 // NOTE 2: ensure that SQL doesn't change its own internal salt when calling rekey (for resumption)
// Note 3: These above two notes are irrelevant if sqlite3_rekey is atomic
	pusher(zero_pthread,(void*)&thrd_change_password)
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	struct pass_strc *pass_strc = (struct pass_strc*) arg; // Casting passed struct
	if(threadsafe_read_uint8(&mutex_global_variable,&currently_changing_pass))
	{ // already changing pass
		error_simple(0,"Action to change password already in process. Stop making repeat calls.");
		change_password_cb(-1);
		goto liberate;
	}
	else if(pass_strc->password_new == NULL || pass_strc->password_verify == NULL || strcmp(pass_strc->password_new,pass_strc->password_verify) != 0) // strcmp is fine to use here because we have no idea what the lengths might be
	{ // passwords do not match.
		error_simple(0,"Passwords do not match or were not provided");
		change_password_cb(2);
		goto liberate;
	}
	else if(pass_strc->password_old == NULL || password_verify(pass_strc->password_old))
	{ // NOTE: we don't actually *need* password_old, but for safety we should utilize it
		error_simple(0,"Current password is incorrect.");
		change_password_cb(1);
		goto liberate;
	}

	uint8_t local_currently_changing_pass = 1;
	threadsafe_write(&mutex_global_variable,&currently_changing_pass,&local_currently_changing_pass,sizeof(local_currently_changing_pass));

	unsigned char salt[crypto_pwhash_SALTBYTES]; // MUST be declared before goto
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	memcpy(salt,saltbuffer,sizeof(salt));
	const long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	const size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	const int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	const size_t password_len = strlen(pass_strc->password_new);
	if(crypto_pwhash(decryption_key,sizeof(decryption_key),pass_strc->password_new,password_len,salt,local_crypto_pwhash_OPSLIMIT,local_crypto_pwhash_MEMLIMIT,local_crypto_pwhash_ALG) != 0)
	{ // XXX if it crashes due to lack of memory, the password might not be removed
		sodium_memzero(salt,sizeof(salt)); // not important
		error_simple(-1,"Ran out of memory.");
		goto liberate;
	}
	sodium_memzero(salt,sizeof(salt)); // not important

	pthread_mutex_lock(&mutex_sql_messages); // 🟥🟥
	int val = sqlite3_rekey(db_messages,decryption_key,(int)sizeof(decryption_key));
	pthread_mutex_unlock(&mutex_sql_messages); // 🟩🟩
	if(val == SQLITE_OK)
	{ // If our larger database was successful, do the smaller one. WARNING: If this fails, big problems.
		pthread_mutex_lock(&mutex_sql_encrypted); // 🟥🟥
		val = sqlite3_rekey(db_encrypted,decryption_key,(int)sizeof(decryption_key));
		pthread_mutex_unlock(&mutex_sql_encrypted); // 🟩🟩
	}
	if(password_len == 0) // DO NOT DELETE THIS, lol. anyone who deletes this conditional is a glowie.
		sql_setting(1,-1,"decryption_key",(const char *)decryption_key, sizeof(decryption_key));
	else
		sql_delete_setting(1,-1,"decryption_key");
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	sodium_memzero(decryption_key,sizeof(decryption_key));
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	local_currently_changing_pass = 0;
	threadsafe_write(&mutex_global_variable,&currently_changing_pass,&local_currently_changing_pass,sizeof(local_currently_changing_pass));
	error_simple(0,"Finished changing password.");
	change_password_cb(val);
	liberate: {}
	torx_free((void*)&pass_strc->password_new);
	torx_free((void*)&pass_strc->password_verify);
	torx_free((void*)&pass_strc->password_old);
	torx_free((void*)&pass_strc);
	return 0;
}

void change_password_start(const char *password_old,const char *password_new,const char *password_verify)
{ /* Careful not to call this more than once */
	struct pass_strc *pass_strc = torx_insecure_malloc(sizeof(struct pass_strc));
	if(password_old)
	{
		const size_t len = strlen(password_old);
		pass_strc->password_old = torx_secure_malloc(len+1);
		memcpy(pass_strc->password_old,password_old,len+1);
	}
	if(password_new)
	{
		const size_t len = strlen(password_new);
		pass_strc->password_new = torx_secure_malloc(len+1);
		memcpy(pass_strc->password_new,password_new,len+1);
	}
	if(password_verify)
	{
		const size_t len = strlen(password_verify);
		pass_strc->password_verify = torx_secure_malloc(len+1);
		memcpy(pass_strc->password_verify,password_verify,len+1);
	}
	if(pthread_create(&thrd_change_password,&ATTR_DETACHED,&change_password_threaded,(void*)pass_strc))
		error_simple(-1,"Failed to create thread");
}

static inline void *login_threaded(void *arg)
{ // this must run after initial
	pusher(zero_pthread,(void*)&thrd_login)
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	unsigned char salt[crypto_pwhash_SALTBYTES]; // 16
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	if(first_run == 1 || (!local_crypto_pwhash_OPSLIMIT && !local_crypto_pwhash_MEMLIMIT && !local_crypto_pwhash_ALG))
	{ // On first run or if login_threaded has never run before
		first_run = 1; // second point at which we might set first_run (2 of 2) (could combine this with the first one)
		randombytes_buf(salt,sizeof(salt));
		const uint8_t local_reduced_memory = threadsafe_read_uint8(&mutex_global_variable,&reduced_memory);
		if(local_reduced_memory == 0)
		{ // Takes 1024 mb of RAM (default)
			local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT_SENSITIVE;
			local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT_SENSITIVE;
		}
		else if(local_reduced_memory == 1)
		{ // Takes 256mb of RAM
			local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
			local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;
		}
		else if(local_reduced_memory == 2)
		{ // Takes 64mb of RAM
			local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT_INTERACTIVE;
			local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT_INTERACTIVE;
		}
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		crypto_pwhash_OPSLIMIT = local_crypto_pwhash_OPSLIMIT;
		crypto_pwhash_MEMLIMIT = local_crypto_pwhash_MEMLIMIT;
		crypto_pwhash_ALG = local_crypto_pwhash_ALG = crypto_pwhash_ALG_DEFAULT;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		sql_setting(1,-1,"salt",(char*)salt,sizeof(salt));
		char p1[21];
		snprintf(p1,sizeof(p1),"%llu",local_crypto_pwhash_OPSLIMIT);
		sql_setting(1,-1,"crypto_pwhash_OPSLIMIT",p1,strlen(p1));
		snprintf(p1,sizeof(p1),"%zu",local_crypto_pwhash_MEMLIMIT);
		sql_setting(1,-1,"crypto_pwhash_MEMLIMIT",p1,strlen(p1));
		snprintf(p1,sizeof(p1),"%d",local_crypto_pwhash_ALG);
		sql_setting(1,-1,"crypto_pwhash_ALG",p1,strlen(p1));
	}
	else
	{
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
		memcpy(salt,saltbuffer,sizeof(salt));
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
/*	printf("OPSLIMIT: %llu\n",crypto_pwhash_OPSLIMIT);
	printf("MEMLIMIT: %lu\n",crypto_pwhash_MEMLIMIT);
	printf("ALG: %d\n",crypto_pwhash_ALG);
	printf("Salt: %s\n",b64_encode(salt,sizeof(salt)));
	printf("Arg: %s\n",(char *)arg);	*/
	const size_t password_len = strlen(arg);
	unsigned char local_decryption_key[crypto_box_SEEDBYTES]; // intermediary is necessary, do not eliminate
	memcpy(local_decryption_key,decryption_key,sizeof(decryption_key)); // necessary
	if(is_null(local_decryption_key,sizeof(local_decryption_key)))
		if(crypto_pwhash(local_decryption_key,sizeof(local_decryption_key),arg,password_len,salt,local_crypto_pwhash_OPSLIMIT,local_crypto_pwhash_MEMLIMIT,local_crypto_pwhash_ALG) != 0)
		{ // XXX if it crashes due to lack of memory, the password might not be removed
			sodium_memzero(salt,sizeof(salt)); // not important
			torx_free(&arg);
			error_simple(-1,"Ran out of memory.");
			return 0;
		}
	sodium_memzero(salt,sizeof(salt)); // not important
	torx_free(&arg); // is password
	sqlite3_key(db_encrypted, local_decryption_key, sizeof(local_decryption_key)); // same as (binary) PRAGMA key = "x'2DD29CA851E7B56E4697B0E1F08507293D761A05CE4D1B628663F411A8086D99'";
	if(sqlite3_exec(db_encrypted, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) == SQLITE_OK) // official recommended way to test if password is good
	{
		sqlite3_key(db_messages, local_decryption_key, sizeof(local_decryption_key));
		if(first_run && password_len == 0) // DO NOT DELETE THIS, lol. anyone who deletes this conditional is a glowie.
			sql_setting(1,-1,"decryption_key",(const char *)local_decryption_key, sizeof(local_decryption_key));
		initial_keyed();
	}
	else
	{
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		lockout = 0;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		login_cb(-1);
	}
	sodium_memzero(local_decryption_key,sizeof(local_decryption_key));
	return 0;
}

void login_start(const char *arg)
{ // Immediately attempts to copy and destroy password from UI // XXX Does not need locks
	if(threadsafe_read_uint8(&mutex_global_variable,&lockout))
	{
		error_simple(0,"Login_start called during lockout. UI bug. Report this to UI dev.");
		return;
	}
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
	lockout = 1;
	pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	char *password = {0};
	if(arg)
	{
		const size_t len = strlen(arg);
		password = torx_secure_malloc(len+1);
		memcpy(password,arg,len+1);
	}
	if(pthread_create(&thrd_login,&ATTR_DETACHED,&login_threaded,(void*)password))
		error_simple(-1,"Failed to create thread");
}

void cleanup_lib(const int sig_num)
{ // Cleanup process: cleanup_cb() saves UI settings, calls cleanup_lib() to save library settings and close databases, then UI exits
	#ifdef WIN32
	WSACleanup(); // TODO this might need to be later

	#endif
	if(sig_num)
		breakpoint();
	error_printf(0,"Cleanup reached. Signal number: %d",sig_num);
	pthread_attr_destroy(&ATTR_DETACHED); // don't start any threads after this or there will be problems
	pthread_mutex_lock(&mutex_closing); // 🟥🟥 // Note: do not unlock, ever. Ensures that this doesn't get called multiple times.
	if(log_last_seen == 1)
	{
		for(int peer_index,n = 0 ; (peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index))) > -1 || getter_byte(n,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 ; n++)
		{ // storing last_seen time to .key file
			if(peer_index < 0)
				continue;
			const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
			const uint8_t sendfd_connected = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected));
			const uint8_t recvfd_connected = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected));
			if(sendfd_connected > 0 && recvfd_connected > 0 && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER))
			{
				char p1[21];
				snprintf(p1,sizeof(p1),"%lld",(long long)time(NULL));
				sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
			}
		}
	}
	pthread_rwlock_wrlock(&mutex_packet); // 🟥 // XXX NOTICE: if it locks up here, its because of mutex_packet wrapping evbuffer_add in send_prep
	pthread_rwlock_wrlock(&mutex_broadcast); // 🟥
	pthread_mutex_lock(&mutex_tor_pipe); // 🟥🟥
	kill_tor(0);
/*	if(tor_pid < 1)
		error_simple(0,"Exiting before Tor started. Goodbye.");
	else if(!pid_kill(tor_pid,SIGTERM))
	{ // we don't need to bother waiting for termination, just signal
		pid_write(0);
		error_simple(0,"Exiting normally after killing Tor. Goodbye.");
	}
	else
		error_simple(0,"Failed to kill Tor for some reason upon shutdown (perhaps it already died?)."); */
	torx_free((void*)&control_password_clear);
	sodium_memzero(control_password_hash,sizeof(control_password_hash));
	const int highest_ever_o_local = threadsafe_read_int(&mutex_global_variable,&highest_ever_o);
	if(highest_ever_o_local > 0) // this does not mean file transfers occured, i think
		error_printf(0,"Highest O level of packet struct reached: %d",highest_ever_o_local);
	// XXX Most activity should be brought to a halt by the above locks XXX
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	for(int g = 0 ; group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE) ;  g++)
	{
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		zero_g(g); // XXX INCLUDES LOCKS mutex_expand_group
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	}
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	pthread_rwlock_wrlock(&mutex_expand_group); // 🟥 // XXX DO NOT EVER UNLOCK XXX can lead to segfaults if unlocked
	torx_free((void*)&group);
	pthread_rwlock_wrlock(&mutex_expand); // 🟥 // XXX DO NOT EVER UNLOCK XXX can lead to segfaults if unlocked
	for(int n = 0 ; peer[n].onion[0] != 0 || peer[n].peer_index > -1 ;  n++)
	{ // DO NOT USE getter_ functions
		thread_kill(peer[n].thrd_send); // must go before zero_n
		thread_kill(peer[n].thrd_recv); // must go before zero_n
		zero_n(n); // XXX INCLUDES LOCKS in zero_i on protocol struct (mutex_protocols)
		const int pointer_location = find_message_struc_pointer(peer[n].min_i); // Note: returns negative
		torx_free((void*)(peer[n].message+pointer_location)); // moved this from zero_n because its issues when run at times other than shutdown. however this change could result in memory leaks?
		#ifndef NO_FILE_TRANSFER
		torx_free((void*)&peer[n].file);
		#endif // NO_FILE_TRANSFER
	}
	#ifndef NO_STICKERS
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥 // XXX DO NOT EVER UNLOCK XXX
	for(int s = 0; (uint32_t)s < torx_allocation_len(sticker)/sizeof(struct sticker_list); s++)
	{
		sodium_memzero(sticker[s].checksum,CHECKSUM_BIN_LEN);
		torx_free((void*)&sticker[s].peers);
		torx_free((void*)&sticker[s].data);
	}
	torx_free((void*)&sticker);
	#endif // NO_STICKERS
	pthread_rwlock_wrlock(&mutex_protocols); // 🟥
	pthread_rwlock_wrlock(&mutex_global_variable); // 🟥 // do not use for debug variable
	pthread_rwlock_wrlock(&mutex_debug_level); // 🟥 // XXX Cannot use error_ll after this
	torx_free((void*)&peer);
	// XXX NOTHING THAT UTILIZES LOCKS CAN COME AFTER THIS POINT (including error_ll) XXX
	thread_kill(thrd_start_tor); // TODO this is probably already dead but not NULL, we need to NULL it
	thread_kill(thrd_tor_log_reader);
	thread_kill(thrd_broadcast);
	thread_kill(thrd_change_password);
	thread_kill(thrd_login);
	sqlite3_close(db_plaintext); // Moved these to after zero_n which kills the threads
	sqlite3_close(db_encrypted);
	sqlite3_close(db_messages);
	sodium_memzero(saltbuffer,sizeof(saltbuffer)); // not important
//	exit(sig_num); // NO. Exit value will be handled afterwards in UI
}

void xstrupr(char *string)
{ // This function converts an array from lowercase to uppercase, which is required for base32 decoding ( decoding 56 character .onions )
	for(int i = 0 ; string[i] != '\0' ; i++)
		if((string[i] >= 'a') && (string[i] <= 'z'))
			string[i] -= 32;
}

void xstrlwr(char *string)
{ // This function converts an array from uppercase to lowercase
	for(int i = 0 ; string[i] != '\0' ; i++)
		if((string[i] >= 'A') && (string[i] <= 'Z'))
			string[i] += 32;
}

static inline char *tor_call_internal_recv(const evutil_socket_t socket)
{
	char *msg_recv = NULL;
	char rbuff[4096]; // zero'd
	ssize_t r;
	size_t current_allocation_size = 0;
	do
	{ // Receive response
		r = recv(SOCKET_CAST_OUT socket,rbuff,sizeof(rbuff),0);
		if(r > 0)
		{ // r is safe to cast to size_t after this check
			if(msg_recv)
			{ // Subsequent
				msg_recv = torx_realloc(msg_recv,current_allocation_size + (size_t)r);
				memcpy(&msg_recv[current_allocation_size-1],rbuff,(size_t)r); // overwrite existing null byte
				current_allocation_size += (size_t)r;
			}
			else
			{ // First
				msg_recv = torx_secure_malloc((size_t)r + 1); // include space for one null byte
				memcpy(&msg_recv[current_allocation_size],rbuff,(size_t)r);
				current_allocation_size += (size_t)r + 1; // include space for one null byte
			}
			msg_recv[current_allocation_size-1] = '\0';
		}
	} while(r == sizeof(rbuff));
	sodium_memzero(rbuff,sizeof(rbuff));
	return msg_recv;
}

static inline long int tor_call_authenticate(const uint16_t local_tor_ctrl_port)
{ // Connect and authenticate
	long int retries = 0;
	if(tor_ctrl_socket < 1)
	{
		struct sockaddr_in serv_addr = {0};
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htobe16(local_tor_ctrl_port);
		if(inet_pton(AF_INET,TOR_CTRL_IP,&serv_addr.sin_addr) <= 0) // Convert IPv4 and IPv6 addresses from text to binary form
		{
			error_simple(0,"Invalid address for Tor Control. Coding error. Report this.");
			return RETRIES_MAX;
		}
		if((tor_ctrl_socket = SOCKET_CAST_IN socket(AF_INET,SOCK_STREAM,0)) < 0)
		{
			error_simple(0,"Socket creation error. Report this.");
			return RETRIES_MAX;
		}
		struct timespec req;
		req.tv_sec = 0; // 0s
		req.tv_nsec = 50000000; // 50ms
		while(retries < RETRIES_MAX)
		{
			if(connect(SOCKET_CAST_OUT tor_ctrl_socket,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0)
			{
				if(nanosleep(&req, NULL) == -1)
				{
					if(!retries)
						error_simple(0,"nanosleep failed. Falling back to sleep(1). Platform may not support nanosleep."); // This is fine
					sleep(1);
					retries += 1000000000 / req.tv_nsec;
				}
				else
					retries++;
			}
			else
			{ // Must authenticate: "To prevent some cross-protocol attacks, the AUTHENTICATE command is still required even if all authentication methods in Tor are disabled."
				const size_t len = control_password_clear ? 17 + strlen(control_password_clear) : 14;
				char apibuffer[len+1]; // TODO arbitary maximum length, needs to be 17+strlen(control_password_clear)
				if(control_password_clear)
					snprintf(apibuffer,sizeof(apibuffer),"authenticate \"%s\"\n",control_password_clear);
				else
					snprintf(apibuffer,sizeof(apibuffer),"authenticate\n");
				const ssize_t s = send(SOCKET_CAST_OUT tor_ctrl_socket,apibuffer,SOCKET_WRITE_SIZE len ,0);
				sodium_memzero(apibuffer,sizeof(apibuffer));
				if(s < (ssize_t)len)
				{
					torx_close_socket(&mutex_global_variable,&tor_ctrl_socket);
					error_simple(0,"Tor call failed. Is Tor not running or is the control port incorrect?");
					return RETRIES_MAX;
				}
				char *ret = tor_call_internal_recv(tor_ctrl_socket);
				if(!ret || strncmp(ret,"250",3))
				{ // Check control port password
					torx_close_socket(&mutex_global_variable,&tor_ctrl_socket);
					error_simple(0,"Tor call authentication failed. Check control port password.");
					if(ret)
						error_printf(4,"Tor Control Response:\n%s",ret);
					torx_free((void*)&ret);
					return RETRIES_MAX;
				}
				torx_free((void*)&ret);
				error_printf(4,"Tor call SUCCESS after %ld retries",retries);
				tor_calls = 0; // must reset
				break;
			}
		}
	}
	return retries;
}

char *tor_call(const char *msg)
{ // Passes messages to Tor and returns the response. Note that messages and responses contain sensitive data. WARNING: Avoid running in main thread. Use tor_call_async() instead. (Warning may be depreciated now that we run in a single control connection?)
	size_t msg_len;
	if(msg == NULL || !(msg_len = strlen(msg)) || msg_len < 2 || msg[msg_len-1] != '\n')
	{
		error_simple(0,"Sanity check fail in tor_call. Calls must be non-null and end with a newline or recv will hang. Coding error. Report this.");
		breakpoint();
		return NULL;
	}
	char *msg_recv = NULL;
	const uint16_t local_tor_ctrl_port = threadsafe_read_uint16(&mutex_global_variable,&tor_ctrl_port);
	pthread_mutex_lock(&mutex_tor_ctrl); // 🟥🟥
	const long int retries = tor_call_authenticate(local_tor_ctrl_port);
	if(retries != RETRIES_MAX && !tor_calls++)
	{ // TODO Work-around for known bug: After authenticating, our first command to tor_call (both binary Tor and system Tor) fails with 510 Unrecognized command ""
		if(send(SOCKET_CAST_OUT tor_ctrl_socket,"This will fail\n",SOCKET_WRITE_SIZE 15,0) == 15)
		{ // We just need to send a newline, or any text terminated with a newline, then recv.
			msg_recv = tor_call_internal_recv(tor_ctrl_socket);
			torx_free((void*)&msg_recv);
		}
	}
	if(retries != RETRIES_MAX && send(SOCKET_CAST_OUT tor_ctrl_socket,msg,SOCKET_WRITE_SIZE msg_len,0) == (ssize_t)msg_len && (msg_recv = tor_call_internal_recv(tor_ctrl_socket)))
	{ // Attempt Send && Receive
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		tor_running = 1;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
	else
	{
		torx_close_socket(&mutex_global_variable,&tor_ctrl_socket);
		if(retries == RETRIES_MAX) // Failed to connect to port
			error_printf(0,"Tor Control Port not running on %s:%u after %ld tries.",TOR_CTRL_IP,local_tor_ctrl_port,retries);
		else
			error_simple(0,"There is likely an orphan Tor process running from a crashed TorX. If so, any Tor proccess run by this user and restart. Alternatively, you are restarting Tor, causing a call to fail. If so, carry on.");
	}
	pthread_mutex_unlock(&mutex_tor_ctrl); // 🟩🟩
	if(torx_debug_level(-1) > 4 || (msg_recv && strncmp(msg_recv,"25",2)))
	{ // Print unsuccessful. Note: We are ignoring both 250 and 251 because 251 commonly occurs on system Tor when using ONION_CLIENT_AUTH_ADD
		error_printf(4,"Tor Control Call:\n%s",msg);
		error_printf(3,"Tor Control Response:\n%s",msg_recv);
	}
	return msg_recv;
}

static inline void *tor_call_async_threaded(void *arg)
{ // Confirmed working, but may no longer be necessary because we are now running in a single control connection.
	if(!arg)
	{
		error_simple(0,"tor_call_async_threaded has null arg. Coding error. Report this.");
		return 0;
	}
	struct tor_call_strc *tor_call_strc = (struct tor_call_strc *)arg;
	pusher(zero_pthread,(void*)&tor_call_strc->thrd) // Note: unnecessary because this thread will not be killed.
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL);
	char *rbuff = tor_call(tor_call_strc->msg);
	if(tor_call_strc->callback)
		(*tor_call_strc->callback)(rbuff);
	else
		torx_free((void*)&rbuff);
	return 0;
}

void tor_call_async(void (*callback)(char*),const char *msg)
{ // This is a UI helper function, especially for making GETINFO calls to determine connectivity status. Ex: "GETINFO network-liveness\r\n" / "GETINFO dormant\r\n" / "GETINFO status/bootstrap-phase\r\n", but may no longer be necessary because we are now running in a single control connection.
	if(!msg)
	{
		error_simple(0,"No message passed to tor_call_async. Coding error. Report this.");
		return;
	}
	const size_t msg_len = strlen(msg);
	struct tor_call_strc *tor_call_strc = torx_insecure_malloc(sizeof(struct tor_call_strc));
	if(!tor_call_strc)
		return;
	tor_call_strc->thrd = 0; // initializing
	tor_call_strc->callback = callback; // Note: may be null
	tor_call_strc->msg = torx_secure_malloc(msg_len + 1);
	memcpy(tor_call_strc->msg,msg,msg_len + 1);
	pthread_create(&tor_call_strc->thrd,&ATTR_DETACHED,&tor_call_async_threaded,tor_call_strc);
}

char *onion_from_privkey(const char *privkey)
{ // Remember to torx_free.
	unsigned char expanded_sk[crypto_hash_sha512_BYTES]; // zero'd
	if(b64_decode(expanded_sk,sizeof(expanded_sk),privkey) != 64)
	{ // NOTE: B64_decode is null safe, so no need for a check
		error_simple(0,"Invalid base64 privkey passed to onion_from_privkey. Bailing out.");
		sodium_memzero(expanded_sk,sizeof(expanded_sk));
		return NULL;
	}
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES] = {0};
	crypto_scalarmult_ed25519_base(ed25519_pk,expanded_sk);
	sodium_memzero(expanded_sk,sizeof(expanded_sk));
	char *onion = onion_from_ed25519_pk(ed25519_pk);
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	return onion;
}

char *torxid_from_onion(const char *onion)
{ // Remember to torx_free
	if(onion == NULL || !utf8_valid(onion,56))
	{
		error_printf(0,"Null or improper onion passed to torxid_from_onion: %s",onion);
		return NULL;
	}
	baseencode_error_t err = {0}; // for base32
	char onion_uppercase[56+1]; // zero'd
	snprintf(onion_uppercase,sizeof(onion_uppercase),"%s",onion);
	xstrupr(onion_uppercase);
	unsigned char *onion_decoded = base32_decode(onion_uppercase,56,&err); // 35/35+1 torx_free((void*)&)'d
	sodium_memzero(onion_uppercase,sizeof(onion_uppercase));
	if(err)
	{
		error_printf(0,"Invalid onion detected: %s",onion); // Not abnormal on startup due to reasons explained elsewhere (peer[-1] / n==-1 is uninitialized)
		return NULL;
	}
	char ed25519_pk_b32[56+1];
	size_t len = base32_encode((unsigned char*)ed25519_pk_b32,onion_decoded,32);
	torx_free((void*)&onion_decoded);
	if(len != 56)
	{ // check has no unnecessary overhead due to re-use of len
		error_printf(0,"Invalid torxid generated: %s",ed25519_pk_b32);
		return NULL;
	}
	size_t d = 0;
	while(ed25519_pk_b32[51-d] == 'Q' || ed25519_pk_b32[51-d] == 'q')
		d++;
	char *torxid = torx_secure_malloc(52+1);
	memcpy(torxid,ed25519_pk_b32,52+1-d); // snprintf is throwing compiling errors	snprintf(torxid,52+1-d,"%52s",ed25519_pk_b32);
	torxid[52-d] = '\0';
	sodium_memzero(ed25519_pk_b32,sizeof(ed25519_pk_b32));
	xstrlwr(torxid);
	return torxid;
}

char *onion_from_torxid(const char *torxid)
{ // Remember to torx_free
	if(torxid == NULL || strlen(torxid) > 52)
	{
		error_printf(0,"Null or improper length onion passed to onion_from_torxid: %s",torxid);
		return NULL;
	}
	baseencode_error_t err = {0}; // for base32
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES] = {0}; // zero'd
	size_t d = 52-strlen(torxid);
	char ed25519_pk_b32[52+1]; // zero'd
	snprintf(ed25519_pk_b32,sizeof(ed25519_pk_b32),"%s",torxid);
	xstrupr(ed25519_pk_b32);
	while(d > 0)
	{
		ed25519_pk_b32[52-d] = 'Q';
		d--;
	}
	unsigned char *p;
	memcpy(ed25519_pk,p=base32_decode(ed25519_pk_b32,52,&err),32); // torx_free((void*)&)'d
	torx_free((void*)&p);
	sodium_memzero(ed25519_pk_b32,sizeof(ed25519_pk_b32));
	if(err)
		return NULL; // some stuff not being zero'd here, but this shouldn't occur
	char *onion = onion_from_ed25519_pk(ed25519_pk);
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	return onion;
}

int custom_input(const uint8_t owner,const char *identifier,const char *privkey)
{ /* Saves and loads and externally generated onion as SING/MULT. Returns N if valid privkey or negative if rejected */ // cat hs_ed25519_secret_key | tail --bytes=64 | base64 -w0 <--- "privkey"
	size_t privkey_len = 0;
	if(owner != ENUM_OWNER_MULT && owner != ENUM_OWNER_SING)
	{
		error_simple(0,"Custom input requires specification of sing or mult type. Coding error. Report this.");
		return -3;
	}
	else if(privkey == NULL || (privkey_len = strlen(privkey)) != 88)
	{
		error_simple(0,"Private Key Length is Wrong.");
		return -2;
	}
	for(int n = 0 ; getter_byte(n,INT_MIN,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index)) > -1 ; n++)
	{
		char privkey_n[88+1];
		getter_array(&privkey_n,sizeof(privkey_n),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
		if(!strncmp(privkey,privkey_n,88))
		{
			sodium_memzero(privkey_n,sizeof(privkey_n));
			error_simple(0,"Externally generated onion already exists. Rejecting.");
			return -4;
		}
		sodium_memzero(privkey_n,sizeof(privkey_n));
	}
	char privkey_local[88+1]; // temporary work-around for generate_onion having non-const privkey arg
	snprintf(privkey_local,sizeof(privkey_local),"%s",privkey);
	const int n = generate_onion(owner,privkey_local,identifier); // Get onion from privkey, save, load. -1 if invalid.
	sodium_memzero(privkey_local,sizeof(privkey_local));
	return n;
}

static inline size_t stripbuffer_b32_len51(char *buffer)
{ // For stealth addresses. This function strips anything other than 2-7 and A-Z, and strips away anything longer than 51 characters. The result should be a TorX-ID that was previously obscured with invalid and/or extraneous characters. DO NOT use this for handshakes, which contain non-base32 characters.
	size_t j = 1; // necessary to initialize as 1 in case of 0 length
	for(size_t i = 0; buffer[i] != '\0'; ++i)
	{
		while(!(buffer[i] >= 'a' && buffer[i] <= 'z') && !(buffer[i] >= 'A' && buffer[i] <= 'Z') && !(buffer[i] >= '2' && buffer[i] <= '7') && !(buffer[i] == '\0')) 
		{
			for(j = i; buffer[j] != '\0'; ++j)
				buffer[j] = buffer[j + 1];
			buffer[j] = '\0';
		}
		if(i == 51)
		{
			buffer[i] = '\0';
			return i;
		}
	}
	if(j-1 == 0 && buffer != NULL) // workaround for case where no modifications need to be done to string
		j = j + strlen(buffer);
	return j-1;
}

int peer_save(const char *unstripped_peerid,const char *peernick) // peeronion, peernick.
{ // Initiate a friend request.
	if(unstripped_peerid == NULL || peernick == NULL || strlen(unstripped_peerid) == 0 || strlen(peernick) == 0)
	{
		error_simple(0,"Passed null or 0 length peeronion or peernick to peer_save. Not allowed.");
		return -1;
	}
	size_t id_len = strlen(unstripped_peerid);
	if(id_len == 44 && unstripped_peerid[43] == '=')
	{ // could like... use a return value other than -1, and do something productive with this.
		error_simple(0,"Highly likely that user attempted to save a public group ID as a peer.");
		return -1;
	}
	char unstripped_peerid_local[id_len+1];
	snprintf(unstripped_peerid_local,sizeof(unstripped_peerid_local),"%s",unstripped_peerid);
	if(id_len == 56) // OnionID
		id_len = stripbuffer(unstripped_peerid_local);
	else // TorX-ID
		id_len = stripbuffer_b32_len51(unstripped_peerid_local);
	char peeronion_or_torxid[56+1];
	snprintf(peeronion_or_torxid,sizeof(peeronion_or_torxid),"%s",unstripped_peerid_local);
	sodium_memzero(unstripped_peerid_local,sizeof(unstripped_peerid_local));
	char *peeronion = {0}; // must set null in case of error
	while(1)
	{ // not a real while loop, just don't want to use goto
		if(id_len == 56)
		{ // onion, check the checksum
			char *torxid = torxid_from_onion(peeronion_or_torxid);
			peeronion = onion_from_torxid(torxid);
			if(peeronion == NULL)
			{ // Invalid input, maybe contained junk.
				error_simple(0,"Save_peer Invalid input, maybe contained junk.");
				torx_free((void*)&torxid);
				break;
			}
			torx_free((void*)&torxid);
			if(strncmp(peeronion,peeronion_or_torxid,56)) // this could be 55 if we wanted to preserve potential forward compatibility (dont do this or people will mess up the d/version byte)
			{
				error_simple(0,"Onion checksum does not match, or unrecognized version. Please verify that it is typed correctly.");
				break;
			}
		}
		else if(id_len > 0 && id_len < 56)
		{
			peeronion = onion_from_torxid(peeronion_or_torxid);
			if(peeronion == NULL)
			{
				error_simple(0,"Save_peer Invalid TorX-ID. Report this.");
				break; // Invalid TorX-ID. This should be rare.
			}
		}
		else // peeronion_or_torxid == NULL, coding error?
			break;
	//	torx_free((void*)&peeronion_or_torxid);
		sodium_memzero(peeronion_or_torxid,sizeof(peeronion_or_torxid));
		int n = set_n(-1,peeronion);
		uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
		if(owner != 0)
		{
			error_simple(0,"Peer already exists.");
			break;
		}
		error_simple(1,"Peer did not exist.");
		if((n = load_peer_struc(-1,ENUM_OWNER_PEER,0,NULL,0,peeronion,peernick,NULL,NULL,NULL)) == -1)
			break;
		owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner)); // probably unnecessary, n should be the same as before?
		const uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
		const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
		char privkey[88+1];
		getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
		char peeronion_local[56+1];
		getter_array(&peeronion_local,sizeof(peeronion_local),n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
		const int peer_index = sql_insert_peer(owner,status,peerversion,privkey,peeronion_local,peernick,0);
		sodium_memzero(privkey,sizeof(privkey));
		sodium_memzero(peeronion_local,sizeof(peeronion_local));
		setter(n,INT_MIN,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
		torx_free((void*)&peeronion);
		const uint16_t vport = INIT_VPORT;
		setter(n,INT_MIN,-1,offsetof(struct peer_list,vport),&vport,sizeof(vport));
		torx_read(n) // 🟧🟧🟧
		pthread_t *thrd_send = &peer[n].thrd_send;
		torx_unlock(n) // 🟩🟩🟩
		if(pthread_create(thrd_send,&ATTR_DETACHED,&peer_init,itovp(n)))
			error_simple(-1,"Failed to create thread1");
		return 0;
	}
	sodium_memzero(peeronion_or_torxid,sizeof(peeronion_or_torxid));
	torx_free((void*)&peeronion);
	return -1;
}

void peer_accept(const int n)
{
	uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
	if(status != ENUM_STATUS_FRIEND)
	{ // sanity check
		error_simple(1,"Accepting a peer.");
		status = ENUM_STATUS_FRIEND;
		setter(n,INT_MIN,-1,offsetof(struct peer_list,status),&status,sizeof(status));
		sql_update_peer(n);
		load_onion(n);
	}
}

void change_nick(const int n,const char *freshpeernick)
{
	size_t len;
	if(freshpeernick == NULL || (len = strlen(freshpeernick)) < 1)
		return;
	char *tmp = torx_secure_malloc(len+1);
	snprintf(tmp,len+1,"%s",freshpeernick);
	torx_write(n) // 🟥🟥🟥
	torx_free((void*)&peer[n].peernick);
	peer[n].peernick = tmp;
	torx_unlock(n) // 🟩🟩🟩
	sql_update_peer(n);
}

void block_peer(const int n)
{
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_GROUP_PEER)
	{
		uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
		char *peernick = getter_string(NULL,n,INT_MIN,-1,offsetof(struct peer_list,peernick));
		if(status == ENUM_STATUS_FRIEND)
		{
			if(owner == ENUM_OWNER_CTRL)
				error_printf(3,"Blocking %s",peernick);
			else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
				error_printf(3,"Disabling %s",peernick);
			status = ENUM_STATUS_BLOCKED;
			setter(n,INT_MIN,-1,offsetof(struct peer_list,status),&status,sizeof(status));
			sql_update_peer(n);
			const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			takedown_onion(peer_index,0);
		}
		else if(status == ENUM_STATUS_BLOCKED)
		{
			if(owner == ENUM_OWNER_CTRL)
				error_printf(3,"Unblocking %s",peernick);
			else if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
				error_printf(3,"Enabling %s",peernick);
			status = ENUM_STATUS_FRIEND;
			setter(n,INT_MIN,-1,offsetof(struct peer_list,status),&status,sizeof(status));
			sql_update_peer(n);
			load_onion(n);
		}
		else
		{
			error_printf(0,"Tried to toggle block status of status=%u. Coding error. Report this.",status);
			breakpoint();
		}
		torx_free((void*)&peernick);
	}
	else
	{
		error_printf(0,"Tried to toggle block status of owner=%u. Coding error. Report this.",owner);
		breakpoint();
	}
}

uint64_t get_file_size(const char *file_path)
{ // rarely used, usually we get it from other functions. We use stat instead of opening the file and fseeking the end because we tested it to be 5 times faster.
	struct stat file_stat;
	if (!file_path || stat(file_path, &file_stat) != 0)
		return 0;
	return (uint64_t)file_stat.st_size;
}

void destroy_file(const char *file_path)
{ /* XXX This function works well. Do not mess with it without extensive testing. XXX */ // 2024/03/17 Consider deleting any .split file in this function, if discovered. Low priority. Couldn't hurt.
	if(file_path == NULL)
		return;
	char new_file_name[20+1];
	random_string(new_file_name,sizeof(new_file_name));
	const size_t file_path_len = strlen(file_path);
	char path_copy[file_path_len+1];
	snprintf(path_copy,sizeof(path_copy),"%s",file_path); // Both dirname() and basename() may modify the contents of path, so it may be desirable to pass a copy when calling one of these functions.
	char *directory = dirname(path_copy);
	char new_file_path[file_path_len+20+4+1];
	snprintf(new_file_path,sizeof(new_file_path), "%s%c%s.tmp",directory,platform_slash,new_file_name);
	sodium_memzero(path_copy,sizeof(path_copy)); // DO NOT do this before using directory. Basename and dirname are peculiar
	if(rename(file_path, new_file_path) != 0)
	{
		error_simple(0,"Error renaming file destroy_file. File may not exist.");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	FILE *fp;
	if((fp = fopen(new_file_path, "a")) == NULL)
	{
		error_simple(0,"Error opening file for appending in destroy_file");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	const long int size = ftell(fp);
	close_sockets_nolock(fp)
	if((fp = fopen(new_file_path, "r+")) == NULL || size == -1)
	{
		error_simple(0,"Error opening file for write in destroy_file");
		sodium_memzero(new_file_path,sizeof(new_file_path));
		return;
	}
	size_t left = (size_t)size;
	size_t written_current = 0;
	unsigned char buf[4096];
	do
	{
		size_t amount;
		if(left < sizeof(buf))
			amount = left;
		else
			amount = sizeof(buf);
		randombytes(buf, (long long unsigned int)amount);
		written_current = fwrite(buf, 1, amount, fp); // this is CORRECT use of fwrite() DO NOT CHANGE IT.
		left -= written_current;
	}
	while (left > 0 && written_current > 0);
	close_sockets_nolock(fp)
	if(remove(new_file_path) != 0)
		error_simple(0,"Error deleting file in destroy_file");
	sodium_memzero(new_file_path,sizeof(new_file_path));
}

char *custom_input_file(const char *hs_ed25519_secret_key_file) // hs_ files have already had crypto_hash_sha512() applied to them, meaning the ed25519 SK is FOREVER LOST
{ // This must be used in conjunction with custom_input() // cat hs_ed25519_secret_key | tail --bytes=64 | base64 <--- "privkey"
	if(hs_ed25519_secret_key_file == NULL)
		return NULL;
	char privkey_decoded[64] = {0};
	FILE *hs_ed25519_secret_key_file_pointer = fopen(hs_ed25519_secret_key_file,"r");
	if(hs_ed25519_secret_key_file_pointer == NULL)
	{
		error_simple(0,"Failed to open custom input file.");
		return NULL;
	}
	const char correct_header[29+1] = "== ed25519v1-secret: type0 ==";
	char header[29]; // no null termination, do not assume string
	const size_t read = fread(header,1,sizeof(header),hs_ed25519_secret_key_file_pointer);
	fseek(hs_ed25519_secret_key_file_pointer,(long int)-sizeof(privkey_decoded),SEEK_END);
	if(read != sizeof(header) || memcmp(header,correct_header,sizeof(header)) || fread(privkey_decoded,1,sizeof(privkey_decoded),hs_ed25519_secret_key_file_pointer) < 64)
	{
		close_sockets_nolock(hs_ed25519_secret_key_file_pointer)
		error_simple(0,"Custom input file was less than 64 bytes or lacked expected header. Bailing.");
		return NULL;
	}
	char *privkey = b64_encode(privkey_decoded,sizeof(privkey_decoded));
	sodium_memzero(privkey_decoded,sizeof(privkey_decoded));
	close_sockets_nolock(hs_ed25519_secret_key_file_pointer)
	return privkey;
}

void takedown_onion(const int peer_index,const int delete) // 0 no, 1 yes, 2 delete without taking down, 3 spoil SING onion (delete, take down).
{ // Takedown PEER/SING/MULT/CTRL TODO delete values and actions are confusing. 0 is possibly redundant with block_peer()
  // TODO deleting individual GROUP_PEER without deleting the GROUP_CTRL is not yet supported... its complex because they would need to be removed from the peerlist/peercount... and it would be added back the next time a peerlist is received. Just block/ignore instead.
	if(peer_index < 0)
	{
		error_printf(0,"Invalid peer_index in takedown_onion: %d. Bailing. Report this.",peer_index);
		breakpoint();
		return;
	}
	const int n = set_n(peer_index,NULL);
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner)); // DO NOT ELIMINATE THIS VARIABLE because .owner will get zero'd
	int g = -1;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Recursively takedown all GROUP_PEER in peerlist // TODO consider sending a kill code to online peers first ( pro: wastes less peer resources. Con: takes more time to shutdown, peers will be added again when someone who didn't get the kill code shares the peerlist . Conclusion: don't bother.)
		uint32_t count = 0;
		g = set_g(n,NULL);
		uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		while(count < g_peercount)
		{
			pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
			const int specific_peer = group[g].peerlist[count++];
			pthread_rwlock_unlock(&mutex_expand_group); // 🟩
			takedown_onion(getter_int(specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_index)),delete);
		}
		error_printf(0,"Took down %u GROUP_PEER associated with group.",count); // TODO increase debug level after confirming this works
	}
	if(delete > 0)
	{
		if(owner == ENUM_OWNER_GROUP_PEER) // This if statement saves a bit of IO/processing but only makes sense if we never delete GROUP_PEER without deleting GROUP_CTRL at he same time
			delete_log(n); // when called with GROUP_CTRL, it should delete GROUP_PEER, so no need to call it twice.
		sql_delete_peer(peer_index); // This should cascading delete anything delete_log missed, or in case we were wrong above
	}
	if(delete != 2 && owner != ENUM_OWNER_PEER)
	{ // 2==delete from file but don't take down // != ENUM_OWNER_PEER because OWNER_PEER doesn't use peer [n]. sendfd
	// TODO find a way to call disconnect_forever() here in a threadsafe manner
	//	torx_read(n) // 🟧🟧🟧
	//	struct bufferevent *bev_recv = peer[n].bev_recv;
	//	torx_unlock(n) // 🟩🟩🟩
	//	bufferevent_free(peer[n].bev); // not threadsafe // TODO segfaults, even with event_base_once or evbuffer_lock. Do not attempt, give up.
	//	event_base_loopexit(bufferevent_get_base(bev_recv), NULL); // not threadsafe
	/*	evbuffer_lock(bev_recv); // XXX
		struct event_base *base = bufferevent_get_base(bev_recv);
		evbuffer_unlock(bev_recv); // XXX
		event_base_once(base, -1, EV_TIMEOUT, enter_thread_to_disconnect_forever, bev_recv, NULL);*/
		char onion[56+1];
		getter_array(&onion,sizeof(onion),n,INT_MIN,-1,offsetof(struct peer_list,onion));
		char apibuffer[512];
		snprintf(apibuffer,sizeof(apibuffer),"del_onion %s\n",onion); // NOTE: This will NOT close existing connections.
		sodium_memzero(onion,sizeof(onion));
		char *rbuff = tor_call(apibuffer);
		torx_free((void*)&rbuff);
		sodium_memzero(apibuffer,sizeof(apibuffer));
		int ret_send = 0;
		int ret_recv = 0;
		torx_write(n) // 🟥🟥🟥
		if(peer[n].sendfd > 0)
		{
			ret_send = evutil_closesocket(peer[n].sendfd);
			peer[n].sendfd = 0;
		}
		if(peer[n].recvfd > 0)
		{
			ret_recv = evutil_closesocket(peer[n].recvfd);
			peer[n].recvfd = 0;
		}
		torx_unlock(n) // 🟩🟩🟩
		if(ret_send == -1 || ret_recv == -1)
			error_printf(0,"Failed to close a socket in takedown_onion. Owner=%u send=%d recv=%d",owner,ret_send,ret_recv);
	} // From control-spec:   It is the Onion Service server application's responsibility to close existing client connections if desired after the Onion Service has been removed via "DEL_ONION".
	if(delete == 1 || delete == 3)
	{
		error_simple(1,"Found matching entry in memory. Zeroing.");
		torx_write(n) // 🟥🟥🟥
		zero_n(n);
		torx_unlock(n) // 🟩🟩🟩
		if(delete == 3)
			onion_deleted_cb(20,n);
		else
			onion_deleted_cb(owner,n);
	}
	else if(delete == 0) // Block only
	{ // TODO WE SHOULD NOT SET MEMORY STATUS TO 0 HERE ??? because we might be taking it down for other reaons, like in write_finished()
		error_simple(1,"Notice: Found matching entry in memory. Changing to status 1 (block) in memory.");
		const uint8_t status = ENUM_STATUS_BLOCKED;
		setter(n,INT_MIN,-1,offsetof(struct peer_list,status),&status,sizeof(status));
	}
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		broadcast_remove(g);
		zero_g(g);
	}
}
