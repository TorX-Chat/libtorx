/*	This file will contain most core functions. There will be no "main" because core is a library.	*/

/*
TODO FIXME XXX

TODO setup e-begging , example : https://github.com/tonyp7/esp32-wifi-manager/commit/5bddfbaf55a83a0411a17ea8654efc776dbb2529

TODO Windows TODO
	* some places use exec without having a system() alternative for windows
	* if pipe() cannot be used on windows, we have problems.
	* our send() might be a problem

TODO Android TODO
	* sleep() should be used carefully because sleep() on android is not accurately one second. Commonly speed up by several times for unknown reasons.

TODO Before Release TODO
	* make a list of functions running in UI thread and anything they call, to make sure there is no sleep(). Currently we have some... tor_call() has a sleep, which is an issue when called by start_tor() in UI thread.
	* rip out libsodium, replace with openssl or libressl XXX be sure that we can do everything in onion_gen.c (ex: crypto_sign_ed25519_pk_to_curve25519)
	* implement sqlcipher to eliminate log correlation potential and space wasted by random_string_max_len
	* wrap all references to log pointers in mutex because we rather commonly overwrite our salt
	* multiple offers of same file to different peers (or same?) is undefined behavior
	* delete relevant .key file setting entries when deleting via takedown_onion() or killing
	* XXX putting no incoming auth doesn't prevent connections. Test this, but based on logs from invalid auth, it seems auth is optional. XXX
	* put a mutex around all reads and writes to keypointer and configpointer
		better than passing around copies because there could be a race on newlines
	* variable length struct + initializer
		stuck, see scratchpad
	* if(value != 0) ---> if(value), otherwise we look amateur. if() only skips if if FALSE or 0
		if(buf == NULL) ---> if(!buf)
	* update .config to reflect
	* implement torx_secure_malloc() and torx_free((void*)&) where suitable, and sodium_memzero() or randombytes_buf() for arrays
	* Consider putting a mutex around any global file pointer
	* eliminate all or most use of strcmp in favor of strncmp

TODO Yellow Orange TODO
	* When orange, messages can be sent.
	* When yellow, any messages should request a ACK (file offer, accept(?), utf-8, etc. Not file parts.)

TODO Full Duplex TODO 
	* have a single pipe offer (existing)
	* have a single pipe accept (existing)
	* if either peer says single pipe, single pipe. (such as if they have PRIORITIZE_MESSAGES == 1)
	* otherwise, double pipe. As of current, FULL DUPLEX transfers will CORRUPT ON RESUME.
		option 1: .aria2 style file (bad)
		option 2: fallocate(linux)/lseek(linux) or pre-allocate files in some sort of null state (so we can see what parts we need/are unwritten
			would have to do this in OS specific manners https://devblogs.microsoft.com/oldnewthing/20160714-00/?p=93875
			TODO i think aria2 has a --file-allocation=falloc, should see what the other options are (maybe lseek)
		option 3: prevent resume on full duplex files by hard coding certain file sizes as full-duplex (say, <10mb)
		option 4: create two seperate files, treat them as two seperate files, and merge/concat them after completion (viable 2nd option after falloc)

TODO BUGS TODO
	* 2022/07/27 occassional double send (different timestamps) occurs in GTK3+4. low priority, will catch in audit.
	* accessing .key .config need mutex because we might be able to crash/corrupt if we click settings too fast
	* restarting tor via start_tor() causes segfault due to lack of testing. Exact location identified via backtrace to socks.c 
	* file transfers probably won't get resumed if the SENDER goes offline and comes online again without the receiver going offline.
		receiver should re-send any /accept messages (as we do on startup) when a peer comes online
	* careful with pointer = pointer, especially regarding our structs; freeing any will destroy the other.
	* MUST delete chat history if deleting a peer (because password might be shit and will not be un-shit when change_password()'d
		- after that is implemented, can permit null passwords (just set "0" or salt as password, anything) for people who want auto-start
		- should change salt when changing password ( then if chat history is not securely deleted or fails to delete when deleting peer, it is ok)
	* getline_c89() has line limits (unsigned int instead of ssize_t)
	* -Wall says we need to convert all strings to unsigned char and cast what cannot be converted via (unsigned char *)
	* Custom fputs() function that will zero the existing line and write to a fresh line if there is a newline in the planned write() space.
		- will make forward compatibility easier and prevent damage if a user makes manual edits and removes spaces in the process
			this could occur as easily as hand-modifying the saved screen resolution
		- shouldn't be too much performance hit if we read the whole line, check in memory, then decide whether to write or move to end first

XXX Theory XXX
	* could require a message confirmation from peer, but this would make traffic analysis easier, so no.
	* SECURITY: Spoofing peers possible on non-v3auth peers if we send messages on .recvfd instead of .sendfd. Sending on Sendfd is FAR SAFER for non-v3auth peers.
	* Tor binary location: Custom setting > Path > Current Dir (tor or tor.exe)
	* 56 character name length is a problem because not all characters are 1 byte. Example: emojis, chinese characters, etc
	* there is lots of opportunity to audit the code and \0 private keys from memory when not absolutely necessary to hold. the 88 char base64 would be really identifiable in a memory dump or core dump.
		might actually be safer to pass around pointers more than we already do? ask #security or #cryptography
	* MUST make a random length string at the end of each logged message. This will be VERY critical for security. Do not ignore this. 2022/06/27.
	* Library lib*.so https://www.youtube.com/watch?app=desktop&v=Slfwk28vhws
	* For KILL CODE, have an "Advanced setting" on whether it should result in BLOCK or DELETE (default: ???)
		killed peers should take down their onions. should be outbound ONLY and require acknowledgment.
	* we probably need to have peer acknowledge receipt of messages by sending a checksum back. At the same time, we *do* need to prevent out-of-order messages.
		using a checksum is more CPU intensive than ideal but ensures the completeness of the message *and* does not require both sides to keep a shared index number of any type.
	Regarding the MitM potential:
	* we could concat the onion & peeronion, make a hash, and then people should compare the hash outside? The value of this is low however and it is stupidly complex for normies to understand.
		- (strings would have to be a particular order(abc..129?).... otherwise the hash would be different)
	*  AUTOMATICALLY_LOAD_CTRL = 0 is not viable because adversaries can monitor disconnection times
	* having connections break after every message (preventing online status checks) is not really viable because an adversary can still do a HSDir lookup to find you status, without ever making a TCP connection to you
	* https://doc.libsodium.org/memory_management should implement this,
		also avoid having the keys and privkeys passed between functions. better to pass N. Would make it easier to wipe stuff on shutdown.
	* It is possible to send an accept_ on a file from long ago that the sender still has in their log history, which may have since changed. Could present security issue.
	* could have a toggleable option about whether to run as a tor binary as a middle node (this would hella support the network, but be bandwidth eating)
	* pluggable contracts https://gitweb.torproject.org/tor-browser.git/tree/tor-config/
	* after p = torx_secure_malloc(), could we just p[0]= '\0'?

XXX Notes XXX
	* Do not use: strcpy,strncpy, strcat,strncat, strcmp, scanf, itoa (strncmp is ok)
	* Our base32 function doesn't use sodium malloc, since it presumably would reduce speed. Ensure to clear its output.
	* %m (allocation related) must be avoided because it is normal malloc and therefore incompatible with torx_free((void*)&)
*/

/* Globally defined variables follow */
const uint16_t protocol_version = 2; // 0-99 max. 00 is no auth, 01 is auth by default. If the handshake, PACKET_SIZE_MAX, and chat protocols don't become incompatible, this doesn't change.
const unsigned int torx_library_version[4] = { protocol_version , 0 , 3 , 1 }; // https://semver.org [0]++ breaks protocol, [1]++ breaks .config/.key, [2]++ breaks api, [3]++ breaks nothing. SEMANTIC VERSIONING.

/* Configurable Options */ // Note: Some don't need rwlock because they are modified only once at startup
uint8_t write_debug_to_file = 1;
const char *debug_file = "debug.log"; // see write_debug_to_file. This is ONLY FOR DEVELOPMENT USE.
uint8_t v3auth_enabled = 1; // global default // 0 (off), 1 (BEST: derived from onion). Should NOT make this user toggleable. For discussion on the safety of using onion derived ed25519 keys and converting to x25519: https://crypto.stackexchange.com/questions/3260/using-same-keypair-for-diffie-hellman-and-signing/3311#3311 
uint8_t reduced_memory = 0; // NOTE: increasing decreases RAM requirements *and* CPU cycles. 0 = 1024mb, 1 = 256mb, 2 = 64mb. More ram allocated will make startup ever-so-slightly slower, but significantly increase security against bruteforcing. Recommended to leave as default (0, 1024mb), but could crash some devices.
int8_t debug = 0; //"0-5" default verbosity. Ensure that privacy related info is not printed before level 3.
long long unsigned int crypto_pwhash_OPSLIMIT = 0;
size_t crypto_pwhash_MEMLIMIT = 0;
int crypto_pwhash_ALG = 0;
char saltbuffer[crypto_pwhash_SALTBYTES]; // 16
char *working_dir = {0}; // directory for containing .db and .pid files
char *file_db_plaintext = {0}; // "plaintext.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_db_encrypted = {0}; // "encrypted.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_db_messages = {0}; // "messages.db"; // Do not set as const since particular UIs may want to define this themselves.
char *file_tor_pid = {0}; // "tor.pid";
char control_password_clear[32+1];
char control_password_hash[61+1] = {0}; // does not need rwlock because only modified once // correct length
char *torrc_content = {0}; // default is set in initial() or after initial() by UI
uint16_t tor_ctrl_port = 0;
uint16_t tor_socks_port = 0;
int tor_version[4] = {0}; // does not need rwlock because only modified once
uint8_t currently_changing_pass = 0; // TODO consider using mutex_sql_encrypted instead
uint8_t first_run = 0; // TODO use for setting default torrc (ie, ask user). do not manually change this. This works and can be used as the basis for stuff (ex: an introduction or opening help in a GUI client)
uint8_t destroy_input = 0; // 0 no, 1 yes. Destroy custom input file.
uint8_t tor_running = 0; // TODO utilize this in UI somehow (but doing so requires wrapping access with rwlock)
uint8_t lockout = 0;
uint8_t keyed = 0; // whether initial_keyed has run. better than checking !torrc_content or !tor_ctrl_port
pid_t tor_pid = -1;
int highest_ever_o = 0; // TODO delete, only for learning purposes. Do not need. On 2023/11/17, we hit 3
uint8_t messages_loaded = 0; // easy way to check whether messages are already loaded, to prevent re-loading when re-running "load_onions" on restarting tor
unsigned char decryption_key[crypto_box_SEEDBYTES] = {0}; // 32 *must* be intialized as zero to permit passwordless login
int max_group = 0; // Should not be used except to constrain expand_messages_struc
int max_peer = 0; // Should not be used except to constrain expand_peer_struc
#ifdef WIN32
HANDLE tor_fd_stdout = {0};
#else
int tor_fd_stdout = -1;
#endif

/* User configurable options that will automatically be checked by initial() */
char *snowflake_location = {0}; // UI should set this
char *obfs4proxy_location = {0}; // UI should set this
char *native_library_directory = {0}; // UI should set this (Android-only)
char *tor_data_directory = {0}; // (currently unnused) TODO can set this as a fixed path (relative paths produce warnings) within working_dir. This will override any path set in torrc.
char *tor_location = {0}; // $PATH will be used if this is not set. Must be set on android/windows.
char *download_dir = {0}; // MUST end in forward or backslash (whichever, depending on OS). XXX Should be set otherwise will save in config directory set in initial().
char *split_folder = {0}; // MUST end in forward or backslash (whichever, depending on OS). For .split files. If NULL, it .split file will go beside the downloading file.
uint32_t sing_expiration_days = 30; // default 30 days, is deleted after. 0 should be no expiration.
uint32_t mult_expiration_days = 365; // default 1 year, is deleted after. 0 should be no expiration.
int show_log_days = 365; // default value. modify in main.c
uint8_t global_log_messages = 1; // 0 no, 1 encrypted, 2 plaintext (depreciated, no longer exists). This is the "global default" which can be overridden per-peer.
uint8_t log_last_seen = 1;
uint8_t auto_accept_mult = 0; // 1 is yes, 0 is no. Yes is not good. Using mults in general is not good. We should rate limit them or have them only come on line for 1 minute every 30 minutes (randomly) and accept 1 connect.
uint8_t shorten_torxids = 1; // 1 is on, 0 is off. Cuts off the version byte, the checksum, and a prefix
uint8_t suffix_length = 4; // 4 is a reasonable default for suffix at this time (or 3 for prefix). Up to 7 has been confirmed possible (45 length torxid).
int global_threads = 1; // for onion_gen(), cpu threads.
int threads_max = 0; // max as detected by cpu_count()
uint8_t auto_resume_inbound = 1; // automatically request resumption of inbound file transfers NOTE: only works on full_duplex transfers (relies on .split) TODO disabling this might be untested
uint8_t full_duplex_requests = 1; // Requested files should utlize full duplex (split == 1), assuminng v3auth. Can interfere with receiving messages due to messages being added to end of buffer. // If 0, allowed for individual transfers to override this (from 0 to 1) for example if they are small and quick.
uint8_t kill_delete = 1; // delete peer and history when receiving kill code (if zero, just block and keep history)
uint8_t hide_blocked_group_peer_messages = 0; // Note: blocking would require re-sorting, if hide is toggled
uint8_t log_pm_according_to_group_setting = 1; // toggles whether or not PM logging should follow the logging settings of the group (useful to UI devs who might want to control group PM logging per-peer)
double file_progress_delay = 1000000000; // nanoseconds (*1 billionth of a second)

uint32_t broadcast_history[BROADCAST_HISTORY_SIZE] = {0}; // NOTE: this is sent OR queued

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
pthread_mutex_t mutex_tor_pipe = PTHREAD_MUTEX_INITIALIZER;
/* 2024 rwmutex */
pthread_rwlock_t mutex_debug_level = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_global_variable = PTHREAD_RWLOCK_INITIALIZER; // do not use for debug variable
pthread_rwlock_t mutex_protocols = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_expand = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_expand_group = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_packet = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t mutex_broadcast = PTHREAD_RWLOCK_INITIALIZER;
//int8_t force_sign = 2; // permanently moved to UI
sqlite3 *db_plaintext = {0};
sqlite3 *db_encrypted = {0};
sqlite3 *db_messages = {0};
uint8_t censored_region = 0;

const char *tor_log_removed_suffixes[] = {". Giving up. (waiting for circuit)\n", "New control connection opened from 127.0.0.1.\n", ". Giving up. (waiting for rendezvous desc)\n", "].onion for reason resolve failed. Fetch status: No more HSDir available to query.\n"};

const char *torrc_content_default = "\
## Contents of this file are encrypted\n\
# Socks5Proxy 127.0.0.1:PORT\n\
# LogTimeGranularity 1\n\
# SafeLogging 0\n\
# Log debug file tor-debug.log\n\
## CircuitsAvailableTimeout 86400\n\
## ConnectionPadding auto\n\
## DormantTimeoutDisabledByIdleStreams 1\n\
## KeepalivePeriod 300\n\
## ReducedConnectionPadding 0\n\
## DormantClientTimeout 1000 week\n\
## MaxCircuitDirtiness 1000 week\n\
"; // This default this all will be replaced by initial_keyed() if user has set something, or UI defaults
const char *torrc_content_default_censored_region_part1 = "\
## Contents of this file are encrypted\n\
## CircuitsAvailableTimeout 86400\n\
## ConnectionPadding auto\n\
## DormantTimeoutDisabledByIdleStreams 1\n\
## KeepalivePeriod 300\n\
## ReducedConnectionPadding 0\n\
## DormantClientTimeout 1000 week\n\
## MaxCircuitDirtiness 1000 week\n\
UseBridges 1\n\
UpdateBridgesFromAuthority 1\n\
ClientTransportPlugin snowflake exec ";
const char *torrc_content_default_censored_region_part2 = "\n\
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn\n\
Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn\n\
";

const char *table_peer = \
	"CREATE TABLE IF NOT EXISTS peer (\
		peer_index	INTEGER	PRIMARY KEY AUTOINCREMENT,\
		owner		INT	STRICT NOT NULL,\
		status		INT	STRICT NOT NULL,\
		peerversion	INT	STRICT NOT NULL,\
		privkey		TEXT	STRICT NOT NULL UNIQUE CHECK (length(privkey) == 88),\
		peeronion	TEXT	STRICT NOT NULL UNIQUE CHECK (length(peeronion) == 56),\
		peernick	TEXT	STRICT NOT NULL CHECK (length(peernick) <= 56),\
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
	pthread_rwlock_rdlock(&mutex_protocols); // this operates recursively, is typically redundant. Just leave it as redundant.
	for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE; p_iter++)
		if(protocols[p_iter].protocol == protocol)
		{
			pthread_rwlock_unlock(&mutex_protocols);
			return p_iter;
		}
	pthread_rwlock_unlock(&mutex_protocols);
//	error_printf(0,"Protocol not found: %u. Be sure to catch this.",protocol);
	return -1; // protocol not found. be sure to catch this.
}

int protocol_registration(const uint16_t protocol,const char *name,const char *description,const uint32_t null_terminated_len,const uint32_t date_len,const uint32_t signature_len,const uint8_t logged,const uint8_t notifiable,const uint8_t file_checksum,const uint8_t file_offer,const uint8_t exclusive_type,const uint8_t utf8,const uint8_t socket_swappable,const uint8_t stream)
{ // Register a custom protocol // TODO probbaly passing a struct + protocol is more rational than this massive amount of args
	if(protocol_lookup(protocol) != -1 || (logged && stream))
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
	pthread_rwlock_wrlock(&mutex_protocols);
	for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE; p_iter++)
		if(protocols[p_iter].protocol == 0)
		{ // set stuff in an unused p_iter
			protocols[p_iter].protocol = protocol;
			if(name)
				snprintf(protocols[p_iter].name,sizeof(protocols[p_iter].name),"%s",name);
			if(description)
				snprintf(protocols[p_iter].description,sizeof(protocols[p_iter].description),"%s",description);
			protocols[p_iter].null_terminated_len = null_terminated_len;
			protocols[p_iter].date_len = date_len;
			protocols[p_iter].signature_len = signature_len;
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
			pthread_rwlock_unlock(&mutex_protocols);
			return p_iter;
		}
	pthread_rwlock_unlock(&mutex_protocols);
	error_simple(0,"Cannot register protocol. Hit PROTOCOL_LIST_SIZE."); // so increase it!
	breakpoint();
	return -1;
}

void torx_fn_read(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read prevented. Coding error. Report this.");
	torx_read(n)
}
void torx_fn_write(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read prevented. Coding error. Report this.");
	torx_write(n)
}
void torx_fn_unlock(const int n)
{ // Consider using this broadly. Note: Sanity check has to be in function, not in macro. We tried in macro and had issues.
	torx_unlock(n)
	if(n < 0)
		error_simple(-1,"Sanity check failed in torx_fn_read. Illegal read occurred. Coding error. Report this.");
}

static inline void write_debug_file(const char *message)
{
	if(!message || !strlen(message))
		return;
	FILE *file = fopen(debug_file, "a+");
	if(file == NULL)
		return;
	if(fputs(message,file) == EOF)
		return;
	fclose(file);
	file = NULL;
}

static inline void error_allocated_already(const int debug_level,char *do_not_free_message)
{ // INTERNAL FUNCTION ONLY. No sanity checks, do_not_free_message must be already allocated by torx_secure_malloc.
	if(write_debug_to_file)
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
	const int length = vsnprintf(NULL, 0, format, copy);
	va_end(copy);
	char *do_not_free_message = NULL;
	if(length > 0)
	{
		do_not_free_message = torx_secure_malloc((size_t)length + 2 - has_newline);
		if(do_not_free_message)
		{
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
	}
	else
		error_simple(0,"Invalid format or zero length passed to error_printf");
    	va_end(args);
}

static inline int torx_pipe(int pipefd[2])
{ // If this is issues, windows offers CreatePipe
	#ifdef WIN32
	return _pipe(pipefd,4096,_O_TEXT); // alt: _O_BINARY // TODO possibly increase this cache?
	#else
	return pipe(pipefd);
	#endif
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
void initialize_f_cb(const int n,const int f)
{
	if(initialize_f_registered)
		initialize_f_registered(n,f);
}
void initialize_g_cb(const int g)
{
	if(initialize_g_registered)
		initialize_g_registered(g);
}
void expand_file_struc_cb(const int n,const int f)
{
	if(expand_file_struc_registered)
		expand_file_struc_registered(n,f);
}
void expand_messages_struc_cb(const int n,const int i)
{
	if(expand_messages_struc_registered)
		expand_messages_struc_registered(n,i);
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
void transfer_progress_cb(const int n,const int f,const uint64_t transferred)
{
	if(transfer_progress_registered)
		transfer_progress_registered(n,f,transferred);
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
}
void print_message_cb(const int n,const int i,const int scroll)
{
	if(print_message_registered)
		print_message_registered(n,i,scroll);
}
void login_cb(const int value)
{
	if(login_registered)
		login_registered(value);
}
void print_log_cb(const int n,const int actual)
{
	if(print_log_registered)
		print_log_registered(n,actual);
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

void initialize_f_setter(void (*callback)(int,int))
{
	if(initialize_f_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_f_registered = callback;
}

void initialize_g_setter(void (*callback)(int))
{
	if(initialize_g_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_g_registered = callback;
}

void expand_file_struc_setter(void (*callback)(int,int))
{
	if(expand_file_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_file_struc_registered = callback;
}

void expand_messages_struc_setter(void (*callback)(int,int))
{
	if(expand_messages_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_messages_struc_registered = callback;
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

void transfer_progress_setter(void (*callback)(int, int, uint64_t))
{
	if(transfer_progress_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		transfer_progress_registered = callback;
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

void print_message_setter(void (*callback)(int,int,int))
{
	if(print_message_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		print_message_registered = callback;
}

void login_setter(void (*callback)(int))
{
	if(login_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		login_registered = callback;
}

void print_log_setter(void (*callback)(int,int))
{
	if(print_log_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		print_log_registered = callback;
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

unsigned char *read_bytes(size_t *data_len,const char *path)
{ // Read a file entirely into an torx_insecure_malloc. Return data and set data_len
	unsigned char *data = NULL;
	size_t allocated = 0;
	FILE *fp;
	if(!path || (fp = fopen(path, "r")) == NULL)
	{
		error_simple(0,"Could not open file. Check permissions. Bailing out.");
		goto end;
	}
	fseek(fp, 0L, SEEK_END);
	allocated = (size_t)ftell(fp);
	data = torx_insecure_malloc(allocated);
	fseek(fp, 0L, SEEK_SET);
	if(fread(data,1,allocated,fp) != allocated)
		error_simple(0,"Read less than expected amount of data. Uncaught bug.");
	end: {}
	if(data_len)
		*data_len = allocated;
	return data;
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
		pthread_rwlock_wrlock(&mutex_debug_level);
		debug = level;
		pthread_rwlock_unlock(&mutex_debug_level);
		return level;
	}
	else
	{ // get
		pthread_rwlock_rdlock(&mutex_debug_level);
		const int8_t current_level = debug;
		pthread_rwlock_unlock(&mutex_debug_level);
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
	*((uint32_t *)allocation) = (uint32_t) len; // ONLY THE REAL DATA LENGTH, not including prefix bytes or padding
	*((uint32_t *)allocation+1) = ENUM_MALLOC_TYPE_INSECURE;
	return ((char*)allocation + 4 + 4);
}

void *torx_secure_malloc(const size_t len)
{
	if(len < 1)
		return NULL; // avoids some occassional very small memory leaks
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
	*((uint32_t *)allocation) = (uint32_t) len; // ONLY THE REAL DATA LENGTH, not including prefix bytes or padding
	*((uint32_t *)allocation+1) = ENUM_MALLOC_TYPE_SECURE;
	return ((char*)allocation + 4 + 4);
}

size_t torx_allocation_len(const void *arg)
{ // Convenience function for running safety checks before read/write to a pointer of unknown allocation. Returns length including/AFTER virtual pointer, not including prefix bytes or padding before the pointer.
	size_t len = 0;
	if(arg)
	{
		const void *real_ptr = (const char *)arg - 8;
		len = *((const uint32_t *)real_ptr);
	}
	return len;
}

void *torx_realloc(void *arg,const size_t len_new)
{
	void *allocation = NULL;
	if(arg)
	{
		void *real_ptr = (char *)arg - 8;
		const size_t len_old = *((uint32_t *)real_ptr);
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
		if(len_new < len_old)
		{ // should work but probably an error which could lead to illegal reads etc
			error_printf(0,"Reducing size in torx_secure_realloc is probably a coding error. Report this. %lu < %lu",len_new,len_old);
			breakpoint();
			memcpy(allocation,arg,len_new); 
		}
		else
			memcpy(allocation,arg,len_old); // could +1 for nullptr? no, old len should include.
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

void torx_free(void **p)
{ // XXX Usage: torx_free((void*)&pointer)
	if(*p == NULL)
		return;
	void *real_ptr = (char *)(*p) - 8;
	const uint32_t size = *((uint32_t *)real_ptr);
	const uint32_t type = *((uint32_t *)real_ptr+1);
	if(type == ENUM_MALLOC_TYPE_SECURE && ENABLE_SECURE_MALLOC)
		sodium_free((char*)*p-8);
	else if(type == ENUM_MALLOC_TYPE_SECURE)
	{
		sodium_memzero(*p,size);
		free((char*)*p-8);
	}
	else if(type == ENUM_MALLOC_TYPE_INSECURE)
		free((char*)*p-8);
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
	if(g < 0 || n < 0 || i < 0)
	{
		error_simple(0,"Message_insert sanity check failed.");
		breakpoint();
		return -1;
	}
	torx_read(n) // XXX
	const time_t time = peer[n].message[i].time;
	const time_t nstime = peer[n].message[i].nstime;
	torx_unlock(n) // XXX
	struct msg_list *page = torx_insecure_malloc(sizeof(struct msg_list));
	page->n = n;
	page->i = i;
	page->time = time;
	page->nstime = nstime;
	pthread_rwlock_rdlock(&mutex_expand_group);
	struct msg_list *current_page = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group);
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
			pthread_rwlock_wrlock(&mutex_expand_group);
			group[g].msg_last = current_page->message_next = page;
			pthread_rwlock_unlock(&mutex_expand_group);
		}
		else
		{ // Current_page is newer than ours, insert behind
			page->message_prior = current_page->message_prior;
			page->message_next = current_page;
			if(current_page->message_prior) // if current page isn't the very first message, ie there are others before it
				current_page->message_prior->message_next = page;
			else
			{
				pthread_rwlock_wrlock(&mutex_expand_group);
				group[g].msg_first = page;
				pthread_rwlock_unlock(&mutex_expand_group);
			}
			current_page->message_prior = page; // do last
		}
	}
	else
	{ // First message
		page->message_prior = NULL;
		page->message_next = NULL;
		pthread_rwlock_wrlock(&mutex_expand_group);
		group[g].msg_last = group[g].msg_first = page;
		pthread_rwlock_unlock(&mutex_expand_group);
	}
	pthread_rwlock_wrlock(&mutex_expand_group);
	group[g].msg_count++;
	pthread_rwlock_unlock(&mutex_expand_group);
	return 0;
}

void message_remove(const int g,const int n,const int i)
{ // Remove message between two messages in our linked list
	if(g < 0 || n < 0 || i < 0)
		error_simple(-1,"Message_remove sanity check failed.");
	pthread_rwlock_rdlock(&mutex_expand_group);
	struct msg_list *current_page = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group);
	while(current_page && (n != current_page->n || i != current_page->i))
		current_page = current_page->message_next;
	if(current_page && n == current_page->n && i == current_page->i)
	{
		if(current_page->message_prior) // not removing first
			current_page->message_prior->message_next = current_page->message_next; // might be NULL, is fine
		else
		{ // removing first
			pthread_rwlock_wrlock(&mutex_expand_group);
			group[g].msg_first = current_page->message_next; // might be NULL, is fine
			pthread_rwlock_unlock(&mutex_expand_group);
		}
		if(current_page->message_next) // removing non-latest
			current_page->message_next->message_prior = current_page->message_prior; // might be NULL, is fine
		else
		{ // removing latest
			pthread_rwlock_wrlock(&mutex_expand_group);
			group[g].msg_last = current_page->message_prior; // might be NULL, is fine
			pthread_rwlock_unlock(&mutex_expand_group);
		}
		pthread_rwlock_wrlock(&mutex_expand_group);
		if(current_page == group[g].msg_index)
		{ // MUST NULL msg_index if it is message_remove'd, to prevent undefined behaviour
			group[g].msg_index = NULL;
			group[g].msg_index_iter = 0;
		}
		group[g].msg_count--;
		pthread_rwlock_unlock(&mutex_expand_group);
		torx_free((void*)&current_page);
	}
	else
	{ // TODO 2024/02/24 unable to discern why some fail and some don't. (ie why some are in struct and others aren't -- review message_insert, message_sort)
		const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
		pthread_rwlock_rdlock(&mutex_protocols);
		const char *name = protocols[p_iter].name;
		pthread_rwlock_unlock(&mutex_protocols);
		error_printf(0,"Sanity message_remove called on non-existant message of protocol: %s. Coding error. Report this.",name);
	//	breakpoint();
		return;
	}
}

void message_sort(const int g)
{ // Sort group messages into a list of msg.
	if(g < 0)
		error_simple(-1,"Message_sort sanity check failed.");
	const uint8_t hide_blocked_group_peer_messages_local = threadsafe_read_uint8(&mutex_global_variable,&hide_blocked_group_peer_messages);
	pthread_rwlock_rdlock(&mutex_expand_group);
	const int group_n = group[g].n;
	const uint32_t peercount = group[g].peercount;
	const int *peerlist = group[g].peerlist;
	struct msg_list *msg_list = group[g].msg_first;
	pthread_rwlock_unlock(&mutex_expand_group);
	if(msg_list != NULL || group_n < 0)
	{ // Do not check peercount >0 because we might have messages to no-one on a new group (which are pointless but nevertheless permitted)
		error_printf(0,"Message_sort has been called twice or upon a deleted group: %d",group_n);
	//	breakpoint();
		return;
	}
	pthread_rwlock_wrlock(&mutex_expand_group);
	group[g].msg_count = 0;
	pthread_rwlock_unlock(&mutex_expand_group);
	struct msg_list *message_prior = NULL; // NOTE: this will change
	const int group_n_message_n = getter_int(group_n,-1,-1,-1,offsetof(struct peer_list,message_n));
	time_t time_last = 0;
	time_t nstime_last = 0;
	for(int i = 0; i < group_n_message_n; i++)
	{ // Do outbound messages on group_n. NOTE: For speed of insertion, we assume they are sequential. If that assumption is wrong, *MUST USE* message_insert instead.
		torx_read(group_n) // XXX
		const uint8_t stat = peer[group_n].message[i].stat;
		const time_t time = peer[group_n].message[i].time;
		const time_t nstime = peer[group_n].message[i].nstime;
		const int p_iter = peer[group_n].message[i].p_iter;
		torx_unlock(group_n) // XXX
		pthread_rwlock_rdlock(&mutex_protocols);
		const uint16_t protocol = protocols[p_iter].protocol;
		pthread_rwlock_unlock(&mutex_protocols);
		if(stat == ENUM_MESSAGE_FAIL || stat == ENUM_MESSAGE_SENT)
		{ // Do outbound messages on group_n. NOTE: For speed of insertion, since this is the first N, it should be in order and therefore there is no need to check time/nstime, we assume they are sequential.
			if(time_last < time || (time_last == time && nstime_last < nstime))
			{ // Indeed sequential
				struct msg_list *page = torx_insecure_malloc(sizeof(struct msg_list));
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
					pthread_rwlock_wrlock(&mutex_expand_group);
					group[g].msg_first = page;
					pthread_rwlock_unlock(&mutex_expand_group);
				}
				if(i == group_n_message_n-1)
				{ // Potentiallly last (can be overruled by message_insert later)
					pthread_rwlock_wrlock(&mutex_expand_group);
					group[g].msg_last = page;
					pthread_rwlock_unlock(&mutex_expand_group);
				}
				else
					message_prior = page; // for the next one
				time_last = time;
				nstime_last = nstime;
			}
			else // If that assumption is wrong, *MUST USE* message_insert instead.
				message_insert(g,group_n,i);
		}
		else if(protocol != ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST && protocol != ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST)
		{ // ENTRY_REQUEST are logged at least until SENT
			error_printf(0,"Checkpoint message_sort unexpected stat: %d %u",stat,protocol);
			breakpoint(); // shouldn't happen, just checking. If this doesn't trigger, can potentially remove stat check
		}
	}
	if(peerlist && peercount > 0)
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{ // Warning: use peer_n not nn
			const int peer_n = peerlist[nn];
			torx_read(peer_n) // XXX
			const uint8_t status = peer[peer_n].status;
			const int message_n = peer[peer_n].message_n;
			torx_unlock(peer_n) // XXX
			if(hide_blocked_group_peer_messages_local && status == ENUM_STATUS_BLOCKED)
				continue; // skip if appropriate
			for(int i = 0; i < message_n; i++)
			{ // Do inbound messages && outbound private messages on peers
				torx_read(peer_n) // XXX
				const int p_iter = peer[peer_n].message[i].p_iter;
				const uint8_t stat =  peer[peer_n].message[i].stat;
				torx_unlock(peer_n) // XXX
				if(p_iter > -1)
				{
					const uint8_t group_pm = protocols[p_iter].group_pm;
					if(stat == ENUM_MESSAGE_RECV || group_pm)
						message_insert(g,peer_n,i);
				}
			}
		}
}

char *run_binary(pid_t *return_pid,void *fd_stdin,void *fd_stdout,char *const args[],const char *input)
{ // Check return_pid > -1 to verify successful run of binary. Note: in Unix, fd_stdin/out is int, and in Windows it is HANDLE (void*). NOTE: The reason this returns char* and needs to be torx_free'd instead of returning pid is because double pointers are annoying in some languages and this is UI exposed.
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
			fd_stdout = NULL;
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
		fd_stdout = g_hChildStd_OUT_Rd;
	else
	{ // Handle stdout, if directed to
		len = 0;
		char buffer[4096];
		DWORD bytesRead;
		while(ReadFile(g_hChildStd_OUT_Rd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead)
		{
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
				output[len-1] = '\0';
			else
				output[len] = '\0';
		}
	}
	return output;
#else
	#define FAILURE_STRING "zSHJNckXURsy82aYoX9KPNR18oGExraN" // can be anything not reasonably likely to be returned by a binary
	int link1[2];
	int link2[2];
	if(torx_pipe(link1) == -1)
		error_simple(-1,"Pipe failure 1 in run_binary");
	if(torx_pipe(link2) == -1)
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
		fclose(pipewrite);
		pipewrite = NULL;
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
		{
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
		error_simple(0,"set_time called on a message that already has time set. Report this.");
		breakpoint();
		return;
	}
	struct timespec ts;
	pthread_mutex_lock(&mutex_clock);
	clock_gettime(CLOCK_REALTIME, &ts);
	pthread_mutex_unlock(&mutex_clock);
	*time = ts.tv_sec;
	*nstime = ts.tv_nsec;
}

static inline uint64_t calculate_average(const int n,const int f,const uint64_t bytes_per_second)
{ // Calculate average file transfer speed over 255 seconds, for the purpose of calculating remaining time
/*	#define smoothing 0.02
	if(peer[n].file[f].average_speed == 0)
		peer[n].file[f].average_speed = peer[n].file[f].bytes_per_second;
	else if(peer[n].file[f].average_speed > peer[n].file[f].bytes_per_second)
		peer[n].file[f].average_speed -= (uint64_t)((double)peer[n].file[f].bytes_per_second*smoothing);
	else if(peer[n].file[f].average_speed < peer[n].file[f].bytes_per_second)
		peer[n].file[f].average_speed += (uint64_t)((double)peer[n].file[f].bytes_per_second*smoothing);
	return peer[n].file[f].average_speed;	*/
//	const time_t last_progress_update_time = getter_time(n,-1,f,-1,offsetof(struct file_list,last_progress_update_time));
//	if(last_progress_update_time == 0) // necessary to prevent putting in bad bytes_per_second data
//		return 0;
	uint64_t sum = 0;
	uint8_t included = 0;
	uint64_t average_speed = 0;
	torx_write(n) // XXX
	peer[n].file[f].last_speeds[peer[n].file[f].speed_iter++] = bytes_per_second;
	torx_unlock(n) // XXX
	torx_read(n) // XXX
	for(uint8_t iter = 0; iter < 255; iter++)
		if(peer[n].file[f].last_speeds[iter])
		{
			sum += peer[n].file[f].last_speeds[iter];
			included++;
		}
	torx_unlock(n) // XXX
	if(included)
		average_speed = sum/included;
	else
		average_speed = 0;
//	setter(n,-1,f,-1,offsetof(struct file_list,average_speed),&average_speed,sizeof(average_speed));
	return average_speed;
}

char *message_time_string(const int n,const int i)
{ // Helper function available to UI devs (but no requirement to use)
	if(n < 0 || i < 0)
		return NULL;
	// Convert Epoch Time to Human Readable
	const time_t rawtime = getter_time(n,i,-1,-1,offsetof(struct message_list,time));
	const time_t diff = time(NULL) - rawtime; // comparing both in UTC
	struct tm *info = localtime(&rawtime);
	char *timebuffer = torx_insecure_malloc(20); // not sure whether there is value in having this secure. going to venture to say no.
	if(diff >= 0 && diff < 86400) // 24 hours
		strftime(timebuffer,20,"%T",info);
	else
		strftime(timebuffer,20,"%Y/%m/%d %T",info);
	return timebuffer;
}

char *file_progress_string(const int n,const int f)
{ // Helper function available to UI devs (but no requirement to use)
	if(n < 0 || f < 0)
		return NULL;
	torx_read(n) // XXX
	const time_t time_left = peer[n].file[f].time_left;
	const uint64_t bytes_per_second = peer[n].file[f].bytes_per_second;
	const uint64_t size = peer[n].file[f].size;
	const uint8_t status = peer[n].file[f].status;
	torx_unlock(n) // XXX
	#define file_size_text_len 128 // TODO perhaps increase this size. its arbitary. By our math it shoud be more than enough though.
	char *file_size_text = torx_insecure_malloc(file_size_text_len); // arbitrary allocation amount
//	printf("Checkpoint string: %ld left, %lu b/s\n",time_left,bytes_per_second);
	if(status == ENUM_FILE_OUTBOUND_REJECTED)
		snprintf(file_size_text,file_size_text_len,"Peer rejected");
	else if(status == ENUM_FILE_OUTBOUND_CANCELLED)
		snprintf(file_size_text,file_size_text_len,"Cancelled");
	else if(status == ENUM_FILE_INBOUND_REJECTED)
		snprintf(file_size_text,file_size_text_len,"Rejected");
	else if(status == ENUM_FILE_INBOUND_CANCELLED)
		snprintf(file_size_text,file_size_text_len,"Peer cancelled");
	else if(time_left > 7200)
	{
		const time_t hours = time_left/60/60;
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %ld hours %ld min left",bytes_per_second/1024,hours,(long int)time_left/60-hours*60);
	}
	else if(time_left > 120)
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %ld min left",bytes_per_second/1024,time_left/60);
	else if(time_left > 0)
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %ld sec left",bytes_per_second/1024,time_left);
	else if(size < 2*1024) // < 2 kb
		snprintf(file_size_text,file_size_text_len,"%zu B",size);
	else if(size < 2*1024*1024) // < 2mb
		snprintf(file_size_text,file_size_text_len,"%zu KiB",size/1024);
	else if(size < (size_t) 2*1024*1024*1024) // < 2gb
		snprintf(file_size_text,file_size_text_len,"%zu MiB",size/1024/1024);
	else if(size < (size_t) 2*1024*1024*1024*1024) // < 2 tb
		snprintf(file_size_text,file_size_text_len,"%zu GiB",size/1024/1024/1024);
	else // > 2tb
		snprintf(file_size_text,file_size_text_len,"%zu TiB",size/1024/1024/1024/1024);
	return file_size_text;
}

void transfer_progress(const int n,const int f,const uint64_t transferred)
{ // This is called every packet on a file transfer. Packets are PACKET_LEN-10 in size, so 488 (as of 2022/08/19, may be changed to accomodate sequencing)
// XXX NOTE: To trigger or indicate stall, call twice with transferred equal on each call
	time_t time_current = 0;
	time_t nstime_current = 0;
	set_time(&time_current,&nstime_current);
	torx_read(n) // XXX
	const uint64_t size = peer[n].file[f].size; // getter_uint64(n,-1,f,-1,offsetof(struct file_list,size));
	const uint64_t last_transferred = peer[n].file[f].last_transferred; // getter_uint64(n,-1,f,-1,offsetof(struct file_list,last_transferred));
	const time_t last_progress_update_time = peer[n].file[f].last_progress_update_time;
	const double diff = (double)(time_current - peer[n].file[f].last_progress_update_time) * 1e9 + (double)(nstime_current - peer[n].file[f].last_progress_update_nstime); // getter_time(n,-1,f,-1,offsetof(struct file_list,last_progress_update_time)); // getter_time(n,-1,f,-1,offsetof(struct file_list,last_progress_update_nstime));
	torx_unlock(n) // XXX
	if(transferred == size)
	{
		torx_write(n) // XXX
		peer[n].file[f].last_transferred = transferred;
		peer[n].file[f].bytes_per_second = 0;
		peer[n].file[f].time_left = 0;
		torx_unlock(n) // XXX
		transfer_progress_cb(n,f,transferred);
	}
	else if(diff > file_progress_delay || last_transferred == transferred /* stalled */)
	{ /* For more accuracy and less variation, do an average over time */
		uint64_t bytes_per_second = 0;
		if(diff > 0)
			bytes_per_second = (uint64_t)((double)(transferred - last_transferred) / (diff / 1000000000));
	//	printf("Checkpoint %lu = (%lu - %lu) / (%f / 1000000000)\n",bytes_per_second,transferred,last_transferred,diff);
		time_t time_left = 0;
		uint64_t average_speed = 0;
		if(last_progress_update_time && bytes_per_second < 1024*1024*1024) // necessary to prevent putting in bad bytes_per_second data (sanity checks)
			average_speed = calculate_average(n,f,bytes_per_second);
		if(bytes_per_second && average_speed)
			time_left = (time_t)((size - transferred) / average_speed); // alt: bytes_per_second
		if(last_transferred == transferred)
			error_printf(0,"Checkpoint transfer_progress received a stall: %ld %lu\n",time_left,bytes_per_second);
	//	printf("Checkpoint bytes_per_second: %lu transferred: %lu\n",bytes_per_second,transferred);
		torx_write(n) // XXX
		peer[n].file[f].time_left = time_left; // will be 0 if bytes_per_second is 0
		peer[n].file[f].bytes_per_second = bytes_per_second;
		peer[n].file[f].last_progress_update_time = time_current;
		peer[n].file[f].last_progress_update_nstime = nstime_current;
		peer[n].file[f].last_transferred = transferred;
		torx_unlock(n) // XXX
		transfer_progress_cb(n,f,transferred);
	//	printf("Checkpoint time_left: %ld Average_speed: %lu Diff: %f Transferred: %lu\n",time_left, average_speed,diff,transferred);
	}
//	else
//		printf("Checkpoint transfer_progress %lu -> %lu\n",last_transferred,transferred);
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
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
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
		if(date_len && !signature_len)
			error_simple(0,"You are trying to date a message without signing it. This is pointless.");
		uint32_t trash = htobe32((uint32_t)time);
		memcpy(&message_prepared[base_message_len + null_terminated_len],&trash,sizeof(trash));
		trash = htobe32((uint32_t)nstime);
		memcpy(&message_prepared[base_message_len + null_terminated_len + sizeof(trash)],&trash,sizeof(trash));
	}
	long long unsigned int sig_len = 0; // discard
	const uint32_t total_unsigned_len = allocation - crypto_sign_BYTES;
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

uint64_t calculate_transferred(const int n,const int f)
{ /* DO NOT make this complicated. It has to be quick and simple because it is called for every packet in/out */
	const uint8_t status = getter_uint8(n,-1,f,-1,offsetof(struct file_list,status));
	uint64_t transferred = 0;
	if(status == ENUM_FILE_OUTBOUND_PENDING || status == ENUM_FILE_OUTBOUND_ACCEPTED || status == ENUM_FILE_OUTBOUND_COMPLETED || status == ENUM_FILE_OUTBOUND_REJECTED || status == ENUM_FILE_OUTBOUND_CANCELLED)
	{ /* Outbound */ // XXX Baseline accounts for what peer is NOT requesting (we assume they already have it) XXX this could cause problems depending how the return is used
		uint64_t transferred_0 = 0;
		uint64_t transferred_1 = 0;
		torx_read(n) // XXX
		if(peer[n].file[f].outbound_end[0] > 0)
			transferred_0 = peer[n].file[f].outbound_end[0] - peer[n].file[f].outbound_start[0] + 1;
		if(peer[n].file[f].outbound_end[1] > 0)
			transferred_1 = peer[n].file[f].outbound_end[1] - peer[n].file[f].outbound_start[1] + 1;
		const uint64_t size = peer[n].file[f].size;
		uint64_t baseline = size - transferred_0 - transferred_1;
		if(size < 4 && peer[n].file[f].outbound_end[0] + peer[n].file[f].outbound_end[1] < size)
			baseline--; // 2023/10/26 this is the simplest way to fix an obscure issue that occurs when transferring a 1 to 3 byte file.... ie one fd has a request for byte 0 only. Don't waste thought, its complicated, just leave it.
		transferred = baseline + peer[n].file[f].outbound_transferred[0] + peer[n].file[f].outbound_transferred[1];
		torx_unlock(n) // XXX
	}
	else /* ENUM_FILE_INBOUND_ */
	{
		torx_read(n) // XXX
		const uint64_t *split_info = peer[n].file[f].split_info;
		torx_unlock(n) // XXX
		if(split_info == NULL) // error_simple(0,"Cannot calculate transferred. Split_info is uninitialized. Should have been initialized by split_update or load_message_struc. Coding error. Report this.");
			return 0; // Sanity check. It should be normally set by load_message_struc or split_update for inbound, or file_init for outbound.
		torx_read(n) // XXX
		uint16_t sections = peer[n].file[f].splits+1;
		while(sections--) // If there are 0 splits, there is 1 section, it is section 0;
			transferred += peer[n].file[f].split_info[sections];
		torx_unlock(n) // XXX
	}
	return transferred; // BEWARE of baseline. See above.
}

uint64_t calculate_section_start(const uint64_t size,const uint8_t splits,const int section) // section starts at 0. One split == 2 sections, 0 and 1.
{ // FUNCTION HAS NO ERROR CHECKING, use carefully.
/*	if(peer[n].file[f].splits == 0)
	{ // TODO open file to check check current file size (note: this assumes we are not pre-allocating) and return ftell+1
		error_simple(0,"TODO: Not checking whether file is already partially transferred.");
		// TEMP INCORRECT
		return peer[n].file[f].size+1;	
	} // NOTE: would only be relevant with non-full duplex so perhaps no point
	else */
	const int sections = splits+1;
	if(section == 0) // prevent division by 0
		return 0;
	else if(section > 0 && section < sections)// any section between 1 and .splits, inclusive
		return (uint64_t)((float)size*((float)section/(float)sections)); // TODO TODO TODO XXX XXX XXX 2023/10/18 UNTESTED: this is a disaster and might cause failure
	else if(section > 0 && section == sections) // non-existant, being called most probably to determine endpoint, so lets humor the request
		return size;//+1;
	else
	{ // Negative or beyond-bounds section
		error_printf(0,"calculate_section_start was called with an invalid section number: %d. Report this. This can be exploited to corrupt a file.",section);
		breakpoint();
		return 0; // XXX will corrupt file, but nothing we can do here because we can't return -1. THIS MUST NOT BE ALLOWED TO OCCUR especially on inbound libevent.c (note: 2023/10/17, implemented a check)
	} // Prevent it from occuring by ensuring that packet_start is always <= file size (<= or < ??)
//		return peer[n].file[f].size*(section/(long double)sections);
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

void random_string(char *destination,const unsigned int destination_size)
{ // Puts length + '\0' in destination // NOTE: srand() must be properly seeded (not with time()) or rand() will produce non-unique results if called more than once a second
	const char alphanumeric[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	destination[destination_size-1] = '\0';
	for(unsigned int i = 0; i < destination_size - 1; i++)
		destination[i] = *(alphanumeric + (rand() % 62)); 
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
	size_t len = base32_encode((unsigned char*)onion,onion_decoded,sizeof(onion_decoded));
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

static inline uint32_t fnv1a_32_salted(const void *data,const size_t len)
{ // we're adding a salt (which salt doesn't matter but it can't change per-session) to prevent malicious peers from being able to easily prevent specific broadcasts (i mean... they could still spam BROADCAST_QUEUE_SIZE)
	uint32_t hash = 0;
	unsigned char src[crypto_pwhash_SALTBYTES+len];
	memcpy(src,saltbuffer,sizeof(saltbuffer)); // using our global salt is fine/safe
	memcpy(&src[sizeof(saltbuffer)],data,len);
	for(size_t i = 0 ; i < sizeof(src) ; ++i)
	{
		hash ^= src[i];
		hash *= 0x01000193;
	}
	if(!hash) // TorX modification: cannot allow return of 0
		hash++;
	sodium_memzero(src,sizeof(src));
	return hash;
}

/*uint32_t fnv1a_32(const void *data,const size_t len)
{ // DO NOT USE: B2sum returns a hex encoded checksum, which we store encoded. Better if we store it in binary. For truncated hashes, we send first 5 bytes in binary instead of 4 bytes of hex encoding.
	uint32_t hash = 0;
	const uint8_t *src = data;
	for(size_t i=0 ; i < len ; ++i) {
		hash ^= src[i];
		hash *= 0x01000193;
	}
	if(!hash) // TorX modification: cannot allow return of 0
		hash++;
	return hash;
}
uint32_t jenkins_one_at_a_time_hash(const uint8_t* key, size_t length)
{ // TODO remove, unused. Using fnv1a_32
	size_t i = 0;
	uint32_t hash = 0;
	while (i != length) {
		hash += key[i++];
		hash += hash << 10;
		hash ^= hash >> 6;
	}
	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;
	return hash;
}
uint32_t fnv_32a_str(char *str, uint32_t hval)
{ // TODO remove, unused. Using fnv1a_32
    unsigned char *s = (unsigned char *)str;
    while (*s) {
	hval ^= (uint32_t)*s++;
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    }
    return hval;
}
*/
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
	fclose(fp); fp = NULL; // close append mode
	return 0;
}

static inline int pid_read(void)
{ // Read Tor's PID from file (used for killing an orphaned process after a crash or improper shutdown)
	FILE *fp;
	if((fp = fopen(file_tor_pid, "r")) == NULL)
		return 0; // no PID
	char pid_string[21] = {0};
	if(fgets(pid_string,sizeof(pid_string)-1,fp) == NULL)
		return 0;
	const int pid = atoi(pid_string);
	fclose(fp); fp = NULL; // close append mode
	return pid;
}

void torrc_save(const char *torrc_content_local)
{ // Pass null or "" to reset defaults
	size_t len;
	char *torrc_content_final;
	uint8_t set_default = 0;
	if(!torrc_content_local || (len = strlen(torrc_content_local)) == 0)
	{ // Setting to defaults
		set_default = 1;
		pthread_rwlock_rdlock(&mutex_global_variable);
		if(censored_region == 1 && snowflake_location)
		{
			pthread_rwlock_unlock(&mutex_global_variable);
			const size_t len_part1 = strlen(torrc_content_default_censored_region_part1);
			const size_t len_snowflake = strlen(snowflake_location);
			const size_t len_part2 = strlen(torrc_content_default_censored_region_part2);
			len = len_part1 + len_snowflake + len_part2;
			torrc_content_final = torx_secure_malloc(len + 1);
			snprintf(torrc_content_final,len + 1,"%s%s%s",torrc_content_default_censored_region_part1,snowflake_location,torrc_content_default_censored_region_part2);
		}
		else
		{
			pthread_rwlock_unlock(&mutex_global_variable);
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
	pthread_rwlock_wrlock(&mutex_global_variable);
	torx_free((void*)&torrc_content);
	torrc_content = torrc_content_final;
	pthread_rwlock_unlock(&mutex_global_variable);
	if(threadsafe_read_int8(&mutex_global_variable,(int8_t*)&keyed))
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
	if(tor_data_directory)
	{
		char* const args_cmd[] = {tor_location,arg1,arg2,arg3,arg4,arg5,tor_data_directory,NULL};
		return run_binary(NULL,NULL,NULL,args_cmd,torrc_content_local);
	}
	else
	{
		char* const args_cmd[] = {tor_location,arg1,arg2,arg3,arg4,NULL};
		return run_binary(NULL,NULL,NULL,args_cmd,torrc_content_local);
	}
}

char *which(const char *binary) 
{ // Locates a binary from PATH and returns the path, or a NULL pointer if it does not exist in path. This could be converted into a function that can call any binary in $PATH with args and return the output. Therefore it could replace get_tor_version, etc
	if(!binary)
		return NULL;
	#ifdef WIN32
	char searcher[] = "where";
	#else
	char searcher[] = "which";
	#endif
	char binary_array[1024];
	snprintf(binary_array,sizeof(binary_array),"%s",binary);
	char* const args_cmd[] = {searcher,binary_array,NULL};
	return run_binary(NULL,NULL,NULL,args_cmd,NULL);
}

/*void error_ll(const int debug_level,...)
{ // TODO DEPRECIATED: use error_simple or error_printf instead
 // XXX List of strings MUST be terminated with NULL or junk will be added. Lower level == higher priority. 3+ is for sensitive info. Could set specific levels to pop up messages, etc.
 // NOTE: Occassionally calls will be wrapped in if(debug > x) where one of the arguments to error_ll is a function, which is appropriate to prevent IO waste
	if(debug_level > torx_debug_level(-1))
		return;
	char *string = {0};
	char *do_not_free_message = {0};
	size_t error_len = 0;
	va_list va_args;
	va_start(va_args,debug_level);
	while(1)
	{
		if((string = va_arg(va_args,char*)) == NULL) // Must be null terminated
		{
			if(do_not_free_message)
				do_not_free_message = torx_realloc(do_not_free_message,error_len+1+1);
			else
				do_not_free_message = torx_secure_malloc(error_len+1+1);
			snprintf(&do_not_free_message[error_len],1+1,"\n");
			error_len++;
			break; // End of list
		}
		const size_t string_len = strlen(string);
		if(do_not_free_message)
			do_not_free_message = torx_realloc(do_not_free_message,error_len+string_len+1);
		else
			do_not_free_message = torx_secure_malloc(error_len+string_len+1);
		memcpy(&do_not_free_message[error_len],string,string_len+1); // includes copying null terminator
		error_len += string_len;
	}
	va_end(va_args);
	error_allocated_already(debug_level,do_not_free_message);
}*/

void zero_i(const int n,const int i) // XXX do not put locks in here (except mutex_global_variable + mutex_protocols)
{ // GROUP_PEER looks hacky because we should maybe use ** but we don't (note: hacky here simplifies a lot of things elsewhere)
	if(peer[n].message[i].p_iter == -1)
		return; // already deleted
	const int p_iter = peer[n].message[i].p_iter;
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint8_t group_msg = protocols[p_iter].group_msg;
	pthread_rwlock_unlock(&mutex_protocols);
	if(group_msg && peer[n].owner == ENUM_OWNER_GROUP_PEER)
		peer[n].message[i].message = NULL; // will be freed in group CTRL
	else
		torx_free((void*)&peer[n].message[i].message);
	peer[n].message[i].message_len = 0;
	peer[n].message[i].p_iter = -1; // must be -1
	peer[n].message[i].stat = 0;
	peer[n].message[i].pos = 0;
	peer[n].message[i].time = 0;
	peer[n].message[i].nstime = 0;
	if(peer[n].message_n == i + 1) // EXPERIMENTAL ROLLBACK FUNCTIONALITY (utilized primarily on streams to try to reduce burden on our struct)
		peer[n].message_n--;
}

static inline void zero_o(const int n,const int f,const int o) // XXX do not put locks in here
{
	torx_free((void*)&peer[n].file[f].offer[o].offer_info);
}

static inline void zero_f(const int n,const int f) // XXX do not put locks in here
{
	for(int o = 0 ; peer[n].file[f].offer[o].offerer_n > -1 ; o++)
		zero_o(n,f,o);
//	torx_free((void*)&peer[n].file[f].offer); // fjadfweoifaf disabled because it might (likely will) break things when deleting peers. Let it free naturally on shutdown, no big loss.
	sodium_memzero(peer[n].file[f].checksum,sizeof(peer[n].file[f].checksum));
	torx_free((void*)&peer[n].file[f].filename);
	torx_free((void*)&peer[n].file[f].file_path);
	torx_free((void*)&peer[n].file[f].split_hashes);
	torx_free((void*)&peer[n].file[f].split_path);
	torx_free((void*)&peer[n].file[f].split_info);
	torx_free((void*)&peer[n].file[f].split_status);
	torx_free((void*)&peer[n].file[f].split_status_fd);
	close_sockets_nolock(peer[n].file[f].fd_out_recvfd) // Do not eliminate
	close_sockets_nolock(peer[n].file[f].fd_out_sendfd)
	close_sockets_nolock(peer[n].file[f].fd_in_recvfd)
	close_sockets_nolock(peer[n].file[f].fd_in_sendfd)
}

void zero_n(const int n) // XXX do not put locks in here
{ // DO NOT SET THESE TO \0 as then the strlen will be different. We presume these are already properly null terminated.
//	torx_write(n) // XXX
	for(int i = 0 ; i < peer[n].message_n ; i++) // must go before .owner, for variations in zero_i
		zero_i(n,i);
	for(int f = 0 ; !is_null(peer[n].file[f].checksum,CHECKSUM_BIN_LEN) ; f++)
		zero_f(n,f);
//	torx_free((void*)&peer[n].message); // **cannot** be here but needs to be elsewhere, at least on cleanup.
	peer[n].message_n = 0; // must be after zero_i
	peer[n].owner = 0;
	peer[n].status = 0;
	memset(peer[n].privkey,'0',sizeof(peer[n].privkey)-1); // DO NOT REPLACE WITH SODIUM MEMZERO as we currently expect these to be 0'd not \0'd
	peer[n].peer_index = -2; // MUST be lower than -1 to properly error by sql_setting if unset
//	memset(peer[n].hashed_privkey,'0',sizeof(peer[n].hashed_privkey)-1);
	memset(peer[n].onion,'0',sizeof(peer[n].onion)-1);
	memset(peer[n].torxid,'0',sizeof(peer[n].torxid)-1);
	peer[n].peerversion = 0;
	memset(peer[n].peeronion,'0',sizeof(peer[n].peeronion)-1);
	memset(peer[n].peernick,'0',sizeof(peer[n].peernick)-1);
	peer[n].log_messages = 0;
	peer[n].last_seen = 0;
	peer[n].v3auth = 0;
	peer[n].vport = 0;
	peer[n].tport = 0;
	peer[n].socket_utilized[0] = -1;
	peer[n].socket_utilized[1] = -1;
	if(peer[n].sendfd > 0)
		evutil_closesocket(peer[n].sendfd); // TODO TODO TODO added 2023/08/09.
	peer[n].sendfd = 0;
	if(peer[n].recvfd > 0)
		evutil_closesocket(peer[n].recvfd); // TODO TODO TODO added 2023/08/09.
	peer[n].recvfd = 0;
	peer[n].sendfd_connected = 0;
	peer[n].recvfd_connected = 0;
	peer[n].bev_send = NULL; // TODO ensure its leaving event loop?
	peer[n].bev_recv = NULL;
	sodium_memzero(peer[n].sign_sk,crypto_sign_SECRETKEYBYTES);
	sodium_memzero(peer[n].peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	sodium_memzero(peer[n].invitation,crypto_sign_BYTES);
//	torx_free((void*)&peer[n].buffer);
//	peer[n].buffer_len = 0;
//	peer[n].untrusted_message_len = 0;
	peer[n].blacklisted = 0;
	peer[n].thrd_send = 0; // thread_kill(peer[n].thrd_send); // NO. will result in deadlocks.
	peer[n].thrd_recv = 0; // thread_kill(peer[n].thrd_recv); // NO. will result in deadlocks.
//	torx_unlock(n) // XXX
// TODO probably need a callback to UI (to zero the UI struct)
}

void zero_g(const int g)
{ // DO NOT SET THESE TO \0 as then the strlen will be different. We presume these are already properly null terminated.
//	printf("Checkpoint zeroing g==%d\n",g);
	pthread_rwlock_wrlock(&mutex_expand_group);
	memset(group[g].id,'0',GROUP_ID_SIZE);
	group[g].n = -1;
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
			torx_free((void*)&page->message_prior);
		}
		else
			torx_free((void*)&page);
	}
//	torx_free((void*)&group[g].msg_first); // redundant
//	torx_free((void*)&group[g].msg_last); // redundant
	pthread_rwlock_unlock(&mutex_expand_group);
// TODO probably need a callback to UI ( for what ? )
}

static inline void sort_n(int sorted_n[],const uint8_t owner,const int size)
{ // Produces an array of N index values that will order our peer[n]. struct from newest to oldest message, without regard to online status or owner (ie, not just CTRL)
// XXX used to work prior to 2022/11/24, but stopped having effect for unknown reason due to our new implementation of refined_list. Totally unsure why and not fully tested.
	if(!sorted_n || size < 0)
		error_simple(-1,"Sanity check failed in sort_n. Coding error. Report this.");
	time_t last_time[size]; // things get moved around in here (will contain sorted selection)
	for(int nn = 0; nn < size; nn++)
	{
		if(owner == ENUM_OWNER_GROUP_CTRL)
		{
			const int g = set_g(nn,NULL);
			pthread_rwlock_rdlock(&mutex_expand_group);
			struct msg_list *page = group[g].msg_last;
			if(page)
				last_time[nn] = group[g].msg_last->time;
			else
				last_time[nn] = 0;
			pthread_rwlock_unlock(&mutex_expand_group);
		}
		else
		{
			const int message_n = getter_int(nn,-1,-1,-1,offsetof(struct peer_list,message_n));
			if(message_n)
				last_time[nn] = getter_time(nn,message_n-1,-1,-1,offsetof(struct message_list,time)); // last message time
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
//printf(WHITE"Checkpoint yellow: %ld >= %ld\n"RESET,last_time[j],highest_time);
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
	while(getter_byte(nn,-1,-1,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(nn,-1,-1,-1,offsetof(struct peer_list,peer_index)) > -1) // find number of onions / array size
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
		sort_n(sorted_n,owner,nn);
		if(owner == ENUM_OWNER_GROUP_PEER || (owner == ENUM_OWNER_CTRL && peer_status == ENUM_STATUS_FRIEND))
		{
			for(int z = 0; z < 4; z++)
			{ // Z relates to colors (online status). It puts the online peers first and the offline peers last.
				int max = nn;
				while(max--)
				{
					const int n = sorted_n[max];
					const uint8_t local_owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
					const uint8_t status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status));
					if(local_owner == owner && ((owner == ENUM_OWNER_CTRL && status == peer_status) || (owner == ENUM_OWNER_GROUP_PEER && (g == set_g(n,NULL)))))
					{
						const uint8_t sendfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
						const uint8_t recvfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,recvfd_connected));
						char peernick[56+1];
						getter_array(&peernick,sizeof(peernick),n,-1,-1,-1,offsetof(struct peer_list,peernick));
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
						sodium_memzero(peernick,sizeof(peernick));
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
				const uint8_t local_owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
				const uint8_t status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status));
				char peernick[56+1];
				getter_array(&peernick,sizeof(peernick),n,-1,-1,-1,offsetof(struct peer_list,peernick));
				if(local_owner == owner && status == peer_status && (search == NULL || mit_strcasestr(peernick,search) != NULL))
				{
					array[relevant] = n;
					relevant++;
				}
				sodium_memzero(peernick,sizeof(peernick));
			}
		}
	}
	else if(owner == ENUM_OWNER_PEER || owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
	{ // note: ignores peer_status, does not sort
		int max = nn;
		while(max--)
		{ // effectively newest first order
			const uint8_t owner_max = getter_uint8(max,-1,-1,-1,offsetof(struct peer_list,owner));
			char peernick[56+1];
			getter_array(&peernick,sizeof(peernick),max,-1,-1,-1,offsetof(struct peer_list,peernick));
			if(owner_max == owner && (search == NULL || mit_strcasestr(peernick,search) != NULL))
			{
				array[relevant] = max;
				relevant++;
			}
			sodium_memzero(peernick,sizeof(peernick));
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

/*void remove_spaces(char* s) 
{ // There is another way of doing this, somewhere
	const char* d = s;
	do
	{
		while(*d == ' ')
			++d;
	}
	while((*s++ = *d++));
}*/

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

static inline void hash_password(const char *password) // XXX Does not need locks for the same reason intial_keyed doesn't.
{ // Hashes the Tor control port password by making a call to the Tor binary
	if(!tor_location || !password)
		return;
	char arg1[] = "--quiet";
	char arg2[] = "--DataDirectory";
	char arg3[] = "FyRH0kIouynnDZmTDZpQ"; // tor_data_directory
	char arg4[] = "--hash-password";
//	char arg5[] = "-"; // cannot, does not work TODO talk to #tor
	const size_t password_len = strlen(password);
	char *arg5 = torx_secure_malloc(password_len+1);
	memcpy(arg5,password,password_len+1);
	char* const args_cmd[] = {tor_location,arg1,arg2,arg3,arg4,arg5,NULL};
	char *ret = run_binary(NULL,NULL,NULL,args_cmd,NULL);
	torx_free((void*)&arg5);
	size_t len = 0;
	if(ret)
		len = strlen(ret);
	if(len == 61)
	{
		memcpy(control_password_hash,ret,sizeof(control_password_hash));
		error_printf(3,"Actual Tor Control Password: %s",control_password_clear);
		error_printf(3,"Hashed Tor Control Password: %s",control_password_hash);
	}
	else
		error_simple(0,"Improper length hashed Tor Control Password. Possibly Tor location incorrect?");
	torx_free((void*)&ret);
}

static inline void get_tor_version(void) // XXX Does not need locks for the same reason intial_keyed doesn't.
{ /* Sets the tor_version, decides v3auth_enabled */
	if(!tor_location)
		return;
	char arg1[] = "--quiet";
	char arg2[] = "--version";
	char* const args_cmd[] = {tor_location,arg1,arg2,NULL};
	char *ret = run_binary(NULL,NULL,NULL,args_cmd,NULL);
	size_t len = 0;
	if(ret)
		len = strlen(ret);
	if(len < 8)
		error_printf(0,"Tor failed to return version. Check binary location and integrity: %s",tor_location);
	else
	{
		sscanf(ret,"%*s %*s %d.%d.%d.%d",&tor_version[0],&tor_version[1],&tor_version[2],&tor_version[3]);
		error_printf(0,"TorX Library Version: %u.%u.%u.%u",torx_library_version[0],torx_library_version[1],torx_library_version[2],torx_library_version[3]);
		error_printf(0,"Tor Version: %d.%d.%d.%d",tor_version[0],tor_version[1],tor_version[2],tor_version[3]);
		if((tor_version[0] > 0 || tor_version[1] > 4 ) || (tor_version[1] == 4 && tor_version[2] > 6) || (tor_version[1] == 4 && tor_version[2] == 6 && tor_version[3] > 0 ))
		{ // tor version >0.4.6.1
			error_simple(0,"V3Auth is enabled by default.");
			v3auth_enabled = 1;
		}
		else // Disable v3auth if tor version <0.4.6.1
		{
			error_simple(0,"V3Auth is disabled by default. Recommended to upgrade Tor to a version >0.4.6.1");
			v3auth_enabled = 0;
		}
	}
	torx_free((void*)&ret);
}

void peer_offline(const int n,const int8_t fd_type)
{ // Internal Function only. Use the callback. Could combine with peer_online() to be peer_online_change() and peer_online_change_cb()
	const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		error_simple(0,"A group ctrl triggered peer_offline. Coding error. Report this.");
		breakpoint();
	}
	torx_write(n) // XXX
	if(fd_type == 0)
	{
		peer[n].recvfd_connected = 0;
		peer[n].bev_recv = NULL; // XXX 2023/10/23 experimental to attempt to stop SQL error in GDB / valgrind error in serv_init
	}
	else /* if(fd_type == 1) */
	{
		peer[n].sendfd_connected = 0;
		peer[n].bev_send = NULL; // XXX 2023/10/23 experimental to attempt to stop SQL error in GDB / valgrind error in serv_init
	}
	torx_unlock(n) // XXX
	if(owner != ENUM_OWNER_CTRL && owner != ENUM_OWNER_GROUP_PEER)
		return; // not CTRL
	const time_t last_seen = time(NULL); // current time
	setter(n,-1,-1,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
	peer_offline_cb(n);
	if(threadsafe_read_uint8(&mutex_global_variable,&log_last_seen) == 1)
	{
		char p1[21];
		snprintf(p1,sizeof(p1),"%ld",last_seen);
		const int peer_index = getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index));
		sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
	}
}

uint16_t randport(const uint16_t arg) // Passing arg tests whether the port is available (currently unused functionality, but works)
{ // Returns an available random port. Mutex used here to prevent race condition when calling randport() concurrently on different threads (which we do)
	uint16_t port = 0;
	int socket_rand = -1;
	struct sockaddr_in serv_addr = {0};
	pthread_mutex_lock(&mutex_socket_rand);
	while(1)
	{
		if(arg)
			port = arg;
		else
			port = (uint16_t)(rand() % (65536 - 10000 + 1)) + 10000; // keeping it over 10000 to keep byte length consistent (5 bytes)
		if((socket_rand = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{ // Unlikely to occur. Could be fatal but shouldnt happen.
			error_simple(0,"Unlikely socket creation error");
			continue;
		}
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = INADDR_ANY;
		serv_addr.sin_port = htobe16(port);
		if(bind(socket_rand,(struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0)
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
			error_printf(2,"Port (%u) not available. Returning -1.",arg);
			port = 0;
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
	pthread_mutex_unlock(&mutex_socket_rand);
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

/*char *read_tor_pipe(void)
{ // Remember to torx_free. This is to be called by GUI periodically or as desired to read any new lines from the Tor log. GUI is responsible for buffering and freeing return value. GUI devs may choose to read directly from pipe_tor1 instead. This may one day change in case libtorx needs to read that cache to determine the status of something.
	char data[40960]; // should be big
	pthread_mutex_lock(&mutex_tor_pipe);
	const ssize_t len = read(pipe_tor1[0],data,sizeof(data)-1);
	pthread_mutex_unlock(&mutex_tor_pipe);
	if(len > 0)
	{ // Casting as size_t is safe because > 0
		data[len] = '\0';
		char *msg = NULL;
		pthread_mutex_lock(&mutex_tor_pipe);
		if(read_tor_pipe_cache)
		{
			const size_t current_size = torx_allocation_len(read_tor_pipe_cache);
			read_tor_pipe_cache = torx_realloc(read_tor_pipe_cache,current_size+(size_t)len);
			memcpy(&read_tor_pipe_cache[current_size-1],data,(size_t)len+1);
		}
		if(data[(size_t)len-1] == '\n')
		{ // complete
			if(read_tor_pipe_cache)
			{
				msg = read_tor_pipe_cache;
				read_tor_pipe_cache = NULL;
			}
			else
			{
				msg = torx_secure_malloc((size_t)len+1);
				memcpy(msg,data,(size_t)len+1); // includes copying null terminator
			}
			remove_lines_with_suffix(msg);
		}
		else if(read_tor_pipe_cache == NULL)
		{ // incomplete, no existing cache
			read_tor_pipe_cache = torx_secure_malloc((size_t)len+1);
			memcpy(read_tor_pipe_cache,data,(size_t)len+1); // includes copying null terminator
		}
		pthread_mutex_unlock(&mutex_tor_pipe);
		sodium_memzero(data,(size_t)len);
		return msg;
	}
	return NULL;
}*/

static inline void *tor_log_reader(void *arg)
{
	pusher(zero_pthread,(void*)&thrd_tor_log_reader)
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
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
		data[len] = '\0';
		char *msg = NULL;
		pthread_mutex_lock(&mutex_tor_pipe);
		if(read_tor_pipe_cache)
		{
			const size_t current_size = torx_allocation_len(read_tor_pipe_cache);
			read_tor_pipe_cache = torx_realloc(read_tor_pipe_cache,current_size+(size_t)len);
			memcpy(&read_tor_pipe_cache[current_size-1],data,(size_t)len+1);
		}
		if(data[(size_t)len-1] == '\n')
		{ // complete
			if(read_tor_pipe_cache)
			{
				msg = read_tor_pipe_cache;
				read_tor_pipe_cache = NULL;
			}
			else
			{
				msg = torx_secure_malloc((size_t)len+1);
				memcpy(msg,data,(size_t)len+1); // includes copying null terminator
			}
			remove_lines_with_suffix(msg);
			pthread_mutex_unlock(&mutex_tor_pipe);
			tor_log_cb(msg);
		}
		else if(read_tor_pipe_cache == NULL)
		{ // incomplete, no existing cache
			read_tor_pipe_cache = torx_secure_malloc((size_t)len+1);
			memcpy(read_tor_pipe_cache,data,(size_t)len+1); // includes copying null terminator
		}
		pthread_mutex_unlock(&mutex_tor_pipe);
		sodium_memzero(data,(size_t)len);
	}
	error_simple(0,"Exiting tor_log_reader, probably because Tor died or was restarted.");
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

static inline void *start_tor_threaded(void *arg)
{ /* Start or Restart Tor and pipe stdout to pipe_tor */ // TODO have a tor_failed global variable that can be somehow set by errors here
	(void) arg;
	pusher(zero_pthread,(void*)&thrd_start_tor)
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	pthread_rwlock_rdlock(&mutex_global_variable);
	const char *tor_location_local = tor_location;
	pthread_rwlock_unlock(&mutex_global_variable);
	if(tor_location_local == NULL)
		return 0;
//	int8_t restart = 0;
	pthread_mutex_lock(&mutex_tor_pipe);
	if(tor_pid == 0 || tor_pid == -1) // prolly could initialize as 0 and drop the -1
		tor_pid = pid_read();
	if(tor_pid > 0)
	{
		error_simple(0,"Tor is being restarted, or a PID file was found."); // XXX might need to re-randomize socksport and ctrlport, though hopefully not considering wait()
//		restart = 1;
		#ifdef WIN32
		if(TerminateProcess(tor_fd_stdout,0))
		{
			DWORD waitResult = WaitForSingleObject(tor_fd_stdout, 1000); // INFINITE
			if (waitResult == WAIT_OBJECT_0)
				error_simple(0,"Windows: Tor terminated before timeout successfully.\n");
			else
				error_simple(0,"Windows: Tor failed to terminate before timeout. Coding error. Report this.\n");
			CloseHandle(tor_fd_stdout);
		}
		else
			error_simple(0,"TerminateProcess failed. Coding error. Report this.");
		#else
		close(tor_fd_stdout);
		signal(SIGCHLD, SIG_DFL); // XXX allow zombies to be reaped by wait()
		kill(tor_pid,SIGTERM); // was 0
		tor_pid = wait(NULL);
		signal(SIGCHLD, SIG_IGN); // XXX prevent zombies again
		#endif
	/*	while(randport(tor_ctrl_port) == -1 || randport(tor_socks_port) == -1)
		{ // does not work because tor is not deregistering these ports properly on shutdown, it seems. 
			fprintf(stderr,"not ready yet\n");
		} */ // Do not delete XXX
		pid_write(0); // TODO this assumes success... we should probably write tor_pid() instead
//		sleep(1); // ok our wait is not enough because socket is still taken, TODO just choose a new ctrl+socks port? (what if our port was 9050?) 
/*		while(randport(tor_ctrl_port) < 1)
		{ // Alternative is to just choose a new port
			error_simple(5,"Waiting for CTRL port to be released...");
			sleep(1);
		}
		while(randport(tor_socks_port) < 1)
		{ // Alternative is to just choose a new port
			error_simple(5,"Waiting for SOCKS port to be released...");
			sleep(1);
		} */ // TODO currently cannot re-use port because it doesnt get released (not sure why) -- but we try anyway
		pthread_rwlock_rdlock(&mutex_global_variable);
		uint16_t tor_ctrl_port_local = tor_ctrl_port;
		uint16_t tor_socks_port_local = tor_socks_port;
		pthread_rwlock_unlock(&mutex_global_variable);
		if(randport(tor_ctrl_port_local) < 1)
		{
			tor_ctrl_port_local = randport(0);
			pthread_rwlock_wrlock(&mutex_global_variable);
			tor_ctrl_port = tor_ctrl_port_local;
			pthread_rwlock_unlock(&mutex_global_variable);
		}
		if(randport(tor_socks_port_local) < 1)
		{
			tor_socks_port_local = randport(0);
			pthread_rwlock_wrlock(&mutex_global_variable);
			tor_socks_port = tor_socks_port_local;
			pthread_rwlock_unlock(&mutex_global_variable);
		}
	}
	#ifdef WIN32
	HANDLE fd_stdout;
	#else
	int fd_stdout;
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
	char arg10[] = "--FetchUselessDescriptors";
	char arg11[] = "1";
	char arg12[] = "--DataDirectory"; // tor_data_directory
	pthread_rwlock_rdlock(&mutex_global_variable);
	char p1[21],p2[21],p3[21],p4[21];
	snprintf(p1,sizeof(p1),"%u",tor_socks_port);
	snprintf(p2,sizeof(p2),"%u",tor_ctrl_port);
	snprintf(p3,sizeof(p3),"%d",ConstrainedSockSize);
	snprintf(p4,sizeof(p4),"%d, %d",INIT_VPORT,CTRL_VPORT);
	char *ret;
	char *torrc_content_local = replace_substring(torrc_content,"nativeLibraryDir",native_library_directory);
	if(!torrc_content_local)
		torrc_content_local = torrc_content;
	if(ConstrainedSockSize)
	{
		if(tor_data_directory)
		{
			char* const args_cmd[] = {tor_location,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg6,arg7,arg8,p3,arg9,p4,arg10,arg11,arg12,tor_data_directory,NULL};
			pthread_rwlock_unlock(&mutex_global_variable);
			#ifdef WIN32
			ret = run_binary(&pid,NULL,fd_stdout,args_cmd,torrc_content_local);
			#else
			ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			#endif
		}
		else
		{
			char* const args_cmd[] = {tor_location,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg6,arg7,arg8,p3,arg9,p4,arg10,arg11,NULL};
			pthread_rwlock_unlock(&mutex_global_variable);
			#ifdef WIN32
			ret = run_binary(&pid,NULL,fd_stdout,args_cmd,torrc_content_local);
			#else
			ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			#endif
		}
	}
	else
	{
		if(tor_data_directory)
		{
			char* const args_cmd[] = {tor_location,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg9,p4,arg10,arg11,arg12,tor_data_directory,NULL};
			pthread_rwlock_unlock(&mutex_global_variable);
			#ifdef WIN32
			ret = run_binary(&pid,NULL,fd_stdout,args_cmd,torrc_content_local);
			#else
			ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			#endif
		}
		else
		{
			char* const args_cmd[] = {tor_location,arg1,arg2,arg3,p1,arg4,p2,arg5,control_password_hash,arg9,p4,arg10,arg11,NULL};
			pthread_rwlock_unlock(&mutex_global_variable);
			#ifdef WIN32
			ret = run_binary(&pid,NULL,fd_stdout,args_cmd,torrc_content_local);
			#else
			ret = run_binary(&pid,NULL,&fd_stdout,args_cmd,torrc_content_local);
			#endif
		}
	}
	torx_free((void*)&ret); // we don't use this and it should be null anyway
	if(torrc_content_local != torrc_content)
		torx_free((void*)&torrc_content_local);
	pthread_rwlock_wrlock(&mutex_global_variable);
	#ifdef WIN32
	tor_fd_stdout = fd_stdout;
	#else
	tor_fd_stdout = fd_stdout;
	#endif
	tor_pid = pid;
	pthread_rwlock_unlock(&mutex_global_variable);
	pthread_mutex_unlock(&mutex_tor_pipe);
	pid_write(pid);
	#ifdef WIN32
	if(pthread_create(&thrd_tor_log_reader,&ATTR_DETACHED,&tor_log_reader,fd_stdout))
		error_simple(-1,"Failed to create thread");
	#else
	if(pthread_create(&thrd_tor_log_reader,&ATTR_DETACHED,&tor_log_reader,itovp(fd_stdout)))
		error_simple(-1,"Failed to create thread");
	#endif
	pthread_rwlock_rdlock(&mutex_global_variable);
	error_printf(1,"Tor PID: %d",tor_pid);
	error_printf(1,"Tor SOCKS Port: %u",tor_socks_port);
	error_printf(3,"Tor Control Port: %u",tor_ctrl_port);
	pthread_rwlock_unlock(&mutex_global_variable);
	sql_populate_peer();
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

static inline void *broadcast_threaded(void *arg)
{ // TODO this runs forever even when nothing is queued. TODO for safety, it should ONLY RUN WHEN WE ARE CONNECTED, otherwise it will queue up all our messages and then send them all at once when we get online... totally defeating the purpose of a queue
	(void) arg;
	pusher(zero_pthread,(void*)&thrd_broadcast)
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	unsigned int broadcast_delay_local;
	while(1)
	{
		broadcast_delay_local = BROADCAST_DELAY_SLEEP;
		pthread_rwlock_rdlock(&mutex_broadcast);
		int random_start_1 = rand() % BROADCAST_QUEUE_SIZE; // Call rand() once as the starting position then iterate.
		for(int iter1 = 0; iter1 < BROADCAST_QUEUE_SIZE ; iter1++,random_start_1++)
		{ // choose a random broadcast
			int random_broadcast = random_start_1;
			if(random_broadcast >= BROADCAST_QUEUE_SIZE)
				random_broadcast -= BROADCAST_QUEUE_SIZE;
			if(broadcasts_queued[random_broadcast].hash)
			{ // found one
			//	error_simple(0,"Checkpoint threaded 1: chose random broadcast");
				int random_start_2 = rand() % BROADCAST_MAX_PEERS; // Call rand() once as the starting position then iterate.
				for(int iter2 = 0; iter2 < BROADCAST_MAX_PEERS ; iter2++,random_start_2++)
				{ // choose a random peer to send it to
					int random_peer = random_start_2;
					if(random_peer >= BROADCAST_MAX_PEERS)
						random_peer -= BROADCAST_MAX_PEERS;
					const int n = broadcasts_queued[random_broadcast].peers[random_peer]; // note: we're not checking if peer is online because might be a group
					if(n == -1) // faster to have this check before we retrieve owner/online status
						continue;
					const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
					const uint8_t sendfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t recvfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
					const uint8_t online = sendfd_connected + recvfd_connected;
					if(online || owner == ENUM_OWNER_GROUP_CTRL)
					{ // chose one and send to it, then delist if applicable
						error_printf(0,"Checkpoint threaded 2: chose ONLINE victim owner=%u",owner); // TODO this must trigger if 1 triggers TODO
						message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						pthread_rwlock_unlock(&mutex_broadcast);
						pthread_rwlock_wrlock(&mutex_broadcast);
						broadcasts_queued[random_broadcast].peers[random_peer] = -1;
						int more_peers = -1;
						for(int iter3 = 0; iter3 < BROADCAST_MAX_PEERS ; iter3++)
							if((more_peers = broadcasts_queued[random_broadcast].peers[iter3]) > -1)
							{
								error_simple(0,"Checkpoint still peers to send to");
								break;
							}
						if(more_peers > -1)
							break;
						error_simple(0,"Checkpoint broadcast sent to all peers");
						broadcasts_queued[random_broadcast].hash = 0; // broadcast has been sent to last peer
						sodium_memzero(broadcasts_queued[random_broadcast].broadcast,GROUP_BROADCAST_LEN);
						broadcast_delay_local = BROADCAST_DELAY; // sent something, so set the lower delay
						break;
					}
//printf("Checkpoint threaded 2: chose OFFLINE victim owner=%u\n",owner); // TODO this must trigger if 1 triggers TODO
				}
				break;
			}
		}
		pthread_rwlock_unlock(&mutex_broadcast);
		sleep(broadcast_delay_local);
	}
	return NULL;
}

static inline void broadcast_start(void)
{ // Should run from late in initial_keyed, after everything is loaded
	if(pthread_create(&thrd_broadcast,&ATTR_DETACHED,&broadcast_threaded,NULL))
		error_simple(-1,"Failed to create thread");
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
	if(tor_location == NULL)
		tor_location = which("tor");
	if(tor_location == NULL)
		error_simple(-1,"Tor could not be located. Please install Tor or report this bug.");
	get_tor_version();
	/* Generate Tor Control Password and Start Tor */
	random_string(control_password_clear,sizeof(control_password_clear));
	hash_password(control_password_clear);

	tor_ctrl_port = randport(0);
	tor_socks_port = randport(9050);
	if(tor_socks_port < 1025)
		tor_socks_port = randport(0);
	start_tor(); // XXX NOTE: might need to make this independently called by UI because on mobile it might be a problem to exec binaries within native code

	if(BROADCAST_QUEUE)
	{
		sodium_memzero(broadcasts_queued,sizeof(broadcasts_queued));
		for(int iter1 = 0; iter1 < BROADCAST_QUEUE_SIZE; iter1++)
			for(int iter2 = 0; iter2 < BROADCAST_MAX_PEERS; iter2++)
				broadcasts_queued[iter1].peers[iter2] = -1;
		broadcast_start();
	}
	keyed = 1; // KEEP THIS AT THE END, after start_tor, etc.
}

static void initialize_offer(const int n,const int f,const int o) // XXX do not put locks in here
{ // initalize an iter of the offer struc.
	peer[n].file[f].offer[o].offerer_n = -1;
	peer[n].file[f].offer[o].offer_info = NULL;
//	peer[n].file[f].offer[o].utilized = 0; // not necessary UNLESS we are using more than 2 sockets concurrently (ie, we are downloading from multiple peers concurrently)
}

static void initialize_f(const int n,const int f) // XXX do not put locks in here
{ // initalize an iter of the file struc.
	sodium_memzero(peer[n].file[f].checksum,sizeof(peer[n].file[f].checksum));
	peer[n].file[f].filename = NULL;
	peer[n].file[f].file_path = NULL;
	peer[n].file[f].size = 0;
	peer[n].file[f].status = 0;
	peer[n].file[f].full_duplex = threadsafe_read_uint8(&mutex_global_variable,&full_duplex_requests); // NOTE: affects outbound
	peer[n].file[f].modified = 0;
	peer[n].file[f].splits = 0;
	peer[n].file[f].split_path = NULL;
	peer[n].file[f].split_info = NULL;
	peer[n].file[f].split_status = NULL;
	peer[n].file[f].split_status_fd = NULL;
	sodium_memzero(peer[n].file[f].outbound_start,sizeof(peer[n].file[f].outbound_start));
	sodium_memzero(peer[n].file[f].outbound_end,sizeof(peer[n].file[f].outbound_end));
	sodium_memzero(peer[n].file[f].outbound_transferred,sizeof(peer[n].file[f].outbound_transferred));
	peer[n].file[f].split_hashes = NULL;
	peer[n].file[f].fd_out_recvfd = NULL;
	peer[n].file[f].fd_out_sendfd = NULL;
	peer[n].file[f].fd_in_recvfd = NULL;
	peer[n].file[f].fd_in_sendfd = NULL;
	peer[n].file[f].last_progress_update_time = 0;
	peer[n].file[f].last_progress_update_nstime = 0;
	peer[n].file[f].bytes_per_second = 0;
	peer[n].file[f].last_transferred = 0;
	peer[n].file[f].time_left = 0;
	peer[n].file[f].speed_iter = 0;
	sodium_memzero(peer[n].file[f].last_speeds,sizeof(peer[n].file[f].last_speeds));
	pthread_mutex_init(&peer[n].file[f].mutex_file, NULL);

	peer[n].file[f].offer = torx_insecure_malloc(sizeof(struct offer_list) *11); // NOT freeing, just ignore the lost bytes. see: fjadfweoifaf
	for(int j = 0; j < 11; j++) /* Initialize iter 0-10 */
		initialize_offer(n,f,j);

	initialize_f_cb(n,f);

//	note: we have no max counter for file struc.... we rely on checksum to never be zero'd after initialization (until shutdown or deletion of file). This is safe.
}

static void initialize_i(const int n,const int i) // XXX do not put locks in here
{ // initalize an iter of the messages struc
	peer[n].message[i].time = 0;
	peer[n].message[i].stat = 0;
	peer[n].message[i].p_iter = -1;
	peer[n].message[i].message = NULL;
	peer[n].message[i].message_len = 0;
	peer[n].message[i].pos = 0;
	peer[n].message[i].nstime = 0;

	initialize_i_cb(n,i);

//	note: our max is message_n which is handled elsewhere
}

static void initialize_n(const int n) // XXX do not put locks in here
{ // initalize an iter of the peer struc XXX ONLY used when expanding. Don't forget to also update zero_n(). TODO consider calling zero_n() here?
	peer[n].owner = 0;
	peer[n].status = 0;
	sodium_memzero(peer[n].privkey,sizeof(peer[n].privkey)); // peer[n].privkey[0] = '\0';
//	sodium_memzero(peer[n].hashed_privkey,sizeof(peer[n].hashed_privkey));
	peer[n].peer_index = -2; // MUST be lower than -1 to properly error by sql_setting if unset
	sodium_memzero(peer[n].onion,sizeof(peer[n].onion)); // peer[n].onion[0] = '\0';
	sodium_memzero(peer[n].torxid,sizeof(peer[n].torxid));
	peer[n].peerversion = 0;
	sodium_memzero(peer[n].peeronion,sizeof(peer[n].peeronion)); // peer[n].peeronion[0] = '\0';
	sodium_memzero(peer[n].peernick,sizeof(peer[n].peernick)); // peer[n].peernick[0] = '\0';
	peer[n].log_messages = 0;
	peer[n].last_seen = 0;
	peer[n].v3auth = 0;
	peer[n].vport = 0;
	peer[n].tport = 0;
	peer[n].socket_utilized[0] = -1;
	peer[n].socket_utilized[1] = -1;
	peer[n].sendfd = 0;
	peer[n].recvfd = 0;
	peer[n].sendfd_connected = 0;
	peer[n].recvfd_connected = 0;
	peer[n].bev_send = NULL;
	peer[n].bev_recv = NULL;
	peer[n].message_n = 0;
	sodium_memzero(peer[n].sign_sk,crypto_sign_SECRETKEYBYTES);
	sodium_memzero(peer[n].peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	sodium_memzero(peer[n].invitation,crypto_sign_BYTES);
//	peer[n].buffer = NULL;
//	peer[n].buffer_len = 0;
//	peer[n].untrusted_message_len = 0;
	peer[n].blacklisted = 0;
	pthread_rwlock_init(&peer[n].mutex_page,NULL);
	peer[n].thrd_send = 0;
	peer[n].thrd_recv = 0;

	initialize_n_cb(n); // must be before initialize_i/f

	peer[n].message = torx_secure_malloc(sizeof(struct message_list) *11);
	for(int j = 0; j < 11; j++) /* Initialize iter 0-10 */
		initialize_i(n,j);

	peer[n].file = torx_secure_malloc(sizeof(struct file_list) *11);
	for(int j = 0; j < 11; j++) /* Initialize iter 0-10 */
		initialize_f(n,j);

	max_peer++;

//	initialize_o(n); // depreciate, do not place here
}

static void initialize_g(const int g) // XXX do not put locks in here
{ // initalize an iter of the group struc
	sodium_memzero(group[g].id,GROUP_ID_SIZE);
	group[g].n = -1;
	group[g].hash = 0; // please don't initialize as -1
	group[g].peercount = 0; // please don't initialize as -1
	group[g].msg_count = 0; // please don't initialize as -1
	group[g].peerlist = NULL;
	group[g].invite_required = 0;
	group[g].msg_index_iter = 0;
	group[g].msg_index = NULL;
	group[g].msg_first = NULL;
	group[g].msg_last = NULL;
	initialize_g_cb(g);
	max_group++;
}

void re_expand_callbacks(void)
{ // UI helper function for re-calling the expand struct callbacks (useful when UI is disposed) // WARNING: if conditions must be equal to those in expand_*_struct functions
	char onion = '\0';
	unsigned char checksum[CHECKSUM_BIN_LEN];
	for(int n = 0; ; n += 10)
	{
		getter_array(&onion,1,n,-1,-1,-1,offsetof(struct peer_list,onion));
		if(onion == '\0' && getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index)) < 0 && n%10 == 0 && n+10 > max_peer)
			break;
		error_simple(0,"Checkpoint re_expand_callbacks n");
		expand_peer_struc_cb(n);
		for(int nn = n+10; nn > n; nn--)
		{
			initialize_n_cb(nn);
			const int message_n = getter_int(nn,-1,-1,-1,offsetof(struct peer_list,message_n));
			for(int i = 0; ; i += 10)
			{
				const int p_iter = getter_int(nn,i,-1,-1,offsetof(struct message_list,p_iter));
				if(p_iter == -1 && i%10 == 0 && i+10 > message_n)
					break;
				error_simple(0,"Checkpoint re_expand_callbacks i");
				expand_messages_struc_cb(nn,i);
				for(int j = i+10; j > i; j--)
					initialize_i_cb(nn,j);
			}
			for(int f = 0; ; f += 10)
			{
				getter_array(&checksum,sizeof(checksum),nn,-1,f,-1,offsetof(struct file_list,checksum));
				if(is_null(checksum,CHECKSUM_BIN_LEN) && f%10 == 0)
					break;
				error_simple(0,"Checkpoint re_expand_callbacks f");
				expand_file_struc_cb(nn,f);
				for(int j = f+10; j > f; j--)
					initialize_f_cb(nn,j);
			}
		}
	}
	for(int g = 0; ; g += 10)
	{
		pthread_rwlock_rdlock(&mutex_expand_group); // XXX
		if(is_null(group[g].id,GROUP_ID_SIZE) && g%10 == 0 && g+10 > max_group)
		{
			pthread_rwlock_unlock(&mutex_expand_group); // XXX
			break;
		}
		pthread_rwlock_unlock(&mutex_expand_group); // XXX
		error_simple(0,"Checkpoint re_expand_callbacks g");
		expand_group_struc_cb(g);
		for(int j = g+10; j > g; j--)
			initialize_g_cb(j);
	}
}

static inline void expand_offer_struc(const int n,const int f,const int o)
{ /* Expand offer struct if our current o is unused && divisible by 10 */
	if(n < 0 || f < 0 || o < 0)
	{
		error_simple(0,"expand_offer_struc failed sanity check. Coding error. Report this.");
		return;
	}
	const int offerer_n = getter_int(n,-1,f,o,offsetof(struct offer_list,offerer_n));
	if(offerer_n == -1 && f%10 == 0)
	{ // Safe to cast f as size_t because > -1
		torx_write(n) // XXX
		peer[n].file[f].offer = torx_realloc(peer[n].file[f].offer,/*sizeof(struct offer_list)*((size_t)o+1),*/ sizeof(struct offer_list)*((size_t)o+1) + sizeof(struct offer_list) *10);
		// callback unnecessary, not doing
		for(int j = o+10; j > o; j--)
			initialize_offer(n,f,j);
		torx_unlock(n) // XXX
	}
}

static inline void expand_file_struc(const int n,const int f)
{ /* Expand file struct if our current f is unused && divisible by 10 */
	if(n < 0 || f < 0)
	{
		error_simple(0,"expand_file_struc failed sanity check. Coding error. Report this.");
		return;
	}
	unsigned char checksum[CHECKSUM_BIN_LEN];
	getter_array(&checksum,sizeof(checksum),n,-1,f,-1,offsetof(struct file_list,checksum));
	if(is_null(checksum,CHECKSUM_BIN_LEN) && f%10 == 0) // XXX not using && f+10 > max_file because we never clear checksum so it is currently a reliable check
	{ // Safe to cast f as size_t because > -1
		torx_write(n) // XXX
		peer[n].file = torx_realloc(peer[n].file, sizeof(struct file_list)*((size_t)f+1) + sizeof(struct file_list) *10);
		expand_file_struc_cb(n,f);
		for(int j = f+10; j > f; j--)
			initialize_f(n,j);
		torx_unlock(n) // XXX
	}
	sodium_memzero(checksum,sizeof(checksum));
}

void expand_messages_struc(const int n,const int i)
{ /* Expand messages struct if our current i is unused && divisible by 10 */
//printf("Checkpoint expand_messages_struc: n=%d i=%d\n",n,i);
	if(n < 0 || i < 0)
	{
		error_simple(0,"expand_messages_struc failed sanity check. Coding error. Report this.");
		return;
	}
	const int message_n = getter_int(n,-1,-1,-1,offsetof(struct peer_list,message_n));
	const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
	if(p_iter == -1 && i%10 == 0 && i+10 > message_n)
	{ // Safe to cast i as size_t because > -1
		torx_write(n) // XXX
		peer[n].message = torx_realloc(peer[n].message, sizeof(struct message_list)*((size_t)i+1) + sizeof(struct message_list) *10);
		expand_messages_struc_cb(n,i);
		for(int j = i+10; j > i; j--)
			initialize_i(n,j);
		torx_unlock(n) // XXX
	}
}

static inline void expand_peer_struc(const int n)
{ /* Expand peer struct if our current n is unused && divisible by 10 */
	if(n < 0)
	{
		error_simple(0,"expand_peer_struc failed sanity check. Coding error. Report this.");
		return;
	}
	char onion = '\0';
	getter_array(&onion,1,n,-1,-1,-1,offsetof(struct peer_list,onion));
	if(n > -1 && onion == '\0' && getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index)) < 0 && n%10 == 0 && n+10 > max_peer)
	{ // Safe to cast n as size_t because > -1
		pthread_rwlock_wrlock(&mutex_expand);
		peer = torx_realloc(peer, sizeof(struct peer_list)*((size_t)n+1) + sizeof(struct peer_list) *10);
		expand_peer_struc_cb(n);
		for(int j = n+10; j > n; j--)
			initialize_n(j);
		pthread_rwlock_unlock(&mutex_expand);
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
	if(is_null(group[g].id,GROUP_ID_SIZE) && g%10 == 0 && g+10 > max_group)
	{ // Safe to cast g as size_t because > -1
		group = torx_realloc(group,sizeof(struct group_list)*((size_t)g+1) + sizeof(struct group_list) *10);
		expand_group_struc_cb(g);
		for(int j = g+10; j > g; j--)
			initialize_g(j);
	}
}

int set_last_message(int *nn,const int n,const int count_back)
{ /* Helper to determine the last message worth displaying in peer list. UI can use this or an alternative. */ // WARNING: May return -1;
	int finalized_count_back = count_back;
	int current_count_back = 0;
	if(finalized_count_back < 1) // non-fatal sanity check
		finalized_count_back = 0;
	const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Last message for a group
		if(!nn)
		{
			error_simple(0,"Set_last_message: nn must not be NULL. Coding error. Report this.");
			return -1;
		}
		const int g = set_g(n,NULL);
		pthread_rwlock_rdlock(&mutex_expand_group);
		struct msg_list *page = group[g].msg_last;
		pthread_rwlock_unlock(&mutex_expand_group);
		while(page)
		{
			const int p_iter = getter_int(page->n,page->i,-1,-1,offsetof(struct message_list,p_iter));
			if(p_iter > -1 && threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) && current_count_back++ == finalized_count_back)
			{
				*nn = page->n;
				return page->i;
			}
			page = page->message_prior;
		}
		*nn = n;
		return -1;
	}
	else
	{ // Last message for non-group
		const int message_n = getter_int(n,-1,-1,-1,offsetof(struct peer_list,message_n));
		int i = message_n-1;
		if(i > -1)
		{ // Critical check
		//	for(int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter)); threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) == 0 ; p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter)))
		//		if(--i == -1) // do NOT modify. this should be --i, not i++
		//			break;
			while(1)
			{ // DO NOT CHANGE ORDER OR LOGIC. The logic is complex
				const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
				if((p_iter > -1 && threadsafe_read_uint8(&mutex_protocols,&protocols[p_iter].notifiable) && current_count_back++ == finalized_count_back) || --i < 0)
					break;
			}
		}
		if(nn)
			*nn = n;
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
			torx_read(n) // XXX
			if(onion) // search by onion
				while((peer[n].onion[0] != '\0' || peer[n].peer_index > -1) && strncmp(peer[n].onion,onion,56))
				{
					torx_unlock(n++) // XXX
					torx_read(n) // XXX
				}
			else // find next blank
				while(peer[n].onion[0] != '\0' || peer[n].peer_index > -1)
				{
					torx_unlock(n++) // XXX
					torx_read(n) // XXX
				}
			torx_unlock(n) // XXX
		}
		else if(peer_index > -1)
		{ // set n from peer_index (sql related)
			torx_read(n) // XXX
			while(peer[n].peer_index != peer_index && (peer[n].onion[0] != '\0' || peer[n].peer_index > -1))
			{
				torx_unlock(n++) // XXX
				torx_read(n) // XXX
			}
			if(peer[n].peer_index != peer_index && onion != NULL)
			{// Blank, go to onion check. IMPORTANT for NAA1AmTDLE: instead of exclusively prioritizing peer_index if both are passed, peer_index is checked first and then .onion is checked, before settling on blank.
				torx_unlock(n) // XXX
				n = 0;
				onion_check = 1;
				continue;
			}
			torx_unlock(n) // XXX
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
		setter(n,-1,-1,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
	if(onion) // do NOT put 'else if'
		setter(n,-1,-1,-1,offsetof(struct peer_list,onion),onion,strlen(onion)); // source is pointer. NOTE: strlen looks odd but it is in case we are looking up with only a partial
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
	pthread_rwlock_rdlock(&mutex_expand_group); // XXX
	if(n > -1 && (owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner))) == ENUM_OWNER_GROUP_CTRL) // search for a GROUP_CTRL by n
		while((!is_null(group[g].id,GROUP_ID_SIZE) || group[g].n > -1) && group[g].n != n)
			g++;
	else if(n > -1 && owner == ENUM_OWNER_GROUP_PEER) // search for a GROUP_PEER by n
		while(!is_null(group[g].id,GROUP_ID_SIZE) || group[g].n > -1)
		{ // XXX EXPERIMENTAL
			uint32_t gg = 0;
			while(gg < group[g].peercount && group[g].peerlist[gg] != n)
				gg++;
			if(gg == group[g].peercount)
				g++; // was not in this group
			else
				break; // winner! set peer[n].associated_group here so that it only need be set once
		}
	else if(group_id)// search by group_id
		while((!is_null(group[g].id,GROUP_ID_SIZE) || group[g].n > -1) && memcmp(group[g].id,group_id,GROUP_ID_SIZE))
			g++;
	else // find next blank, allow re-use
		while((!is_null(group[g].id,GROUP_ID_SIZE) && memcmp(group[g].id,zero_array,GROUP_ID_SIZE)) || group[g].n > -1)
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
		pthread_rwlock_unlock(&mutex_expand_group); // XXX
		error_printf(-1,"Set_g landed on a blank group g==%d ENUM_OWNER_GROUP_PEER. Report this.",g); // TODO 2024/02/24 happened in a private group when clicking peerlist. Same group has allowed PMing wrong person
		error = 1;
	} */
	pthread_rwlock_unlock(&mutex_expand_group); // XXX
	pthread_rwlock_wrlock(&mutex_expand_group); // XXX
	expand_group_struc(g); // Expand struct if necessary
	if(!error && n > -1)
		if(owner == ENUM_OWNER_GROUP_CTRL) // necessary check, to ensure we're not setting group_n to GROUP_PEER
			group[g].n = n;
	if(group_id) // do NOT set 'else if'
		memcpy(group[g].id,group_id,GROUP_ID_SIZE);
//	if(group_id)
//		printf("Checkpoint GID: %s\n",b64_encode(group_id,GROUP_ID_SIZE));
/*	if(n > -1)
		printf("Checkpoint set_g by n, n==%d g==%d\n",n,g);
	else if(arg)
		printf("Checkpoint set_g by hash\n");
	else
		printf("Checkpoint set_g by fresh g==%d\n",g); */
	pthread_rwlock_unlock(&mutex_expand_group); // XXX
	return g;
}

int set_f(const int n,const unsigned char *checksum,const size_t checksum_len)
{ // Set the f initially via checksum search or truncated checksum. XXX BE CAREFUL: this function process on potentially dangerous peer messages. XXX
  // XXX BE AWARE: This function WILL return >-1 as long as CHECKSUM_BIN_LEN is passed as checksum_len XXX
	if(n < 0 || !checksum || checksum_len < 1)
	{
		error_simple(0,"n < 0 or null or 0 length checksum passed to set_f. Report this.");
		breakpoint();
		return -1;
	}
	int f = 0;
	uint64_t size;
//	while((size = getter_uint64(n,-1,f,-1,offsetof(struct file_list,size))) && memcmp(peer[n].file[f].checksum,checksum,checksum_len))
//		f++; // check if file already exists in our struct
	int cmp = 1;
	for( ; (size = getter_uint64(n,-1,f,-1,offsetof(struct file_list,size))) ; f++)
	{ // check if file already exists in our struct
		unsigned char checksum_local[CHECKSUM_BIN_LEN];
		getter_array(&checksum_local,sizeof(checksum_local),n,-1,f,-1,offsetof(struct file_list,checksum));
		cmp = memcmp(checksum_local,checksum,checksum_len);
		sodium_memzero(checksum_local,sizeof(checksum_local));
		if(!cmp) // prevent f++
			break;
	}
	if(checksum_len < CHECKSUM_BIN_LEN && size == 0)
		return -1; // do not put error message, valid reasons why this could occur
	expand_file_struc(n,f); // Expand struct if necessary
	// TODO if desired, reserve here. DO NOT RESERVE BEFORE EXPAND_ or it will be lost
	if(cmp) // does not exist yet at this n,f
		setter(n,-1,f,-1,offsetof(struct file_list,checksum),checksum,checksum_len); // source is pointer
	//	memcpy(peer[n].file[f].checksum,checksum,checksum_len);
	return f;
}

int set_g_from_i(uint32_t *untrusted_peercount,const int n,const int i)
{ // Returns -1 if message protocol isn't group offer. Helper function to be used on Group Offers.
	if(n < 0 || i < 0)
		return -1;
	const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	pthread_rwlock_unlock(&mutex_protocols);
	if(protocol != ENUM_PROTOCOL_GROUP_OFFER && protocol != ENUM_PROTOCOL_GROUP_OFFER_FIRST)
		return -1;
	const uint32_t message_len = getter_uint32(n,i,-1,-1,offsetof(struct message_list,message_len));
	if((protocol == ENUM_PROTOCOL_GROUP_OFFER && message_len < GROUP_OFFER_LEN) || (protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST && message_len < GROUP_OFFER_FIRST_LEN))
		return -1;
	char tmp_message[GROUP_ID_SIZE + sizeof(uint32_t)];
	torx_read(n) // XXX
	memcpy(tmp_message,peer[n].message[i].message,sizeof(tmp_message));
	torx_unlock(n) // XXX
	const int g = set_g(-1,tmp_message);
	if(untrusted_peercount)
		*untrusted_peercount = be32toh(align_uint32((void*)&tmp_message[GROUP_ID_SIZE]));
	sodium_memzero(tmp_message,sizeof(tmp_message));
	return g;
}

int set_f_from_i(const int n,const int i)
{ // Returns -1 if message protocol lacks file_checksum
	if(n < 0 || i < 0)
		return -1;
	const uint32_t message_len = getter_uint32(n,i,-1,-1,offsetof(struct message_list,message_len));
	if(message_len < CHECKSUM_BIN_LEN)
		return -1;
	const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint8_t file_checksum = protocols[p_iter].file_checksum;
	pthread_rwlock_unlock(&mutex_protocols);
	if(!file_checksum)
		return -1;
	unsigned char checksum[CHECKSUM_BIN_LEN];
	memcpy(checksum,peer[n].message[i].message,sizeof(checksum));
	const int f = set_f(n,checksum,sizeof(checksum));
	sodium_memzero(checksum,sizeof(checksum));
	return f;
}

int set_o(const int n,const int f,const int passed_offerer_n)
{ // set offer iterator
	if(n < 0 || f < 0 || passed_offerer_n < 0)
		return -1;
	int o = 0;
	int offerer_n;
	while((offerer_n = getter_int(n,-1,f,o,offsetof(struct offer_list,offerer_n))) > -1 && offerer_n != passed_offerer_n)
		o++; // check if offerer already exists in our struct
	expand_offer_struc(n,f,o); // Expand struct if necessary
	// TODO if desired, reserve here. DO NOT RESERVE BEFORE EXPAND_ or it will be lost
	setter(n,-1,f,o,offsetof(struct offer_list,offerer_n),&passed_offerer_n,sizeof(passed_offerer_n));
	return o;
}

int group_online(const int g)
{ // Returns number of online peers (Only measures those we are connected to, 
	int online = 0;
	pthread_rwlock_rdlock(&mutex_expand_group);
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group);
	if(peerlist != NULL)
	{
		const uint32_t peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t nn = 0 ; nn < peercount ; nn++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group);
			const uint8_t sendfd_connected = getter_uint8(peer_n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
			if(sendfd_connected == 1)
				online++;
		}
	}
	return online;
}

int group_check_sig(const int g,const char *message,const uint32_t message_len,const uint16_t untrusted_protocol,const unsigned char *sig,const char *peeronion_prefix)
{ // This function checks signatures of messages sent to a GROUP_CTRL and returns who sent them. NOTICE: message_len is peer struct message_len, so contains signature if appropriate
// Any length of prefix can be passed, NULL / 0-56. If there are multiple matches (ex: short prefix), each will be tried.
//TODO This could be a burden on file transfers and it might be worthwhile in the future to assign peers to a specific port or otherwise authenticate sockets/streams instead.
	uint32_t signature_len = 0;
	if(untrusted_protocol)
	{
		const int untrusted_p_iter = protocol_lookup(untrusted_protocol);
		if(untrusted_p_iter < 0)
		{
			error_simple(0,"Peer sent an untrusted protocol that we don't recognize. We're not checking its signature validity because we don't know what it is.");
			breakpoint();
			return -1;
		}
		pthread_rwlock_rdlock(&mutex_protocols);
		signature_len = protocols[untrusted_p_iter].signature_len;
		pthread_rwlock_unlock(&mutex_protocols);
	}
	const int group_n = getter_group_int(g,offsetof(struct group_list,n));
	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	size_t peeronion_len = 0;
	if(peeronion_prefix)
		peeronion_len = strlen(peeronion_prefix);
	pthread_rwlock_rdlock(&mutex_expand_group);
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group);
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
		prefixed_message = affix_protocol_len(untrusted_protocol,message, message_len - signature_len);
		prefix_length = 2+4;
	}
	if(peerlist) // NOTE: peerlist is null when adding first peer, so we skip and check for self-sign
		for(uint32_t nn = 0; nn != g_peercount; nn++)
		{
			pthread_rwlock_wrlock(&mutex_expand_group); // YES this is wrlock
			const int peer_n = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group);
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),peer_n,-1,-1,-1,offsetof(struct peer_list,peeronion));
			unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
			getter_array(&peer_sign_pk,sizeof(peer_sign_pk),peer_n,-1,-1,-1,offsetof(struct peer_list,peer_sign_pk));
			if((peeronion_len == 0 || !memcmp(peeronion,peeronion_prefix,peeronion_len)) && crypto_sign_verify_detached(sig,(const unsigned char *)(untrusted_protocol ? prefixed_message : message), prefix_length + message_len - signature_len, peer_sign_pk) == 0)
			{
				sodium_memzero(peeronion,sizeof(peeronion));
				sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
			//	printf("Checkpoint SUCCESS of GROUP peer-sign: %u\n",untrusted_protocol);
				error_simple(4,"Success of group_check_sig: Signed by a peer.");
				torx_free((void*)&prefixed_message);
				return peer_n;
			}
		//	else // Failure here isn't really failure. It just means we check the next one.
		//		printf(YELLOW"Checkpoint signing pk key: %s\n"RESET,b64_encode(peer_sign_pk,sizeof(peer_sign_pk)));
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
	getter_array(&sign_sk,sizeof(sign_sk),group_n,-1,-1,-1,offsetof(struct peer_list,sign_sk));
	crypto_sign_ed25519_sk_to_pk(ed25519_pk,sign_sk);
	sodium_memzero(sign_sk,sizeof(sign_sk));
	if(crypto_sign_verify_detached(sig,(const unsigned char *)(untrusted_protocol ? prefixed_message : message), prefix_length + message_len - signature_len, ed25519_pk) == 0)
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
		error_printf(3,MAGENTA"Checkpoint failed message(b64) of len %lu: %s"RESET,message_len-signature_len,b64_encode(message, message_len-signature_len));
	//	breakpoint();
	}
	else if(g_peercount != 0)
	{ // old depreciated note: this occurs when joining a new group.... its not fatal error always (TODO remove this note)
		error_simple(0,"Failure of sanity check in group_check_sig: Peerlist is null while peercount is not 0. Report this.");
		breakpoint();
	}
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
	pthread_mutex_lock(&mutex_group_peer_add);
	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
	pthread_rwlock_rdlock(&mutex_expand_group);
	const int *peerlist = group[g].peerlist;
	pthread_rwlock_unlock(&mutex_expand_group);
	if(peerlist)
	{
		char onion_group_n[56+1];
		getter_array(&onion_group_n,sizeof(onion_group_n),group_n,-1,-1,-1,offsetof(struct peer_list,onion));
		for(uint32_t nn = 0 ; nn < g_peercount ; nn++) // check for existing before adding
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int nnn = group[g].peerlist[nn];
			pthread_rwlock_unlock(&mutex_expand_group);
			char peeronion[56+1];
			getter_array(&peeronion,sizeof(peeronion),nnn,-1,-1,-1,offsetof(struct peer_list,peeronion));
			const int ret = memcmp(peeronion,local_group_peeronion,56);
			sodium_memzero(peeronion,sizeof(peeronion));
			if(!ret || !memcmp(onion_group_n,local_group_peeronion,56))
			{
				pthread_mutex_unlock(&mutex_group_peer_add);
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
			pthread_mutex_unlock(&mutex_group_peer_add);
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
				pthread_mutex_unlock(&mutex_group_peer_add);
				error_simple(0,"Group requires invite but peer failed signature check.");
				sodium_memzero(peer_invite,sizeof(peer_invite));
				sodium_memzero(local_group_peeronion,sizeof(local_group_peeronion));
				return -1;
			}
		}
		sodium_memzero(peer_invite,sizeof(peer_invite));
	}
	const char *local_group_peernick;
	char nick_array[56+1] = {0};
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
		pthread_mutex_unlock(&mutex_group_peer_add);
		error_simple(0,"Coding error 57518. Report this.");
		breakpoint();	
		return -1;
	}
	sql_update_peer(n); // saves group_peer_ed25519_pk
	// Associate it with a group, save setting
//	const int peer_index = getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index));
	char setting_name[64]; // arbitrary size
	snprintf(setting_name,sizeof(setting_name),"group_peer%d",peer_index); // "group_peer" + peer_index, for uniqueness. might make deleting complex.
	const int peer_index_group = getter_int(group_n,-1,-1,-1,offsetof(struct peer_list,peer_index));
	sql_setting(0,peer_index_group,setting_name,"",0);
	// Add it to our peerlist
	pthread_rwlock_wrlock(&mutex_expand_group);
	if(group[g].peerlist)
	{
		error_simple(0,"Checkpoint realloc called in group_add_peer");
		group[g].peerlist = torx_realloc(group[g].peerlist,((size_t)g_peercount+1)*sizeof(int));
	}
	else
		group[g].peerlist = torx_insecure_malloc(((size_t)g_peercount+1)*sizeof(int));
	group[g].peerlist[group[g].peercount] = n;
	group[g].peercount++;
//	printf("Checkpoint group_add_peer g==%d peercount==%u\n",g,group[g].peercount);
	pthread_rwlock_unlock(&mutex_expand_group);
	pthread_mutex_unlock(&mutex_group_peer_add);
	load_onion(n); // connect to their onion with our signed onion, also in sql_populate_peer()
	peer_new_cb(n);
	return n;
}

static inline void broadcast_remove(const int g)
{ // Remove hash from queue because we joined the group successfully, or for other reasons
	if(g < 0)
		return;
	pthread_rwlock_rdlock(&mutex_expand_group);
	const uint32_t hash = group[g].hash;
	pthread_rwlock_unlock(&mutex_expand_group);
	if(!hash)
		return;
	pthread_rwlock_rdlock(&mutex_broadcast);
	for(int iter1 = 0; iter1 < BROADCAST_QUEUE_SIZE; iter1++)
		if(broadcasts_queued[iter1].hash == hash)
		{
			pthread_rwlock_unlock(&mutex_broadcast);
			pthread_rwlock_wrlock(&mutex_broadcast);
			broadcasts_queued[iter1].hash = 0;
			sodium_memzero(broadcasts_queued[iter1].broadcast,GROUP_BROADCAST_LEN);
			for(int iter2 = 0; iter2 < BROADCAST_MAX_PEERS; iter2++)
				broadcasts_queued[iter1].peers[iter2] = -1;
			error_simple(0,WHITE"Checkpoint removed a hash successfully\n"RESET); // great!
			break;
		}
	pthread_rwlock_unlock(&mutex_broadcast);
}

void broadcast_add(const int origin_n,const unsigned char broadcast[GROUP_BROADCAST_LEN])
{ // Add or discard a broadcast, depending on queue and whether it has already been added/sent
// "Broadcast should be added to queue if checksum (single int) is not in broadcast_history array. Queue should store an integer hash of each sent broadcast to avoid repetition. It should also be rate limited (random rate, random delays) to avoid facilitating mapping of the network. Broadcast thread should run perpetually if there is anything in the queue, otherwise close. Broadcasts exceeding queue should be discarded? Undecided."
// TODO (?) Queue should take note of how many broadcasts came from each user
	if(!broadcast)
	{
		error_simple(0,"Sanity check fail in broadcast_add. Coding error. Report this.");
		breakpoint();
		return;
	}
	const uint32_t hash = fnv1a_32_salted(broadcast,GROUP_BROADCAST_LEN);
	pthread_rwlock_rdlock(&mutex_broadcast);
printf(WHITE"Checkpoint broadcast_add 1\n"RESET);
	for(int iter1 = 0; iter1 < BROADCAST_HISTORY_SIZE; iter1++)
	{
		if(broadcast_history[iter1] == 0)
		{ // Not in queued/sent list, add it
printf(WHITE"Checkpoint broadcast_add 2: adding\n"RESET);
			int iter2 = 0;
			for(; iter2 < BROADCAST_QUEUE_SIZE; iter2++)
				if(broadcasts_queued[iter2].hash == 0)
				{ // found empty slot
					pthread_rwlock_unlock(&mutex_broadcast);
					pthread_rwlock_wrlock(&mutex_broadcast);
					broadcasts_queued[iter2].hash = hash;
					memcpy(broadcasts_queued[iter2].broadcast,broadcast,GROUP_BROADCAST_LEN);
					int origin_group_n = origin_n;
					if(origin_n > -1)
					{ // This can only trigger from goto send_out
						const uint8_t owner = getter_uint8(origin_n,-1,-1,-1,offsetof(struct peer_list,owner));
						if(owner == ENUM_OWNER_GROUP_PEER)
						{
							const int g = set_g(origin_n,NULL);
							origin_group_n = getter_group_int(g,offsetof(struct group_list,n));
						}
					}
					int iter3 = BROADCAST_MAX_PEERS - 1;
					int n = 0;
					torx_read(n) // XXX
					while(iter3 > -1)
					{
						if(peer[n].onion[0] == '\0' && peer[n].peer_index == -2)
							break;
						const uint8_t owner = peer[n].owner;
						const uint8_t status = peer[n].status;
						if(n != origin_group_n && status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER))
							broadcasts_queued[iter2].peers[iter3] = n; // TODO using GROUP_PEER instead of GROUP_CTRL so we can check online status later
						torx_unlock(n++) // XXX
						torx_read(n) // XXX
						iter3--;
					}
					torx_unlock(n) // XXX
printf(WHITE"Checkpoint broadcast_add 3: got slot, peers=%d\n"RESET,BROADCAST_MAX_PEERS-iter3);
					break;
				}
			if(iter2 == BROADCAST_QUEUE_SIZE)
			{
				error_simple(0,"Queue is full. Broadcast will be discarded.");
				break; // queue is full, bail out. broadcast will be discarded.
			}
printf(WHITE"Checkpoint broadcast_add 4: queued!\n"RESET);
			broadcast_history[iter1] = hash; // NOTE: this is sent OR queued
			break;
		}
		else if(broadcast_history[iter1] == hash)
		{
			error_simple(0,"Broadcast already queued. Broadcast will be discarded.");
			break; // Already in queued/sent list, bail
		}
	}
	pthread_rwlock_unlock(&mutex_broadcast);
}

void broadcast_prep(unsigned char ciphertext[GROUP_BROADCAST_LEN],const int g)
{ // Audited 2024/02/15 // ciphertext must be an array sized 48 + 16 + 56 + 32 (crypto_box_SEALBYTES + crypto_pwhash_SALTBYTES + 56 + crypto_box_PUBLICKEYBYTES)
	if(ciphertext == NULL || g < 0)
	{
		error_simple(0,"Sanity check in broadcast_prep failed. Coding error. Report this.");
		breakpoint();
		return;
	}
	const int group_n = getter_group_int(g,offsetof(struct group_list,n));
	unsigned char message[GROUP_BROADCAST_DECRYPTED_LEN];
	randombytes_buf(message,crypto_pwhash_SALTBYTES); // salt the message. crypto_pwhash_SALTBYTES is 16
	getter_array(&message[crypto_pwhash_SALTBYTES],56,group_n,-1,-1,-1,offsetof(struct peer_list,onion)); // affix the group_n
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	getter_array(&sign_sk,sizeof(sign_sk),group_n,-1,-1,-1,offsetof(struct peer_list,sign_sk));
	crypto_sign_ed25519_sk_to_pk(&message[crypto_pwhash_SALTBYTES+56],sign_sk); // affix the pk of size crypto_box_PUBLICKEYBYTES
	sodium_memzero(sign_sk,sizeof(sign_sk));
	unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
	pthread_rwlock_rdlock(&mutex_expand_group);
	crypto_scalarmult_base(recipient_pk, group[g].id); // convert sk_to_pk
	pthread_rwlock_unlock(&mutex_expand_group);
	crypto_box_seal(ciphertext, message, sizeof(message), recipient_pk); // add some error checking? is of value or perhaps not?
	sodium_memzero(message,sizeof(message));
	sodium_memzero(recipient_pk,sizeof(recipient_pk));

	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
	if(!g_peercount)
	{ // store the hash so that we can broadcast_remove the broadcast from queue after we join the group
		const uint32_t hash = fnv1a_32_salted(ciphertext,GROUP_BROADCAST_LEN);
		pthread_rwlock_wrlock(&mutex_expand_group);
		group[g].hash = hash;
		pthread_rwlock_unlock(&mutex_expand_group);
	}
}

void broadcast(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN])
{ // Origin_n is utilized on recv, origin_n == -1 is utilized when sending
	// TODO put message_send here on some sort of queuing system to prevent timing based network topography analysis
	// TODO store a integer hash of sent broadcast messages in some sort of array to prevent resending the same message multiple times? (per session)
	// TODO determine some way to avoid sending out broadcast messages (on startup) if we created the group? how do we know that?
	if(ciphertext == NULL)
	{
		error_simple(0,"Sanity check failed in broadcast function. Report this.");
		breakpoint();
		return;
	}
	if(origin_n < 0)
	{ // Attempting to join a public group (or, if send_out, re-broadcast). We should be queuing. TODO
		send_out: {}
		if(BROADCAST_QUEUE)
			broadcast_add(origin_n,ciphertext);
		else
		{
			int origin_group_n = origin_n;
			if(origin_n > -1)
			{ // This can only trigger from goto send_out
				const uint8_t owner = getter_uint8(origin_n,-1,-1,-1,offsetof(struct peer_list,owner));
				if(owner == ENUM_OWNER_GROUP_PEER)
				{
					const int g = set_g(origin_n,NULL);
					origin_group_n = getter_group_int(g,offsetof(struct group_list,n));
				}
			}
			for(int n = 0 ; getter_byte(n,-1,-1,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index)) > -1 ; n++)
			{ // Send to EVERYONE other than orign_n and origin_n's group
				const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
				const uint8_t status = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,status));
				if(n != origin_group_n && status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL))
					message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,ciphertext,GROUP_BROADCAST_LEN);
			/*	{
					if(owner == ENUM_OWNER_GROUP_CTRL)
					{
						const int g = set_g(n,NULL);
						if(getter_group_uint8(g,offsetof(struct group_list,invite_required))) // date sign
							message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST_DATE_SIGNED,ciphertext,GROUP_BROADCAST_LEN);
						else // send normally
							message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,ciphertext,GROUP_BROADCAST_LEN);
					}	
					else // send normally
						message_send(n,ENUM_PROTOCOL_GROUP_BROADCAST,ciphertext,GROUP_BROADCAST_LEN);
				} */
			}
		}
	}
	else // if(origin_n > -1) // this if statement must be here because we reserve with set_g in group_join (???)
	{ // Handle Inbound Broadcast
		pthread_rwlock_rdlock(&mutex_expand_group);
		for(int group_n,g = 0 ; (group_n = group[g].n) > -1 || !is_null(group[g].id,GROUP_ID_SIZE); g++)
		{ // Attempt decryption of ciphertext, in all circumstances
			if(group_n < 0)
				continue; // this group is deleted, skip checking it
			pthread_rwlock_unlock(&mutex_expand_group);
			const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
			if(!g_invite_required)
			{ // Only try public groups
				unsigned char x25519_pk[crypto_box_PUBLICKEYBYTES]; // 32
				unsigned char x25519_sk[crypto_box_SECRETKEYBYTES]; // 32
				pthread_rwlock_rdlock(&mutex_expand_group);
				memcpy(x25519_sk,group[g].id,sizeof(x25519_sk));
				pthread_rwlock_unlock(&mutex_expand_group);
				crypto_scalarmult_base(x25519_pk, x25519_sk); // convert sk_to_pk
				unsigned char decrypted[GROUP_BROADCAST_DECRYPTED_LEN];
				if(crypto_box_seal_open(decrypted,ciphertext,GROUP_BROADCAST_LEN,x25519_pk, x25519_sk) == 0)
				{ // Successful decryption, meaning we have this group
					sodium_memzero(x25519_pk,sizeof(x25519_pk));
					sodium_memzero(x25519_sk,sizeof(x25519_sk));
					char onion[56+1];
					getter_array(&onion,sizeof(onion),group_n,-1,-1,-1,offsetof(struct peer_list,onion)); // TODO 2024/02/19 hit this with group_n being -1, which is a possible race because we *have* this group or we couldn't decrypt
					if(!memcmp(onion,&decrypted[crypto_pwhash_SALTBYTES],56)) // TODO hit error here in valgrind on 2023/10/24
					{ // Check if this is our own broadcast being returned to us (which is fine and normal)
						sodium_memzero(onion,sizeof(onion));
						sodium_memzero(decrypted,sizeof(decrypted));
						error_simple(0,"Public broadcast returned to us (our onion was encrypted). Do nothing, ignore.");
						return;
					}
					else
					{ // Some user wants into a group we are in.
						sodium_memzero(onion,sizeof(onion));
						const int new_peer = group_add_peer(g,(char*)&decrypted[crypto_pwhash_SALTBYTES],NULL,&decrypted[crypto_pwhash_SALTBYTES+56],NULL);
						sodium_memzero(decrypted,sizeof(decrypted));
						if(new_peer > -1)
						{ // Send them a peerlist
							error_simple(0,RED"Checkpoint New group peer!(broadcast)\n"RESET);
							broadcast_remove(g);
						//	error_simple(1,"Sending a peerlist to our brand new peer in public group");
						//	const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
						//	message_send(new_peer,ENUM_PROTOCOL_GROUP_PEERLIST,itovp(g),GROUP_PEERLIST_PUBLIC_LEN);
							unsigned char ciphertext_new[GROUP_BROADCAST_LEN];
							broadcast_prep(ciphertext_new,g);
						/*	torx_read(new_peer) // TODO remove
							const uint8_t owner = peer[new_peer].owner; // TODO remove
							torx_unlock(new_peer) // TODO remove
							printf("Checkpoint REQUESTING RECIPROCITY via GROUP_BROADCAST to specific peer: %u =? 5\n",owner); // TODO remove // should be ENUM_OWNER_GROUP_PEER ??? but isn't by the time we go to message_send
							if(owner != 5) // TODO remove
								breakpoint(); // TODO remove
							printf("Checkpoint ciphertext: %s\n",b64_encode(ciphertext_new,sizeof(ciphertext_new)));	*/
							message_send(new_peer,ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,ciphertext_new,GROUP_BROADCAST_LEN);  // REQUEST RECIPROCITY CONNECTION (critical)
						//	printf("Checkpoint did it message_send?\n");
							sodium_memzero(ciphertext_new,sizeof(ciphertext_new));
						}
						else if(new_peer == -1)
						{ // == -2 is already have it
							error_simple(0,"New peer is -1 therefore there was an error. Bailing.");
						}
						return;
					}
				}
				sodium_memzero(x25519_pk,sizeof(x25519_pk));
				sodium_memzero(x25519_sk,sizeof(x25519_sk));
			//	printf("Checkpoint decryption fail on g==%d\n",g);
			}
			pthread_rwlock_rdlock(&mutex_expand_group);
		} // If getting here, means unable to decrypt ciphertext with any public group ID. Carry on.
		pthread_rwlock_unlock(&mutex_expand_group);
		goto send_out;
	}
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
	pthread_mutex_lock(&mutex_group_join);
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
		error_simple(0,"Have already attempted to join or joined this group. Bailing out.");
		pthread_mutex_unlock(&mutex_group_join);
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
	pthread_mutex_unlock(&mutex_group_join);
	const int peer_index = getter_int(group_n,-1,-1,-1,offsetof(struct peer_list,peer_index));
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
		broadcast(-1,ciphertext);
		sodium_memzero(ciphertext,sizeof(ciphertext));
	}
	return g; // now it waits for a our signed ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY
}

int group_join_from_i(const int n,const int i)
{
	if(n < 0 || i < 0)
		return -1;
	const int p_iter = getter_int(n,i,-1,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
		return -1;
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	pthread_rwlock_unlock(&mutex_protocols);
	if(protocol != ENUM_PROTOCOL_GROUP_OFFER_FIRST && protocol != ENUM_PROTOCOL_GROUP_OFFER)
		return -1;
	int g;
	unsigned char id[GROUP_ID_SIZE];
	torx_read(n) // XXX
	memcpy(id,peer[n].message[i].message,sizeof(id));
	torx_unlock(n) // XXX
	if(protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST)
	{
		char creator_onion[56+1];
		unsigned char creator_ed25519_pk[crypto_sign_PUBLICKEYBYTES];
		torx_read(n) // XXX
		memcpy(creator_onion,&peer[n].message[i].message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)],56);
		memcpy(creator_ed25519_pk,&peer[n].message[i].message[GROUP_ID_SIZE+sizeof(uint32_t)+sizeof(uint8_t)+56],sizeof(creator_ed25519_pk));
		torx_unlock(n) // XXX
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
	const int peer_index = getter_int(group_n,-1,-1,-1,offsetof(struct peer_list,peer_index));
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
	{
		error_simple(-1,"Error initializing LibSodium library. Be sure to compile with -lsodium flag");
		return;
	}
	#ifdef WIN32
		evthread_use_windows_threads();
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

	srand(randombytes_random()); // seed rand() with libsodium, in case we use rand() somewhere, Do not use rand() for sensitive operations.
	umask(S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // umask 600 equivalent. man 2 umask

	sodium_memzero(protocols,sizeof(protocols)); // XXX initialize protocols struct XXX

	// protocol, name, description,	null_terminated_len, date_len, signature_len, logged, notifiable, file_checksum, file_offer, exclusive_type, utf8, socket_swappable, stream XXX NOTE: cannot depreciate group mechanics, as stream is not suitable (stream deletes upon fail)
	protocol_registration(ENUM_PROTOCOL_FILE_PIECE,"File Piece","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,0,0);
	// TODO ENUM_PROTOCOL_AUDIO_WAV TODO
	// TODO ENUM_PROTOCOL_AUDIO_WAV TODO
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_GROUP,"File Offer Group","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,"File Offer Group Date Signed","",0,2*sizeof(uint32_t),crypto_sign_BYTES,1,1,1,1,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_PARTIAL,"File Offer Partial","",0,0,0,0,0,1,1,ENUM_EXCLUSIVE_GROUP_MSG,0,1,1);
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_PNG TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_PNG TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_GIF TODO
	// TODO ENUM_PROTOCOL_FILE_PREVIEW_GIF TODO
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER,"File Offer","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_NONE,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_OFFER_PRIVATE,"File Offer Private","",0,0,0,1,1,1,1,ENUM_EXCLUSIVE_GROUP_PM,1,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_REQUEST,"File Request","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,0,0); // must NOT be stream (because must save)
	protocol_registration(ENUM_PROTOCOL_FILE_PAUSE,"File Pause","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_FILE_CANCEL,"File Cancel","",0,0,0,1,0,1,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_PROPOSE_UPGRADE,"Propose Upgrade","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,1);
	protocol_registration(ENUM_PROTOCOL_KILL_CODE,"Kill Code","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT,"UTF8 Text","",1,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
//	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_SIGNED,"UTF8 Text Signed","",1,0,crypto_sign_BYTES,1,1,0,0,ENUM_EXCLUSIVE_NONE,1,1,0); // not in use
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_DATE_SIGNED,"UTF8 Text Date Signed","",1,2*sizeof(uint32_t),crypto_sign_BYTES,1,1,0,0,ENUM_EXCLUSIVE_GROUP_MSG,1,1,0);
	protocol_registration(ENUM_PROTOCOL_UTF8_TEXT_PRIVATE,"UTF8 Text Private","",1,0,0,1,1,0,0,ENUM_EXCLUSIVE_GROUP_PM,1,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_BROADCAST,"Group Broadcast","",0,0,0,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MSG,0,1,0);
//	protocol_registration(ENUM_PROTOCOL_GROUP_BROADCAST_DATE_SIGNED,"Group Broadcast Date Signed","",0,2*sizeof(uint32_t),crypto_sign_BYTES,0,0,0,0,x,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_FIRST,"Group Offer First","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER,"Group Offer","",0,0,0,1,1,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_FIRST,"Group Offer Accept First","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT,"Group Offer Accept","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_OFFER_ACCEPT_REPLY,"Group Offer Accept Reply","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_NONE,0,1,0);
	protocol_registration(ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST,"Group Public Entry Request","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,0,0); // group_mechanics, must be logged until sent
	protocol_registration(ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST,"Group Private Entry Request","",0,0,0,1,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,0,0); // group_mechanics, must be logged until sent
	protocol_registration(ENUM_PROTOCOL_GROUP_REQUEST_PEERLIST,"Group Request Peerlist","",0,2*sizeof(uint32_t),crypto_sign_BYTES,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,1,0); // group_mechanics
	protocol_registration(ENUM_PROTOCOL_GROUP_PEERLIST,"Group Peerlist","",0,2*sizeof(uint32_t),crypto_sign_BYTES,0,0,0,0,ENUM_EXCLUSIVE_GROUP_MECHANICS,0,1,0); // group_mechanics
	protocol_registration(ENUM_PROTOCOL_PIPE_AUTH,"Pipe Authentication","",0,0,crypto_sign_BYTES,0,0,0,0,ENUM_EXCLUSIVE_NONE,0,0,1);

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
			if(GetFileAttributesW(appdata_path) == INVALID_FILE_ATTRIBUTES && CreateDirectoryW(appdata_path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
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

	if(get_file_size(file_db_plaintext) == 0)
		first_run = 1; // first point to set (1 of 2)

	if(peer == NULL)
	{ // make safe for repeated calls of initial, in case UI is buggy // XXX 2024 this check is safe because variables declared in .h are zero initialized https://en.wikipedia.org/wiki/.bss
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
		peer = torx_secure_malloc(sizeof(struct peer_list) *11);
		for(int j = 0; j < 11; j++)
			initialize_n(j);
		/* Initialize group struct */
		group = torx_secure_malloc(sizeof(struct group_list) *11);
		for(int j = 0; j < 11; j++)
			initialize_g(j);
		/* Initalize the packet struc */
		for(int o = 0; o < SIZE_PACKET_STRC; o++)
		{
			pthread_rwlock_wrlock(&mutex_packet);
			packet[o].n = -1;
			packet[o].f_i = -1;
			packet[o].packet_len = 0;
			packet[o].p_iter = -1; // initialize but DO NOT reset this, unless all sendbuffers are clear. this keeps track of maximum used packets at any given moment across all buffers.
			packet[o].fd_type = -1;
			packet[o].start = 0;
			pthread_rwlock_unlock(&mutex_packet);
		}
		const int count = cpucount();
		pthread_rwlock_wrlock(&mutex_global_variable);
		threads_max = count;
		if(threads_max > 256 || threads_max < 1) // Triggered if cpucount() returns an obviously bad value, which could occur on mobile or obscure platforms
			threads_max = 8; // error_simple(0,"Failed to detect CPU count automatically. Defaulting to 8 threads.");
		global_threads = threads_max; // (can be overwritten by any settings loaded from file subsequently)
		pthread_rwlock_unlock(&mutex_global_variable);
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
	pthread_rwlock_rdlock(&mutex_global_variable);
	memcpy(salt,saltbuffer,sizeof(salt));
	const long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	const size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	const int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable);
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
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
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
	pthread_rwlock_rdlock(&mutex_global_variable);
	memcpy(salt,saltbuffer,sizeof(salt));
	const long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	const size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	const int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable);
	const size_t password_len = strlen(pass_strc->password_new);
	if(crypto_pwhash(decryption_key,sizeof(decryption_key),pass_strc->password_new,password_len,salt,local_crypto_pwhash_OPSLIMIT,local_crypto_pwhash_MEMLIMIT,local_crypto_pwhash_ALG) != 0)
	{ // XXX if it crashes due to lack of memory, the password might not be removed
		sodium_memzero(salt,sizeof(salt)); // not important
		error_simple(-1,"Ran out of memory.");
		goto liberate;
	}
	sodium_memzero(salt,sizeof(salt)); // not important

	pthread_mutex_lock(&mutex_sql_messages);
	int val = sqlite3_rekey(db_messages,decryption_key,(int)sizeof(decryption_key));
	pthread_mutex_unlock(&mutex_sql_messages);
	if(val == SQLITE_OK)
	{ // If our larger database was successful, do the smaller one. WARNING: If this fails, big problems.
		pthread_mutex_lock(&mutex_sql_encrypted);
		val = sqlite3_rekey(db_encrypted,decryption_key,(int)sizeof(decryption_key));
		pthread_mutex_unlock(&mutex_sql_encrypted);
	}
	if(password_len == 0) // DO NOT DELETE THIS, lol. anyone who deletes this conditional is a glowie.
		sql_setting(1,-1,"decryption_key",(const char *)decryption_key, sizeof(decryption_key));
	else
		sql_delete_setting(1,-1,"decryption_key");
	pthread_rwlock_wrlock(&mutex_global_variable);
	sodium_memzero(decryption_key,sizeof(decryption_key));
	pthread_rwlock_unlock(&mutex_global_variable);
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
	setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
	unsigned char salt[crypto_pwhash_SALTBYTES]; // 16
	pthread_rwlock_rdlock(&mutex_global_variable);
	long long unsigned int local_crypto_pwhash_OPSLIMIT = crypto_pwhash_OPSLIMIT;
	size_t local_crypto_pwhash_MEMLIMIT = crypto_pwhash_MEMLIMIT;
	int local_crypto_pwhash_ALG = crypto_pwhash_ALG;
	pthread_rwlock_unlock(&mutex_global_variable);
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
		pthread_rwlock_wrlock(&mutex_global_variable);
		crypto_pwhash_OPSLIMIT = local_crypto_pwhash_OPSLIMIT;
		crypto_pwhash_MEMLIMIT = local_crypto_pwhash_MEMLIMIT;
		crypto_pwhash_ALG = local_crypto_pwhash_ALG = crypto_pwhash_ALG_DEFAULT;
		pthread_rwlock_unlock(&mutex_global_variable);
		sql_setting(1,-1,"salt",(char*)salt,sizeof(salt));
		char p1[21];
		snprintf(p1,sizeof(p1),"%llu",local_crypto_pwhash_OPSLIMIT);
		sql_setting(1,-1,"crypto_pwhash_OPSLIMIT",p1,strlen(p1));
		snprintf(p1,sizeof(p1),"%lu",local_crypto_pwhash_MEMLIMIT);
		sql_setting(1,-1,"crypto_pwhash_MEMLIMIT",p1,strlen(p1));
		snprintf(p1,sizeof(p1),"%d",local_crypto_pwhash_ALG);
		sql_setting(1,-1,"crypto_pwhash_ALG",p1,strlen(p1));
	}
	else
	{
		pthread_rwlock_rdlock(&mutex_global_variable);
		memcpy(salt,saltbuffer,sizeof(salt));
		pthread_rwlock_unlock(&mutex_global_variable);
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
		pthread_rwlock_wrlock(&mutex_global_variable);
		memcpy(decryption_key,local_decryption_key, sizeof(local_decryption_key)); // intermediary is necessary, do not eliminate
		sodium_memzero(decryption_key,sizeof(decryption_key));
		pthread_rwlock_unlock(&mutex_global_variable);
		initial_keyed();
	}
	else
	{
		pthread_rwlock_wrlock(&mutex_global_variable);
		lockout = 0;
		pthread_rwlock_unlock(&mutex_global_variable);
		login_cb(-1);
	}
	sodium_memzero(local_decryption_key,sizeof(local_decryption_key));
	return 0;
}

void login_start(const char *arg)
{ // Immediately attempts to copy and destroy password from UI // XXX Does not need locks
	if(threadsafe_read_int8(&mutex_global_variable,(int8_t*)&lockout))
	{
		error_simple(0,"Login_start called during lockout. UI bug. Report this to UI dev.");
		return;
	}
	char *password = {0};
	if(arg)
	{
		const size_t len = strlen(arg);
		password = torx_secure_malloc(len+1);
		memcpy(password,arg,len+1);
	}
	pthread_rwlock_wrlock(&mutex_global_variable);
	lockout = 1;
	pthread_rwlock_unlock(&mutex_global_variable);
	if(pthread_create(&thrd_login,&ATTR_DETACHED,&login_threaded,(void*)password))
		error_simple(-1,"Failed to create thread");
}

void cleanup_lib(const int sig_num)
{ // Cleanup process: cleanup_cb() saves UI settings, calls cleanup_lib() to save library settings and close databases, then UI exits
	#ifdef WIN32
	#define kill_tor_successfully TerminateProcess(tor_fd_stdout,0) != 0
	#else
	#define kill_tor_successfully kill(tor_pid,SIGTERM) == 0
	#endif
	if(sig_num)
		breakpoint();
	error_printf(0,"Cleanup reached. Signal number: %d",sig_num);
	pthread_attr_destroy(&ATTR_DETACHED); // don't start any threads after this or there will be problems
	pthread_mutex_lock(&mutex_closing); // Note: do not unlock, ever. Ensures that this doesn't get called multiple times.
	if(log_last_seen == 1)
	{
		for(int peer_index,n = 0 ; (peer_index = getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index))) > -1 || getter_byte(n,-1,-1,-1,offsetof(struct peer_list,onion)) != 0 ; n++)
		{ // storing last_seen time to .key file
			if(peer_index < 0)
				continue;
			const uint8_t owner = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,owner));
			const uint8_t sendfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,sendfd_connected));
			const uint8_t recvfd_connected = getter_uint8(n,-1,-1,-1,offsetof(struct peer_list,recvfd_connected));
			if(sendfd_connected > 0 && recvfd_connected > 0 && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_PEER))
			{
				char p1[21];
				snprintf(p1,sizeof(p1),"%ld",time(NULL));
				sql_setting(0,peer_index,"last_seen",p1,strlen(p1));
			}
		}
	}
	pthread_rwlock_wrlock(&mutex_packet); // XXX NOTICE: if it locks up here, its because of mutex_packet wrapping evbuffer_add in send_prep
	pthread_rwlock_wrlock(&mutex_broadcast);
	if(tor_pid < 1)
		error_simple(0,"Exiting before Tor started. Goodbye.");
	else if(kill_tor_successfully)
	{ // we don't need to bother waiting for termination, just signal
		pid_write(0);
		error_simple(0,"Exiting normally after killing Tor. Goodbye.");
	}
	else
		error_simple(0,"Failed to kill Tor for some reason upon shutdown (perhaps it already died?).");
	if(highest_ever_o > 0) // this does not mean file transfers occured, i think
		error_printf(0,"Highest O level from packet struct reached: %d",highest_ever_o);
	// XXX Most activity should be brought to a halt by the above locks XXX
	pthread_rwlock_rdlock(&mutex_expand_group);
	for(int g = 0 ; !is_null(group[g].id,GROUP_ID_SIZE) || group[g].n > -1 ;  g++)
	{
		pthread_rwlock_unlock(&mutex_expand_group);
		zero_g(g); // XXX INCLUDES LOCKS mutex_expand_group
		pthread_rwlock_rdlock(&mutex_expand_group);
	}
	pthread_rwlock_unlock(&mutex_expand_group);
	pthread_rwlock_wrlock(&mutex_expand_group); // XXX DO NOT EVER UNLOCK XXX can lead to segfaults if unlocked
	torx_free((void*)&group);
	pthread_rwlock_wrlock(&mutex_expand); // XXX DO NOT EVER UNLOCK XXX can lead to segfaults if unlocked
	for(int n = 0 ; peer[n].onion[0] != 0 || peer[n].peer_index > -1 ;  n++)
	{ // DO NOT USE getter_ functions
		thread_kill(peer[n].thrd_send); // must go before zero_n
		thread_kill(peer[n].thrd_recv); // must go before zero_n
		zero_n(n); // XXX INCLUDES LOCKS in zero_i on protocol struct (mutex_protocols)
		torx_free((void*)&peer[n].message); // moved this from zero_n because its issues when run at times other than shutdown. however this change could result in memory leaks?
		torx_free((void*)&peer[n].file);
	}
	pthread_rwlock_wrlock(&mutex_protocols);
	pthread_rwlock_wrlock(&mutex_global_variable); // do not use for debug variable
	pthread_rwlock_wrlock(&mutex_debug_level); // XXX Cannot use error_ll after this
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

int tor_call(void (*callback)(int),const int n,const char *msg)
{  /* Passes messages to Tor. Note that they can contain sensitive data. */ // 204 is the length of a successful gen response at the time of writing. 275 is with a single valid ClientAuthv3. Every additional ClientAuthv3 adds 70.
 // TODO investigate viability of having all tor calls on a single connection instead of using a password. Could facilitate the use of Orbot/System-Tor/Tails and also takedown onions during crashes.
	if(msg == NULL)
	{ // do not check if n is negative
		error_simple(0,"Sanity check fail in tor_call. Possible coding error. Report this. Bailing.");
		breakpoint();
		return -1;
	}
	struct sockaddr_in serv_addr = {0};
	evutil_socket_t sock; 
	if((sock = socket(AF_INET,SOCK_STREAM,0)) < 0)
	{
		error_simple(0,"Socket creation error. Report this. Bailing.");
		return -1;
	}
	const uint16_t local_tor_ctrl_port = threadsafe_read_uint16(&mutex_global_variable,&tor_ctrl_port);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htobe16(local_tor_ctrl_port);
	if(inet_pton(AF_INET,TOR_CTRL_IP,&serv_addr.sin_addr) <= 0) 	// Convert IPv4 and IPv6 addresses from text to binary form
	{
		error_simple(0,"Invalid address for Tor Control. Report this. Bailing.");
		if(evutil_closesocket(sock) < 0)
			error_simple(0,"Unlikely socket failed to close error.2");
		return -1;
	}
	int retries = 0;
	int8_t success = 0;
	while(retries < RETRIES_MAX && !success)
	{
		if(connect(sock,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) != 0)
			retries++;
		else
			success = 1;
	}
	const size_t tor_call_len = strlen(msg);
	if(!success)
	{ // Verify connection
		if(evutil_closesocket(sock) < 0)
			error_simple(0,"Unlikely socket failed to close error.3");
		error_printf(0,"Tor Control Port not running on %s:%u after %d tries.",TOR_CTRL_IP,local_tor_ctrl_port,retries); // DO NOT make -1 or a bad forced torrc setting is unrecoverable
		pthread_rwlock_wrlock(&mutex_global_variable);
		tor_running = 0; // XXX this occurs when tor is not running at all
		pthread_rwlock_unlock(&mutex_global_variable);
		return -1; // fail
	}
	else
	{ // Attempt Send
		error_printf(5,"Tor call SUCCESS after %d retries: %s",retries,msg);
		const ssize_t s = send(sock,msg,tor_call_len,0);
		char rbuff[4096]; // zero'd
		const ssize_t r = recv(sock,rbuff,sizeof(rbuff)-1,0);
		if(s > 0 && r > -1)
		{ // 250 is from the tor api spec which indicates success
			rbuff[r] = '\0'; // do not remove, recv is not null terminating
			if(evutil_closesocket(sock) < 0)
				error_simple(0,"Unlikely socket failed to close error.4"); // DO NOT error out here. This occured once even with a 250 success. Not a big deal. 2023/08
			pthread_rwlock_wrlock(&mutex_global_variable);
			tor_running = 1;
			pthread_rwlock_unlock(&mutex_global_variable);
			if(r > 0 && !strncmp(rbuff,"250",3))
				error_simple(4,"Received success code from Tor.");
			else
				error_simple(0,"Received FAILURE code from Tor.");
			sodium_memzero(rbuff,sizeof(rbuff));
			if(callback && n > -1)
				(*callback)(n);
			return 0; // success
		}
		pthread_rwlock_wrlock(&mutex_global_variable);
		tor_running = 0; // XXX this occurs when another instance of tor is already running, from a crashed TorX... also seemingly false positives?
		pthread_rwlock_unlock(&mutex_global_variable);
		error_simple(0,"There is likely an orphan Tor process running from a crashed TorX. If so, any Tor proccess run by this user and restart. Alternatively, you are restarting Tor, causing a call to fail. If so, carry on.");
		sodium_memzero(rbuff,sizeof(rbuff));
		return -1; // fail
	}

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
	for(int n = 0 ; getter_byte(n,-1,-1,-1,offsetof(struct peer_list,onion)) != 0 || getter_int(n,-1,-1,-1,offsetof(struct peer_list,peer_index)) > -1 ; n++)
	{
		char privkey_n[88+1];
		getter_array(&privkey_n,sizeof(privkey_n),n,-1,-1,-1,offsetof(struct peer_list,privkey));
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
