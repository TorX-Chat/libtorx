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
#include <string.h>
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


/* Internal Use Struct Models */
struct blake3 {
	unsigned char input[64];	/* current input bytes */
	uint32_t bytes;			/* bytes in current input block */
	unsigned block;			/* block index in chunk */
	uint64_t chunk;			/* chunk index */
	uint32_t *cv, cv_buf[54 * 8];	/* chain value stack */
};
/* Internal Use Functions */
void blake3_init(struct blake3 *);
void blake3_update(struct blake3 *, const void *, size_t);
void blake3_out(struct blake3 *, unsigned char *restrict, size_t);
//int blake3_test(void);

/* torx_core.c */
void zero_o(const int n,const int f,const int o);
void zero_r(const int n,const int f,const int r);
void zero_f(const int n,const int f);

/* broadcast.c */
void broadcast_prep(unsigned char ciphertext[GROUP_BROADCAST_LEN],const int g);
void broadcast_inbound(const int origin_n,const unsigned char ciphertext[GROUP_BROADCAST_LEN]);
void broadcast_start(void);

/* sql.c */
int load_peer_struc(const int peer_index,const uint8_t owner,const uint8_t status,const char *privkey,const uint16_t peerversion,const char *peeronion,const char *peernick,const unsigned char *sign_sk,const unsigned char *peer_sign_pk,const unsigned char *invitation);
int sql_exec(sqlite3** db,const char *command,const char *setting_value,const size_t setting_value_len);

/* Global variables (defined here, declared elsewhere, primarily in torx_core.c) */
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
