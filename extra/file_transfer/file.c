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
XXX WARNINGS XXX
	* don't use a file descriptor after close or it could result in corruption, according to https://www.sqlite.org/howtocorrupt.html
*/

#define SPLIT_DELAY 1 // 0 is writing checkpoint every packet, 1 is every 120kb, 2 is every 240kb, ... Recommend 1+. XXX 0 may cause divide by zero errors/crash?
#define MINIMUM_SECTION_SIZE (5*1024*1024) // Bytes. for groups only, currently, because we don't use split files in P2P. Set by the file offerer exlusively.
#define REALISTIC_PEAK_TRANSFER_SPEED (50*1024*1024) // In bytes/s. Throws away bytes_per_second calculations above this level, for the purpose of calculating average transfer speed. It's fine and effective to set this as high as 1024*1024*1024 (1gb/s).

void (*initialize_f_registered)(const int n,const int f) = NULL;
void (*expand_file_struc_registered)(const int n,const int f) = NULL;
void (*transfer_progress_registered)(const int n,const int f,const uint64_t transferred) = NULL;

struct file_strc { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	int n;
	char *path;
	time_t modified;
	size_t size;
};

int file_piece_p_iter = -1; // save some CPU cycles by setting this on startup.
char *download_dir = {0}; // XXX Should be set otherwise will save in config directory set in initial().
char *split_folder = {0}; // For .split files. If NULL, it .split file will go beside the downloading file.
uint8_t auto_resume_inbound = 1; // automatically request resumption of inbound file transfers NOTE: only works on full_duplex transfers (relies on .split) TODO disabling this might be untested
double file_progress_delay = 500000000; // nanoseconds (*1 billionth of a second)

void initialize_f_setter(void (*callback)(int,int))
{
	if(initialize_f_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		initialize_f_registered = callback;
}

void initialize_f_cb(const int n,const int f)
{
	if(initialize_f_registered)
		initialize_f_registered(n,f);
}

void expand_file_struc_setter(void (*callback)(int,int))
{
	if(expand_file_struc_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		expand_file_struc_registered = callback;
}

void expand_file_struc_cb(const int n,const int f)
{
	if(expand_file_struc_registered)
		expand_file_struc_registered(n,f);
}

void transfer_progress_setter(void (*callback)(int, int, uint64_t))
{
	if(transfer_progress_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		transfer_progress_registered = callback;
}

void transfer_progress_cb(const int n,const int f,const uint64_t transferred)
{
	if(transfer_progress_registered)
		transfer_progress_registered(n,f,transferred);
}

static inline void initialize_offer(const int n,const int f,const int o) // XXX do not put locks in here
{ // initalize an iter of the offer struc.
	peer[n].file[f].offer[o].offerer_n = -1;
	peer[n].file[f].offer[o].offer_progress = NULL;
}

static inline void initialize_request(const int n,const int f,const int r) // XXX do not put locks in here
{ // initalize an iter of the request struc.
	peer[n].file[f].request[r].requester_n = -1;
	sodium_memzero(peer[n].file[f].request[r].start,sizeof(peer[n].file[f].request[r].start));
	sodium_memzero(peer[n].file[f].request[r].end,sizeof(peer[n].file[f].request[r].end));
	sodium_memzero(peer[n].file[f].request[r].transferred,sizeof(peer[n].file[f].request[r].transferred));
	peer[n].file[f].request[r].previously_sent = 0;
}

void initialize_f(const int n,const int f) // XXX do not put locks in here
{ // initalize an iter of the file struc.
	sodium_memzero(peer[n].file[f].checksum,sizeof(peer[n].file[f].checksum));
	peer[n].file[f].filename = NULL;
	peer[n].file[f].file_path = NULL;
	peer[n].file[f].size = 0;
	peer[n].file[f].modified = 0;
	peer[n].file[f].splits = 0;
	peer[n].file[f].split_path = NULL;
	peer[n].file[f].split_progress = NULL;
	peer[n].file[f].split_status_n = NULL;
	peer[n].file[f].split_status_fd = NULL;
	peer[n].file[f].split_status_req = NULL;
	peer[n].file[f].split_hashes = NULL;
	peer[n].file[f].fd = NULL;
	peer[n].file[f].last_progress_update_time = 0;
	peer[n].file[f].last_progress_update_nstime = 0;
	peer[n].file[f].bytes_per_second = 0;
	peer[n].file[f].last_transferred = 0;
	peer[n].file[f].time_left = 0;
	peer[n].file[f].speed_iter = 0;
	sodium_memzero(peer[n].file[f].last_speeds,sizeof(peer[n].file[f].last_speeds));
//	pthread_mutex_lock(&peer[n].file[f].mutex_file); // Do not replace // TODO disabling because suspicion of lock-order-inversion (see comments on torx_fd_lock)
	pthread_mutex_init(&peer[n].file[f].mutex_file, NULL);
//	pthread_mutex_unlock(&peer[n].file[f].mutex_file); // Do not replace // TODO disabling because suspicion of lock-order-inversion (see comments on torx_fd_lock)

	peer[n].file[f].offer = torx_insecure_malloc(sizeof(struct offer_list) *11);
	peer[n].file[f].request = torx_insecure_malloc(sizeof(struct request_list) *11);
	for(int j = 0; j < 11; j++) // Initialize iter 0 - 10
	{
		initialize_offer(n,f,j);
		initialize_request(n,f,j);
	}
//	note: we have no max counter for file struc.... we rely on checksum to never be zero'd after initialization (until shutdown or deletion of file). This is safe.
}

static inline void expand_offer_struc(const int n,const int f,const int o)
{ /* Expand offer struct if our current o is unused && divisible by 10 */
	if(n < 0 || f < 0 || o < 0)
	{
		error_simple(0,"expand_offer_struc failed sanity check. Coding error. Report this.");
		return;
	}
	int offerer_n = -2; // must not initialize as -1
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].offer)
		offerer_n = peer[n].file[f].offer[o].offerer_n;
	torx_unlock(n) // 🟩🟩🟩
	if(offerer_n == -1 && o && o % 10 == 0)
	{
		torx_write(n) // 🟥🟥🟥
		const uint32_t current_allocation_size = torx_allocation_len(peer[n].file[f].offer);
		peer[n].file[f].offer = torx_realloc(peer[n].file[f].offer,current_allocation_size + sizeof(struct offer_list) *10);
		// callback unnecessary, not doing
		for(int j = o + 10; j > o; j--)
			initialize_offer(n,f,j);
		torx_unlock(n) // 🟩🟩🟩
	}
}

static inline void expand_request_struc(const int n,const int f,const int r)
{ /* Expand request struct if our current r is unused && divisible by 10 */
	if(n < 0 || f < 0 || r < 0)
	{
		error_simple(0,"expand_request_struc failed sanity check1. Coding error. Report this.");
		return;
	}
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].request == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"expand_request_struc failed sanity check2. Coding error. Report this.");
		return;
	}
	const int requester_n = peer[n].file[f].request[r].requester_n;
	torx_unlock(n) // 🟩🟩🟩
	if(requester_n == -1 && r && r % 10 == 0)
	{
		torx_write(n) // 🟥🟥🟥
		const uint32_t current_allocation_size = torx_allocation_len(peer[n].file[f].request);
		peer[n].file[f].request = torx_realloc(peer[n].file[f].request,current_allocation_size + sizeof(struct request_list) *10);
		// callback unnecessary, not doing
		for(int j = r + 10; j > r; j--)
			initialize_request(n,f,j);
		torx_unlock(n) // 🟩🟩🟩
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
	getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
	if(f && f % 10 == 0 && is_null(checksum,CHECKSUM_BIN_LEN)) // XXX not using && f + 10 > max_file because we never clear checksum so it is currently a reliable check
	{
		torx_write(n) // 🟥🟥🟥
		const uint32_t current_allocation_size = torx_allocation_len(peer[n].file);
		peer[n].file = torx_realloc(peer[n].file,current_allocation_size + sizeof(struct file_list) *10);
		for(int j = f + 10; j > f; j--)
			initialize_f(n,j);
		torx_unlock(n) // 🟩🟩🟩
		expand_file_struc_cb(n,f);
		for(int j = f + 10; j > f; j--)
			initialize_f_cb(n,j);
	}
	sodium_memzero(checksum,sizeof(checksum));
}

static inline uint64_t calculate_average(const int n,const int f,const uint64_t bytes_per_second)
{ // Calculate average file transfer speed over 255 seconds, for the purpose of calculating remaining time // TODO consider weighting the most recent speeds
/*	#define smoothing 0.02
	if(peer[n].file[f].average_speed == 0)
		peer[n].file[f].average_speed = peer[n].file[f].bytes_per_second;
	else if(peer[n].file[f].average_speed > peer[n].file[f].bytes_per_second)
		peer[n].file[f].average_speed -= (uint64_t)((double)peer[n].file[f].bytes_per_second*smoothing);
	else if(peer[n].file[f].average_speed < peer[n].file[f].bytes_per_second)
		peer[n].file[f].average_speed += (uint64_t)((double)peer[n].file[f].bytes_per_second*smoothing);
	return peer[n].file[f].average_speed;	*/
//	const time_t last_progress_update_time = getter_time(n,INT_MIN,f,offsetof(struct file_list,last_progress_update_time));
//	if(last_progress_update_time == 0) // necessary to prevent putting in bad bytes_per_second data
//		return 0;
	uint64_t sum = 0;
	uint8_t included = 0;
	uint64_t average_speed = 0;
	torx_write(n) // 🟥🟥🟥
	peer[n].file[f].last_speeds[peer[n].file[f].speed_iter++] = bytes_per_second;
	torx_unlock(n) // 🟩🟩🟩
	torx_read(n) // 🟧🟧🟧
	for(uint8_t iter = 0; iter < 255; iter++)
		if(peer[n].file[f].last_speeds[iter])
		{
			sum += peer[n].file[f].last_speeds[iter];
			included++;
		}
	torx_unlock(n) // 🟩🟩🟩
	if(included)
		average_speed = sum/included;
	else
		average_speed = 0;
//	setter(n,INT_MIN,f,offsetof(struct file_list,average_speed),&average_speed,sizeof(average_speed));
	return average_speed;
}

char *file_progress_string(const int n,const int f)
{ // Helper function available to UI devs (but no requirement to use)
	if(n < 0 || f < 0)
		return NULL;
	torx_read(n) // 🟧🟧🟧
	const time_t time_left = peer[n].file[f].time_left;
	const uint64_t bytes_per_second = peer[n].file[f].bytes_per_second;
	const uint64_t size = peer[n].file[f].size;
	torx_unlock(n) // 🟩🟩🟩
	#define file_size_text_len 128 // TODO perhaps increase this size. its arbitary. By our math it shoud be more than enough though.
	char *file_size_text = torx_insecure_malloc(file_size_text_len); // arbitrary allocation amount
//	printf("Checkpoint string: %ld left, %lu b/s\n",time_left,bytes_per_second);
	if(file_is_cancelled(n,f))
		snprintf(file_size_text,file_size_text_len,"Cancelled");
	else if(time_left > 7200)
	{
		const time_t hours = time_left/60/60;
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %lld hours %lld min left",bytes_per_second/1024,(long long)hours,(long long)time_left/60-hours*60);
	}
	else if(time_left > 120)
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %lld min left",bytes_per_second/1024,(long long)time_left/60);
	else if(time_left > 0)
		snprintf(file_size_text,file_size_text_len,"\t%zu KBps %lld sec left",bytes_per_second/1024,(long long)time_left);
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

void transfer_progress(const int n,const int f)
{ // This is called every packet on a file transfer (IN / OUT). Packets are PACKET_LEN-10 in size, so 488 (as of 2022/08/19, may be changed to accomodate sequencing)
	const uint64_t transferred = calculate_transferred(n,f);
	if(transferred == 0)
		return; // This occurs when sending a file in a group
	time_t time_current = 0;
	time_t nstime_current = 0;
	set_time(&time_current,&nstime_current);
	torx_read(n) // 🟧🟧🟧
	const uint64_t size = peer[n].file[f].size; // getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	const uint64_t last_transferred = peer[n].file[f].last_transferred; // getter_uint64(n,INT_MIN,f,offsetof(struct file_list,last_transferred));
	const time_t last_progress_update_time = peer[n].file[f].last_progress_update_time;
	const double diff = (double)(time_current - peer[n].file[f].last_progress_update_time) * 1e9 + (double)(nstime_current - peer[n].file[f].last_progress_update_nstime); // getter_time(n,INT_MIN,f,offsetof(struct file_list,last_progress_update_time)); // getter_time(n,INT_MIN,f,offsetof(struct file_list,last_progress_update_nstime));
	torx_unlock(n) // 🟩🟩🟩
	if(transferred == size && transferred != last_transferred)
	{
		torx_write(n) // 🟥🟥🟥
		peer[n].file[f].last_transferred = transferred;
		peer[n].file[f].bytes_per_second = 0;
		peer[n].file[f].time_left = 0;
		torx_unlock(n) // 🟩🟩🟩
		printf(BRIGHT_TEAL"Checkpoint transfer_progress COMPLETE\n"RESET);
		transfer_progress_cb(n,f,transferred);
	}
	else if(transferred == size)
		return;
	else if(diff > file_progress_delay || last_transferred == transferred /* stalled */)
	{ // For more accuracy and less variation, do an average over time
		if(last_transferred > transferred) // Necessary to prevent readtime errors when calculating bytes_per_second.
		{ // XXX Frequently occurs when starting transfer (on sender side) when peer requests only one section of file, then another, making it initially look like more is transferred than actually is; could theoretically also occur on receiving side when cancelling a file's progress after a bad checksum. XXX
			torx_write(n) // 🟥🟥🟥
			peer[n].file[f].last_progress_update_time = time_current;
			peer[n].file[f].last_progress_update_nstime = nstime_current;
			peer[n].file[f].last_transferred = transferred;
			torx_unlock(n) // 🟩🟩🟩
			return; // No callback necessary because we have no change in bytes_per_second. Wait until we have more/better data.
		}
		uint64_t bytes_per_second = 0;
		if(diff > 0)
			bytes_per_second = (uint64_t)((double)(transferred - last_transferred) * 1e9 / diff );
	//	printf("Checkpoint %lu = ((%lu - %lu) * 1e9 / %f);\n",bytes_per_second,transferred,last_transferred,diff);
		time_t time_left = 0;
		uint64_t average_speed = 0;
		if(last_progress_update_time && bytes_per_second < REALISTIC_PEAK_TRANSFER_SPEED) // XXX Necessary to prevent putting in bad bytes_per_second data (sanity checks) on startup
			average_speed = calculate_average(n,f,bytes_per_second);
		if(bytes_per_second && average_speed)
			time_left = (time_t)((size - transferred) / average_speed); // alt: bytes_per_second
	//	if(last_transferred == transferred) // XXX Do not delete
	//		error_printf(0,"Checkpoint transfer_progress received a stall: %ld %lu\n",time_left,bytes_per_second);
		torx_write(n) // 🟥🟥🟥
		peer[n].file[f].time_left = time_left; // will be 0 if bytes_per_second is 0
		peer[n].file[f].bytes_per_second = bytes_per_second;
		peer[n].file[f].last_progress_update_time = time_current;
		peer[n].file[f].last_progress_update_nstime = nstime_current;
		peer[n].file[f].last_transferred = transferred;
		torx_unlock(n) // 🟩🟩🟩
		if(last_transferred == transferred)
			printf("Checkpoint transfer_progress STALLED at %zu\n",transferred);
	//	else
	//		printf("Checkpoint transfer_progress %zu of %lu\n",transferred,size);
		transfer_progress_cb(n,f,transferred);
	}
}

uint64_t calculate_transferred_inbound(const int n,const int f)
{ /* DO NOT make this complicated. It has to be quick and simple because it is called for every packet in/out */
	uint64_t transferred = 0;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_progress)
		for(int16_t section = 0; section <= peer[n].file[f].splits; section++)
			transferred += peer[n].file[f].split_progress[section];
	torx_unlock(n) // 🟩🟩🟩
	return transferred;
}

uint64_t calculate_transferred_outbound(const int n,const int f,const int r)
{ // For non-group transfers, pass r=0. Note: Due to the inclusion of previously_sent, this function should only be used in the UI (and UI related functions) and not internally.
	uint64_t transferred = 0;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].request)
		transferred = peer[n].file[f].request[r].previously_sent + peer[n].file[f].request[r].transferred[0] + peer[n].file[f].request[r].transferred[1];
	torx_unlock(n) // 🟩🟩🟩
	return transferred;
}

uint64_t calculate_transferred(const int n,const int f)
{ // We are considering depreciating this due to the lack of support for outgoing group transfers
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	uint64_t transferred = 0;
	const int is_active = file_is_active(n,f); // DO NOT REPLACE WITH file_status_get because it is more costly
	if(owner != ENUM_OWNER_GROUP_CTRL && is_active != ENUM_FILE_ACTIVE_IN && is_active != ENUM_FILE_ACTIVE_IN_OUT && (transferred = calculate_transferred_outbound(n,f,0)))
		return transferred; // Return outbound, if not active in, not GROUP_CTRL,
	return calculate_transferred_inbound(n,f); // Otherwise return inbound
}

uint64_t calculate_section_start(uint64_t *end_p,const uint64_t size,const uint8_t splits,const int16_t section)
{ // XXX DO NOT MODIFY/REMOVE THE CASTING OR MATH IN HERE WITHOUT EXTENSIVE TESTING XXX
	if(size < (uint64_t)splits + 1 || section > splits + 1 || section < 0 || !size) // Sanity checks necessary to prevent exploitation that could corrupt a file.
		error_printf(-1,"Sanity check failure in calculate_section_start: %lu %u %d. Coding error. Report this.",size,splits,section);
	if(end_p)
		*end_p = size*(uint64_t)(section+1)/(splits+1)-1;
	return size*(uint64_t)section/(splits+1);
}


void zero_o(const int n,const int f,const int o) // XXX do not put locks in here. Be sure to check if(peer[n].file[f].offer) before calling! XXX
{ // Note: We don't `.offer_n = -1` because it could cause issues in select_peer if this function was called from outside of zero_f
	torx_free((void*)&peer[n].file[f].offer[o].offer_progress);
}

void zero_r(const int n,const int f,const int r) // XXX do not put locks in here. Be sure to check if(peer[n].file[f].request) before calling! XXX
{ // Note: We don't `.requester_n = -1` because it will interfere with expand_request_struc
//	peer[n].file[f].request[r].requester_n = -1; // Must not reset
	sodium_memzero(peer[n].file[f].request[r].start,sizeof(peer[n].file[f].request[r].start));
	sodium_memzero(peer[n].file[f].request[r].end,sizeof(peer[n].file[f].request[r].end));
	peer[n].file[f].request[r].previously_sent += peer[n].file[f].request[r].transferred[0] + peer[n].file[f].request[r].transferred[1]; // Need to store the progress before clearing it
	sodium_memzero(peer[n].file[f].request[r].transferred,sizeof(peer[n].file[f].request[r].transferred));
}

void zero_f(const int n,const int f) // XXX do not put locks in here
{ // see similarities in process_pause_cancel
	if(peer[n].file[f].offer)
		for(int o = 0 ; peer[n].file[f].offer[o].offerer_n > -1 ; o++)
			zero_o(n,f,o);
	if(peer[n].file[f].request)
		for(int r = 0 ; peer[n].file[f].request[r].requester_n > -1 ; r++)
			zero_r(n,f,r);
	torx_free((void*)&peer[n].file[f].offer);
	torx_free((void*)&peer[n].file[f].request);
	sodium_memzero(peer[n].file[f].checksum,sizeof(peer[n].file[f].checksum));
	torx_free((void*)&peer[n].file[f].filename);
	torx_free((void*)&peer[n].file[f].file_path);
	torx_free((void*)&peer[n].file[f].split_hashes);
	torx_free((void*)&peer[n].file[f].split_path);
	torx_free((void*)&peer[n].file[f].split_progress);
	torx_free((void*)&peer[n].file[f].split_status_n);
	torx_free((void*)&peer[n].file[f].split_status_fd);
	torx_free((void*)&peer[n].file[f].split_status_req);
	close_sockets_nolock(peer[n].file[f].fd) // Do not eliminate
}

int set_f(const int n,const unsigned char *checksum,const size_t checksum_len)
{ // Set the f initially via checksum search or truncated checksum. XXX BE CAREFUL: this function processes on potentially dangerous peer messages. XXX
  // XXX BE AWARE: This function WILL return >-1 as long as CHECKSUM_BIN_LEN is passed as checksum_len XXX
	if(n < 0 || !checksum || checksum_len < 1)
	{
		error_simple(0,"n < 0 or null or 0 length checksum passed to set_f. Report this.");
		breakpoint();
		return -1;
	}
	int f = 0;
	int checksum_is_null;
	torx_read(n) // 🟧🟧🟧
	while(!(checksum_is_null = is_null(peer[n].file[f].checksum,CHECKSUM_BIN_LEN)) && memcmp(peer[n].file[f].checksum,checksum,checksum_len))
		f++; // Not null, and not matching.
	torx_unlock(n) // 🟩🟩🟩
	if(checksum_len < CHECKSUM_BIN_LEN && checksum_is_null)
		return -1; // do not put error message, valid reasons why this could occur
	expand_file_struc(n,f); // Expand struct if necessary
	if(checksum_is_null) // DO NOT RESERVE BEFORE EXPAND_ or it will be lost
		setter(n,INT_MIN,f,offsetof(struct file_list,checksum),checksum,checksum_len); // source is pointer
	return f;
}

int set_f_from_i(int *file_n,const int n,const int i)
{ // Returns -1 if message protocol lacks file_checksum. This is primarily a UI helper function.
	if(n < 0 || !file_n || i == INT_MIN)
	{
		error_simple(0,"set_f_from_i sanity check failure. Coding error. Report this.");
		return -1;
	}
	torx_read(n) // 🟧🟧🟧
	const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);
	torx_unlock(n) // 🟩🟩🟩
	if(message_len < CHECKSUM_BIN_LEN)
		return -1;
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
		return -1;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint8_t file_checksum = protocols[p_iter].file_checksum;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(!file_checksum)
		return -1;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(group_msg && owner == ENUM_OWNER_GROUP_PEER)
	{
		const int g = set_g(n,NULL);
		*file_n = getter_group_int(g,offsetof(struct group_list,n));
	}
	else
		*file_n = n;
	unsigned char checksum[CHECKSUM_BIN_LEN];
	getter_array(&checksum,sizeof(checksum),n,i,-1,offsetof(struct message_list,message));
	const int f = set_f(*file_n,checksum,sizeof(checksum)-1); // XXX MUST be -1 to detect errors, otherwise we'll reserve with potentially bad data.
	sodium_memzero(checksum,sizeof(checksum));
	if(f < 0) // Likely a UI coding error where they passed the wrong N (Likely they passed a GROUP_PEER instead of a GROUP_CTRL)
		error_simple(0,"set_f_from_i returned -1. Coding error. Report this.");
	return f;
}

int set_o(const int n,const int f,const int passed_offerer_n)
{ // set offer iterator
	if(n < 0 || f < 0 || passed_offerer_n < 0)
		return -1;
	int o = -1;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].offer)
	{ // necessary sanity check to prevent race conditions
		o = 0;
		while(peer[n].file[f].offer[o].offerer_n > -1 && peer[n].file[f].offer[o].offerer_n != passed_offerer_n)
			o++; // check if offerer already exists in our struct
	}
	torx_unlock(n) // 🟩🟩🟩
	if(o > -1)
	{
		expand_offer_struc(n,f,o); // Expand struct if necessary
		torx_write(n) // 🟥🟥🟥
		if(peer[n].file[f].offer) // necessary sanity check to prevent race conditions
			peer[n].file[f].offer[o].offerer_n = passed_offerer_n; // DO NOT RESERVE BEFORE EXPAND_ or it will be lost
		torx_unlock(n) // 🟩🟩🟩
	}
	return o;
}

int set_r(const int n,const int f,const int passed_requester_n)
{ // set request iterator
	if(n < 0 || f < 0 || passed_requester_n < 0)
		return -1;
	int r = 0;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].request == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Sanity check failure in set_r. Coding error. Report this.");
		return -1;
	}
	for(int requester_n ; (requester_n = peer[n].file[f].request[r].requester_n) > -1 && requester_n != passed_requester_n ; )
		r++; // check if offerer already exists in our struct
	torx_unlock(n) // 🟩🟩🟩
	expand_request_struc(n,f,r); // Expand struct if necessary
	// TODO if desired, reserve here. DO NOT RESERVE BEFORE EXPAND_ or it will be lost
	torx_write(n) // 🟥🟥🟥
	if(peer[n].file[f].request) // Necessary sanity check to avoid race conditions
		peer[n].file[f].request[r].requester_n = passed_requester_n;
	torx_unlock(n) // 🟩🟩🟩
	return r;
}

int file_is_active(const int n,const int f)
{ // Returns 0 if inactive, 1 if outbound active, 2 if inbound active, 3 if both in/outbound active.
	int active = 0;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].request)
		for(int8_t fd_type = 0 ; fd_type < 2 && active == 0 ; fd_type++)
			for(int r = 0 ; peer[n].file[f].request[r].requester_n > -1 && active == 0 ; r++)
				if(peer[n].file[f].request[r].end[fd_type] > peer[n].file[f].request[r].start[fd_type] + peer[n].file[f].request[r].transferred[fd_type])
					active += ENUM_FILE_ACTIVE_OUT; // Outbound active, 1
	if(peer[n].file[f].split_status_fd)
		for(int16_t section = 0 ; section <= peer[n].file[f].splits && active < 2 ; section++)
			if(peer[n].file[f].split_status_fd[section] > -1)
				active += ENUM_FILE_ACTIVE_IN; // Inbound active, 2
	torx_unlock(n) // 🟩🟩🟩
	return active;
}

int file_is_cancelled(const int n,const int f)
{ // Returns 1 if file is cancelled
	int cancelled = 0;
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].request == NULL && peer[n].file[f].offer == NULL && peer[n].file[f].split_status_fd == NULL) // && etc...
		cancelled = 1;
	torx_unlock(n) // 🟩🟩🟩
	return cancelled;
}

int file_is_complete(const int n,const int f)
{ // Assumes split_path is free'd when file is completed
	torx_read(n) // 🟧🟧🟧
	const uint64_t size = peer[n].file[f].size;
	const uint8_t split_path_exists = peer[n].file[f].split_path ? 1 : 0;
	const uint8_t file_path_exists = peer[n].file[f].file_path ? 1 : 0;
	torx_unlock(n) // 🟩🟩🟩
	if(split_path_exists || !file_path_exists)
		return 0;
	if(size == calculate_transferred_inbound(n,f))
		return 1; // Saves checking on disk, if this file is already completed.
//	if(file_is_active(n,f) == ENUM_FILE_ACTIVE_IN) // TODO Still considering. Do not delete. This might be useful because checking size on disk should really be last-ditch because it indicates only that the last section is completed.
//		return 0;
	char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
	const uint64_t size_on_disk = get_file_size(file_path);
	torx_free((void*)&file_path);
	if(size == size_on_disk)
		return 1;
	return 0;
}

int file_status_get(const int n,const int f)
{ // Unified function. Do not change the order. The order is important for efficiency and other reasons. // TODO How can we pause? Do we need pauses? Pauses were weird anyway because either peer could unpause.
	if(n < 0 || f < 0)
		error_simple(-1,"Negative value passed to file_status_get. Sanity check failed.");
	if(file_is_cancelled(n,f))
		return ENUM_FILE_INACTIVE_CANCELLED;
	torx_read(n) // 🟧🟧🟧
	const uint8_t file_path_exists = peer[n].file[f].file_path ? 1 : 0;
	torx_unlock(n) // 🟩🟩🟩
	if(!file_path_exists)
		return ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND;
	const int active = file_is_active(n,f);
	if(active)
		return active; // ENUM_FILE_ACTIVE_OUT / ENUM_FILE_ACTIVE_IN / ENUM_FILE_ACTIVE_IN_OUT
	if(file_is_complete(n,f))
		return ENUM_FILE_INACTIVE_COMPLETE;
	return ENUM_FILE_INACTIVE_ACCEPTED; // Inbound
}

static inline int remove_offer(const int file_n,const int f,const int peer_n)
{
	const int o = set_o(file_n,f,peer_n);
	if(o > -1)
	{
		torx_write(file_n) // 🟥🟥🟥
		if(peer[file_n].file[f].offer)
			zero_o(file_n,f,o);
		torx_unlock(file_n) // 🟩🟩🟩
		return 1;
	}
	return 0;
}

static inline int remove_request(const int file_n,const int f,const int peer_n,const int8_t fd_type)
{
	const int r = set_r(file_n,f,peer_n);
	if(r > -1)
	{
		torx_write(file_n) // 🟥🟥🟥
		if(peer[file_n].file[f].request)
		{ // Necessary sanity check to prevent race conditions
			if(fd_type == 0 || fd_type == 1)
			{
				peer[file_n].file[f].request[r].start[fd_type] = 0;
				peer[file_n].file[f].request[r].end[fd_type] = 0;
				peer[file_n].file[f].request[r].previously_sent += peer[file_n].file[f].request[r].transferred[fd_type]; // Need to store the progress before clearing it
				peer[file_n].file[f].request[r].transferred[fd_type] = 0;
			}
			else // if(fd_type == -1)
				zero_r(file_n,f,r);
		}
		torx_unlock(file_n) // 🟩🟩🟩
		return 1;
	}
	return 0;
}

int file_remove_offer(const int file_n,const int f,const int peer_n)
{ // modelled after section_unclaim(
	if(file_n < 0 || peer_n < 0)
	{ // All other things can be -1
		error_simple(0,"file_remove_offer failed sanity check.");
		return 0;
	}
	int removed_offers = 0;
	if(f > -1) // Specific file
		removed_offers += remove_offer(file_n,f,peer_n);
	else
	{ // All relevant files
		torx_read(file_n) // 🟧🟧🟧
		for(int ff = 0 ; !is_null(peer[file_n].file[ff].checksum,CHECKSUM_BIN_LEN) ; ff++)
		{
			torx_unlock(file_n) // 🟩🟩🟩
			removed_offers += remove_offer(file_n,ff,peer_n);
			torx_read(file_n) // 🟧🟧🟧
		}
		torx_unlock(file_n) // 🟩🟩🟩
	}
	return removed_offers;
}

int file_remove_request(const int file_n,const int f,const int peer_n,const int8_t fd_type)
{ // modelled after section_unclaim(
	if(file_n < 0 || peer_n < 0)
	{ // All other things can be -1
		error_simple(0,"file_remove_request failed sanity check.");
		return 0;
	}
	int removed_requests = 0;
	if(f > -1) // Specific file
		removed_requests += remove_request(file_n,f,peer_n,fd_type);
	else
	{ // All relevant files
		torx_read(file_n) // 🟧🟧🟧
		for(int ff = 0 ; !is_null(peer[file_n].file[ff].checksum,CHECKSUM_BIN_LEN) ; ff++)
		{
			torx_unlock(file_n) // 🟩🟩🟩
			removed_requests += remove_request(file_n,ff,peer_n,fd_type);
			torx_read(file_n) // 🟧🟧🟧
		}
		torx_unlock(file_n) // 🟩🟩🟩
	}
	return removed_requests;
}

static inline void split_update(const int n,const int f,const int16_t section,const uint64_t transferred)
{ // Updates split or deletes it if complete. section starts at 0. One split == 2 sections, 0 and 1. Set them via: 	peer[n].file[f].split_progress[0] = 123; peer[n].file[f].split_progress[1] = 456; split_update (n,f);
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	torx_read(n) // 🟧🟧🟧
	const uint8_t split_path_exists = peer[n].file[f].split_path ? 1 : 0;
	const uint8_t split_progress_exists = peer[n].file[f].split_progress ? 1 : 0;
	const uint64_t size = peer[n].file[f].size;
	torx_unlock(n) // 🟩🟩🟩
	if(splits == 0 || !split_path_exists)
		return;
	const char *split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	if(split_path && (transferred == size || section == -1)) // DO NOT USE file_status or file_is_complete, use transferred from calculate_transferred_inbound here
	{
		printf(PINK"Checkpoint DELETING SPLIT PATH\n"RESET);
		destroy_file(split_path);
		torx_free((void*)&split_path);
		torx_write(n) // 🟥🟥🟥
		torx_free((void*)&peer[n].file[f].split_path);
	//	torx_free((void*)&peer[n].file[f].split_progress); // No need to free this. Leave it. Likewise, don't change number of splits
		torx_free((void*)&peer[n].file[f].split_status_n);
		torx_free((void*)&peer[n].file[f].split_status_fd);
		torx_free((void*)&peer[n].file[f].split_status_req);
		torx_unlock(n) // 🟩🟩🟩
		return;
	}
	if(section > -1 && split_progress_exists) // sanity check, should be unnecessary
	{
		FILE *fp;
		if((fp = fopen(split_path,"r+")) == NULL)
			if((fp=fopen(split_path,"w+")) == NULL)
			{
				error_printf(0,"Check permissions. Cannot open split file2: %s",split_path);
				torx_free((void*)&split_path);
				return;
			}
		torx_free((void*)&split_path);
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].split_progress)
		{ // Sanity check to prevent race condition
			const uint64_t relevant_split_progress = peer[n].file[f].split_progress[section];
			torx_unlock(n) // 🟩🟩🟩
			fseek(fp,(long int)(CHECKSUM_BIN_LEN+sizeof(splits)+sizeof(uint64_t)*(size_t)section), SEEK_SET); // jump to correct location based upon number of splits
			fwrite(&relevant_split_progress,1,sizeof(relevant_split_progress),fp); // write contents
		}
		else
			torx_unlock(n) // 🟩🟩🟩
		close_sockets_nolock(fp)
	}
}

void process_pause_cancel(const int file_n,const int f,const int peer_n,const uint16_t protocol,const uint8_t message_stat)
{ // see similarities in zero_f
	if(file_n < 0 || f < 0 || peer_n < 0 || (protocol != ENUM_PROTOCOL_FILE_PAUSE && protocol != ENUM_PROTOCOL_FILE_CANCEL))
	{
		error_printf(0,"Sanity check failed in process_pause_cancel: %u",protocol);
		return;
	}
	section_unclaim(file_n,f,peer_n,-1); // Calling this regardless of file_is_active to avoid potential race conditons. Only relevant to ENUM_FILE_ACTIVE_IN / ENUM_FILE_ACTIVE_IN_OUT
	const int is_active = file_is_active(file_n,f); // Should be before we do anything. This is "was_active"
	if(file_n == peer_n && protocol == ENUM_PROTOCOL_FILE_CANCEL)
	{ // Cancel. Free everything *EXCEPT* checksum, filename, file_path, split_hashes, split_path. XXX DO NOT CALL zero_f.
		torx_write(file_n) // 🟥🟥🟥
		if(peer[file_n].file[f].offer)
			for(int o = 0 ; peer[file_n].file[f].offer[o].offerer_n > -1 ; o++)
				zero_o(file_n,f,o);
		if(peer[file_n].file[f].request)
			for(int r = 0 ; peer[file_n].file[f].request[r].requester_n > -1 ; r++)
				zero_r(file_n,f,r);
		torx_free((void*)&peer[file_n].file[f].offer);
		torx_free((void*)&peer[file_n].file[f].request);
		torx_free((void*)&peer[file_n].file[f].split_progress);
		torx_free((void*)&peer[file_n].file[f].split_status_n);
		torx_free((void*)&peer[file_n].file[f].split_status_fd);
		torx_free((void*)&peer[file_n].file[f].split_status_req);
		torx_unlock(file_n) // 🟩🟩🟩
	}
	else
	{ // Pause
		file_remove_request(file_n,f,peer_n,-1);
		if(message_stat == ENUM_MESSAGE_RECV)
			file_remove_offer(file_n,f,peer_n);
	}
	if(file_n == peer_n)
	{ // PM or P2P, or if *we* are pausing/cancelling a group transfer.
		close_sockets(file_n,f)
		if(protocol == ENUM_PROTOCOL_FILE_CANCEL && (is_active == ENUM_FILE_ACTIVE_IN || is_active == ENUM_FILE_ACTIVE_IN_OUT)) // must go after close_sockets
		{ // MUST only trigger on files that are actively inbound. DO NOT REMOVE THE CHECK for ACTIVE_IN/ACTIVE_IN_OUT
			char *file_path = getter_string(NULL,file_n,INT_MIN,f,offsetof(struct file_list,file_path));
			torx_write(file_n) // 🟥🟥🟥
			torx_free((void*)&peer[file_n].file[f].file_path); // Free this to be sure no one will write to it after we delete it
			torx_unlock(file_n) // 🟩🟩🟩
			destroy_file(file_path); // delete partially sent inbound files (note: may also delete fully transferred but that can never be guaranteed)
			torx_free((void*)&file_path);
			split_update(file_n,f,-1,0); // destroys split file and frees/nulls resources
		}
	}
}

int process_file_offer_outbound(const int n,const unsigned char *checksum,const uint8_t splits,const unsigned char *split_hashes_and_size,const uint64_t size,const time_t modified,const char *file_path)
{ // Populates peer[n].file[f].{stuff} for outbound ENUM_PROTOCOL_FILE_OFFER
	if(n < 0 || !checksum || !file_path || !size)
	{
		error_printf(0,"Sanity check failed in process_file_offer_outbound: n=%d size=%llu. Coding error. Report this.",n,size);
		breakpoint();
		return -1;
	}
	const int f = set_f(n,checksum,CHECKSUM_BIN_LEN);
//	printf("Checkpoint file_init n==%d f==%d checksum==%s\n",n,f,b64_encode(checksum,CHECKSUM_BIN_LEN));
	if(split_hashes_and_size)
	{ // set splits and split_hashes for group files
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
		if(owner != ENUM_OWNER_GROUP_CTRL)
		{
			error_simple(0,"Improperly attempting to set split_hashes for a non-GROUP_CTRL. Outbound. Coding error. Report this.");
			breakpoint();
			return -1;
		}
		setter(n,INT_MIN,f,offsetof(struct file_list,splits),&splits,sizeof(splits));
		const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
		torx_write(n) // 🟥🟥🟥
		peer[n].file[f].split_hashes = torx_secure_malloc(split_hashes_len+sizeof(uint64_t));
		memcpy(peer[n].file[f].split_hashes,split_hashes_and_size,split_hashes_len+sizeof(uint64_t));
		torx_unlock(n) // 🟩🟩🟩
	}
	const size_t file_path_len = strlen(file_path);
	char path_copy[file_path_len+1]; // Both dirname() and basename() may modify the contents of path, so it may be desirable to pass a copy when calling one of these functions.
	memcpy(path_copy,file_path,file_path_len+1); // copy null byte
	const char *filename = basename(path_copy);
	const size_t filename_len = strlen(filename);
	torx_write(n) // 🟥🟥🟥
	peer[n].file[f].filename = torx_secure_malloc(filename_len+1);
	snprintf(peer[n].file[f].filename,filename_len+1,"%s",filename);
	peer[n].file[f].file_path = torx_secure_malloc(file_path_len+1);
	snprintf(peer[n].file[f].file_path,file_path_len+1,"%s",file_path);
	peer[n].file[f].size = size;
	peer[n].file[f].modified = modified;
	torx_unlock(n) // 🟩🟩🟩
	sodium_memzero(path_copy,sizeof(path_copy)); // DO NOT DO THIS EARLIER as it modifies 'filename' variable
	return f;
}

int process_file_offer_inbound(const int n,const int p_iter,const char *message,const uint32_t message_len)
{ // processes inbound ENUM_PROTOCOL_FILE_OFFER
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL || message == NULL || p_iter < 0 || n < 0 || message_len == 0)
	{ // could do more extensive sanity check on message_len here. we do that later though, so no need
		error_simple(0,"process_file_offer_inbound triggered on group ctrl or sanity check fail. Coding error. Report this.");
		printf("Checkpoint %u %d %d %d %u",owner,message ? 1 : 0,p_iter,n,message_len);
		breakpoint();
		return -1;
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t utf8 = protocols[p_iter].utf8;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	int f;
	if(protocol == ENUM_PROTOCOL_FILE_OFFER || protocol == ENUM_PROTOCOL_FILE_OFFER_PRIVATE)
	{ // Receive File offer
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t) + 1)
			goto error;
		f = set_f(n,(const unsigned char*)message,CHECKSUM_BIN_LEN); // using checksum is correct here
		const size_t filename_len = message_len - (CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t));
		if(utf8 && !utf8_valid(&message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],filename_len))
		{
			error_simple(0,"Peer offered a file with a non-UTF8 filename. Discarding offer.");
			return -1;
		}
		torx_write(n) // 🟥🟥🟥
		if(peer[n].file[f].filename) // wipe if existing // this might be undesirable? especially if already accepted. should be fine. the old .split file/partial transfer will be abandoned?
			torx_free((void*)&peer[n].file[f].filename); // TODO could cause issue if someone renamed a file then offered it again, in the same instance, after a partial transfer already occured? idk
		peer[n].file[f].filename = torx_secure_malloc(filename_len+1);
		memcpy(peer[n].file[f].filename,&message[CHECKSUM_BIN_LEN + sizeof(uint64_t) + sizeof(uint32_t)],filename_len); // source is not null terminated
		peer[n].file[f].filename[filename_len] = '\0';
		peer[n].file[f].size = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN]));
		peer[n].file[f].modified = be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint64_t)]));
		torx_unlock(n) // 🟩🟩🟩
		// not setting .transferred, will default to 0 if the destination file is empty // TODO open file/split?
		// file_path is also set elsewhere
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_PARTIAL)
	{ // HashOfHashes + sizeof(uint8_t) + sizeof(uint64_t)*(splits+1)
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint8_t))
			goto error;
		const uint8_t splits = *(const uint8_t*)(const void*)&message[CHECKSUM_BIN_LEN];
		if(message_len < FILE_OFFER_PARTIAL_LEN)
			goto error;
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		if(group_n < 0)
			goto error; // received protocol on normal CTRL?
		f = set_f(group_n,(const unsigned char*)message,CHECKSUM_BIN_LEN); // Note: passing full length will register checksum, if not existing
		const int o = set_o(group_n,f,n);
		if(o > -1)
		{
			torx_read(group_n) // 🟧🟧🟧
			const uint8_t offer_exists = peer[group_n].file[f].offer ? 1 : 0;
			const uint8_t split_hashes_exists = peer[group_n].file[f].split_hashes ? 1 : 0;
			const uint8_t filename_exists = peer[group_n].file[f].filename ? 1 : 0;
			const uint8_t offer_progress_exists = peer[group_n].file[f].offer[o].offer_progress ? 1 : 0; // only exists if we have received a partial before
			torx_unlock(group_n) // 🟩🟩🟩
			if(offer_exists)
			{ // Sanity check
				torx_write(group_n) // 🟥🟥🟥
				if(peer[group_n].file[f].offer[o].offer_progress == NULL)
				{
					peer[group_n].file[f].offer[o].offer_progress = torx_insecure_malloc(sizeof(uint64_t)*(splits+1));
					if(o == 0) // Certainly the first time we saw this HashOfHashes
						peer[group_n].file[f].splits = splits;
				}
				for(int16_t section = 0; section <= splits; section++)
					peer[group_n].file[f].offer[o].offer_progress[section] = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + (size_t)section*sizeof(uint64_t)]));
				torx_unlock(group_n) // 🟩🟩🟩
			}
			else
				error_simple(0,"Critical failure in process_file_offer_inbound caused by !offer. Coding error. Report this.1");
			if(!split_hashes_exists && !filename_exists) // Whether this is the first time seeing the file or not, we need additional info
			{ // Do not modify logic here.
				if(offer_progress_exists) // Only requesting if this is the second time or greater that we got a _PARTIAL, because otherwise we could be requesting an offer that is already on its way (due to _PARTIAL being sent on a different socket and arriving first)
					message_send(n,ENUM_PROTOCOL_FILE_INFO_REQUEST,message,CHECKSUM_BIN_LEN);
			}
			else
			{
				const int file_status = file_status_get(group_n,f);
				if(file_status == ENUM_FILE_ACTIVE_IN || file_status == ENUM_FILE_ACTIVE_IN_OUT || file_status == ENUM_FILE_INACTIVE_ACCEPTED) // TODO NOTE: ENUM_FILE_INACTIVE_ACCEPTED here will make pauses really pointless in group transfers, but we need it
					file_request_internal(group_n,f,-1);
			}
		}
	}
	else if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
	{ // HashOfHashes + sizeof(uint8_t) + CHECKSUM_BIN_LEN *(splits + 1)) + sizeof(uint64_t) + sizeof(uint32_t) + filename_len
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint8_t))
			goto error;
		const uint8_t splits = *(const uint8_t*)(const void*)&message[CHECKSUM_BIN_LEN];
		const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
		const uint64_t size = be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len]));
		if((uint64_t)splits + 1 > size)
			goto error; // cannot have more sections than bytes
		if(message_len < CHECKSUM_BIN_LEN + sizeof(uint8_t) + (size_t)(CHECKSUM_BIN_LEN *(splits + 1)) + sizeof(uint64_t) + sizeof(uint32_t) + 1 + date_len + signature_len)
			goto error;
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		if(group_n < 0)
			goto error; // received protocol on normal CTRL?
		f = set_f(group_n,(const unsigned char*)message,CHECKSUM_BIN_LEN); // Note: passing full length will register checksum, if not existing
		size_t filename_len = 0;
		const size_t prefix = CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t);
		filename_len = message_len - (prefix + date_len + signature_len);
		if(utf8 && !utf8_valid(&message[prefix],filename_len))
		{ // sanity check filename
			error_simple(0,"Peer offered a file with a non-UTF8 filename. Discarding offer.");
			for(size_t zzz = 0; zzz < filename_len ; zzz++)
				printf("Checkpoint: (%c)\n",message[prefix + zzz]);
			return -1;
		}
		unsigned char hash_of_hashes[CHECKSUM_BIN_LEN];
		if(b3sum_bin(hash_of_hashes,NULL,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],0,split_hashes_len+sizeof(uint64_t)) != split_hashes_len+sizeof(uint64_t) || memcmp(hash_of_hashes,message,CHECKSUM_BIN_LEN))
		{ // this probably will also error out if peer sends a wrong number of splits, which is necessary to check
			error_simple(0,"Received invalid group file offer. Invalid hash of hashes.");
			sodium_memzero(hash_of_hashes,sizeof(hash_of_hashes));
			return -1;
		}
		sodium_memzero(hash_of_hashes,sizeof(hash_of_hashes));
		torx_read(group_n) // 🟧🟧🟧
		const uint8_t split_hashes_exists = peer[group_n].file[f].split_hashes ? 1 : 0;
		const uint8_t filename_exists = peer[group_n].file[f].filename ? 1 : 0;
		torx_unlock(group_n) // 🟩🟩🟩
		if(!split_hashes_exists && !filename_exists)
		{
			torx_write(group_n) // 🟥🟥🟥
			peer[group_n].file[f].splits = splits; // verified via hash of hashes
			peer[group_n].file[f].split_hashes = torx_secure_malloc(split_hashes_len+sizeof(uint64_t)); // verified via hash of hashes
			memcpy(peer[group_n].file[f].split_hashes,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],split_hashes_len+sizeof(uint64_t));
			peer[group_n].file[f].size = size; // verified via hash of hashes
			peer[group_n].file[f].modified = be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)]));
			peer[group_n].file[f].filename = torx_secure_malloc(filename_len+1);
			memcpy(peer[group_n].file[f].filename,&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t) + sizeof(uint32_t)],filename_len);
			peer[group_n].file[f].filename[filename_len] = '\0';
			printf("Checkpoint inbound GROUP FILE_OFFER nos=%u size=%"PRIu64" %s\n",splits,peer[group_n].file[f].size,peer[group_n].file[f].filename);
			torx_unlock(group_n) // 🟩🟩🟩
		}
	}
	return 0;
	error: {}
	error_simple(0,"Got a complete file offer below minimum size. Bailing. Report this.");
	printf("Checkpoint below minimum size: %u protocol: %u\n",message_len,protocol);
	return -1;
}

static void set_split_path(const int n,const int f)
{
	torx_read(n) // 🟧🟧🟧
	if(!peer[n].file[f].filename || !peer[n].file[f].file_path)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Cannot set split path due to lack of filename or path. Coding error. Report this.");
		return;
	}
	torx_unlock(n) // 🟩🟩🟩
	torx_write(n) // 🟥🟥🟥
	if(peer[n].file[f].split_path)
		torx_free((void*)&peer[n].file[f].split_path);
	size_t allocation_size;
	pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
	if(split_folder)
	{
		allocation_size = strlen(split_folder) + 1 + strlen(peer[n].file[f].filename) + 6 + 1;
		peer[n].file[f].split_path = torx_secure_malloc(allocation_size);
		snprintf(peer[n].file[f].split_path,allocation_size,"%s%c%s.split",split_folder,platform_slash,peer[n].file[f].filename);
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
	else
	{
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		allocation_size = strlen(peer[n].file[f].file_path) + 6 + 1;
		peer[n].file[f].split_path = torx_secure_malloc(allocation_size);
		snprintf(peer[n].file[f].split_path,allocation_size,"%s.split",peer[n].file[f].file_path);
	}
	torx_unlock(n) // 🟩🟩🟩
}

static inline int split_read(const int n,const int f)
{ // File is in binary format. Checksum,nos,split_progress
	char *split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	if(!split_path)
	{
		set_split_path(n,f);
		split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
	}
	FILE *fp = fopen(split_path, "r"); // read file contents, while checking compliance of checksum.
	torx_free((void*)&split_path);
	uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	if(fp)
	{
		unsigned char checksum_local[CHECKSUM_BIN_LEN];
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
		if(fread(checksum_local,1,CHECKSUM_BIN_LEN,fp) != CHECKSUM_BIN_LEN)
			error_simple(0,"Failed to read checksum from split file. Invalid split file exists."); // read checksum
		else if(memcmp(checksum,checksum_local,CHECKSUM_BIN_LEN))
			error_simple(0,"Checksum did not match. Invalid split file exists."); // compare checksum
		else if(fread(&splits,1,sizeof(splits),fp) == 0)
			error_simple(0,"Failed to read number of splits from split file. Invalid split file exists."); // read splits
		else
		{ // this is correct, the previous else if modified splits
			setter(n,INT_MIN,f,offsetof(struct file_list,splits),&splits,sizeof(splits));
			sodium_memzero(checksum,sizeof(checksum));
		}
	}
//	else
//		printf("Checkpoint no split file found\n");
	const size_t read_size = sizeof(uint64_t)*(size_t)(splits+1);
//	printf("Checkpoint split_read allocating n=%d f=%d splits=%u\n",n,f,splits);
	uint64_t *split_progress = torx_insecure_malloc(read_size);
	int *split_status_n = torx_insecure_malloc(sizeof(int)*(size_t)(splits+1));
	int8_t *split_status_fd = torx_insecure_malloc(sizeof(int8_t)*(size_t)(splits+1));
	uint64_t *split_status_req = torx_insecure_malloc(sizeof(uint64_t)*(size_t)(splits+1));
	for(int16_t section = 0; section <= splits; section++)
	{ // initialize info to zero and status to -1 (invalid n)
		split_progress[section] = 0;
		split_status_n[section] = -1; // no one yet claims this
		split_status_fd[section] = -1; // no one yet claims this
		split_status_req[section] = 0;
	}
	if(fp && fread(split_progress,1,read_size,fp) != read_size)
		error_simple(0,"Could not open split file or found an invalid checksum."); // read sections
	torx_write(n) // 🟥🟥🟥
	peer[n].file[f].split_progress = split_progress;
	peer[n].file[f].split_status_n = split_status_n;
	peer[n].file[f].split_status_fd = split_status_fd;
	peer[n].file[f].split_status_req = split_status_req;
	torx_unlock(n) // 🟩🟩🟩
	if(fp)
	{ // condition is necessary with fclose it seems
	//	printf("Checkpoint Reading nos: %d\n",peer[n].file[f].splits);
	//	printf("Checkpoint Reading split data: %lu %lu\n",peer[n].file[f].split_progress[0],peer[n].file[f].split_progress[1]);
		close_sockets_nolock(fp)
		return 0; // successfully read
	}
	return -1; // no file exists, wrong checksum, or cannot be read
}

int initialize_split_info(const int n,const int f)
{ // Should read split file and set the details, or create and initialize split file ( as 0,0,0,0,etc ). File is in binary format. Checksum,nos,split_progress. XXX DO NOT CALL UNLESS ACCEPTING FILE, or a cancelled file can be uncancelled.
	const uint64_t size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_path && peer[n].file[f].split_progress)
	{ // Split info appears already initialized. No need to do it again.
		torx_unlock(n) // 🟩🟩🟩
		return 0;
	}
	if(size == 0 || peer[n].file[f].file_path == NULL)
	{ // Sanity check
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Cannot initialize split info. Sanity check failed.");
		printf("Checkpoint owner==%d size==%"PRIu64"\n",getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner)),size);
		return -1;
	}
	const uint8_t split_progress_exists = peer[n].file[f].split_progress ? 1 : 0;
	torx_unlock(n) // 🟩🟩🟩
	if(!split_progress_exists)
	{ // Initialize if not already
		split_read(n,f); // reads split file or initializes in memory
		struct stat file_stat = {0};
		char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
		const int stat_file = stat(file_path, &file_stat); // Note: file_path cannot be null, but we checked it earlier.
		torx_free((void*)&file_path);
		const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
		char *split_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,split_path));
		if(stat_file && split_path && stat(split_path, &file_stat) && splits > 0) // note: we use stat() for speed because it doesn't need to open the files. If the file isn't readable, it'll error out elsewhere. Do not change.
		{ // file nor .split exists; write an initialized .split file
			FILE *fp;
			if((fp = fopen(split_path,"w+")) == NULL)
			{ // BAD, permissions issue, cannot create file
				error_printf(0,"Check permissions. Cannot open split file1: %s",split_path);
				torx_free((void*)&split_path);
				return -1;
			}
			unsigned char split_data[CHECKSUM_BIN_LEN + sizeof(splits) + sizeof(uint64_t)*(splits+1)];
			getter_array(&split_data,CHECKSUM_BIN_LEN,n,INT_MIN,f,offsetof(struct file_list,checksum));
			memcpy(&split_data[CHECKSUM_BIN_LEN],&splits,sizeof(splits));
			torx_read(n) // 🟧🟧🟧
			memcpy(&split_data[CHECKSUM_BIN_LEN + sizeof(splits)],peer[n].file[f].split_progress,sizeof(uint64_t)*(splits+1));
			torx_unlock(n) // 🟩🟩🟩
			fwrite(split_data,1,sizeof(split_data),fp);
			close_sockets_nolock(fp)
			sodium_memzero(split_data,sizeof(split_data));
		}
		torx_free((void*)&split_path);
	}
	return 0;
}

int16_t section_determination(const uint64_t size,const uint8_t splits,const uint64_t packet_start)
{ // WARNING: Must handle -1 return by disgarding packet. Note: packet_start is 0 offset byte number.
	if(packet_start >= size)
		return -1;
	int16_t section = splits+1;
	uint64_t section_start = 0;
	while(packet_start < (section_start = calculate_section_start(NULL,size,splits,section)))
		section--; // XXX DO NOT MODIFY WITHOUT EXTENSIVE TESTING XXX
	return section;
}

void section_update(const int n,const int f,const uint64_t packet_start,const size_t wrote,const int8_t fd_type,const int16_t section,const uint64_t section_end,const int peer_n)
{ // INBOUND FILE TRANSFER ONLY To be called after write during file transfer. Updates .split_progress, determines whether to call split_update. peer_n is only used for blacklisting.
	if(wrote < 1)
		return;
	if(n < 0 || f < 0 || fd_type < 0 || section < 0 || peer_n < 0)
	{
		error_simple(0,"Sanity check failure in section_update1. Coding error. Report this.");
		return;
	}
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	torx_write(n) // 🟥🟥🟥 yes, its a write, see += several lines later
	const uint8_t split_progress_exists = peer[n].file[f].split_progress ? 1 : 0;
	const uint8_t split_status_req_exists = peer[n].file[f].split_status_req ? 1 : 0;
	if(!split_progress_exists || !split_status_req_exists)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Sanity check failure in section_update2. Coding error. Report this.");
		return;
	}
	const uint64_t section_info_current = peer[n].file[f].split_progress[section] += wrote;
	const uint64_t section_req_current = peer[n].file[f].split_status_req[section];
	torx_unlock(n) // 🟩🟩🟩
	const uint8_t section_complete = (packet_start + wrote == section_end + 1);
	const uint64_t transferred = calculate_transferred_inbound(n,f); // DO NOT USE file_is_complete, use calculate_transferred_inbound
	if(section_complete || section_info_current == section_req_current)
	{ // Section complete. Close file descriptors (flushing data to disk)
		close_sockets(n,f)
		const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
		char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
		const uint64_t size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
		if(section_complete)
		{ // Verify checksum
			if(owner == ENUM_OWNER_GROUP_CTRL)
			{ // Run checksum on the group file's individual section
				uint64_t end = 0;
				const uint64_t start = calculate_section_start(&end,size,splits,section);
				const uint64_t len = end - start + 1;
				unsigned char checksum[CHECKSUM_BIN_LEN];
				const uint64_t ret1 = b3sum_bin(checksum,file_path,NULL,start,len);
				torx_read(n) // 🟧🟧🟧
				const int ret2 = memcmp(checksum,&peer[n].file[f].split_hashes[CHECKSUM_BIN_LEN*section],CHECKSUM_BIN_LEN);
				torx_unlock(n) // 🟩🟩🟩
				sodium_memzero(checksum,sizeof(checksum));
				if(ret1 == 0 || ret2)
				{ // Has been tested, works.
					error_printf(0,"Bad section checksum: n=%d f=%d peer_n=%d sec=%u. Blacklisting peer and marking section as incomplete. Requesting from others, if available.",n,f,peer_n,section);
					torx_write(n) // 🟥🟥🟥
					if(peer[n].file[f].split_progress) // sanity check to prevent race condition
						peer[n].file[f].split_progress[section] = 0;
					torx_unlock(n) // 🟩🟩🟩
					torx_write(peer_n) // 🟥🟥🟥
					peer[peer_n].blacklisted++;
					torx_unlock(peer_n) // 🟩🟩🟩
				}
				else
				{
					error_printf(1,"Successfully verified checksum n=%d f=%d peer_n=%d sec=%d",n,f,peer_n,section);
					struct file_request_strc file_request_strc = {0};
					file_request_strc.n = n; // potentially group_n. THIS IS NOT target_n
					file_request_strc.f = f;
					message_send(n,ENUM_PROTOCOL_FILE_OFFER_PARTIAL,&file_request_strc,FILE_OFFER_PARTIAL_LEN);
				}
			}
		}
		section_unclaim(n,f,peer_n,fd_type); // must be before file_request_internal
		if(section_complete && transferred == size)
		{
			if(CHECKSUM_ON_COMPLETION && owner != ENUM_OWNER_GROUP_CTRL) // Note: Group file generate section hashes and compare individually. Not necessary to check hash of hashes or size.
			{ // TODO This blocks, so it should be used for debug purposes only
				unsigned char checksum_complete[CHECKSUM_BIN_LEN];
				unsigned char checksum[CHECKSUM_BIN_LEN];
				getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
				if(b3sum_bin(checksum_complete,file_path,NULL,0,0) && !memcmp(checksum_complete,checksum,CHECKSUM_BIN_LEN))
					error_printf(0,PINK"Successfully VERIFIED checksum n=%d f=%d"RESET,n,f);
				else
				{
					error_simple(0,PINK"Checkpoint Failed checksum verification."RESET); // non-group
					breakpoint();
				}
				sodium_memzero(checksum,sizeof(checksum));
				sodium_memzero(checksum_complete,sizeof(checksum_complete));
			}
			struct utimbuf new_times;
			new_times.actime = time(NULL); // set access time to current time
			torx_read(n) // 🟧🟧🟧
			new_times.modtime = peer[n].file[f].modified; // set modification time
			torx_unlock(n) // 🟩🟩🟩
			if(utime(file_path, &new_times))
			{ // Failed to set modification time (this is fine)
				struct stat file_stat = {0};
				if(!stat(file_path, &file_stat))
				{ // Read modification time from disk instead
					torx_write(n) // 🟥🟥🟥
					peer[n].file[f].modified = file_stat.st_mtime;
					torx_unlock(n) // 🟩🟩🟩
				}
			}
		}
		else if(owner == ENUM_OWNER_GROUP_CTRL) // (peer_n > -1 && peer[peer_n].blacklisted)
			file_request_internal(n,f,-1); // 2024/12/17 Experimental, requesting from a different peer on any fd_type
		else
			file_request_internal(n,f,fd_type);
		torx_free((void*)&file_path);
		split_update(n,f,section,transferred);
	}
	else if(splits && section_info_current && (section_info_current - wrote) / (120*SPLIT_DELAY*1024) != section_info_current / (120*SPLIT_DELAY*1024)) // Checking whether to call split_update
		split_update(n,f,section,transferred); // ~8 times per 1mb with SPLIT_DELAY = 1
}

int calculate_file_request_start_end(uint64_t *start,uint64_t *end,const int n,const int f,const int o,const int16_t section)
{ // NOTE: This does NOT account for contents of peer offer, unless o is passed. This accounts mainly for what we already have.
	if(!start || !end || n < 0 || f < 0 || section < 0)
	{
		error_simple(0,"Sanity check failed in calculate_file_request_start_end1. Coding error. Report this.");
		return -1;
	}
	const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_progress == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Sanity check failed in calculate_file_request_start_end2. Coding error. Report this.");
		goto error;
	}
	const uint64_t our_progress = peer[n].file[f].split_progress[section];
	torx_unlock(n) // 🟩🟩🟩
	const uint64_t section_start = calculate_section_start(end,file_size,splits,section);
	*start = section_start + our_progress;
	if(o > -1)
	{ // Group transfer
		uint64_t peer_progress;
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].offer && peer[n].file[f].offer[o].offer_progress)
			peer_progress = peer[n].file[f].offer[o].offer_progress[section];
		else
			peer_progress = 0;
		torx_unlock(n) // 🟩🟩🟩
		if(!peer_progress)
			goto error; // XXX DO NOT ELIMINATE THIS CHECK, otherwise we can get a negative int overflow on the next line
		*end = section_start + peer_progress - 1; // XXX previously was followed by -1
	//	printf("Checkpoint calculate_file_request_start_end %lu = %lu + %lu\n",*end,section_start,peer_progress);
	}
	if(*start > *end)
		goto error; // Section appears finished. Cannot request any data.
	return 0;
	error: {}
	*start = *end = 0;
	return -1;
}

static inline int unclaim(uint16_t *active_transfers_ongoing,const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p).
	const uint8_t peer_owner = getter_uint8(peer_n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(n < 0 || f < 0 || peer_n < 0 || peer_owner == ENUM_OWNER_GROUP_CTRL || active_transfers_ongoing == NULL)
	{
		error_printf(0,"Unclaim sanity check fail: n=%d f=%d peer_n=%d peer_owner=%u\n",n,f,peer_n,peer_owner);
		return 0;
	}
	int was_transferring = 0;
	torx_write(n) // 🟥🟥🟥 YES, must be write, because we can't unlock or we could have races
	if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL || peer[n].file[f].split_status_req == NULL)
	{
		torx_unlock(n) // 🟩🟩🟩
		return was_transferring;
	}
	for(int16_t section = 0; section <= peer[n].file[f].splits; section++)
	{
		if(peer[n].file[f].split_status_n[section] == peer_n && (peer[n].file[f].split_status_fd[section] == fd_type || fd_type < 0))
		{
			peer[n].file[f].split_status_n[section] = -1; // unclaim section
			peer[n].file[f].split_status_fd[section] = -1;
			peer[n].file[f].split_status_req[section] = 0;
			error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status_n[%d] = -1"RESET,n,f,section); // TODO this triggers a callback within a mutex
			was_transferring++;
		}
		else if(peer[n].file[f].split_status_n[section] > -1)
			*active_transfers_ongoing = *active_transfers_ongoing + 1; // cannot use ++ here. Would be invalid pointer math.
	}
	torx_unlock(n) // 🟩🟩🟩
	return was_transferring;
}

int section_unclaim(const int n,const int f,const int peer_n,const int8_t fd_type)
{ // This is used on ALL TYPES of file transfer (group, PM, p2p) // To unclaim all sections, pass fd_type == -1
	if(n < 0 || peer_n < 0)
	{ // All other things can be -1
		error_simple(0,"Section unclaim failed sanity check.");
		return 0;
	}
	uint16_t active_transfers_ongoing = 0;
	int was_transferring = 0;
	if(f > -1)  // Unclaim sections of a specific file (typical upon pause)
		was_transferring += unclaim(&active_transfers_ongoing,n,f,peer_n,fd_type);
	else
	{ // Unclaim sections of all files (typical when a socket closes during inbound transfer)
		torx_read(n) // 🟧🟧🟧
		for(int ff = 0 ; !is_null(peer[n].file[ff].checksum,CHECKSUM_BIN_LEN) ; ff++)
		{
			torx_unlock(n) // 🟩🟩🟩
			uint16_t ongoing = 0;
			was_transferring += unclaim(&ongoing,n,ff,peer_n,fd_type);
			active_transfers_ongoing += ongoing;
			torx_read(n) // 🟧🟧🟧
		}
		torx_unlock(n) // 🟩🟩🟩
	}
	if(!active_transfers_ongoing && f > -1)
		transfer_progress(n,f); // XXX This intentionally triggers a stall because no transfer has occurred since last_transferred was last updated. XXX
	return was_transferring;
}

static inline int select_peer(const int n,const int f,const int8_t fd_type)
{ // Check: blacklist, online status, how much data they have. Determine which group peer to request file from. Claim section. Used to be called section_claim().
	if(n < 0 || f < 0)
	{
		error_simple(0,"Sanity check failed in select_peer. Coding error. Report this.");
		return -1;
	}
	torx_read(n) // 🟧🟧🟧
	if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL)
	{ // TODO (old note: ) Can trigger upon Accept -> Reject / Cancel -> Re-offer -> Accept
		torx_unlock(n) // 🟩🟩🟩
		error_printf(0,"select_peer split_status_n/fd is NULL; file may be unaccepted, completed, or cancelled: %d",file_status_get(n,f)); //  If this is an error, call split_read or section_update first, either of which will initialize.
		return -1;
	}
	torx_unlock(n) // 🟩🟩🟩
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
	const uint64_t file_size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
	struct file_request_strc file_request_strc = {0};
	file_request_strc.n = n; // potentially group_n. THIS IS NOT target_n
	file_request_strc.f = f;
	int target_n = -1;
	uint64_t target_progress = 0;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Group transfers, non-PM
		int target_o = -1;
		torx_read(n) // 🟧🟧🟧
		if(peer[n].file[f].offer && peer[n].file[f].split_status_n && peer[n].file[f].split_progress && peer[n].file[f].split_status_fd)
		{
			if(peer[n].file[f].offer[0].offerer_n == -1)
			{ // Request _PARTIAl from everyone because we don't have any offers (we probably just retarted our client)
				torx_unlock(n) // 🟩🟩🟩
				unsigned char checksum[CHECKSUM_BIN_LEN];
				getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
				message_send(n,ENUM_PROTOCOL_FILE_PARTIAL_REQUEST,checksum,CHECKSUM_BIN_LEN);
				sodium_memzero(checksum,sizeof(checksum));
			}
			else
			{
				for(int o = 0 ; peer[n].file[f].offer[o].offerer_n != -1 ; o++)
				{
					const uint8_t sendfd_connected = peer[peer[n].file[f].offer[o].offerer_n].sendfd_connected;
					const uint8_t recvfd_connected = peer[peer[n].file[f].offer[o].offerer_n].recvfd_connected;
					const uint8_t online = recvfd_connected + sendfd_connected;
					const uint8_t blacklisted = peer[peer[n].file[f].offer[o].offerer_n].blacklisted;
					if(!online || blacklisted) // check blacklist and online status
						continue;
					uint8_t utilized = 0;
					int8_t utilized_fd_type = -1;
					for(int16_t section = 0; section <= splits; section++)
					{ // Making sure we don't request more than two sections of the same file from the same peer concurrently, nor more than one on one fd_type.
						const int relevant_split_status_n = peer[n].file[f].split_status_n[section];
						const int8_t tmp_fd_type = peer[n].file[f].split_status_fd[section];
						if(relevant_split_status_n == peer[n].file[f].offer[o].offerer_n)
						{
							utilized++;
							utilized_fd_type = tmp_fd_type;
						}
					}
					if(utilized >= online)
						continue; // We already have 2+ requests of this file from this peer. Go to the next peer.
					for(int16_t section = 0; section <= splits; section++)
					{ // Loop through all peers looking for the largest (most complete) section... literally any section. Continue if we have completed this section or if it is already being requested from someone else.
						const uint64_t offerer_progress = peer[n].file[f].offer[o].offer_progress[section];
						const int relevant_split_status_n = peer[n].file[f].split_status_n[section];
						const uint64_t relevant_progress = peer[n].file[f].split_progress[section];
						const int8_t relevant_split_status_fd = peer[n].file[f].split_status_fd[section];
						if(relevant_split_status_n != -1 || relevant_progress >= offerer_progress)
						{
							if(relevant_split_status_fd > -1)
								error_printf(5,"select_peer existing: n=%d fd=%d sec=%d %lu of %lu",relevant_split_status_n,relevant_split_status_fd,section,relevant_progress,offerer_progress);
							continue; // Already requested from another peer, or the progress is less than we have. Go to the next section.
						}
						if(offerer_progress >= target_progress)
						{ // >= should result in the largest most recent offer being selected
							target_n = peer[n].file[f].offer[o].offerer_n;
							target_progress = offerer_progress;
							file_request_strc.section = section;
							target_o = o;
							if(utilized && utilized_fd_type == 0) // XXX must prevent requesting two different sections of the same file concurrently on the same socket!!!
								file_request_strc.fd_type = 1;
							else if(utilized && utilized_fd_type == 1)
								file_request_strc.fd_type = 0;
							else if(sendfd_connected)
								file_request_strc.fd_type = 1; // we'll prefer sendfd for transfers because we prefer recvfd for messages
							else
								file_request_strc.fd_type = 0;
						}
					}
				}
				torx_unlock(n) // 🟩🟩🟩
			}
		}
		if(target_n > -1)
		{
			if(getter_uint8(target_n,INT_MIN,-1,offsetof(struct peer_list,owner)) != ENUM_OWNER_GROUP_PEER)
			{ // Sanity check, should be unnecessary
				error_simple(0,"target_n can only be GROUP_PEER. Coding error. Report this.");
				return -1;
			}
			if(calculate_file_request_start_end(&file_request_strc.start,&file_request_strc.end,n,f,target_o,file_request_strc.section))
			{
				error_simple(0,"calculate_file_request_start_end failed with a group_ctrl. Coding error. Report this."); // possible race if this occurs?
				return -1;
			}
			error_printf(4,"select_peer n=%d f=%d target_o=%d splits=%u section=%d start=%lu end=%lu",n,f,target_o,splits,file_request_strc.section,file_request_strc.start,file_request_strc.end);
		}
	}
	else
	{ // _CTRL or _GROUP_PEER, ie: PM/p2p, not group transfers. This section is NOT suitable for group transfers because we pass -1 as offer_o to calculate_file_request_start_end, which means we are assuming our peer has 100% of the file.
		printf(BRIGHT_GREEN"Checkpoint select_peer _CTRL or _GROUP_PEER owner=%u n=%d f=%d splits=%u\n"RESET,owner,n,f,splits);
		if(fd_type == -1)
		{ // Sanity check
			error_simple(0,"Wrong fd_type passed to select_peer. Coding error. Report this.");
			return -1;
		}
		target_n = n;
		file_request_strc.fd_type = fd_type; // must be set by caller
		for(file_request_strc.section = 0; file_request_strc.section <= splits ; file_request_strc.section++)
		{ // There should only be 1 or 2 sections, 0 or 1 splits.
			torx_read(n) // 🟧🟧🟧
			if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL)
			{ // Sanity check to prevent race condition
				torx_unlock(n) // 🟩🟩🟩
				error_simple(0,"select_peer file is probably cancelled1. Possible coding error. Report this.");
				return -1;
			}
			const int relevant_split_status_n = peer[n].file[f].split_status_n[file_request_strc.section];
			const int8_t tmp_fd_type = peer[n].file[f].split_status_fd[file_request_strc.section];
			torx_unlock(n) // 🟩🟩🟩
			if(relevant_split_status_n != -1 && tmp_fd_type == fd_type)
			{ // Cannot concurrently request more than one section of the same file on the same file descriptor or we'll have errors about non-consecutive writes.
				error_simple(0,"Request already exists for a section of this file on this fd_type. Coding error. Report this.");
				return -1;
			}
			if(relevant_split_status_n == -1 && calculate_file_request_start_end(&file_request_strc.start,&file_request_strc.end,n,f,-1,file_request_strc.section) == 0)
				break; // Target section aquired
		}
		if(file_request_strc.section > splits)
			return -1; // No unfinished sections available to request.
		const uint64_t section_start = calculate_section_start(NULL,file_size,splits,file_request_strc.section);
		target_progress = file_request_strc.end - section_start + 1; // MUST utilize section_start, not file_request_strc.start // NOTE: This is unnecessary/unutilized in non-group transfers.
	}
	if(target_n > -1)
	{
		if(file_request_strc.end >= file_size)
		{
			error_printf(0,"Sanity check failure in select_peer: end=%lu >= size=%lu",file_request_strc.end,file_size);
			return -1;
		}
		torx_write(n) // 🟥🟥🟥
		if(peer[n].file[f].split_status_n == NULL || peer[n].file[f].split_status_fd == NULL || peer[n].file[f].split_status_req == NULL)
		{ // Sanity check to prevent race condition
			torx_unlock(n) // 🟩🟩🟩
			error_simple(0,"select_peer file is probably cancelled2. Possible coding error. Report this.");
			return -1;
		}
		peer[n].file[f].split_status_n[file_request_strc.section] = target_n; // XXX claim it. NOTE: do NOT have any 'goto error' after this. MUST NOT ERROR AFTER CLAIMING XXX
		peer[n].file[f].split_status_fd[file_request_strc.section] = file_request_strc.fd_type;
		peer[n].file[f].split_status_req[file_request_strc.section] = target_progress;
		torx_unlock(n) // 🟩🟩🟩
		error_printf(0,RED"Checkpoint split_status setting peer[%d].file[%d].split_status_n[%d] = %d, fd_type = %d"RESET,n,f,file_request_strc.section,target_n,file_request_strc.fd_type);
		message_send(target_n,ENUM_PROTOCOL_FILE_REQUEST,&file_request_strc,FILE_REQUEST_LEN);
		return target_n;
	}
	return -1;
}

static inline int file_unwritable(const int n,const int f,const char *file_path)
{ // Check whether file permissions issues exist at the destination before requesting a file. Pass either n+f or file_path.
	if((n < 0 || f < 0) && file_path == NULL)
	{
		error_simple(0,"Sanity check in file_unwritable failed.");
		breakpoint();
		return 1;
	}
	FILE *fp;
	if(file_path)
		fp = fopen(file_path, "a");
	else
	{
		char *file_path_local = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
		fp = fopen(file_path_local, "a");
		torx_free((void*)&file_path_local);
	}
	if(fp)
	{
		close_sockets_nolock(fp)
		return 0;
	}
	else if(file_path == NULL)
	{ // n,f was necessarily passed
		torx_write(n) // 🟥🟥🟥
		torx_free((void*)&peer[n].file[f].file_path);
		torx_free((void*)&peer[n].file[f].split_path);
		torx_unlock(n) // 🟩🟩🟩
	}
	error_simple(0,"File location permissions issue. Refusing to request file. Cleaing the file_path if n,f was passed so that it can be reset.");
	return 1;
}

void file_request_internal(const int n,const int f,const int8_t fd_type)
{ // Internal function only, do not call from UI. Use file_accept
	if(n < 0 || f < 0)
		return;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	torx_read(n) // 🟧🟧🟧
	const uint8_t file_path_exists = peer[n].file[f].file_path ? 1 : 0;
	torx_unlock(n) // 🟩🟩🟩
	if(file_path_exists)
	{
		if(file_unwritable(n,f,NULL))
			return;
	}
	else
	{
		error_simple(0,"Lack of file_path in file_request_internal. Coding error. Report this.");
		breakpoint();
		return;
	}
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		while(select_peer(n,f,-1) > -1)
			continue; // Request from lots of people concurrently.
	}
	else
	{ // These are _CTRL(p2p) and _GROUP_CTRL(PM) transfers
		if(fd_type == -1)
		{ // Probably got here from file_accept
			if(getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,sendfd_connected))) // DO NOT MAKE else if
				select_peer(n,f,1);
			if(getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,recvfd_connected))) // DO NOT MAKE else if
				select_peer(n,f,0);
		}
		else // Probably got here from packet_removal
			select_peer(n,f,fd_type);
	}
}

void file_offer_internal(const int target_n,const int file_n,const int f,const uint8_t send_partial)
{ // Internal function only, do not call from UI. Use file_send
	const uint8_t owner = getter_uint8(file_n,INT_MIN,-1,offsetof(struct peer_list,owner)); // yes, MUST be file_n owner
	if(owner != ENUM_OWNER_GROUP_CTRL && target_n != file_n)
	{ // Could also check that target_n is in the same group as file_n, but should be unnecessary.
		error_simple(0,"Sanity check failure in file_offer_internal. Coding error. Report this.");
		return;
	}
	struct file_request_strc file_request_strc = {0};
	file_request_strc.n = file_n;
	file_request_strc.f = f;
	torx_read(file_n) // 🟧🟧🟧
	const size_t filename_len = strlen(peer[file_n].file[f].filename);
	const uint8_t splits = peer[file_n].file[f].splits;
	torx_unlock(file_n) // 🟩🟩🟩
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{
		const int g = set_g(file_n,NULL);
		const uint8_t invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
		if(invite_required)
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED,&file_request_strc,FILE_OFFER_GROUP_LEN);
		else
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_GROUP,&file_request_strc,FILE_OFFER_GROUP_LEN);
		if(send_partial) // NOT else if
			message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_PARTIAL,&file_request_strc,FILE_OFFER_PARTIAL_LEN); // tell them that we have 100%
	}
	else if(owner == ENUM_OWNER_GROUP_PEER)
		message_send(target_n,ENUM_PROTOCOL_FILE_OFFER_PRIVATE,&file_request_strc,FILE_OFFER_LEN);
	else
		message_send(target_n,ENUM_PROTOCOL_FILE_OFFER,&file_request_strc,FILE_OFFER_LEN);
}

void file_set_path(const int n,const int f,const char *path)
{ // To be called before file_accept. This is a helper function for FFI/Flutter. TODO Have this function utilize torx_fd_lock and other things to move/rename an existing file, mid transfer or otherwise.
	size_t len;
	if(!path || !(len = strlen(path)))
	{
		error_simple(0,"Zero length or null path passed to file_set_path");
		return;
	}
	torx_write(n) // 🟥🟥🟥
	if(peer[n].file[f].file_path == NULL)
	{
		peer[n].file[f].file_path = torx_secure_malloc(len+1);
		memcpy(peer[n].file[f].file_path,path,len+1);
		torx_unlock(n) // 🟩🟩🟩
	}
	else
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Currently, changing file_path is not facilitated. (we would have to change file name too and make sure its not active, maybe move the actual file...");
	}
}

void file_accept(const int n,const int f)
{ // Toggle to accept or pause file transfer
	if(n < 0 || f < 0)
		return;
	torx_read(n) // 🟧🟧🟧
	const uint8_t owner = peer[n].owner;
	const uint8_t filename_exists = peer[n].file[f].filename ? 1 : 0;
	torx_unlock(n) // 🟩🟩🟩
	const int file_status = file_status_get(n,f);
	if(!filename_exists)
	{ // probably ENUM_OWNER_GROUP_PEER, non-PM message, or where the file path is not yet set by UI
		error_simple(0,"File information not provided. Cannot accept. Coding error. Report this.");
		printf("Checkpoint file_accept owner: %u file_status: %d\n",owner,file_status);
		return;
	}
	if(file_status == ENUM_FILE_ACTIVE_IN || file_status == ENUM_FILE_ACTIVE_OUT || file_status == ENUM_FILE_ACTIVE_IN_OUT)
	{ // pause in/outbound transfer. Reciever can unpause it.  // Much redundancy in logic applies with file cancel  For group file transfers, like a _PARTIAL, the message is broadcast to everyone.
		unsigned char checksum[CHECKSUM_BIN_LEN];
		getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
		message_send(n,ENUM_PROTOCOL_FILE_PAUSE,checksum,CHECKSUM_BIN_LEN); // request the sender to stop sending
		sodium_memzero(checksum,sizeof(checksum));
		process_pause_cancel(n,f,n,ENUM_PROTOCOL_FILE_PAUSE,ENUM_MESSAGE_FAIL);
	}
	else if(file_status == ENUM_FILE_INACTIVE_COMPLETE) // User unpause by re-offering file (safer than setting _ACCEPTED and directly start re-pushing (Section 6RMA8obfs296tlea), even though it could mean some packets / data is sent twice.)
		file_offer_internal(n,n,f,1); // DO NOT CALL process_pause_cancel here, do not set _ACCEPTED ; we wait for peer to accept
	else if(file_status == ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND || file_status == ENUM_FILE_INACTIVE_ACCEPTED)
	{ // Accept, re-accept, or unpause a file
		pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
		const uint8_t download_dir_exists = download_dir ? 1 : 0;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		torx_read(n) // 🟧🟧🟧
		const uint8_t file_path_exists = peer[n].file[f].file_path ? 1 : 0;
		torx_unlock(n) // 🟩🟩🟩
		if(download_dir_exists && !file_path_exists)
		{ // Setting file_path to inside download_dir if existing. Client may have already set .file_path, preventing this from occuring.
			torx_write(n) // 🟥🟥🟥
			pthread_rwlock_rdlock(&mutex_global_variable); // 🟧
			const size_t allocated_size = strlen(download_dir)+1+strlen(peer[n].file[f].filename)+1;
			peer[n].file[f].file_path = torx_secure_malloc(allocated_size);
			snprintf(peer[n].file[f].file_path,allocated_size,"%s%c%s",download_dir,platform_slash,peer[n].file[f].filename);
			pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			torx_unlock(n) // 🟩🟩🟩
		}
		else if(!download_dir_exists && !file_path_exists)
		{
			error_simple(0,"Cannot accept file. Have not set file path nor download directory.");
			return;
		}
		uint8_t splits = getter_uint8(n,INT_MIN,f,offsetof(struct file_list,splits));
		torx_read(n) // 🟧🟧🟧
		const uint8_t split_hashes_exists = peer[n].file[f].split_hashes ? 1 : 0;
		torx_unlock(n) // 🟩🟩🟩
		if(splits == 0 && !split_hashes_exists)
		{ // set splits to 1 if not already, but not on group files (which will have split_hashes)
			splits = 1; // set default before split_read, which might overwrite it.
			setter(n,INT_MIN,f,offsetof(struct file_list,splits),&splits,sizeof(splits));
		}
		initialize_split_info(n,f); // calls split_read(n,f);
		const uint64_t size = getter_uint64(n,INT_MIN,f,offsetof(struct file_list,size));
		if(calculate_transferred_inbound(n,f) < size)
			file_request_internal(n,f,-1);
		else // Complete. Not checking if oversized or wrong hash.
			error_simple(0,"This code should never execute. If it executes, the split file hasn't been deleted but should have been. Report this.");
	}
	else
	{ // NOTE: This is probably a UI error caused by ENUM_FILE_INACTIVE_CANCELLED
		error_printf(0,"Attempted file_accept on file %d with unrecognized file_status: %u. Coding error. Report this.",f,file_status);
		breakpoint();
	}
}

void file_cancel(const int n,const int f)
{ // Much redundancy in logic applies with file pause. For group file transfers, like a _PARTIAL, the message is broadcast to everyone.
	if(n < 0 || f < 0)
		return;
	unsigned char checksum[CHECKSUM_BIN_LEN];
	getter_array(&checksum,sizeof(checksum),n,INT_MIN,f,offsetof(struct file_list,checksum));
	message_send(n,ENUM_PROTOCOL_FILE_CANCEL,checksum,CHECKSUM_BIN_LEN);
	sodium_memzero(checksum,sizeof(checksum));
	process_pause_cancel(n,f,n,ENUM_PROTOCOL_FILE_CANCEL,ENUM_MESSAGE_FAIL);
}

unsigned char *file_split_hashes(unsigned char *hash_of_hashes,const char *file_path,const uint8_t splits,const uint64_t size)
{ // Be sure to torx_free. This is for group files.
	if(!file_path)
		return NULL;
	const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
	unsigned char *split_hashes_and_size = torx_secure_malloc(split_hashes_len+sizeof(uint64_t));
	size_t size_total = 0; // sum of sections
	for(int16_t section = 0; section <= splits; section++)
	{ // populate split_hashes
		uint64_t end = 0;
		const uint64_t start = calculate_section_start(&end,size,splits,section);
		const uint64_t len = end - start + 1;
		size_total += b3sum_bin(&split_hashes_and_size[CHECKSUM_BIN_LEN*section],file_path,NULL,start,len);
	//	printf("Checkpoint section=%d start=%lu end=%lu len=%lu total=%lu\n",section,start,end,len,size_total);
	}
	if(size != size_total)
	{
		error_printf(0,"Coding or IO error. File size %zu != %zu sum of sections. Splits=%u",size,size_total,splits);
		torx_free((void*)&split_hashes_and_size);
		return NULL;
	}
	const uint64_t trash = htobe64(size);
	memcpy(&split_hashes_and_size[split_hashes_len],&trash,sizeof(uint64_t));
	if(hash_of_hashes)
		b3sum_bin(hash_of_hashes,NULL,split_hashes_and_size,0,split_hashes_len+sizeof(uint64_t)); // hash of hashes and size
	return split_hashes_and_size;
}

static inline void *file_init(void *arg)
{ // Send File Offer
	struct file_strc *file_strc = (struct file_strc*) arg; // Casting passed struct
	const int n = file_strc->n;
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL); // TODO not utilized. Need to track then pthread_cleanup_push + pop + thread_kill
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	unsigned char checksum[CHECKSUM_BIN_LEN];
	size_t size = 0;
	uint8_t splits = 0;
	unsigned char *split_hashes_and_size = NULL;
//	printf("Checkpoint file_init owner==%u path==%s\n",owner,file_strc->path);
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Determine split count, allocate and populate split_hashes, generate hash of hashes
		splits = UINT8_MAX;
		size = file_strc->size;
		while(splits && size / splits < MINIMUM_SECTION_SIZE)
			splits--;
		split_hashes_and_size = file_split_hashes(checksum,file_strc->path,splits,size);
		if(split_hashes_and_size == NULL)
			goto error;
	}
	else // TODO running a checksum on a file to determine its f value. Might already have it but didn't bother checking from the path + time. (note: different checksum type on group files, cannot check GROUP_CTRL's files)
		size = b3sum_bin(checksum,file_strc->path,NULL,0,0);
	if(size < 1)
	{
		error_printf(0,"File is empty: %s",file_strc->path);
		goto error;
	}
	const int f = process_file_offer_outbound(n,checksum,splits,split_hashes_and_size,size,file_strc->modified,file_strc->path);
//	printf("Checkpoint file_init n==%d f==%d size==%lu checksum==%s\n",n,f,size,b64_encode(checksum,CHECKSUM_BIN_LEN));
	sodium_memzero(checksum,sizeof(checksum));
	file_offer_internal(n,n,f,1);
	error: {}
	torx_free((void*)&split_hashes_and_size);
	torx_free((void*)&file_strc->path);
	torx_free((void*)&file_strc);
	return 0;
}

int file_send(const int n,const char *path)
{ // Caller is responsible for freeing *path
	if(n < 0 || path == NULL || path[0] == '\0')
		return -1;
	struct stat file_stat = {0};
	if(stat(path, &file_stat) < 0)
	{
		error_simple(0,"File seems to not exist. Cannot send.");
		return -1;
	}
	struct file_strc *file_strc = torx_insecure_malloc(sizeof(struct file_strc));
	file_strc->modified = file_stat.st_mtime;
	file_strc->size = (size_t)file_stat.st_size;
	file_strc->n = n;
	const size_t path_len = strlen(path);
	file_strc->path = torx_secure_malloc(path_len+1);
	snprintf(file_strc->path,path_len+1,"%s",path);
	pthread_t thrd_file_init; // TODO 2024/03/25 track this thread somehow and/or put a mutex inside file_init? both are of questionable utility.
	if(pthread_create(&thrd_file_init,&ATTR_DETACHED,&file_init,(void*)file_strc))
		error_simple(-1,"Failed to create thread6");
	return 0;
}
