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

/* Notes
- https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_integrity_check
- https://www.zetetic.net/sqlcipher/sqlcipher-api/#Changing_Key
- set PRAGMA kdf_iter to some random value (> 500,000 + random) stored in the plaintext database ("If a non-default value is used PRAGMA kdf_iter to create a database, it must also be called every time that database is opened.")
- secure password changes (with resumption)
	- If a sqlcipher rekey is interupted, causing some pages to be keyed with the old key an some pages to be keyed with the new key, the cipher_integrity_check can determine which pages are effected. is there any way to resume rekeying on these effected pages?
	- no, there is no built-in way to resume the rekeying process for only the affected pages. The sqlcipher_rekey function is designed to work on the entire database file, and cannot be used to selectively rekey specific pages.
- vaccuum function
- TODO Save_log used to reformat file related messages (to include file_path) and load_messages_struc used to read that and then remove file_path (perhaps find a better way)
- ensure that we've sufficiently utilized parameterized statements (re: any text data that could potentially come from a peer), to prevent injection attacks
- https://en.wikipedia.org/wiki/Strong_and_weak_typing

Other:
- Return codes: https://www.sqlite.org/c3ref/c_abort.html
- Types of returned data: https://www.sqlite.org/c3ref/column_blob.html
- Query language: https://www.sqlite.org/lang.html
- Overview of preparing statement: https://www.sqlite.org/c3ref/prepare.html
- string printing functions (ex: snprintf style) https://www.sqlite.org/c3ref/mprintf.html
- Other info ?: https://www.sqlite.org/c3ref/value.html

Legal:
- Export controls (US/EU) && Apple Appstore: https://discuss.zetetic.net/t/export-requirements-for-applications-using-sqlcipher/47
*/

/* static inline void shrink_message_struct(const int n)
{ // XXX DO NOT DELETE XXX
// TODO: Integrate zero_i calls. Callback to the UI to shrink its' t_message struct too
// Issue(s): race conditions caused by message_deleted_cb() occuring after the struct has shrunk, so we would have to eliminate message_deleted_cb() calls (in delete_log) and rely solely on shrink_message_struct_cb
// Further: How will we handle caching messages while offloaded? What if we don't? See todo.html for current ideas.
	const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	const int pointer_location = find_message_struc_pointer(min_i); // Note: returns negative
	torx_write(n) // 🟥🟥🟥
	peer[n].message = (struct message_list*)torx_realloc(peer[n].message + pointer_location, sizeof(struct message_list) *21) + 10;
	for(int j = -10; j < 11; j++)
		initialize_i(n,j);
	peer[n].min_i = 0;
	torx_unlock(n) // 🟩🟩🟩
//TODO	shrink_message_struct_cb(n); // TODO remember to remove message_deleted_cb from delete_log
} */

static uint8_t library_settings_loaded_plaintext = 0; // prevent loading library settings twice if sql_populate_setting(1) is called repeatedly (Android)
static uint8_t library_settings_loaded_encrypted = 0; // prevent loading library settings twice if sql_populate_setting(0) is called repeatedly (Android)

void message_offload(const int n)
{ // Unload all messages from RAM.
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_PEER) // TODO 2025/02/28 The issue may occur in not calling message_remove near the end of this function. We should probably utilize the same "VERY IMPORTANT / COMPLEX if statement, do not change" if statement, if _GROUP_PEER, if this warning occurs.
		error_simple(0,"message_unload may not be prepared (yet) for deleting solely ENUM_OWNER_GROUP_PEER. Coding error. Report this.");
	const int g = (owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL) ? set_g(n,NULL) : -1;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Handle GROUP_PEER ; not tested fully. Must go first before GROUP_CTRL
		for(int peer_n,p = 0; (peer_n = group_peerlist_get(g,p)) > -1 ; p++)
		{
			const int max_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
			const int min_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
			for(uint8_t cycle = 0; cycle < 2; cycle++)
				for(int i = cycle ? -1 : 0, plus_or_minus = cycle ? -1 : 1; cycle ? i >= min_i : i <= max_i ; i += plus_or_minus)
				{ // same as 2j0fj3r202k20f
					const int p_iter = getter_int(peer_n,i,-1,offsetof(struct message_list,p_iter));
					if(p_iter > -1) // snuff out deleted messages
					{
						pthread_rwlock_rdlock(&mutex_protocols); // 🟧
						const uint8_t group_msg = protocols[p_iter].group_msg;
						const uint8_t group_pm = protocols[p_iter].group_pm;
						pthread_rwlock_unlock(&mutex_protocols); // 🟩
						const uint8_t stat = getter_uint8(peer_n,i,-1,offsetof(struct message_list,stat));
						if((stat == ENUM_MESSAGE_RECV && (group_msg || group_pm)) || ((stat == ENUM_MESSAGE_SENT || stat == ENUM_MESSAGE_FAIL) && group_pm)) // XXX VERY IMPORTANT / COMPLEX if statement, do not change
							message_remove(g,peer_n,i); // do not remove (segfaults will happen). Conditions are to avoid sanity check errors.
						torx_write(peer_n) // 🟥🟥🟥
						const int shrinkage = zero_i(peer_n,i);
						torx_unlock(peer_n) // 🟩🟩🟩
						message_deleted_cb(peer_n,i); // optional
						if(shrinkage)
							shrinkage_cb(peer_n,shrinkage); // must be AFTER message_deleted_cb or UI structs might have issues deleting the messages
					}
				}
		}
	}
	const int max_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(uint8_t cycle = 0; cycle < 2; cycle++)
		for(int i = cycle ? -1 : 0, plus_or_minus = cycle ? -1 : 1; cycle ? i >= min_i : i <= max_i ; i += plus_or_minus)
		{ // same as 2j0fj3r202k20f
			const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
			if(p_iter > -1) // snuff out deleted messages
			{
				if(owner == ENUM_OWNER_GROUP_CTRL)
					message_remove(g,n,i);
				torx_write(n) // 🟥🟥🟥
				const int shrinkage = zero_i(n,i);
				torx_unlock(n) // 🟩🟩🟩
				message_deleted_cb(n,i); // optional
				if(shrinkage)
					shrinkage_cb(n,shrinkage); // must be AFTER message_deleted_cb or UI structs might have issues deleting the messages
			}
		}
}

static inline int log_check(const int n,const uint8_t group_pm,const uint16_t protocol)
{
	if(protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
		return 1; // Entry requests MUST always be logged.
	const int8_t log_messages = getter_int8(n,INT_MIN,-1,offsetof(struct peer_list,log_messages));
	const uint8_t global = threadsafe_read_uint8(&mutex_global_variable,&global_log_messages);
	if(log_messages == -1 || (global < 1 && log_messages < 1))
		return 0; // do not log these
	if(group_pm && threadsafe_read_uint8(&mutex_global_variable,&log_pm_according_to_group_setting))
	{
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int8_t group_log_messages = getter_int8(group_n,INT_MIN,-1,offsetof(struct peer_list,log_messages));
		if(group_log_messages == -1 || (global < 1 && group_log_messages < 1))
			return 0;
	}
	return 1;
}

#ifndef NO_FILE_TRANSFER
static inline void sql_delete_file_messages_by_checksum(const int n,const unsigned char *checksum)
{ // Delete from disk all of a peer's logged messages bearing this checksum: any protocol registered with file_checksum, leaving room for UI protocols. Via sql_delete_message, so that GROUP_CTRL rows also remove their GROUP_PEER copies.
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	if(peer_index < 0)
		return;
	char command[1024]; // size must accommodate a list of every registered file_checksum protocol
	size_t len = (size_t)snprintf(command,sizeof(command),"SELECT time,nstime FROM message WHERE peer_index = %d AND substr(message_bin,1,%u) = (?) AND protocol IN (",peer_index,(unsigned int)CHECKSUM_BIN_LEN);
	uint8_t none = 1;
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	for(int p_iter = 0; p_iter < PROTOCOL_LIST_SIZE && len < sizeof(command) - 10; p_iter++)
		if(protocols[p_iter].protocol && protocols[p_iter].file_checksum)
		{
			len += (size_t)snprintf(&command[len],sizeof(command)-len,none ? "%u" : ",%u",protocols[p_iter].protocol);
			none = 0;
		}
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(none)
		return; // no file_checksum protocols registered
	snprintf(&command[len],sizeof(command)-len,");");
	time_t *times = NULL; // pairs of time,nstime
	sqlite3_stmt *stmt;
	pthread_mutex_lock(&mutex_sql_messages); // 🟥🟥
	if(sqlite3_prepare_v2(db_messages,command,(int)strlen(command),&stmt,NULL) == SQLITE_OK)
	{
		if(sqlite3_bind_blob(stmt,1,checksum,CHECKSUM_BIN_LEN,SQLITE_TRANSIENT) == SQLITE_OK)
			while(sqlite3_step(stmt) == SQLITE_ROW)
			{ // Copy times out, to delete only after unlocking (sql_delete_message takes the same mutex)
				const size_t count = torx_allocation_len(times)/sizeof(time_t);
				if(times)
					times = torx_realloc(times,(count+2)*sizeof(time_t));
				else
					times = torx_insecure_malloc(2*sizeof(time_t));
				times[count] = (time_t)sqlite3_column_int(stmt,0);
				times[count+1] = (time_t)sqlite3_column_int(stmt,1);
			}
		sqlite3_finalize(stmt);
	}
	pthread_mutex_unlock(&mutex_sql_messages); // 🟩🟩
	sodium_memzero(command,sizeof(command));
	if(times)
	{
		const size_t count = torx_allocation_len(times)/sizeof(time_t);
		for(size_t iter = 0; iter + 1 < count; iter += 2)
			sql_delete_message(peer_index,times[iter],times[iter+1]);
		torx_free((void*)&times);
	}
}

static inline void delete_by_checksum(const int n,const int g,const unsigned char *checksum,const char *encoded)
{ // For a single peer: delete every message bearing this checksum (disk + RAM + callbacks) and any of its peer settings whose name ends in the b64 of the checksum (ex: file-<b64>, or UI equivalents adopting the same convention)
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	if(peer_index < 0)
		return;
	sql_delete_file_messages_by_checksum(n,checksum); // Must go first. Consider verifying return before deleting in memory.
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d AND substr(setting_name,-%zu) = (?);",peer_index,strlen(encoded));
	sql_exec(&db_encrypted,command,encoded,strlen(encoded),NULL);
	sodium_memzero(command,sizeof(command));
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const int max_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(uint8_t cycle = 0; cycle < 2; cycle++)
		for(int i = cycle ? -1 : 0, plus_or_minus = cycle ? -1 : 1; cycle ? i >= min_i : i <= max_i ; i += plus_or_minus)
		{ // same as 2j0fj3r202k20f
			const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
			if(p_iter > -1) // snuff out deleted messages
			{
				pthread_rwlock_rdlock(&mutex_protocols); // 🟧
				const uint8_t file_checksum = protocols[p_iter].file_checksum;
				const uint8_t group_msg = protocols[p_iter].group_msg;
				const uint8_t group_pm = protocols[p_iter].group_pm;
				pthread_rwlock_unlock(&mutex_protocols); // 🟩
				if(!file_checksum)
					continue;
				torx_read(n) // 🟧🟧🟧
				const uint8_t matches = peer[n].message[i].message && torx_allocation_len(peer[n].message[i].message) >= CHECKSUM_BIN_LEN && !memcmp(peer[n].message[i].message,checksum,CHECKSUM_BIN_LEN) ? 1 : 0;
				torx_unlock(n) // 🟩🟩🟩
				if(!matches)
					continue;
				if(g > -1)
				{
					const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
					if(owner == ENUM_OWNER_GROUP_CTRL || (stat == ENUM_MESSAGE_RECV && (group_msg || group_pm)) || ((stat == ENUM_MESSAGE_SENT || stat == ENUM_MESSAGE_FAIL) && group_pm)) // XXX VERY IMPORTANT / COMPLEX if statement, do not change (mirrors message_offload)
						message_remove(g,n,i);
				}
				torx_write(n) // 🟥🟥🟥
				const int shrinkage = zero_i(n,i);
				torx_unlock(n) // 🟩🟩🟩
				message_deleted_cb(n,i);
				if(shrinkage)
					shrinkage_cb(n,shrinkage); // must be AFTER message_deleted_cb or UI structs might have issues deleting the messages
			}
		}
}

static inline void file_offer_delete(const int n,const int g,const unsigned char *checksum)
{ // Not for delete_log. Cascade for a deleted file offer: delete the file itself from disk (if inbound & incomplete), plus every message and checksum-keyed peer setting bearing its checksum, for this peer or the whole group
	int file_n = n;
	int f = set_f(file_n,checksum,CHECKSUM_BIN_LEN-1); // XXX MUST be -1 to prevent reserving
	const int group_n = g > -1 ? getter_group_int(g,offsetof(struct group_list,n)) : -1;
	if(f < 0 && group_n > -1 && group_n != n)
	{ // not pm/p2p, must be a group transfer
		file_n = group_n;
		f = set_f(file_n,checksum,CHECKSUM_BIN_LEN-1); // XXX MUST be -1 to prevent reserving
	}
	if(f > -1)
	{
		file_cancel(file_n,f);
		char *encoded = b64_encode(checksum,CHECKSUM_BIN_LEN);
		if(g > -1)
		{ // GROUP_PEERs must be swept before GROUP_CTRL because their outbound group messages share the GROUP_CTRL's message allocations (see message_offload)
			for(int peer_n,iter = 0; (peer_n = group_peerlist_get(g,iter)) > -1 ; iter++)
			{
				delete_by_checksum(peer_n,g,checksum,encoded);
			}
			if(group_n > -1)
				delete_by_checksum(group_n,g,checksum,encoded);
		}
		else
			delete_by_checksum(n,g,checksum,encoded);
		torx_free((void*)&encoded);
	}
	else
		error_simple(0,"File checksum not found. Cannot delete.");
}

static inline void delete_files_of_peer(const int n)
{ // For delete_log. Cancel transfers and delete from disk all of a peer's inbound & incomplete files + .split, then delete all of its file- settings.
	if(n < 0)
		return;
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	if(peer_index < 0)
		return;
	torx_read(n) // 🟧🟧🟧
	for(int f = 0 ; !is_null(peer[n].file[f].checksum,CHECKSUM_BIN_LEN) ; f++)
	{
		const uint8_t split_progress_exists = peer[n].file[f].split_progress ? 1 : 0;
		const uint64_t size = peer[n].file[f].size;
		torx_unlock(n) // 🟩🟩🟩
		if(split_progress_exists && calculate_transferred_inbound(n,f) < size && file_status_get(n,f) == ENUM_FILE_INACTIVE_ACCEPTED)
		{ // Idle partial: must delete from disk here, because the teardown below only deletes actively-inbound files. XXX .split_progress ensures it is inbound-only
			char *file_path = getter_string(n,INT_MIN,f,offsetof(struct file_list,file_path));
			char *split_path = getter_string(n,INT_MIN,f,offsetof(struct file_list,split_path)); // Authoritative. Prefer it over deriving, which is keyed on basename alone and can therefore resolve to an unrelated file's .split
			if(!split_path)
				split_path = split_path_from_file_path(file_path);
			destroy_file(file_path);
			destroy_file(split_path);
			torx_free((void*)&file_path);
			torx_free((void*)&split_path);
		}
		if(file_is_active(n,f))
			file_cancel(n,f);
		else // Local teardown only, without calling sql_save_file_status because we'll delete saved settings after the loop
			process_pause_cancel(n,f,n,ENUM_PROTOCOL_FILE_CANCEL,ENUM_MESSAGE_FAIL);
		torx_read(n) // 🟧🟧🟧
	}
	torx_unlock(n) // 🟩🟩🟩
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d AND substr(setting_name,1,5) = 'file-';",peer_index);
	sql_exec(&db_encrypted,command,NULL);
	sodium_memzero(command,sizeof(command));
}

static inline void file_status_apply(const int file_n,const int f,const uint8_t saved_status,const uint8_t splits)
{ // Apply the status loaded from file-<b64_checksum> peer setting (set by sql_save_file_status). Called from sql_populate_setting's file- handler *AFTER* the setting has restored size/modified/filename/file_path.
  // XXX splits is passed in rather than read back from the struct: nothing is allocated yet at this point, so there is nothing for splits_determination() to derive it from.
	if(saved_status == 0 || file_n < 0 || f < 0)
		return; // Saved status may equal zero if this file is outbound (normal, not an error)
	if(saved_status == ENUM_FILE_INACTIVE_CANCELLED)
		process_pause_cancel(file_n,f,file_n,ENUM_PROTOCOL_FILE_CANCEL,ENUM_MESSAGE_RECV); // tear down structs so file_status_get reports CANCELLED
	else if(saved_status == ENUM_FILE_INACTIVE_ACCEPTED)
	{ // Accepted/in-progress: restore split progress from the .split file, falling back to the file's size on disk only where that recovered nothing.
		torx_read(file_n) // 🟧🟧🟧
		const uint8_t file_path_exists = peer[file_n].file[f].file_path ? 1 : 0;
		const uint64_t size = peer[file_n].file[f].size;
		torx_unlock(file_n) // 🟩🟩🟩
		if(!file_path_exists)
			return; // Never accepted, or its path was not saved.
		initialize_split_info(file_n,f,splits); // XXX Do not call file_status_get before this
		uint64_t transferred = calculate_transferred_inbound(file_n,f); // The .split file is authoritative. Only consult the disk below if it yielded nothing.
		if(transferred == 0)
		{ // Either splits==0 (which never has a .split file) or the .split is missing/invalid.
			char *file_path = getter_string(file_n,INT_MIN,f,offsetof(struct file_list,file_path));
			const uint64_t size_on_disk = get_file_size(file_path);
			torx_free((void*)&file_path);
			torx_write(file_n) // 🟥🟥🟥
			const uint32_t sections = peer[file_n].file[f].split_progress ? torx_allocation_len(peer[file_n].file[f].split_progress)/(uint32_t)sizeof(uint64_t) : 0;
			if(sections == 1)
			{ // A lone section is written sequentially from its start, so its size on disk *is* its progress
				peer[file_n].file[f].split_progress[0] = size_on_disk;
				transferred = size_on_disk;
			}
			else if(sections > 1 && size_on_disk == size && size >= (uint64_t)sections)
			{ // Full size on disk with no progress to read: mark every section complete rather than re-downloading over it.
				for(uint32_t section = 0; section < sections; section++)
				{
					uint64_t end = 0;
					const uint64_t start = calculate_section_start(&end,size,(uint8_t)(sections - 1),(int16_t)section);
					peer[file_n].file[f].split_progress[section] = end - start + 1;
				}
				transferred = size;
			}
			torx_unlock(file_n) // 🟩🟩🟩
		}
		if(transferred == size)
		{ // Completed before its COMPLETE status could be persisted. file_is_complete requires split_path == NULL
			torx_write(file_n) // 🟥🟥🟥
			torx_free((void*)&peer[file_n].file[f].split_path);
			torx_unlock(file_n) // 🟩🟩🟩
		}
	}
	else if(saved_status == ENUM_FILE_INACTIVE_COMPLETE)
	{ // Reconstruct a finished transfer's end-state: split_progress sized (splits+1) with every section full, split_status_* and split_path NULL, split_hashes already restored by the file- handler.
	// file_status_get reports COMPLETE from split_progress alone (never depends on the file still being on disk), and split_hashes makes a group file seedable without re-hashing.
	// XXX Deliberately does NOT call initialize_split_info: leaving split_status_fd NULL is what prevents peer_online/select_peer from re-downloading a deleted file.
		const uint64_t size = getter_uint64(file_n,INT_MIN,f,offsetof(struct file_list,size));
		torx_write(file_n) // 🟥🟥🟥
		torx_free((void*)&peer[file_n].file[f].split_path); // file_is_complete requires split_path == NULL
		if(size >= (uint64_t)splits + 1)
		{ // calculate_section_start's precondition (a valid split file always satisfies it); avoids its fatal sanity check on empty/degenerate files
			peer[file_n].file[f].split_progress = torx_insecure_malloc(sizeof(uint64_t)*(splits+1)); // always NULL prior: f was freshly reserved by the file- handler
			for(int16_t section = 0; section <= splits; section++)
			{ // mark every section fully transferred so file_status_get reports COMPLETE and any outbound "100%" FILE_OFFER_PARTIAL advertises correctly
				uint64_t end = 0;
				const uint64_t start = calculate_section_start(&end,size,splits,section); // pure function, safe under lock
				peer[file_n].file[f].split_progress[section] = end - start + 1;
			}
		}
		torx_unlock(file_n) // 🟩🟩🟩
	}
}

void sql_save_file_status(const int file_n,const int f,const uint8_t status)
{ // Persist a file's status + metadata as a peer setting named file-<b64_checksum> on file_n's peer_index. Layout: [status:uint8_t][splits:uint8_t][size:uint64_t BE][modified:uint64_t BE][filename_len:uint16_t BE][filename][file_path_len:uint16_t BE][file_path][split_hashes]. split_hashes (group files only) has no length prefix: it occupies the remaining bytes and holds only the CHECKSUM_BIN_LEN*(splits+1) hash portion, the trailing htobe64(size) being re-appended on load.
	if(file_n < 0 || f < 0)
	{
		error_simple(0,"Negative file_n or f in sql_save_file_status. Coding error. Report this.");
		breakpoint();
		return;
	}
	const uint8_t owner = getter_uint8(file_n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(!log_check(file_n,owner == ENUM_OWNER_GROUP_PEER ? 1 : 0,0))
		return; // Respect logging preferences: do not persist file metadata of peers whose messages are not logged
	const int peer_index = getter_int(file_n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	if(peer_index < 0)
	{
		error_simple(0,"Invalid peer_index in sql_save_file_status. Coding error. Report this.");
		breakpoint();
		return;
	}
	unsigned char checksum[CHECKSUM_BIN_LEN]; // zero'd
	getter_array(&checksum,sizeof(checksum),file_n,INT_MIN,f,offsetof(struct file_list,checksum));
	char *encoded = b64_encode(checksum,sizeof(checksum)); // free'd
	sodium_memzero(checksum,sizeof(checksum));
	char setting_name[256]; // zero'd
	snprintf(setting_name,sizeof(setting_name),"file-%s",encoded);
	torx_free((void*)&encoded);
	const uint64_t size = getter_uint64(file_n,INT_MIN,f,offsetof(struct file_list,size));
	const time_t modified = getter_time(file_n,INT_MIN,f,offsetof(struct file_list,modified));
	char *filename = getter_string(file_n,INT_MIN,f,offsetof(struct file_list,filename)); // May be NULL
	char *file_path = getter_string(file_n,INT_MIN,f,offsetof(struct file_list,file_path)); // May be NULL (ex: cancelled before accepting)
	const size_t filename_len = filename ? torx_allocation_len(filename)-1 : 0;
	const size_t file_path_len = file_path ? torx_allocation_len(file_path)-1 : 0;
	if(filename_len > UINT16_MAX || file_path_len > UINT16_MAX)
	{ // Cannot occur under PATH_MAX, but the length prefixes are uint16_t
		error_simple(0,"Filename or file_path too long in sql_save_file_status. Report this.");
		sodium_memzero(setting_name,sizeof(setting_name));
		torx_free((void*)&filename);
		torx_free((void*)&file_path);
		return;
	}
	unsigned char *split_hashes = NULL; // group files only
	torx_read(file_n) // 🟧🟧🟧
	const uint8_t splits = splits_determination_nolock(file_n,f); // derived under the same lock as split_hashes so the pair stays consistent
	const size_t split_hashes_portion = (size_t)CHECKSUM_BIN_LEN*(splits+1); // hash portion only (excludes the trailing htobe64(size))
	if(peer[file_n].file[f].split_hashes && torx_allocation_len(peer[file_n].file[f].split_hashes) >= split_hashes_portion)
	{ // Copy just the hash portion; the trailing size is redundant with the size field and re-derived on load
		split_hashes = torx_secure_malloc(split_hashes_portion);
		memcpy(split_hashes,peer[file_n].file[f].split_hashes,split_hashes_portion);
	}
	torx_unlock(file_n) // 🟩🟩🟩
	const size_t split_hashes_len = split_hashes ? split_hashes_portion : 0;
	const size_t value_len = sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + filename_len + sizeof(uint16_t) + file_path_len + split_hashes_len;
	char *setting_value = torx_secure_malloc(value_len);
	size_t pos = 0;
	setting_value[pos] = (char)status;
	pos += sizeof(uint8_t);
	setting_value[pos] = (char)splits;
	pos += sizeof(uint8_t);
	const uint64_t size_be = htobe64(size);
	memcpy(&setting_value[pos],&size_be,sizeof(uint64_t));
	pos += sizeof(uint64_t);
	const uint64_t modified_be = htobe64((uint64_t)modified);
	memcpy(&setting_value[pos],&modified_be,sizeof(uint64_t));
	pos += sizeof(uint64_t);
	const uint16_t filename_len_be = htobe16((uint16_t)filename_len);
	memcpy(&setting_value[pos],&filename_len_be,sizeof(uint16_t));
	pos += sizeof(uint16_t);
	if(filename_len)
	{
		memcpy(&setting_value[pos],filename,filename_len);
		pos += filename_len;
	}
	const uint16_t file_path_len_be = htobe16((uint16_t)file_path_len);
	memcpy(&setting_value[pos],&file_path_len_be,sizeof(uint16_t));
	pos += sizeof(uint16_t);
	if(file_path_len)
	{
		memcpy(&setting_value[pos],file_path,file_path_len);
		pos += file_path_len;
	}
	if(split_hashes_len)
		memcpy(&setting_value[pos],split_hashes,split_hashes_len);
	// Not (pos+=split_hashes_len) because we no longer need it, but it should equal value_len if we update it
	sql_setting(0,peer_index,setting_name,setting_value,value_len);
	sodium_memzero(setting_name,sizeof(setting_name));
	torx_free((void*)&setting_value);
	torx_free((void*)&filename);
	torx_free((void*)&file_path);
	torx_free((void*)&split_hashes);
}
#endif // NO_FILE_TRANSFER

void delete_log(const int n)
{ // WARNING: If called on GROUP_CTRL, THIS WILL ALSO DELETE PRIVATE MESSAGES
	#ifndef NO_FILE_TRANSFER
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // PM transfers are held by GROUP_PEER, so those must be handled too
		const int g = set_g(n,NULL);
		for(int peer_n,p = 0; (peer_n = group_peerlist_get(g,p)) > -1 ; p++)
		{
			delete_files_of_peer(peer_n);
		}
	}
	delete_files_of_peer(n); // deletes inbound & incomplete files from disk, and all file- settings
	#endif // NO_FILE_TRANSFER
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	sql_delete_history(peer_index); // TODO must go first. consider verifying return before deleting in memory
	message_offload(n);
}

int message_edit(const int n,const int i,const char *message)
{ // Pass NULL to delete // NOTE: Changing a message's length while it is queued to send may result in abnormal behavior in packet_removal.
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_printf(0,"Message's p_iter is <0 which indicates it is deleted or buggy.3 n=%d i=%d",n,i);
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const int protocol = protocols[p_iter].protocol;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	#ifndef NO_FILE_TRANSFER
	const uint8_t file_offer = protocols[p_iter].file_offer;
	#endif // NO_FILE_TRANSFER
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	char *message_old = NULL;
	char *message_new = NULL; // must initialize
	const uint32_t base_message_len = message ? (uint32_t)strlen(message) : 0;
	const int g = (owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL) ? set_g(n,NULL) : -1;
	#ifndef NO_FILE_TRANSFER
	if(!message && file_offer)
	{ // Deleting a file offer: cascade. Deletes the file itself from disk (if inbound & incomplete), plus every message and checksum-keyed peer setting bearing its checksum (RAM + disk), including this message and any GROUP_PEER copies.
		torx_read(n) // 🟧🟧🟧
		const uint32_t message_len = torx_allocation_len(peer[n].message[i].message);
		torx_unlock(n) // 🟩🟩🟩
		if(message_len >= CHECKSUM_BIN_LEN)
		{
			unsigned char checksum[CHECKSUM_BIN_LEN];
			getter_array(&checksum,sizeof(checksum),n,i,-1,offsetof(struct message_list,message));
			file_offer_delete(n,g,checksum);
			sodium_memzero(checksum,sizeof(checksum));
			return 0;
		}
	}
	#endif // NO_FILE_TRANSFER
	if(!message || (signature_len && getter_uint8(n,i,-1,offsetof(struct message_list,stat)) != ENUM_MESSAGE_RECV && protocol == ENUM_PROTOCOL_UTF8_TEXT_DATE_SIGNED) || protocol == ENUM_PROTOCOL_UTF8_TEXT || protocol == ENUM_PROTOCOL_UTF8_TEXT_PRIVATE)
	{ // Don't mess with the logic here
		if(message)
		{ // A message was passed
			if(signature_len)
			{ // Need to sign
				unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
				const int signing_n = (owner == ENUM_OWNER_GROUP_PEER) ? getter_group_int(g,offsetof(struct group_list,n)) : n;
				getter_array(&sign_sk,sizeof(sign_sk),signing_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
				message_new = message_sign(sign_sk,time,nstime,p_iter,message,base_message_len);
				sodium_memzero(sign_sk,sizeof(sign_sk));
			}
			else
				message_new = message_sign(NULL,time,nstime,p_iter,message,base_message_len);
		}
		if(message_new || !message) // NOT else if
		{
			if(message_new)
			{ // Replacing a message
				torx_write(n) // 🟥🟥🟥
				message_old = peer[n].message[i].message; // need to free this *after* swap
				peer[n].message[i].message = message_new;
				torx_unlock(n) // 🟩🟩🟩
			}
			else
			{ // Deleting a message
				const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
				sql_delete_message(peer_index,time,nstime); // Must go first. Consider verifying return before deleting in memory.
				if(owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
					message_remove(g,n,i);
			}
			if(owner == ENUM_OWNER_GROUP_CTRL)
			{ // private messages will NOT come here
				for(int peer_n,p = 0; (peer_n = group_peerlist_get(g,p)) > -1 ; p++)
				{
					const int max_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
					const int min_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
					for(int ii = max_i ; ii >= min_i ; ii--)
					{
						const time_t time_ii = getter_time(peer_n,ii,-1,offsetof(struct message_list,time));
						const time_t nstime_ii = getter_time(peer_n,ii,-1,offsetof(struct message_list,nstime));
						if(time_ii == time && nstime_ii == nstime)
						{ // DO NOT need to sql_update_message or print_message_cb here. No private messages will come here.
							int shrinkage = 0;
							torx_write(peer_n) // 🟥🟥🟥
							if(message_new)
								peer[peer_n].message[ii].message = message_new;
							else
								shrinkage = zero_i(peer_n,ii);
							torx_unlock(peer_n) // 🟩🟩🟩
							if(shrinkage)
								shrinkage_cb(peer_n,shrinkage);
							break;
						}
					}
				}
			}
			if(message_new)
			{
				torx_write(n) // 🟥🟥🟥
				torx_free((void*)&message_old);
				torx_unlock(n) // 🟩🟩🟩
				sql_update_message(n,i);
				message_modified_cb(n,i);
			}
			else
			{
				torx_write(n) // 🟥🟥🟥
				const int shrinkage = zero_i(n,i);
				torx_unlock(n) // 🟩🟩🟩
				message_deleted_cb(n,i);
				if(shrinkage)
					shrinkage_cb(n,shrinkage); // must be AFTER message_deleted_cb or UI structs might have issues deleting the messages
			}
		}
		else
			error_simple(0,"Message_new is null. Coding error. Report this");
	}
	else
	{ // Example: inbound signed messages cannot be modified, only deleted.
		pthread_rwlock_rdlock(&mutex_protocols); // 🟧
		const char *name = protocols[p_iter].name;
		pthread_rwlock_unlock(&mutex_protocols); // 🟩
		error_printf(0,"Editing for this message type is unsupported: %s",name);
		return -1;
	}
	return 0;
}

int sql_exec(sqlite3** db,const char *command,...)
{ // Usage: sql_exec(&db_plaintext,"command here (?,?)",value1,value1_len,value2,value2_len,NULL);
	if(command == NULL)
	{
		error_simple(0,"NULL command passed to sql_exec. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	pthread_mutex_t *mutex; // note POINTER to mutex
	if(*db == db_encrypted)
		mutex = &mutex_sql_encrypted;
	else if(*db == db_plaintext)
		mutex = &mutex_sql_plaintext;
	else if(*db == db_messages)
		mutex = &mutex_sql_messages;
	else // coding error
	{
		error_simple(0,"Invalid database. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	sqlite3_stmt *stmt;
	int val;
	pthread_mutex_lock(mutex); // 🟥🟥 // Prepare the statement with a parameterized query
	if((val = sqlite3_prepare_v2(*db, command, (int)strlen(command), &stmt, NULL)) != SQLITE_OK)
	{
		error_printf(0,"Cannot prepare statement: %s",sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
		pthread_mutex_unlock(mutex); // 🟩🟩
		return val;
	}
	va_list ap;
	const char *string_or_blob;
	size_t string_or_blob_len;
	va_start(ap, command);
	for(int wildcard = 1; (string_or_blob = va_arg(ap, const char *)) && (string_or_blob_len = va_arg(ap, size_t)); wildcard++)
	{
		if(utf8_valid(string_or_blob,string_or_blob_len)) // Alt: pass SQLITE_TEXT,SQLITE_BLOB, but SQLITE_TEXT is 0 so it can interfere with null termination
			val = sqlite3_bind_text(stmt, wildcard, string_or_blob,(int)string_or_blob_len, SQLITE_TRANSIENT);
		else // WARNING: This can cause failure if attempting to place in a TEXT STRICT column, but it will still return SQLITE_OK
			val = sqlite3_bind_blob(stmt, wildcard, string_or_blob,(int)string_or_blob_len, SQLITE_TRANSIENT);
		if(val != SQLITE_OK) // Bind the parameter, if passed
		{
			error_printf(0, "Cannot bind value to parameter: %s",sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
			sqlite3_finalize(stmt);
			pthread_mutex_unlock(mutex); // 🟩🟩
			return val;
		}
	}
	va_end(ap);
	if((val = sqlite3_step(stmt)) != SQLITE_DONE) // Execute the statement
	{ // Occurs whenever already exists
		error_printf(0, "Cannot execute statement %s: %s",command,sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
		sqlite3_finalize(stmt);
		pthread_mutex_unlock(mutex); // 🟩🟩
		return val;
	}
	sqlite3_finalize(stmt);	// XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(mutex); // 🟩🟩
	return SQLITE_OK; // == 0
}

int sql_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len)
{ // For inserting or modifying setting. Passing a NULL setting_value or !setting_value_len results in deletion. For GLOBAL setting, pass -1 as peer_index.
	if(peer_index < -1)
	{
		error_printf(0,"Attempted to save %s setting with an uninitialized peer_index. Coding error. Report this.",setting_name);
		breakpoint();
		return -1;
	}
	else if(force_plaintext && peer_index != -1)
	{
		error_simple(0,"Tried to save a peer specific setting in plaintext database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	else if(!setting_name)
	{
		error_simple(0,"Tried to save a NULL setting in database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	else if(!setting_value || !setting_value_len)
		return sql_delete_setting(force_plaintext,peer_index,setting_name);
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	if(force_plaintext)
		snprintf(command,sizeof(command),"INSERT INTO setting_clear (setting_name,setting_value) VALUES (?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value = excluded.setting_value;");
	else if(peer_index == -1)
		snprintf(command,sizeof(command),"INSERT INTO setting_global (setting_name,setting_value) VALUES (?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value = excluded.setting_value;");
	else /* encrypted */
		snprintf(command,sizeof(command),"INSERT INTO setting_peer (peer_index,setting_name,setting_value) VALUES (%d,?,?) ON CONFLICT(peer_index,setting_name) DO UPDATE SET setting_value = excluded.setting_value;",peer_index);
	const int val = sql_exec(force_plaintext ? &db_plaintext : &db_encrypted,command,setting_name,strlen(setting_name),setting_value,setting_value_len,NULL);
//	sodium_memzero(command,sizeof(command)); // unnecessary
	return val;
}

static inline int load_messages_struc(const int offset,const int n,const time_t time,const time_t nstime,const uint8_t stat,const int p_iter,const char *message,const uint32_t base_message_len,const unsigned char *signature,const size_t signature_length)
{
	if(n < 0 || p_iter < 0/* || !message*/)
	{
		char *name = NULL;
		if(p_iter > -1)
		{
			pthread_rwlock_rdlock(&mutex_protocols); // 🟧
			name = protocols[p_iter].name;
			pthread_rwlock_unlock(&mutex_protocols); // 🟩
		}
		if(message)
			error_printf(0,"Load_messages_struc failed sanity check: n=%d p_iter=%d has message",n,p_iter);
		else // TODO currently triggers on all non-PM GROUP_PEER messages
			error_printf(0,"Load_messages_struc failed sanity check: n=%d p_iter=%d, null message, time: %ld, nstime: %ld, base_message_len: %u, signature_length: %lu, protocol: %s",n,p_iter,time,nstime,base_message_len,signature_length,name);
		return INT_MIN;
	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	#ifndef NO_FILE_TRANSFER
	const uint8_t file_offer = protocols[p_iter].file_offer;
	#endif // NO_FILE_TRANSFER
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	uint32_t message_len;
	char *tmp_message;
	if(group_msg && owner == ENUM_OWNER_GROUP_PEER && stat != ENUM_MESSAGE_RECV)
	{ // Match outbound .message with equivalent GROUP_CTRL's .message, based on time/nstime check ( DO NOT RELY ON n+i because PMs will shift those )
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int max_i = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
		const int min_i = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
		int group_i = min_i; // must be OUTSIDE while loop to prevent infinity loop
		while(1)
		{ // Careful with the logic and prioritize efficiency. This loop is for when two messages have the same time but different nstime.
			while(group_i <= max_i && getter_time(group_n,group_i,-1,offsetof(struct message_list,time)) != time)
				group_i++;
			if(group_i <= max_i && getter_time(group_n,group_i,-1,offsetof(struct message_list,nstime)) == nstime)
			{
				torx_read(group_n) // 🟧🟧🟧
				tmp_message = peer[group_n].message[group_i].message;
				message_len = torx_allocation_len(peer[group_n].message[group_i].message);
				torx_unlock(group_n) // 🟩🟩🟩
				break; // winner
			}
			else if(group_i > max_i)
			{ // 2024/05/25 this probably occurs due to deleted messages?
				error_printf(0,"Message not found. Cannot match GROUP_PEER with GROUP_CTRL message. Protocol: %u. Report this for science.",protocol);
				return INT_MIN; // fail
			}
			group_i++;
		}
	}
	else // Most/All message types get here
	{ // For signed messages, this is where we re-attach signatures and network order time / nstime to messages when loading them
		if(!message)
		{
			error_simple(0,"Load_messages_struc failed sanity check due to message being inappropriately NULL");
			return INT_MIN;
		}
		message_len = base_message_len + null_terminated_len + date_len + signature_len;
		tmp_message = torx_secure_malloc(message_len);
		memcpy(tmp_message,message,base_message_len);
		if(null_terminated_len)
			tmp_message[base_message_len] = '\0';
		if(date_len)
		{
			uint32_t trash = htobe32((uint32_t)time);
			memcpy(&tmp_message[base_message_len + null_terminated_len],&trash,sizeof(uint32_t));
			trash = htobe32((uint32_t)nstime);
			memcpy(&tmp_message[base_message_len + null_terminated_len + sizeof(int32_t)],&trash,sizeof(uint32_t));
		}
		if(signature_len)
			memcpy(&tmp_message[message_len - signature_length],signature,signature_length); // affix signature, if applicable
		if((protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST) && stat != ENUM_MESSAGE_RECV)
		{ // Outbound group offer. Must add target peer to invitees.
			const int g = set_g(-1,tmp_message);
			invitee_add(g,n);
		}
		#ifndef NO_FILE_TRANSFER
		else if(file_offer)
		{
			if(stat == ENUM_MESSAGE_RECV)
			{
				if(process_file_offer_inbound(n,p_iter,tmp_message,message_len) == -1)
				{ // Bad message
					error_simple(0,"process_file_offer_inbound returned -1 in load_messages_struc");
					return INT_MIN;
				}
			}
			else if(message_len)  // TODO use protocol_lookup to check all protocols for minimum size
			{
				if(protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED)
				{
					const uint8_t splits = *(const uint8_t*)(const void*)&message[CHECKSUM_BIN_LEN];
					const size_t split_hashes_len = (size_t)CHECKSUM_BIN_LEN*(splits + 1);
					const int g = set_g(n,NULL);
					const int group_n = getter_group_int(g,offsetof(struct group_list,n));
					const int f = set_f(group_n,(const unsigned char*)message,CHECKSUM_BIN_LEN);
					char *file_path = getter_string(group_n,INT_MIN,f,offsetof(struct file_list,file_path)); // set by the file- peer setting, which loads before messages
					if(file_path)
					{
						process_file_offer_outbound(group_n,(const unsigned char*)message,splits,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len])),be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)])),file_path);
						torx_free((void*)&file_path);
					}
					else // file- setting is missing (logging disabled when offered, or deleted); file cannot be served unless re-offered
						error_printf(2,"Outbound group file offer loaded without a saved file path: %u",protocol);
				}
				else
				{
					const int f = set_f(n,(const unsigned char*)message,CHECKSUM_BIN_LEN);
					char *file_path = getter_string(n,INT_MIN,f,offsetof(struct file_list,file_path)); // set by the file- peer setting, which loads before messages
					if(file_path)
					{
						process_file_offer_outbound(n,(const unsigned char*)message,0,NULL,be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN])),be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN+sizeof(uint64_t)])),file_path);
						torx_free((void*)&file_path);
					}
					else // file- setting is missing (logging disabled when offered, or deleted); file cannot be served unless re-offered
						error_printf(2,"Outbound file offer loaded without a saved file path: %u",protocol);
				}
			}
		}
		#endif // NO_FILE_TRANSFER
	}
	return increment_i(n,offset,time,nstime,stat,-1,p_iter,tmp_message);
}

int load_peer_struc(const int peer_index,const uint8_t owner,const uint8_t status,const char *privkey,const uint16_t peerversion,const char *peeronion,const char *peernick,const unsigned char *sign_sk,const unsigned char *peer_sign_pk,const unsigned char *invitation)
{ // Be very careful when modifying the logic of this function. It is incredibly important.
	// Start of sanity checks
	if((owner < 1 || owner > 6)
	|| (owner == ENUM_OWNER_PEER
	&& ((peeronion == NULL || peernick == NULL) || (strlen(peeronion) != 56 || strlen(peernick) < 1)))
	|| ((owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)
	&& ((status == 0 || privkey == NULL || peeronion == NULL || peernick == NULL) || (strlen(privkey) != 88 || strlen(peeronion) < 1 || strlen(peernick) < 1)))
	|| ((owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
	&& ((status == 0 || privkey == NULL || peeronion == NULL || peernick == NULL) || (strlen(privkey) != 88 || strlen(peeronion) != 56 || strlen(peernick) < 1))))
	{ // ENUM_OWNER_GROUP_PEER does not require privkey, but we have a fake one (non working random string)
		error_printf(0,"Something was provided as NULL to load_peer_struc or sanity check failed: %u %u %u %s %s %s",owner,status,peerversion,privkey,peeronion,peernick);
		return -1;
	}
	// End of sanity checks
	int n = -1;
	if(owner == ENUM_OWNER_PEER || owner == ENUM_OWNER_GROUP_PEER)
	{ // careful with the logic here
		if((n = set_n(peer_index,peeronion)) < 0) // XXX Writing peeronion to onion to prevent empty space/trash THIS IS IMPORTANT, DO NOT CHANGE (2023/04/07)
		{
			error_simple(0,"Invalid n in load_peer_struc. Bailing out. Report this.");
			breakpoint();
			return -1;
		}
	}
	else
	{ // set by privkey
		char *onion = onion_from_privkey(privkey);
		if(onion == NULL || (n = set_n(peer_index,onion)) < 0)
		{
			error_simple(0,"Failed to create onion or valid n from privkey in load_peer_struc. Bailing out. Report this.");
			breakpoint();
			return -1; // hit this on 2023/05/15
		}
		torx_free((void*)&onion);
	}
	torx_write(n) // 🟥🟥🟥
	peer[n].owner = owner;
	peer[n].status = status;
	peer[n].peerversion = peerversion;
	if(peer[n].peeronion != peeronion) // checking to avoid "Source and destination overlap"
		snprintf(peer[n].peeronion,56+1,"%s",peeronion);
	if(peer[n].peernick != peernick) // checking to avoid "Source and destination overlap"
	{
		const size_t allocation_len = strlen(peernick)+1;
		peer[n].peernick = torx_secure_malloc(allocation_len);
		snprintf(peer[n].peernick,allocation_len,"%s",peernick);
	}
	if(owner == ENUM_OWNER_PEER)
		random_string(peer[n].privkey,88+1);
	else if(peer[n].privkey != privkey) // checking to avoid "Source and destination overlap"
		snprintf(peer[n].privkey,88+1,"%s",privkey);
	if(sign_sk != NULL)
		memcpy(peer[n].sign_sk,sign_sk,crypto_sign_SECRETKEYBYTES);
	if(peer_sign_pk != NULL)
		memcpy(peer[n].peer_sign_pk,peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	if(invitation != NULL)
		memcpy(peer[n].invitation,invitation,crypto_sign_BYTES);
	char *torxid = torxid_from_onion(peer[n].onion);
	if(torxid)
	{
		snprintf(peer[n].torxid,sizeof(peer[n].torxid),"%s",torxid); // note: using peer[n].onion instead of onion because onion might be empty for ENUM_OWNER_PEER, whereas .onion is not
		torx_unlock(n) // 🟩🟩🟩
		torx_free((void*)&torxid);
	}
	else
	{
		torx_unlock(n) // 🟩🟩🟩
		error_simple(0,"Failed to convert onion to torxid.");
		return -1;
	}
	return n;
}

int sql_insert_peer(const uint8_t owner,const uint8_t status,const uint16_t peerversion,const char *privkey,const char *peeronion,const char *peernick,const int expiration)
{ // not filling 'peer_sign_pk' and 'sign_sk', leaving them as NULL. Fill them during handshake with sql_update_peer.
	if(!privkey || !peeronion || !peernick) // TODO could add some additional checks here
	{
		error_simple(-1,"Sanity check failed in sql_insert_peer. Coding error. Report this.");
		return -1;
	}
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"INSERT OR ABORT INTO peer (owner,status,peerversion,privkey,peeronion,peernick,expiration) VALUES (%u,%u,%u,?,?,?,%d);",owner,status,peerversion,expiration);
	sql_exec(&db_encrypted,command,privkey,88,peeronion,56,peernick,strlen(peernick),NULL);
	sodium_memzero(command,sizeof(command));
	sqlite3_stmt *stmt;
	const char command_array[] = "SELECT peer_index FROM peer WHERE privkey = (?);";
	pthread_mutex_lock(&mutex_sql_encrypted); // 🟥🟥
	const int val1 = sqlite3_prepare_v2(db_encrypted,command_array,sizeof(command_array)-1, &stmt,NULL);
	const int val2 = sqlite3_bind_text(stmt, 1, privkey, 88, SQLITE_TRANSIENT);
	if(val1 != SQLITE_OK || val2 != SQLITE_OK)
	{
		error_printf(0, "Can't prepare peer statement: %s",sqlite3_errmsg(db_encrypted));
		pthread_mutex_unlock(&mutex_sql_encrypted); // 🟩🟩
		return -1;
	}
	else if(sqlite3_step(stmt) == SQLITE_ROW)
	{ // Retrieve and return new peer_index
		const int peer_index = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
		pthread_mutex_unlock(&mutex_sql_encrypted); // 🟩🟩
		return peer_index;
	}
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(&mutex_sql_encrypted); // 🟩🟩
	error_printf(0, "Can't insert peer to DB. Report this: %d %d",val1,val2);
	return -1;
}

static int sql_exec_msg(const int n,const int i,const char *passed_command)
{
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_printf(0,"Message's p_iter is <0 which indicates it is deleted or buggy.0 n=%d i=%d",n,i);
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
	int val = -1;
	char *message = getter_string(n,i,-1,offsetof(struct message_list,message));
	const uint32_t message_len = torx_allocation_len(message);
	if(group_msg && owner == ENUM_OWNER_GROUP_PEER && stat != ENUM_MESSAGE_RECV)
		val = sql_exec(&db_messages,passed_command,NULL); // XXX must NOT be triggered for an inbound or private message. It should go to 'else' (private message is more of a standard message)
	else if(null_terminated_len == 0 && message)
	{ // Prevent update_blob from triggering on outbound group_public messages, even if binary only
		val = sql_exec(&db_messages,passed_command,NULL);
		const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
		snprintf(command,sizeof(command),"UPDATE OR ABORT message SET message_bin = (?) WHERE peer_index = %d AND time = %ld AND nstime = %ld;", peer_index, time, nstime);
		sql_exec(&db_messages,command,message,message_len - (null_terminated_len + date_len + signature_len),NULL);
		sodium_memzero(command,sizeof(command));
	}
	else if(null_terminated_len && message)
		val = sql_exec(&db_messages,passed_command,message,message_len - (null_terminated_len + date_len + signature_len),NULL);
	else
		error_printf(0,"Bailing out from sql_exec_msg because we don't know how to handle this message: protocol=%u is_null=%d",protocol,message ? 1 : 0);
	torx_free((void*)&message);
	return val;
}

static inline void sql_message_tail_section(const int peer_index,const int n,const time_t time,const time_t nstime,const uint8_t stat,const uint8_t file_offer,const char *message,const uint32_t message_len,const uint32_t signature_len)
{ // Warning: no error checks, this is a macro converted to a function. TODO this triggers far more often than necessary. Triggers once for every outbound file request, which occurs for every split. Ideally should just trigger upon first and then again after unpause perhaps...
	if(signature_len) // Update signature (only)
	{
		char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
		snprintf(command,sizeof(command),"UPDATE OR ABORT message SET signature = (?) WHERE peer_index = %d AND time = %ld AND nstime = %ld;", peer_index, time, nstime);
		sql_exec(&db_messages,command,&message[message_len-crypto_sign_BYTES],crypto_sign_BYTES,NULL);
		sodium_memzero(command,sizeof(command));
	}
	#ifndef NO_FILE_TRANSFER
	if(file_offer && stat != ENUM_MESSAGE_RECV)
	{ // Persist our own (outbound) offer's file_path as a peer setting (a received offer's status+path is saved by file_accept/file_cancel/etc)
		int file_n = n;
		int f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN-1);
		if(f < 0)
		{ // not pm/p2p, must be group transfer
			const int g = set_g(n,NULL);
			file_n = getter_group_int(g,offsetof(struct group_list,n));
			f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN);
		}
		if(f > -1) // NOT else if
		{ // Claim COMPLETE if we actually hold the whole file. An inbound FILE_INFO_REQUEST triggers an offer for a file we may still be receiving, so file_status is a required check
			const int file_status = file_status_get(file_n,f);
			if(file_status == ENUM_FILE_INACTIVE_COMPLETE || file_status == ENUM_FILE_ACTIVE_OUT)
				sql_save_file_status(file_n,f,ENUM_FILE_INACTIVE_COMPLETE);
		}
	}
	#else
	(void)n;
	(void)stat;
	(void)file_offer;
	#endif // NO_FILE_TRANSFER
}

int sql_insert_message(const int n,const int i)
{ // Save an new message
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_printf(0,"Message's p_iter is <0 which indicates it is deleted or buggy.1 n=%d i=%d",n,i);
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t logged = protocols[p_iter].logged;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(logged == 0 || !log_check(n,group_pm,protocol))
		return 0; // do not log these.
	char *message = getter_string(n,i,-1,offsetof(struct message_list,message));
	const uint32_t message_len = torx_allocation_len(message);
	if(!message)
	{
		error_printf(0,"Null message passed to sql_insert_message. Not saving. Report this. Protocol: %u",protocol);
		breakpoint();
		return -1;
	}
	int val;
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
	if(group_msg && owner == ENUM_OWNER_GROUP_PEER && stat != ENUM_MESSAGE_RECV)
	{ // XXX must NOT be triggered for an inbound or private message. It should go to 'else' (private message is more of a standard message)
		char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
		snprintf(command,sizeof(command),"INSERT OR ABORT INTO message (time,nstime,peer_index,stat,protocol) VALUES (%lld,%lld,%d,%d,%d);",(long long)time,(long long)nstime,peer_index,stat,protocol);
		val = sql_exec_msg(n,i,command);
		sodium_memzero(command,sizeof(command));
	}
	else
	{
		char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
		snprintf(command,sizeof(command),"INSERT OR ABORT INTO message (time,nstime,peer_index,stat,protocol,message_txt) VALUES (%lld,%lld,%d,%d,%d,?);",(long long)time,(long long)nstime,peer_index,stat,protocol);
		val = sql_exec_msg(n,i,command);
		sodium_memzero(command,sizeof(command));
		sql_message_tail_section(peer_index,n,time,nstime,stat,file_offer,message,message_len,signature_len);
	}
	torx_free((void*)&message);
	return val;
}

int sql_update_message(const int n,const int i)
{ // Update a saved message (for example: after status changed when it is sent, or to manipulate the saved message)
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_printf(0,"Message's p_iter is <0 which indicates it is deleted or buggy.2 n=%d i=%d",n,i);
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols); // 🟧
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t logged = protocols[p_iter].logged;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols); // 🟩
	if(logged == 0 || !log_check(n,group_pm,protocol))
		return 0; // do not log these.
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));

	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"UPDATE OR ABORT message SET (stat,protocol,message_txt) = (%d,%d,?) WHERE time = %lld AND nstime = %lld AND peer_index = %d;",stat,protocol,(long long)time,(long long)nstime,peer_index);
	const int val = sql_exec_msg(n,i,command); // Update message
	sodium_memzero(command,sizeof(command));
	char *message = getter_string(n,i,-1,offsetof(struct message_list,message));
	const uint32_t message_len = torx_allocation_len(message);
	sql_message_tail_section(peer_index,n,time,nstime,stat,file_offer,message,message_len,signature_len);
	torx_free((void*)&message);
	return val;
}

int sql_update_peer(const int n)
{
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	if(peer_index < 0)
	{
		error_simple(0,"Negative peer_index exists in peer struct. Bailing out from sql_update_peer. Report this.");
		breakpoint();
		return -1;
	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const uint8_t status = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,status));
	const uint16_t peerversion = getter_uint16(n,INT_MIN,-1,offsetof(struct peer_list,peerversion));
	char privkey[88+1]; // zero'd
	getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
	char peeronion[56+1]; // zero'd
	getter_array(&peeronion,sizeof(peeronion),n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
	char *peernick = getter_string(n,INT_MIN,-1,offsetof(struct peer_list,peernick));
	const uint32_t peernick_len = torx_allocation_len(peernick);
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	getter_array(&sign_sk,sizeof(sign_sk),n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
	unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
	getter_array(&peer_sign_pk,sizeof(peer_sign_pk),n,INT_MIN,-1,offsetof(struct peer_list,peer_sign_pk));
	unsigned char invitation[crypto_sign_BYTES];
	getter_array(&invitation,sizeof(invitation),n,INT_MIN,-1,offsetof(struct peer_list,invitation));
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"UPDATE OR ABORT peer SET (owner,status,peerversion,privkey,peeronion,peernick,sign_sk,peer_sign_pk,invitation) = (%u,%u,%u,?,?,?,?,?,?) WHERE peer_index = %d;",owner,status,peerversion,peer_index);
	const int val = sql_exec(&db_encrypted,command,privkey,88,peeronion,56,peernick,peernick_len-1,sign_sk,crypto_sign_SECRETKEYBYTES,peer_sign_pk,crypto_sign_PUBLICKEYBYTES,invitation,crypto_sign_BYTES,NULL);
	torx_free((void*)&peernick);
	sodium_memzero(privkey,sizeof(privkey));
	sodium_memzero(peeronion,sizeof(peeronion));
	sodium_memzero(command,sizeof(command));
	sodium_memzero(sign_sk,sizeof(sign_sk));
	sodium_memzero(peer_sign_pk,sizeof(peer_sign_pk));
	sodium_memzero(invitation,sizeof(invitation));
	return val;
}

int sql_populate_message(const int peer_index,const uint32_t days,const uint32_t messages,const time_t since)
{ // Note: Groups can only be populated by since
	if(peer_index < 0 || (days && messages) || (since && days) || (since && messages))
	{
		error_simple(0,"Sanity check fail in sql_populate_message. Bailing out. Report this.");
		breakpoint();
		return 0;
	}
	const int n = set_n(peer_index,NULL);
	pthread_mutex_lock(&mutex_sql_messages); // 🟥🟥 // better to put this before we get the earliest_time
	torx_read(n) // 🟧🟧🟧
	const uint8_t owner = peer[n].owner;
	const int min_i = peer[n].min_i;
	int tmp_i = peer[n].min_i;
	while(tmp_i < peer[n].max_i && !peer[n].message[tmp_i].time)
		tmp_i++;// Loading a message with zero time must be avoided, or no further messages can be loaded. Note: On startup zero is OK, because we don't use earliest_time.
	time_t earliest_time = peer[n].message[tmp_i].time;
	time_t earliest_nstime = peer[n].message[tmp_i].nstime;
	torx_unlock(n) // 🟩🟩🟩
	if(!earliest_time)
		earliest_time = time(NULL); // 2024/09/27 experimental solution to a hypothetical problem
	if(since > earliest_time || ((messages || days) && owner != ENUM_OWNER_CTRL))
	{ // We've already loaded this far back or further, or we're trying to load group/group peer messages in a bad way
		error_simple(0,"Sanity check fail in sql_populate_message at point two. Bailing out. Report this.");
		pthread_mutex_unlock(&mutex_sql_messages); // 🟩🟩
		return 0; // no messages to retrieve
	}
	sqlite3_stmt *stmt;
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	int len = 0; // clang thinks this should be initialized, but I disagree.
	uint8_t reverse;
	if(!messages_loaded)
	{ // On startup
		reverse = 0;
		if(days)
			len = snprintf(command,sizeof(command),"SELECT *FROM message WHERE peer_index = %d AND time > %lld ORDER BY time ASC,nstime ASC;",peer_index,(long long)startup_time - 60*60*24*days);
		else if(messages)
			len = snprintf(command,sizeof(command),"SELECT *FROM ( SELECT *FROM message WHERE peer_index = %d ORDER BY time DESC,nstime DESC LIMIT %u ) ORDER BY time ASC,nstime ASC;",peer_index,messages);
		else // default to since, even if it is 0
			len = snprintf(command,sizeof(command),"SELECT *FROM message WHERE peer_index = %d AND time >= %lld ORDER BY time ASC,nstime ASC;",peer_index,(long long)since);
	}
	else
	{ // This is for "load more" aka populate peer struct from -1--
		reverse = 1;
		if(days)
			len = snprintf(command,sizeof(command),"SELECT *FROM message WHERE peer_index = %d AND time > %lld AND time < %lld OR peer_index = %d AND time = %lld AND nstime < %lld ORDER BY time DESC,nstime DESC;",peer_index,(long long)earliest_time - 60*60*24*days,(long long)earliest_time,peer_index,(long long)earliest_time,(long long)earliest_nstime);
		else if(messages)
			len = snprintf(command,sizeof(command),"SELECT *FROM message WHERE peer_index = %d AND time < %lld OR peer_index = %d AND time = %lld AND nstime < %lld ORDER BY time DESC,nstime DESC LIMIT %u;",peer_index,(long long)earliest_time,peer_index,(long long)earliest_time,(long long)earliest_nstime,messages);
		else // default to since, even if it is 0
			len = snprintf(command,sizeof(command),"SELECT *FROM message WHERE peer_index = %d AND time >= %lld AND time < %lld OR peer_index = %d AND time = %lld AND nstime < %lld ORDER BY time DESC,nstime DESC;",peer_index,(long long)since,(long long)earliest_time,peer_index,(long long)earliest_time,(long long)earliest_nstime);
	}
	int val = sqlite3_prepare_v2(db_messages,command, len, &stmt, NULL);
	sodium_memzero(command,sizeof(command));
	if(val != SQLITE_OK)
	{
		error_printf(0, "Can't prepare message statement: %s. Not loading messages. Report this.",sqlite3_errmsg(db_messages));
		pthread_mutex_unlock(&mutex_sql_messages); // 🟩🟩
		return 0;
	}
	int offset = 0;
	if(reverse)
	{ // Need to calculate the offset and appropriately expand the struct.
		for(int i = min_i; (val = sqlite3_step(stmt)) == SQLITE_ROW ;)
		{
			i--;
			offset--;
			uint8_t expanded = 0;
			torx_write(n) // 🟥🟥🟥
			if(peer[n].message[i].p_iter == -1 && i && i % 10 == 0 && (i + 10 > peer[n].max_i + 1 || i - 10 < peer[n].min_i - 1))
			{ // NOTE: same as joafdoiwfoefjioasdf
				expand_message_struc(n,i); // before adjusting min_i
				expanded = 1;
			}
			peer[n].min_i--;
			torx_unlock(n) // 🟩🟩🟩
			if(expanded)
				expand_message_struc_followup(n,i);
		}
		sqlite3_reset(stmt);
	}
	uint32_t loaded = 0; // start at 0
	while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		const time_t time = (time_t)sqlite3_column_int(stmt, 0);
		const time_t nstime = (time_t)sqlite3_column_int(stmt, 1);
		const uint8_t message_stat = (uint8_t)sqlite3_column_int(stmt, 3);
		const uint16_t protocol = (uint16_t)sqlite3_column_int(stmt, 4);
		int column;
		const int p_iter = protocol_lookup(protocol);
		if(p_iter < 0)
		{ // Save memory and trouble by not loading unrecognized message types. Note: Usually they probably just won't be saved to begin with. These might be old messages of a depreciated type.
			error_printf(0,"Unrecognized protocol not loaded: %u",protocol);
			continue;
		}
		pthread_rwlock_rdlock(&mutex_protocols); // 🟧
		const uint8_t logged = protocols[p_iter].logged;
		const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
		const uint8_t group_msg = protocols[p_iter].group_msg;
		pthread_rwlock_unlock(&mutex_protocols); // 🟩
		if(null_terminated_len == 0 && logged)
			column = 6;
		else
			column = 5;
		const char *message = (const char *)sqlite3_column_text(stmt, column);
		uint32_t message_len = (uint32_t)sqlite3_column_bytes(stmt, column);
		const unsigned char *signature = sqlite3_column_blob(stmt, 7);
		const size_t signature_length = (size_t)sqlite3_column_bytes(stmt, 7);
		const char *extraneous = NULL;
		const uint32_t extraneous_len = (uint32_t)sqlite3_column_bytes(stmt, 8);
		if(extraneous_len)
			extraneous = (const char *)sqlite3_column_blob(stmt, 8);
		const int i = load_messages_struc(offset,n,time,nstime,message_stat,p_iter,message,message_len,signature,signature_length);
		if(i != INT_MIN && (message_stat == ENUM_MESSAGE_RECV || !group_msg || owner != ENUM_OWNER_GROUP_PEER))
			loaded++; // XXX j2fjq0fiofg WARNING: The second part of this if statement MUST be the same as in inline_load_array
		if(extraneous_len && i != INT_MIN)
		{ // Must allocate because _cb is probably asyncronous
			unsigned char *extraneous_allocated = torx_secure_malloc(extraneous_len);
			memcpy(extraneous_allocated,extraneous,extraneous_len);
			message_extra_cb(n,i,extraneous_allocated,extraneous_len);
		}
		if(offset > 0)
			offset--;
		else if(offset < 0)
			offset++;
	//	if(messages && messages == loaded)
	//		break;
	}
	if(val != SQLITE_DONE/* && val != SQLITE_ROW*/) // SQLITE_ROW can occur when we broke the loop above because message arg was passed
		error_printf(0, "Can't retrieve data: %s",sqlite3_errmsg(db_messages));
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(&mutex_sql_messages); // 🟩🟩
	return (int)loaded;
}

void message_extra(const int n,const int i,const void *data,const uint32_t data_len)
{ // Save some extra data related to a message, which will be retrievable via message_extra_cb when loading the message
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"UPDATE OR ABORT message SET extraneous = (?) WHERE peer_index = %d AND time = %ld AND nstime = %ld;", peer_index, time, nstime);
	sql_exec(&db_messages,command,data,data_len,NULL);
	sodium_memzero(command,sizeof(command));
}

static inline void inline_load_messages(const uint8_t owner,const int peer_index,const int n,const uint32_t local_show_log_messages)
{ // Warning: we don't sanity check args
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // XXX This *should* always occur first before any GROUP_PEERS load. If it doesn't, we should get lots of errors. XXX
		const time_t since = message_find_since(n);
		sql_populate_message(peer_index,0,0,since);
	}
	else if(owner == ENUM_OWNER_GROUP_PEER)
	{
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int min_i = getter_int(group_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
		const time_t since = getter_time(group_n,min_i,-1,offsetof(struct message_list,time));
		sql_populate_message(peer_index,0,0,since);
	}
	else if(owner == ENUM_OWNER_CTRL) // do not use else here
		sql_populate_message(peer_index,0,local_show_log_messages,0);
	peer_loaded_cb(n);
}

int sql_populate_peer(void)
{ // "load_onions"
	pthread_mutex_lock(&mutex_message_loading); // 🟥🟥 // must be BEFORE messages_loaded != 0
	if(messages_loaded != 0)
	{ // This occurs after restarting Tor. We don't necessarily need to load from disk.
		pthread_mutex_unlock(&mutex_message_loading); // 🟩🟩
		error_simple(0,"NOTICE: sql_populate_peer is being called despite messages already being loaded.");
		int n = 0;
		torx_read(n) // 🟧🟧🟧
		while(peer[n].onion[0] != '\0' || peer[n].peer_index > -1)
		{ // we do need to load_onion(n) any ENUM_STATUS_FRIEND except EMUM_OWNER_PEER and ENUM_OWNER_GROUP_PEER. If we load those two, we will have problems.
			const uint8_t status = peer[n].status;
			const uint8_t owner = peer[n].owner;
			torx_unlock(n) // 🟩🟩🟩
			if(status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL))
				load_onion(n); // logically, ENUM_OWNER_CTRL, we may need to prevent load_onion->tor_call->load_onion_events->send_init, however in practice it seems no.
			torx_read(++n) // 🟧🟧🟧
		}
		torx_unlock(n) // 🟩🟩🟩
		return 0;
	}
	sqlite3_stmt *stmt;
	const char command[] = "SELECT *FROM peer";
	int val = sqlite3_prepare_v2(db_encrypted,command,(int)sizeof(command)-1, &stmt, NULL);
	if(val != SQLITE_OK)
	{
		pthread_mutex_unlock(&mutex_message_loading); // 🟩🟩
		error_printf(0, "Can't prepare populate peer statement: %s",sqlite3_errmsg(db_messages));
		return -1;
	}
	const uint32_t local_show_log_messages = threadsafe_read_uint32(&mutex_global_variable,&show_log_messages);
	while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
	{ // Retrieve data here using sqlite3_column_* functions,
		const int peer_index = sqlite3_column_int(stmt, 0);
		const uint8_t owner = (uint8_t)sqlite3_column_int(stmt, 1);
		const uint8_t status = (uint8_t)sqlite3_column_int(stmt, 2);
		const uint16_t peerversion = (uint16_t)sqlite3_column_int(stmt, 3);
		const char *privkey = (const char *)sqlite3_column_text(stmt, 4);
		const char *peeronion = (const char *)sqlite3_column_text(stmt, 5);
		const char *peernick = (const char *)sqlite3_column_text(stmt, 6);
		const unsigned char *peer_sign_pk = sqlite3_column_blob(stmt, 7); // TODO should probably check length to prevent potential overflow read in case of error
		const unsigned char *sign_sk = sqlite3_column_blob(stmt, 8); // TODO should probably check length to prevent potential overflow read in case of error
		const unsigned char *invitation = sqlite3_column_blob(stmt, 9); // TODO should probably check length to prevent potential overflow read in case of error
		const int expiration = sqlite3_column_int(stmt, 10);
		int n = -1;
		if(owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT || owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)
		{
			if((owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT) && expiration > 0 && time(NULL) > expiration)
			{ // WARNING THIS WILL DELETE ANY EXPIRED SING / MULTS WITHOUT WARNING (a system clock error could trigger this)
				takedown_onion(peer_index,1);
			}
			else if((status == ENUM_STATUS_BLOCKED && (owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT)) /* handle disabled SING/MULT */
				|| (status == ENUM_STATUS_PENDING && owner == ENUM_OWNER_CTRL)) /* handle pending incoming CTRL */
			{
				if((n = load_peer_struc(peer_index,owner,status,privkey,peerversion,peeronion,peernick,sign_sk,peer_sign_pk,invitation)) == -1)
					continue;
				peer_loaded_cb(n);
			}
			else if((status == ENUM_STATUS_BLOCKED || AUTOMATICALLY_LOAD_CTRL == 0) && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER))
			{ // handle blocked 		CTRL		load struct + log
				if((n = load_peer_struc(peer_index,owner,status,privkey,peerversion,peeronion,peernick,sign_sk,peer_sign_pk,invitation)) == -1)
					continue;
				inline_load_messages(owner,peer_index,n,local_show_log_messages);
			}
			else if((status == ENUM_STATUS_FRIEND && (owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT))
				|| (status == ENUM_STATUS_FRIEND && AUTOMATICALLY_LOAD_CTRL == 1 && (owner == ENUM_OWNER_CTRL || owner == ENUM_OWNER_GROUP_CTRL || owner == ENUM_OWNER_GROUP_PEER)))
			{
				if((n = load_peer_struc(peer_index,owner,status,privkey,peerversion,peeronion,peernick,sign_sk,peer_sign_pk,invitation)) == -1)
					continue;
				load_onion(n);
				inline_load_messages(owner,peer_index,n,local_show_log_messages);
				if(owner == ENUM_OWNER_GROUP_CTRL)
				{
					const int g = set_g(n,NULL);
					const uint32_t g_peercount = group_peercount(g);
					const uint8_t g_invite_required = getter_group_uint8(g,offsetof(struct group_list,invite_required));
					if(g_invite_required == 0 && g_peercount == 0 /* && expiration != 0 ???*/)
					{ // Broadcast if the group is public and empty. Do not check if we created the group first (expiration) because even so it could be operating independantly even if empty (we could have created it then two users could have joined each other without joining us). Public groups must be wholely ownerless.
						unsigned char ciphertext[GROUP_BROADCAST_LEN];
						broadcast_prep(ciphertext,g);
						broadcast_add(-1,ciphertext);
						sodium_memzero(ciphertext,sizeof(ciphertext));
					}
					unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES];
					torx_read(n) // 🟧🟧🟧
					crypto_sign_ed25519_sk_to_pk(ed25519_pk,peer[n].sign_sk);
				//	if(g_invite_required)
				//		error_printf(0,"Checkpoint PRIVATE group_n: %s group_n_pk: %s",peer[n].onion,b64_encode(ed25519_pk,sizeof(ed25519_pk)));
				//	else
				//		error_printf(0,"Checkpoint PUBLIC group_n: %s group_n_pk: %s",peer[n].onion,b64_encode(ed25519_pk,sizeof(ed25519_pk)));
					torx_unlock(n) // 🟩🟩🟩
					sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
				}
			}
			else
			{
				error_simple(0,"REPORT THIS ERROR 8102");
				breakpoint();
			}
		}
		else if(owner == ENUM_OWNER_PEER)
		{ // handle pending outgoing	PEER		load struct + async friend request
			if((n = load_peer_struc(peer_index,owner,status,privkey,peerversion,peeronion,peernick,sign_sk,peer_sign_pk,invitation)) == -1)
				continue;
			start_outgoing_friend_request(n); // TODO 2023/01/17 issue: this must not be run on re-loads (when start_tor() restarts tor)
		}
		else
		{
			error_printf(0,"Unrecognized peer owner in SQL database: %u. Report this.",owner);
			breakpoint();
		}
	}
	if(val != SQLITE_DONE)
	{
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
		pthread_mutex_unlock(&mutex_message_loading); // 🟩🟩
		error_printf(3, "Can't retrieve data: %s",sqlite3_errmsg(db_messages));
		return -1;
	}
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	for(int g = 0 ; group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE); g++)
	{
		pthread_rwlock_unlock(&mutex_expand_group); // 🟩
		message_sort(g);
		pthread_rwlock_rdlock(&mutex_expand_group); // 🟧
	}
	pthread_rwlock_unlock(&mutex_expand_group); // 🟩
	messages_loaded = 1; // must be at the end
	pthread_mutex_unlock(&mutex_message_loading); // 🟩🟩 // must be AFTER messages_loaded = 1;
	return 0;
}

unsigned char *sql_retrieve_setting(const int force_plaintext,const char *setting_name)
{ // WARNING: only returns the FIRST match
	size_t setting_value_len = 0;
	unsigned char *data = NULL;
	size_t setting_name_len;
	if(setting_name == NULL || (setting_name_len = strlen(setting_name)) == 0)
		return data;
	sqlite3 **db;
	pthread_mutex_t *mutex; // note POINTER to mutex
	int cycles = 2;
	if(force_plaintext)
	{
		cycles = 1;
		db = &db_plaintext;
		mutex = &mutex_sql_plaintext;
	}
	else /* encrypted */
	{
		db = &db_encrypted;
		mutex = &mutex_sql_encrypted;
	}
	sqlite3_stmt *stmt;
	pthread_mutex_lock(mutex); // 🟥🟥
	while(cycles--)
	{
		const char *command;
		if(force_plaintext)
			command = "SELECT *FROM setting_clear WHERE setting_name = (?)";
		else if(cycles)
			command = "SELECT *FROM setting_global WHERE setting_name = (?)";
		else
			command = "SELECT *FROM setting_peer WHERE setting_name = (?)";
		int val = sqlite3_prepare_v2(*db,command,(int)strlen(command), &stmt, NULL);
		if(val != SQLITE_OK)
		{
			error_printf(0, "Can't prepare populate setting statement: %s",sqlite3_errmsg(*db));
			pthread_mutex_unlock(mutex); // 🟩🟩
			return data;
		}
		sqlite3_bind_text(stmt, 1, setting_name, (int)setting_name_len, SQLITE_TRANSIENT);
		const char *setting_value = NULL;
		if((val = sqlite3_step(stmt)) == SQLITE_ROW)
		{ // Retrieve data here using sqlite3_column_* functions,
			if(force_plaintext || cycles) // (force_plaintext)
			{ // TODO 2024/03/09 consider using sqlite3_column_blob for setting_value
				setting_value = (const char *)sqlite3_column_text(stmt, 2);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 2);
			}
			else  /* encrypted */
			{
				setting_value = (const char *)sqlite3_column_text(stmt, 3);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 3);
			}
		}
		if(val != SQLITE_DONE)
			error_printf(3, "Can't retrieve data: %s",sqlite3_errmsg(*db));
		if(setting_value && setting_value_len)
		{ // Got something worth returning!
			data = torx_secure_malloc(setting_value_len);
			memcpy(data,setting_value,setting_value_len);
		}
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	}
	pthread_mutex_unlock(mutex); // 🟩🟩
	return data;
}

void sql_populate_setting(const int force_plaintext)
{
	#define sanity_check /* can not wrap in do while(0) because of continue */\
	if(peer_index < 0) \
	{ \
		error_simple(0,"Invalid peer_index in sql_populate_setting. Bailing. Report this."); \
		breakpoint(); \
		continue; \
	}
	sqlite3 **db;
	pthread_mutex_t *mutex; // note POINTER to mutex
	int cycles = 2;
	if(force_plaintext)
	{
		cycles = 1;
		db = &db_plaintext;
		mutex = &mutex_sql_plaintext;
	}
	else /* encrypted */
	{
		db = &db_encrypted;
		mutex = &mutex_sql_encrypted;
	}
	sqlite3_stmt *stmt;
	uint8_t attempt_login = 0;
	pthread_mutex_lock(mutex); // 🟥🟥
	while(cycles--)
	{
		const char *command;
		if(force_plaintext)
			command = "SELECT *FROM setting_clear";
		else if(cycles)
			command = "SELECT *FROM setting_global";
		else
			command = "SELECT *FROM setting_peer";
		int val = sqlite3_prepare_v2(*db,command,(int)strlen(command), &stmt, NULL);
		if(val != SQLITE_OK)
		{
			error_printf(0, "Can't prepare populate setting statement: %s",sqlite3_errmsg(*db));
			pthread_mutex_unlock(mutex); // 🟩🟩
			return;
		}
		while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
		{ // Retrieve data here using sqlite3_column_* functions,
			int peer_index = -1;
			const char *setting_name;
			const char *setting_value;
			size_t setting_name_len;
			size_t setting_value_len;
			if(force_plaintext || cycles) // (force_plaintext)
			{ // TODO 2024/03/09 consider using sqlite3_column_blob for setting_value
				setting_name = (const char *)sqlite3_column_text(stmt, 1);
				setting_name_len = (size_t)sqlite3_column_bytes(stmt, 1);
				setting_value = (const char *)sqlite3_column_text(stmt, 2);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 2);
			}
			else  /* encrypted */
			{
				peer_index = sqlite3_column_int(stmt, 1);
				setting_name = (const char *)sqlite3_column_text(stmt, 2);
				setting_name_len = (size_t)sqlite3_column_bytes(stmt, 2);
				setting_value = (const char *)sqlite3_column_text(stmt, 3);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 3);
			}
		//	int bytes = sqlite3_column_bytes(stmt, 0);
			if(force_plaintext)
			{
				error_printf(2,"Plaintext Setting: %s",setting_name);
				if(!library_settings_loaded_plaintext)
					pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
				if(!strncmp(setting_name,"salt",4) && setting_value_len == sizeof(saltbuffer)) // NOT else if
				{
					if(!library_settings_loaded_plaintext)
						memcpy(saltbuffer,setting_value,sizeof(saltbuffer));
				}
				else if(!strncmp(setting_name,"crypto_pwhash_OPSLIMIT",22))
				{
					if(!library_settings_loaded_plaintext)
						crypto_pwhash_OPSLIMIT = strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"crypto_pwhash_MEMLIMIT",22))
				{
					if(!library_settings_loaded_plaintext)
						crypto_pwhash_MEMLIMIT = strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"crypto_pwhash_ALG",17))
				{
					if(!library_settings_loaded_plaintext)
						crypto_pwhash_ALG = (int)strtoll(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"tor_location",12))
				{
					if(!library_settings_loaded_plaintext)
					{
						torx_free((void*)&tor_location);
						tor_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
						memcpy(tor_location,setting_value,setting_value_len);
						tor_location[setting_value_len] = '\0';
					}
				}
				else if(!strncmp(setting_name,"lyrebird_location",17))
				{
					if(!library_settings_loaded_plaintext)
					{
						torx_free((void*)&lyrebird_location);
						lyrebird_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
						memcpy(lyrebird_location,setting_value,setting_value_len);
						lyrebird_location[setting_value_len] = '\0';
					}
				}
				else if(!strncmp(setting_name,"conjure_location",16))
				{
					if(!library_settings_loaded_plaintext)
					{
						torx_free((void*)&conjure_location);
						conjure_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
						memcpy(conjure_location,setting_value,setting_value_len);
						conjure_location[setting_value_len] = '\0';
					}
				}
				else if(!strncmp(setting_name,"censored_region",15))
				{
					if(!library_settings_loaded_plaintext)
						censored_region = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"decryption_key",14))
				{
					if(!library_settings_loaded_plaintext && !keyed && setting_value_len > 0 && setting_value_len <= sizeof(decryption_key))
					{
						memcpy(decryption_key,setting_value,setting_value_len);
						attempt_login = 1;
					}
				}
				else
				{
					if(!library_settings_loaded_plaintext)
						pthread_rwlock_unlock(&mutex_global_variable); // 🟩
					char *setting_name_allocated = torx_secure_malloc(setting_name_len+1);
					snprintf(setting_name_allocated,setting_name_len+1,"%s",setting_name);
					char *setting_value_allocated = torx_secure_malloc(setting_value_len+1); // TODO +1/Null termination could interfere with binary interpretation if callback utilizes torx_allocation_len(setting_value_allocated) instead of setting_value_len
					memcpy(setting_value_allocated,setting_value,setting_value_len);
					setting_value_allocated[setting_value_len] = '\0';
					custom_setting_cb(peer_index,setting_name_allocated,setting_value_allocated,setting_value_len,1);
					if(!library_settings_loaded_plaintext)
						pthread_rwlock_rdlock(&mutex_global_variable); // 🟧 // yes rdlock is correct here, because we have no more actions upon it
				}
				if(!library_settings_loaded_plaintext)
					pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			}
			else /* encrypted */
			{
				error_printf(3,"Encrypted Setting: peer_index=%d %s",peer_index,setting_name);
				if(!library_settings_loaded_encrypted && peer_index < 0) // global variable
					pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
				if(!strncmp(setting_name,"torrc",5)) // NOT else if
				{
					if(!library_settings_loaded_encrypted)
					{
						torx_free((void*)&torrc_content);
						torrc_content = torx_secure_malloc(setting_value_len+1); // could free on shutdown
						memcpy(torrc_content,setting_value,setting_value_len);
						torrc_content[setting_value_len] = '\0';
					}
				}
				#ifndef NO_FILE_TRANSFER
				else if(!strncmp(setting_name,"download_dir",12))
				{
					if(!library_settings_loaded_encrypted)
					{
						torx_free((void*)&download_dir);
						download_dir = torx_secure_malloc(setting_value_len+1); // could free on shutdown
						memcpy(download_dir,setting_value,setting_value_len);
						download_dir[setting_value_len] = '\0';
					}
				}
				else if(!strncmp(setting_name,"auto_resume_inbound",19))
				{
					if(!library_settings_loaded_encrypted)
						auto_resume_inbound = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"file-",5))
				{
					if(!library_settings_loaded_encrypted)
					{ // Restore a file's status + metadata saved by sql_save_file_status (see it for layout). XXX Do NOT call sql_* functions in here (mutex is held); file_status_apply calls none.
						sanity_check
						if(setting_value_len < sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint16_t)) // minimum is the fixed header + both (possibly empty) filename/file_path length prefixes
						{
							error_simple(0,"Invalid file- setting loaded from sql. Report this.");
							continue;
						}
						size_t pos = 0;
						const uint8_t saved_status = (uint8_t)setting_value[pos];
						pos += sizeof(uint8_t);
						const uint8_t splits = (uint8_t)setting_value[pos];
						pos += sizeof(uint8_t);
						const uint64_t size = be64toh(align_uint64(&setting_value[pos]));
						pos += sizeof(uint64_t);
						const time_t modified = (time_t)be64toh(align_uint64(&setting_value[pos]));
						pos += sizeof(uint64_t);
						const uint16_t filename_len = be16toh(align_uint16(&setting_value[pos]));
						pos += sizeof(uint16_t);
						if(pos + filename_len + sizeof(uint16_t) > setting_value_len)
						{
							error_simple(2,"Invalid file- setting (filename length) loaded from sql. Report this.");
							continue;
						}
						const char *filename_ptr = &setting_value[pos];
						pos += filename_len;
						const uint16_t file_path_len = be16toh(align_uint16(&setting_value[pos]));
						pos += sizeof(uint16_t);
						if(pos + file_path_len > setting_value_len)
						{
							error_simple(0,"Invalid file- setting (file_path length) loaded from sql. Report this.");
							continue;
						}
						const char *file_path_ptr = &setting_value[pos];
						pos += file_path_len;
						const size_t split_hashes_portion = setting_value_len - pos; // remaining bytes = split_hashes hash portion (0 for p2p/PM)
						if(split_hashes_portion && split_hashes_portion != (size_t)CHECKSUM_BIN_LEN*(splits+1))
						{
							error_simple(0,"Invalid file- setting (split_hashes length) loaded from sql. Report this.");
							continue;
						}
						const char *split_hashes_ptr = &setting_value[pos];
						unsigned char checksum[CHECKSUM_BIN_LEN];
						if(b64_decode(checksum,sizeof(checksum),&setting_name[5]) != (size_t)CHECKSUM_BIN_LEN) // we depend on setting_name to be null terminated, which it is guaranteed to be
						{
							error_simple(0,"Invalid file- setting name loaded from sql. Report this.");
							continue;
						}
						const int file_n = set_n(peer_index,NULL);
						const int f = set_f(file_n,checksum,CHECKSUM_BIN_LEN); // reserves
						sodium_memzero(checksum,sizeof(checksum));
						if(f < 0)
							continue;
						torx_write(file_n) // 🟥🟥🟥
						peer[file_n].file[f].size = size;
						peer[file_n].file[f].modified = modified;
						torx_free((void*)&peer[file_n].file[f].filename);
						if(filename_len)
						{ // Restore the filename
							peer[file_n].file[f].filename = torx_secure_malloc(filename_len+1);
							memcpy(peer[file_n].file[f].filename,filename_ptr,filename_len);
							peer[file_n].file[f].filename[filename_len] = '\0';
						}
						torx_free((void*)&peer[file_n].file[f].file_path);
						if(file_path_len)
						{ // Restore the file path
							peer[file_n].file[f].file_path = torx_secure_malloc(file_path_len+1);
							memcpy(peer[file_n].file[f].file_path,file_path_ptr,file_path_len);
							peer[file_n].file[f].file_path[file_path_len] = '\0';
						}
						torx_free((void*)&peer[file_n].file[f].split_hashes);
						if(split_hashes_portion)
						{ // Restore split_hashes (group files): stored is the hash portion only; re-append the trailing htobe64(size) that the file's hash-of-hashes covers
							peer[file_n].file[f].split_hashes = torx_secure_malloc(split_hashes_portion + sizeof(uint64_t));
							memcpy(peer[file_n].file[f].split_hashes,split_hashes_ptr,split_hashes_portion);
							const uint64_t size_be = htobe64(size);
							memcpy(&peer[file_n].file[f].split_hashes[split_hashes_portion],&size_be,sizeof(uint64_t));
						}
						torx_unlock(file_n) // 🟩🟩🟩
						file_status_apply(file_n,f,saved_status,splits); // Must call AFTER restoring path, filename, size, modified, split_hashes, etc. INBOUND ONLY: status loaded from the file-<b64_checksum> peer setting (see sql_save_file_status).
					}
				}
				#endif // NO_FILE_TRANSFER
				else if(!strncmp(setting_name,"shorten_torxids",15))
				{
					if(!library_settings_loaded_encrypted)
						shorten_torxids = (uint8_t)strtoull(setting_value, NULL, 10); // A bunch of casts here is not wonderful but should not be harmful either since we control
				}
				else if(!strncmp(setting_name,"suffix_length",13))
				{
					if(!library_settings_loaded_encrypted)
						suffix_length = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"global_threads",14))
				{
					if(!library_settings_loaded_encrypted)
						global_threads = (uint32_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"global_log_messages",19))
				{
					if(!library_settings_loaded_encrypted)
						global_log_messages = (uint8_t)strtoull(setting_value, NULL, 10); // SIGNED
				}
				else if(!strncmp(setting_name,"sing_expiration_days",20))
				{
					if(!library_settings_loaded_encrypted)
						sing_expiration_days = (uint32_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"mult_expiration_days",20))
				{
					if(!library_settings_loaded_encrypted)
						mult_expiration_days = (uint32_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"auto_accept_mult",16))
				{
					if(!library_settings_loaded_encrypted)
						auto_accept_mult = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"destroy_input",13))
				{
					if(!library_settings_loaded_encrypted)
						destroy_input = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"reduced_memory",14))
				{
					if(!library_settings_loaded_encrypted)
						reduced_memory = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"log_last_seen",13))
				{
					if(!library_settings_loaded_encrypted)
						log_last_seen = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"last_seen",9))
				{
					if(!library_settings_loaded_encrypted)
					{
						sanity_check
						const int n = set_n(peer_index,NULL);
						const time_t last_seen = strtoll(setting_value, NULL, 10);
						setter(n,INT_MIN,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
					}
				}
				else if(!strncmp(setting_name,"logging",7))
				{
					if(!library_settings_loaded_encrypted)
					{
						sanity_check
						const int n = set_n(peer_index,NULL);
						const int8_t log_messages = (int8_t)strtoll(setting_value, NULL, 10);
						setter(n,INT_MIN,-1,offsetof(struct peer_list,log_messages),&log_messages,sizeof(log_messages));
					}
				}
				else if(!strncmp(setting_name,"group_id",8))
				{
					if(!library_settings_loaded_encrypted)
					{ // IMPORTANT: This MUST be the FIRST setting saved because it will also be the first loaded.
						unsigned char id[GROUP_ID_SIZE];
						sanity_check
						if(setting_value_len != GROUP_ID_SIZE)
						{
							error_simple(0,"Invalid group id loaded from sql. Report this."); // TODO should probably skip the next steps
							continue;
						}
						memcpy(id,setting_value,sizeof(id));
						const int ctrl_n = set_n(peer_index,NULL);
						const uint8_t owner = ENUM_OWNER_GROUP_CTRL;
						setter(ctrl_n,INT_MIN,-1,offsetof(struct peer_list,owner),&owner,sizeof(owner)); // XXX HAVE TO set this because set_g relies on it
				/*int g = */	const int g = set_g(ctrl_n,id); // just for reserving
						(void)g;
						sodium_memzero(id,GROUP_ID_SIZE);
					}
				}
				else if(!strncmp(setting_name,"invite_required",15))
				{
					if(!library_settings_loaded_encrypted)
					{ // DO NOT assume any specific group setting will be read before any other
						sanity_check
						const int ctrl_n = set_n(peer_index,NULL);
						const uint8_t owner = ENUM_OWNER_GROUP_CTRL;
						setter(ctrl_n,INT_MIN,-1,offsetof(struct peer_list,owner),&owner,sizeof(owner)); // XXX HAVE TO set this because set_g relies on it
						const int g = set_g(ctrl_n,NULL); // reserved
						const uint8_t invite_required = (uint8_t)strtoull(setting_value, NULL, 10);
						setter_group(g,offsetof(struct group_list,invite_required),&invite_required,sizeof(invite_required));
					}
				}
				else if(!strncmp(setting_name,"group_peer",10))
				{
					if(!library_settings_loaded_encrypted)
					{ // Onion of a peer, associated with peer_index XXX NOTE: can only compare first 10 letters. what follows is peer_index of the GROUP_PEER, for uniqueness // XXX do use setting_value, its trash XXX
						sanity_check
						const int ctrl_n = set_n(peer_index,NULL); // this is group_n's peer_index, not group_peer's
						const uint8_t owner = ENUM_OWNER_GROUP_CTRL;
						setter(ctrl_n,INT_MIN,-1,offsetof(struct peer_list,owner),&owner,sizeof(owner)); // XXX HAVE TO set this because set_g relies on it
						const int g = set_g(ctrl_n,NULL); // reserved
						const int stripped_peer_index = (int)strtoull(&setting_name[10], NULL, 10);
						const int peer_n = set_n(stripped_peer_index,NULL); // XXX do use setting_value, its trash XXX
						pthread_rwlock_wrlock(&mutex_expand_group); // 🟥
						const uint32_t count = group_peercount_nolock(g); // so, this grows as we load more. XXX Growing .peerlist IS how the peercount is incremented.
						if(group[g].peerlist)
							group[g].peerlist = torx_realloc(group[g].peerlist,((size_t)count+1)*sizeof(int));
						else
							group[g].peerlist = torx_insecure_malloc(((size_t)count+1)*sizeof(int));
						group[g].peerlist[count] = peer_n;
					//	error_printf(0,"Checkpoint sql_populate_setting g==%d peercount==%u",g,count+1);
						pthread_rwlock_unlock(&mutex_expand_group); // 🟩
					}
				}
				else if(!strncmp(setting_name,"tor_socks_port",14))
				{
					if(!library_settings_loaded_encrypted)
						tor_socks_port = (uint16_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"tor_ctrl_port",13))
				{
					if(!library_settings_loaded_encrypted)
						tor_ctrl_port = (uint16_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"control_password_clear",22))
				{
					if(!library_settings_loaded_encrypted)
					{
						torx_free((void*)&control_password_clear);
						control_password_clear = torx_secure_malloc(setting_value_len+1);
						memcpy(control_password_clear,setting_value,setting_value_len);
						control_password_clear[setting_value_len] = '\0';
					}
				}
				#ifndef NO_STICKERS
				else if(!strncmp(setting_name,"stickers_save_all",17))
				{
					if(!library_settings_loaded_encrypted)
						stickers_save_all = (uint8_t)strtoull(setting_value, NULL, 10);
				}
				else if(!strncmp(setting_name,"sticker-gif-",12))
				{
					if(!library_settings_loaded_encrypted)
					{ // NOTE: the following CANNOT be locked by mutex_global_variable because sticker_register utilizes it
						if(peer_index < 0) // should always be true
							pthread_rwlock_unlock(&mutex_global_variable); // 🟩
						const int s = sticker_register((const unsigned char *)setting_value,setting_value_len);
						pthread_rwlock_wrlock(&mutex_sticker); // 🟥
						sticker[s].saved = 1; // we got this from disk, so we must mark it as saved
						pthread_rwlock_unlock(&mutex_sticker); // 🟩
						if(stickers_offload_on_startup)
							sticker_offload(s);
						if(peer_index < 0) // should always be true
							pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
					}
				}
				else if(!strncmp(setting_name,"sticker-peers-",14))
				{
					if(!library_settings_loaded_encrypted)
					{ // Cannot use sticker_add_peer() because it calls sticker_save_peers
						if(peer_index < 0) // should always be true
							pthread_rwlock_unlock(&mutex_global_variable); // 🟩
						const size_t peer_count = setting_value_len/sizeof(int); // NOTE: where we get the size from
						unsigned char checksum[CHECKSUM_BIN_LEN];
						b64_decode(checksum,sizeof(checksum),&setting_name[14]); // we depend on setting_name to be null terminated, which it is guaranteed to be
						int s = 0;
						pthread_rwlock_wrlock(&mutex_sticker); // 🟥
						while((uint32_t)s < torx_allocation_len(sticker)/sizeof(struct sticker_list) && memcmp(sticker[s].checksum,checksum,CHECKSUM_BIN_LEN))
							s++;
						if((uint32_t)s == torx_allocation_len(sticker)/sizeof(struct sticker_list))
						{ // Checksum hasn't been placed by sticker_register yet, need to place checksum and initialize
							if(sticker)
								sticker = torx_realloc(sticker,torx_allocation_len(sticker) + sizeof(struct sticker_list));
							else
								sticker = torx_secure_malloc(sizeof(struct sticker_list));
							memcpy(sticker[s].checksum,checksum,sizeof(checksum));
							sticker[s].saved = 0; // initializing
							sticker[s].data = NULL; // initializing
						}
						sticker[s].peers = torx_insecure_malloc(sizeof(int)*peer_count); // NOTE: we assume this is so-far unallocated
						for(size_t iter = 0; iter < peer_count; iter++)
						{
							const int peer_index_from_list = (int)be32toh(align_uint32((const void*)&setting_value[iter*sizeof(int)]));
							const int n_from_list = set_n(peer_index_from_list,NULL);
							if(n_from_list > -1)
								sticker[s].peers[iter] = n_from_list;
						}
						pthread_rwlock_unlock(&mutex_sticker); // 🟩
						sodium_memzero(checksum,sizeof(checksum));
						if(peer_index < 0) // should always be true
							pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
					}
				}
				#endif // NO_STICKERS
				else
				{ // Send unrecognized settings to UI
					if(!library_settings_loaded_encrypted && peer_index < 0) // prevent potential for deadlock by unpredictable contents of custom_setting_cb
						pthread_rwlock_unlock(&mutex_global_variable); // 🟩
					const int n = set_n(peer_index,NULL); // XXX WARNING: N could be negative, indicating a global value
					char *setting_name_allocated = torx_secure_malloc(setting_name_len+1);
					snprintf(setting_name_allocated,setting_name_len+1,"%s",setting_name);
					char *setting_value_allocated = torx_secure_malloc(setting_value_len+1); // TODO +1/Null termination could interfere with binary interpretation if callback utilizes torx_allocation_len(setting_value_allocated) instead of setting_value_len
					memcpy(setting_value_allocated,setting_value,setting_value_len);
					setting_value_allocated[setting_value_len] = '\0';
					custom_setting_cb(n,setting_name_allocated,setting_value_allocated,setting_value_len,0);
					if(!library_settings_loaded_encrypted && peer_index < 0) // prevent potential for deadlock by unpredictable contents of custom_setting_cb
						pthread_rwlock_rdlock(&mutex_global_variable); // 🟧 // yes rdlock is correct here, because we have no more actions upon it
				}
				if(!library_settings_loaded_encrypted && peer_index < 0) // global variable
					pthread_rwlock_unlock(&mutex_global_variable); // 🟩
			}
		}
		if(val != SQLITE_DONE)
			error_printf(3, "Can't retrieve data: %s",sqlite3_errmsg(*db));
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	}
	pthread_mutex_unlock(mutex); // 🟩🟩
	if(force_plaintext)
	{
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		library_settings_loaded_plaintext = 1;
		const char *tor_location_local_pointer = tor_location;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
		if(tor_location_local_pointer && attempt_login)
			login_start("");
	}
	else
	{
		pthread_rwlock_wrlock(&mutex_global_variable); // 🟥
		library_settings_loaded_encrypted = 1;
		pthread_rwlock_unlock(&mutex_global_variable); // 🟩
	}
}

int sql_delete_setting(const int force_plaintext,const int peer_index,const char *setting_name)
{ // For GLOBAL setting, pass -1 as peer_index
	if(force_plaintext && peer_index != -1)
	{
		error_simple(0,"Tried to delete a peer specific setting in plaintext database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	else if(!setting_name)
	{
		error_simple(0,"Tried to delete a NULL setting in database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	if(force_plaintext)
		snprintf(command,sizeof(command),"DELETE FROM setting_clear WHERE setting_name = (?);");
	else if(peer_index == -1)
		snprintf(command,sizeof(command),"DELETE FROM setting_global WHERE setting_name = (?);");
	else // encrypted
		snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d AND setting_name = (?);",peer_index);
	const int val = sql_exec(force_plaintext ? &db_plaintext : &db_encrypted,command,setting_name,strlen(setting_name),NULL);
	sodium_memzero(command,sizeof(command));
	return val;
}

int sql_delete_message(const int peer_index,const time_t time,const time_t nstime)
{
	if(peer_index < 0)
	{
		error_printf(0,"Invalid peer_index passed to sql_delete_message: %d. Coding error. Report this.",peer_index);
		breakpoint();
		return -1;
	}
	const int n = set_n(peer_index,NULL);
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // delete all the associated GROUP_PEER messages
		const int g = set_g(n,NULL);
		for(int specific_peer,p = 0; (specific_peer = group_peerlist_get(g,p)) > -1 ; p++)
		{
			const int peer_index_other = getter_int(specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d AND time = %lld AND nstime = %lld;",peer_index_other,(long long)time,(long long)nstime);
			sql_exec(&db_messages,command,NULL);
		}
	}
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d AND time = %lld AND nstime = %lld;",peer_index,(long long)time,(long long)nstime);
	const int val = sql_exec(&db_messages,command,NULL);
	sodium_memzero(command,sizeof(command));
	return val;
}

int sql_delete_history(const int peer_index)
{ // Internal function. Use delete_log. Note: does not delete from ram, just disk.
	if(peer_index < 0)
	{
		error_printf(0,"Invalid peer_index passed to sql_delete_history: %d. Coding error. Report this.",peer_index);
		breakpoint();
		return -1;
	}
	const int n = set_n(peer_index,NULL);
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // delete all the associated GROUP_PEER message history first
		const int g = set_g(n,NULL);
		for(int specific_peer,p = 0; (specific_peer = group_peerlist_get(g,p)) > -1 ; p++)
		{
			const int peer_index_other = getter_int(specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index_other);
			sql_exec(&db_messages,command,NULL);
		}
	}
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index);
	const int val = sql_exec(&db_messages,command,NULL);
	sodium_memzero(command,sizeof(command));
	return val;
}

int sql_delete_peer(const int peer_index)
{ // INTERNAL FUNCTION ONLY use takedown_onion // SHOULD delete all related settings and history. "cascade" // takedown_onion calls this, which handles groups properly
	if(peer_index < 0)
	{
		error_printf(0,"Invalid peer_index passed to sql_delete_peer: %d. Coding error. Report this.",peer_index);
		breakpoint();
		return -1;
	}
	int val;
	char command[256]; // size is somewhat arbitrary, content not sensitive, consider not calling memzero
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_messages,command,NULL);
	snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_encrypted,command,NULL);
	snprintf(command,sizeof(command),"DELETE FROM peer WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_encrypted,command,NULL);
	sodium_memzero(command,sizeof(command));
	return val;
}
