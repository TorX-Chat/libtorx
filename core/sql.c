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

void delete_log(const int n)
{ // WARNING: If called on GROUP_CTRL, THIS WILL ALSO DELETE PRIVATE MESSAGES
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	sql_delete_history(peer_index); // TODO must go first. consider verifying return before deleting in memory
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_PEER) // TODO 2025/02/28 The issue may occur in not calling message_remove near the end of this function. We should probably utilize the same "VERY IMPORTANT / COMPLEX if statement, do not change" if statement, if _GROUP_PEER, if this warning occurs.
		error_simple(0,"delete_log may not be prepared (yet) for deleting solely ENUM_OWNER_GROUP_PEER. Coding error. Report this.");
	const int g = (owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL) ? set_g(n,NULL) : -1;
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // Handle GROUP_PEER ; not tested fully. Must go first before GROUP_CTRL
		const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t p = 0; p < g_peercount; p++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int peer_n = group[g].peerlist[p];
			pthread_rwlock_unlock(&mutex_expand_group);
			const int max_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
			const int min_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
			for(int i = min_i ; i <= max_i ; i++)
			{
				const int p_iter = getter_int(peer_n,i,-1,offsetof(struct message_list,p_iter));
				if(p_iter > -1) // snuff out deleted messages
				{
					pthread_rwlock_rdlock(&mutex_protocols);
					const uint8_t group_msg = protocols[p_iter].group_msg;
					const uint8_t group_pm = protocols[p_iter].group_pm;
					pthread_rwlock_unlock(&mutex_protocols);
					const uint8_t stat = getter_uint8(peer_n,i,-1,offsetof(struct message_list,stat));
					if((stat == ENUM_MESSAGE_RECV && (group_msg || group_pm)) || ((stat == ENUM_MESSAGE_SENT || stat == ENUM_MESSAGE_FAIL) && group_pm)) // XXX VERY IMPORTANT / COMPLEX if statement, do not change
						message_remove(g,peer_n,i); // do not remove (segfaults will happen). Conditions are to avoid sanity check errors.
					torx_write(peer_n) // 🟥🟥🟥
					zero_i(peer_n,i);
					torx_unlock(peer_n) // 🟩🟩🟩
					message_deleted_cb(peer_n,i); // optional
				}
			}
			torx_write(peer_n) // 🟥🟥🟥
			peer[peer_n].max_i = -1;
			torx_unlock(peer_n) // 🟩🟩🟩
		//TODO	shrink_message_struct(peer_n);
		}
	}
	const int max_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,max_i));
	const int min_i = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,min_i));
	for(int i = min_i ; i <= max_i ; i++)
	{
		if(owner == ENUM_OWNER_GROUP_CTRL)
			message_remove(g,n,i);
		torx_write(n) // 🟥🟥🟥
		zero_i(n,i);
		torx_unlock(n) // 🟩🟩🟩
		message_deleted_cb(n,i); // optional
	}
	torx_write(n) // 🟥🟥🟥
	peer[n].max_i = -1;
	torx_unlock(n) // 🟩🟩🟩
//TODO	shrink_message_struct(n);
}

int message_edit(const int n,const int i,const char *message)
{ // Pass NULL to delete // NOTE: Changing a message's length while it is queued to send may result in abnormal behavior in packet_removal.
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_simple(0,"Message's p_iter is <0 which indicates it is deleted or buggy.3");
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const int protocol = protocols[p_iter].protocol;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	char *message_old = NULL;
	char *message_new = NULL; // must initialize
	const uint32_t base_message_len = message ? (uint32_t)strlen(message) : 0;
	const int g = (owner == ENUM_OWNER_GROUP_PEER || owner == ENUM_OWNER_GROUP_CTRL) ? set_g(n,NULL) : -1;
	if(!message || (signature_len && getter_uint8(n,i,-1,offsetof(struct message_list,stat)) != ENUM_MESSAGE_RECV && protocol == ENUM_PROTOCOL_UTF8_TEXT_DATE_SIGNED) || protocol == ENUM_PROTOCOL_UTF8_TEXT || protocol == ENUM_PROTOCOL_UTF8_TEXT_PRIVATE)
	{ // Don't mess with the logic here
		uint32_t final_len = 0;
		if(message)
		{ // A message was passed
			if(signature_len)
			{ // Need to sign
				unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
				const int signing_n = (owner == ENUM_OWNER_GROUP_PEER) ? getter_group_int(g,offsetof(struct group_list,n)) : n;
				getter_array(&sign_sk,sizeof(sign_sk),signing_n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
				message_new = message_sign(&final_len,sign_sk,time,nstime,p_iter,message,base_message_len);
				sodium_memzero(sign_sk,sizeof(sign_sk));
			}
			else
				message_new = message_sign(&final_len,NULL,time,nstime,p_iter,message,base_message_len);
		}
		if(message_new || !message) // NOT else if
		{
			if(message_new)
			{ // Replacing a message
				torx_write(n) // 🟥🟥🟥
				message_old = peer[n].message[i].message; // need to free this *after* swap
				peer[n].message[i].message_len = final_len;
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
				const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
				for(uint32_t p = 0; p < g_peercount; p++)
				{
					pthread_rwlock_rdlock(&mutex_expand_group);
					const int peer_n = group[g].peerlist[p];
					pthread_rwlock_unlock(&mutex_expand_group);
					const int max_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,max_i));
					const int min_i = getter_int(peer_n,INT_MIN,-1,offsetof(struct peer_list,min_i));
					for(int ii = min_i ; ii <= max_i ; ii++) // should perhaps reverse this check, for greater speed?
					{
						const time_t time_ii = getter_time(peer_n,ii,-1,offsetof(struct message_list,time));
						const time_t nstime_ii = getter_time(peer_n,ii,-1,offsetof(struct message_list,nstime));
						if(time_ii == time && nstime_ii == nstime)
						{ // DO NOT need to sql_update_message or print_message_cb here. No private messages will come here.
							torx_write(peer_n) // 🟥🟥🟥
							if(message_new)
							{
								peer[peer_n].message[ii].message_len = final_len;
								peer[peer_n].message[ii].message = message_new;
							}
							else
								zero_i(peer_n,ii);
							torx_unlock(peer_n) // 🟩🟩🟩
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
				zero_i(n,i);
				torx_unlock(n) // 🟩🟩🟩
				message_deleted_cb(n,i);
			}
		}
		else
			error_simple(0,"Message_new is null. Coding error. Report this");
	}
	else
	{ // Example: inbound signed messages cannot be modified, only deleted.
		pthread_rwlock_rdlock(&mutex_protocols);
		const char *name = protocols[p_iter].name;
		pthread_rwlock_unlock(&mutex_protocols);
		error_printf(0,"Editing for this message type is unsupported: %s",name);
		return -1;
	}
	return 0;
}

int sql_exec(sqlite3** db,const char *command,const char *setting_value,const size_t setting_value_len)
{ // XXX THIS CAN ONLY TAKE STRINGS AS ARGUMENTS XXX setting_value is optional but needs to be used if there is possibility of dangerous data in text. NOTE: can still segfault if not string (it calls strlen)
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
	pthread_mutex_lock(mutex); // Prepare the statement with a parameterized query
	if((val = sqlite3_prepare_v2(*db, command, (int)strlen(command), &stmt, NULL)) != SQLITE_OK) // XXX passing length + null terminator for testing because sqlite is weird 
	{
		error_printf(0,"Cannot prepare statement: %s",sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
		pthread_mutex_unlock(mutex);
		return val;
	}
	if(setting_value != NULL && setting_value_len && (val = sqlite3_bind_blob(stmt, 1, setting_value,(int)setting_value_len, SQLITE_TRANSIENT)) != SQLITE_OK) // Bind the parameter, if passed
	{
		error_printf(0, "Cannot bind value to parameter: %s",sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
		sqlite3_finalize(stmt);
		pthread_mutex_unlock(mutex);
		return val;
	}
	if((val = sqlite3_step(stmt)) != SQLITE_DONE) // Execute the statement
	{ // Occurs whenever already exists
		error_printf(4, "Cannot execute statement: %s",sqlite3_errmsg(*db)); // return value is const, cannot be freed, so leave it as is
		sqlite3_finalize(stmt);
		pthread_mutex_unlock(mutex);
		return val;
	}
	sqlite3_finalize(stmt);	// XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(mutex);
	return SQLITE_OK; // == 0
}

static inline int sql_insert_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len)
{ // INTERNAL FUNCTION ONLY. DO NOT USE DIRECTLY. Call sql_setting instead.
	if(force_plaintext && peer_index != -1)
	{
		error_simple(0,"Tried to save a peer specific setting in plaintext database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	if(!setting_name || !setting_value/* || !setting_value_len*/)
	{
		error_simple(0,"Tried to save a NULL setting or setting value in database. Rejected. Report this.");
		breakpoint();
		return -1;
	}
	char *table_sql;
	if(force_plaintext)
		table_sql = sqlite3_mprintf("INSERT OR ABORT INTO setting_clear (setting_name,setting_value) VALUES ('%s',?);",setting_name);
	else if(peer_index == -1)
		table_sql = sqlite3_mprintf("INSERT OR ABORT INTO setting_global (setting_name,setting_value) VALUES ('%s',?);",setting_name);
	else /* encrypted */
	{ // For plaintext we have a unqiue setting_name, so we don't need to check first with a select whether it exists (find row)
		sqlite3_stmt *stmt;
		table_sql = sqlite3_mprintf("SELECT *FROM setting_peer WHERE peer_index = %d AND setting_name = '%s';",peer_index,setting_name);
		pthread_mutex_lock(&mutex_sql_encrypted);
		if(sqlite3_prepare_v2(db_encrypted,table_sql, -1, &stmt, NULL) != SQLITE_OK) // XXX passing length + null terminator for testing because sqlite is weird
		{
			error_printf(0, "Can't prepare setting statement: %s",sqlite3_errmsg(db_encrypted)); // return value is const, cannot be freed, so leave it as is
			pthread_mutex_unlock(&mutex_sql_encrypted);
			sqlite3_free(table_sql);
			return -1;
		}
		if(sqlite3_step(stmt) == SQLITE_ROW)
		{
			sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
			pthread_mutex_unlock(&mutex_sql_encrypted);
			sqlite3_free(table_sql);
			return SQLITE_CONSTRAINT; // unique failure, same as would be returned by force_plaintext == 1 unique failure
		}
		else 
		{
			sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
			pthread_mutex_unlock(&mutex_sql_encrypted);
			sqlite3_free(table_sql);
			table_sql = sqlite3_mprintf("INSERT OR ABORT INTO setting_peer (peer_index,setting_name,setting_value) VALUES (%d,'%s',?);",peer_index,setting_name);
		}
	}
	int val;
	if(force_plaintext)
		val = sql_exec(&db_plaintext,table_sql,setting_value,setting_value_len);
	else
		val = sql_exec(&db_encrypted,table_sql,setting_value,setting_value_len);
	sqlite3_free(table_sql);
	return val;
}

static inline int sql_update_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len)
{ // INTERNAL FUNCTION ONLY. DO NOT USE DIRECTLY. Call sql_setting instead.
	if((force_plaintext && peer_index != -1) || !setting_name || !setting_value || !setting_value_len)
	{
		error_simple(0,"Tried to update a peer specific setting in plaintext database, or sanity check otherwise failed. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	char command[strlen(setting_name)+256+2]; // size is somewhat arbitrary
	if(force_plaintext)
		snprintf(command,sizeof(command),"UPDATE OR ABORT setting_clear SET (setting_value) = (?) WHERE setting_name = '%s';",setting_name);
	else if(peer_index == -1)
		snprintf(command,sizeof(command),"UPDATE OR ABORT setting_global SET (setting_value) = (?) WHERE setting_name = '%s';",setting_name);
	else // encrypted
		snprintf(command,sizeof(command),"UPDATE OR ABORT setting_peer SET (setting_value) = (?) WHERE peer_index = %d AND setting_name = '%s';",peer_index,setting_name);
	int val;
	if(force_plaintext)
		val = sql_exec(&db_plaintext,command,setting_value,setting_value_len);
	else
		val = sql_exec(&db_encrypted,command,setting_value,setting_value_len);
	sodium_memzero(command,sizeof(command));
	return val;
}

int sql_setting(const int force_plaintext,const int peer_index,const char *setting_name,const char *setting_value,const size_t setting_value_len)
{ // For inserting or modifying setting. For GLOBAL setting, pass -1 as peer_index.
	if(peer_index < -1)
	{
		error_printf(0,"Attempted to save %s setting with an uninitialized peer_index. Coding error. Report this.",setting_name);
		breakpoint();
		return -1;
	}
	int val;
	if((val = sql_insert_setting(force_plaintext,peer_index,setting_name,setting_value,setting_value_len)) == SQLITE_CONSTRAINT)
	{
		error_simple(4,"Setting exists, updating");
		val = sql_update_setting(force_plaintext,peer_index,setting_name,setting_value,setting_value_len);
	}
	if(torx_debug_level(-1) > 3)
		error_printf(4,"Saved setting peer_index=%d %s",peer_index,setting_name);
	return val;
}

static inline int load_messages_struc(const int offset,const int n,const time_t time,const time_t nstime,const uint8_t stat,const int p_iter,const char *message,const uint32_t base_message_len,const unsigned char *signature,const size_t signature_length)
{
	if(n < 0 || p_iter < 0/* || !message*/)
	{
		char *name = NULL;
		if(p_iter > -1)
		{
			pthread_rwlock_rdlock(&mutex_protocols);
			name = protocols[p_iter].name;
			pthread_rwlock_unlock(&mutex_protocols);
		}
		if(message)
			error_printf(0,"Load_messages_struc failed sanity check: n=%d p_iter=%d has message",n,p_iter);
		else // TODO currently triggers on all non-PM GROUP_PEER messages
			error_printf(0,"Load_messages_struc failed sanity check: n=%d p_iter=%d, null message, time: %u, nstime: %u, base_message_len: %u, signature_length: %lu, protocol: %s",n,p_iter,time,nstime,base_message_len,signature_length,name);
		return INT_MIN;
	}
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	pthread_rwlock_unlock(&mutex_protocols);
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
				message_len = peer[group_n].message[group_i].message_len;
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
		if(file_offer)
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
					char *file_path = getter_string(NULL,group_n,INT_MIN,f,offsetof(struct file_list,file_path));
					process_file_offer_outbound(group_n,(const unsigned char*)message,splits,(const unsigned char*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t)],be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len])),be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN + sizeof(uint8_t) + split_hashes_len + sizeof(uint64_t)])),file_path);
					torx_free((void*)&file_path);
				}
				else
				{
					const int f = set_f(n,(const unsigned char*)message,CHECKSUM_BIN_LEN);
					char *file_path = getter_string(NULL,n,INT_MIN,f,offsetof(struct file_list,file_path));
					process_file_offer_outbound(n,(const unsigned char*)message,0,NULL,be64toh(align_uint64((const void*)&message[CHECKSUM_BIN_LEN])),be32toh(align_uint32((const void*)&message[CHECKSUM_BIN_LEN+sizeof(uint64_t)])),file_path);
					torx_free((void*)&file_path);
				}
			}
		}
		else if((protocol == ENUM_PROTOCOL_GROUP_OFFER || protocol == ENUM_PROTOCOL_GROUP_OFFER_FIRST) && stat != ENUM_MESSAGE_RECV)
		{ // Outbound group offer. Must add target peer to invitees.
			const int g = set_g(-1,tmp_message);
			invitee_add(g,n);
		}
	}
	return increment_i(n,offset,time,nstime,stat,-1,p_iter,tmp_message,message_len);
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

static inline char *v3auth_ll(const char *privkey,const uint16_t vport,const uint16_t tport,const int maxstreams,...)
{ /* Takes a linked list of v3authkeys and applies them to onion. Ready for groupchats */ // we have to detach because we dont use one single tor_call() control connection
// TODO 2022, not using detach / single control connection, is why we have to harden access to control port. If we use a single control connection, we can perhaps do API calls over insecure controlport (ie, we can use an existing Orbot instance, but we must "TAKEOWNERSHIP" to shutdown when control connection closes)
//	note: orbot would require custom configuration for controlport access, so either we use their intents api or we require manual controlport configuration, or we run our own tor
// TODO for groups, how do we know which authorized peer is sending messages if they are all unsigned messages on the same port? cannot
// different ports are not an option because then peers could spoof each other. we might HAVE TO use signed messages, or one onion per peer, which means no size cap but huge overhead.
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
				snprintf(buffer,512,"authenticate \"%s\"\nADD_ONION ED25519-V3:%s Flags=MaxStreamsCloseCircuit,Detach MaxStreams=%d Port=%u,%u",control_password_clear,privkey,maxstreams,vport,tport);
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
				snprintf(buffer,512,"authenticate \"%s\"\nADD_ONION ED25519-V3:%s Flags=MaxStreamsCloseCircuit,Detach,V3Auth MaxStreams=%d Port=%u,%u",control_password_clear,privkey,maxstreams,vport,tport);
			strcat(buffer," ClientAuthv3=");
			strcat(buffer,string);
		}
	}
	va_end(va_args);
	return buffer;
}

void load_onion(const int n)
{ // SING/MULT/CTRL. TODO refine TODO v3auth_ll() probably doesn't need to be called for SING/MULT/Group
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
	char incomingauthkey[56+1] = {0}; // zero'd
	uint16_t vport;
	if(owner == ENUM_OWNER_CTRL)
	{ /* Handle CTRL, which may have v3auth */
		vport = CTRL_VPORT;
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
				return;
			}
			sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
			if(base32_encode((unsigned char*)incomingauthkey,x25519_pk,sizeof(ed25519_pk)) != 56)
			{
				error_simple(0,"Serious error in load_onion relating to incoming auth key. Report this");
				sodium_memzero(x25519_pk,sizeof(x25519_pk));
				return;
			}
			sodium_memzero(x25519_pk,sizeof(x25519_pk));
			error_printf(3,"Incoming Auth: %s",incomingauthkey);
		}
		else if(local_v3auth_enabled)
			error_simple(0,"Warning: Peer does not support v3auth. Tell peer to upgrade Tor to >0.4.6.1.");
	}
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
	if(owner == ENUM_OWNER_GROUP_PEER)
		load_onion_events(n); // no recv on this to setup, so no need to tor_call
	else
	{ /* Build and send API call to Tor */ // Group Peer doesn't have a listening service nor v3auth. Everything else goes through this, even without v3auth
		int max_streams = MAX_STREAMS_PEER;
		if(owner == ENUM_OWNER_GROUP_CTRL)
			max_streams = MAX_STREAMS_GROUP;
		char privkey[88+1];
		getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
		char *apibuffer = v3auth_ll(privkey,vport,tport,max_streams,incomingauthkey,NULL);
		sodium_memzero(privkey,sizeof(privkey));
		sodium_memzero(incomingauthkey,sizeof(incomingauthkey));
		tor_call(load_onion_events,n,apibuffer);
		torx_free((void*)&apibuffer);
	}
}

int sql_insert_peer(const uint8_t owner,const uint8_t status,const uint16_t peerversion,const char *privkey,const char *peeronion,const char *peernick,const int expiration)
{ // not filling 'peer_sign_pk' and 'sign_sk', leaving them as NULL. Fill them during handshake with sql_update_peer.
	if(!privkey || !peeronion || !peernick) // TODO could add some additional checks here
		error_simple(-1,"Sanity check failed in sql_insert_peer. Coding error. Report this.");
	char command[1024]; // size is arbitrary
	snprintf(command,sizeof(command),"INSERT OR ABORT INTO peer (owner,status,peerversion,privkey,peeronion,peernick,expiration) VALUES (%u,%u,%u,'%s','%s',?,%d);",owner,status,peerversion,privkey,peeronion,expiration);
	int val = sql_exec(&db_encrypted,command,peernick,strlen(peernick));
	sqlite3_stmt *stmt;
	int len = snprintf(command,sizeof(command),"SELECT peer_index FROM peer WHERE privkey = '%s';",privkey);
	pthread_mutex_lock(&mutex_sql_encrypted);
	val = sqlite3_prepare_v2(db_encrypted,command,len, &stmt,NULL); // XXX passing length + null terminator for testing because sqlite is weird
	sodium_memzero(command,sizeof(command));
	if(val != SQLITE_OK)
	{
		error_printf(0, "Can't prepare peer statement: %s",sqlite3_errmsg(db_encrypted));
		pthread_mutex_unlock(&mutex_sql_encrypted);
		return -1;
	}
	else if((val = sqlite3_step(stmt)) == SQLITE_ROW)
	{ // Retrieve and return new peer_index
		const int peer_index = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
		pthread_mutex_unlock(&mutex_sql_encrypted);
		return peer_index;
	}
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(&mutex_sql_encrypted);
	error_simple(0, "Can't insert peer to DB. Report this.");
	return -1;
}

static int sql_update_blob(sqlite3** db,const char* table_name,const char* column_name,const int peer_index,const time_t time,const time_t nstime,const void* data,const int size)
{ // Store or update a blob to an existing peer_index row
	sqlite3_stmt *stmt;
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
	char* table_sql;
	if(!strncmp(table_name,"message",7))
		table_sql = sqlite3_mprintf("UPDATE OR ABORT '%s' SET ('%s') = (?) WHERE peer_index = %d AND time = %ld AND nstime = %ld;", table_name, column_name, peer_index, time, nstime);
	else if(!strncmp(table_name,"peer",4))
		table_sql = sqlite3_mprintf("UPDATE OR ABORT '%s' SET ('%s') = (?) WHERE peer_index = %d;", table_name, column_name, peer_index);
	else // coding error
		return -1;
	pthread_mutex_lock(mutex);
	int result = sqlite3_prepare_v2(*db, table_sql, -1, &stmt, NULL);
	if(result != SQLITE_OK)
	{
		error_printf(0, "Error preparing statement: %s",sqlite3_errmsg(*db));
		pthread_mutex_unlock(mutex);
		sqlite3_free(table_sql);
		return result;
	}
	result = sqlite3_bind_blob(stmt, 1, data, size, SQLITE_TRANSIENT);
	while(1)
	{ // not a real loop... just to avoid goto
		if(result != SQLITE_OK)
		{
			error_printf(0, "Error binding parameter: %s",sqlite3_errmsg(*db));
			break;
		}
		result = sqlite3_step(stmt);
		if(result != SQLITE_DONE)
		{
			error_printf(0, "Error executing statement: %s",sqlite3_errmsg(*db));
			break;
		}
	//	printf("Checkpoint sql_update_blob: %s\n",b649_encode(data,size));
		result = SQLITE_OK;
		break;
	}
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	pthread_mutex_unlock(mutex);
	sqlite3_free(table_sql);
	return result;
}

static int sql_exec_msg(const int n,const int i,const char *command)
{
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_simple(0,"Message's p_iter is <0 which indicates it is deleted or buggy.0");
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
	const uint32_t date_len = protocols[p_iter].date_len;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	pthread_rwlock_unlock(&mutex_protocols);
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));
	int val = -1;
	uint32_t message_len;
	char *message = getter_string(&message_len,n,i,-1,offsetof(struct message_list,message));;
	if(group_msg && owner == ENUM_OWNER_GROUP_PEER && stat != ENUM_MESSAGE_RECV)
		val = sql_exec(&db_messages,command,NULL,0); // XXX must NOT be triggered for an inbound or private message. It should go to 'else' (private message is more of a standard message)
	else if(null_terminated_len == 0 && message)
	{ // Prevent update_blob from triggering on outbound group_public messages, even if binary only
		val = sql_exec(&db_messages,command,NULL,0);
		const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
		sql_update_blob(&db_messages,"message","message_bin",peer_index,time,nstime,message,(int)(message_len - (null_terminated_len + date_len + signature_len)));
	}
	else if(null_terminated_len && message)
		val = sql_exec(&db_messages,command,message,strlen(message));
	else
		error_printf(0,"Bailing out from sql_exec_msg because we don't know how to handle this message: protocol=%u is_null=%d",protocol,message ? 1 : 0);
	torx_free((void*)&message);
	return val;
}

/* TODO this triggers far more often than necessary. Triggers once for every outbound file request, which occurs for every split. Ideally should just trigger upon first and then again after unpause perhaps... */
#define sql_message_tail_section \
	if(signature_len) /* Update signature (only) */ \
		sql_update_blob(&db_messages,"message","signature",peer_index,time,nstime,&message[message_len-crypto_sign_BYTES],crypto_sign_BYTES); \
	if((file_offer || protocol == ENUM_PROTOCOL_FILE_REQUEST) && stat != ENUM_MESSAGE_RECV) \
	{ /* save file_path as extraneous */ /* goat */ \
		int file_n = n; \
		int f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN-1); \
		if(f < 0) \
		{ /* not pm/p2p, must be group transfer */ \
			const int g = set_g(n,NULL); \
			file_n = getter_group_int(g,offsetof(struct group_list,n)); \
			f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN); \
		} \
		if(f > -1) /* NOT else if */ \
		{ \
			char *file_path = getter_string(NULL,file_n,INT_MIN,f,offsetof(struct file_list,file_path)); \
			if(file_path) /* not always true */ \
			{ \
				sql_update_blob(&db_messages,"message","extraneous",peer_index,time,nstime,file_path,(int)strlen(file_path)); \
				torx_free((void*)&file_path); \
			} \
		} \
	}

static inline int log_check(const int n,const uint8_t group_pm,const uint16_t protocol)
{
	if(protocol == ENUM_PROTOCOL_GROUP_PUBLIC_ENTRY_REQUEST || protocol == ENUM_PROTOCOL_GROUP_PRIVATE_ENTRY_REQUEST)
		return 1; // Entry requests MUST always be logged.
	const int8_t log_messages = getter_int8(n,INT_MIN,-1,offsetof(struct peer_list,log_messages));
	const uint8_t global = threadsafe_read_uint8(&mutex_global_variable,&global_log_messages);
	if(!(log_messages != -1 && (global > 0 || log_messages > 0)))
		return 0; // do not log these
	if(group_pm && threadsafe_read_uint8(&mutex_global_variable,&log_pm_according_to_group_setting))
	{
		const int g = set_g(n,NULL);
		const int group_n = getter_group_int(g,offsetof(struct group_list,n));
		const int8_t group_log_messages = getter_int8(group_n,INT_MIN,-1,offsetof(struct peer_list,log_messages));
		if(!(group_log_messages != -1 && (global > 0 || group_log_messages > 0)))
			return 0;
	}
	return 1;	
}

int sql_insert_message(const int n,const int i)
{ // Save an new message
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_simple(0,"Message's p_iter is <0 which indicates it is deleted or buggy.1");
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t logged = protocols[p_iter].logged;
	const uint8_t group_msg = protocols[p_iter].group_msg;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols);
	if(logged == 0 || !log_check(n,group_pm,protocol))
		return 0; // do not log these.
	uint32_t message_len;
	char *message = getter_string(&message_len,n,i,-1,offsetof(struct message_list,message));
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
		char command[512]; // size is somewhat arbitrary
		snprintf(command,sizeof(command),"INSERT OR ABORT INTO message (time,nstime,peer_index,stat,protocol) VALUES (%lld,%lld,%d,%d,%d);",(long long)time,(long long)nstime,peer_index,stat,protocol);
		val = sql_exec_msg(n,i,command);
		sodium_memzero(command,sizeof(command));
	}
	else
	{
		char command[512]; // size is somewhat arbitrary
		snprintf(command,sizeof(command),"INSERT OR ABORT INTO message (time,nstime,peer_index,stat,protocol,message_txt) VALUES (%lld,%lld,%d,%d,%d,?);",(long long)time,(long long)nstime,peer_index,stat,protocol);
		val = sql_exec_msg(n,i,command);
		sodium_memzero(command,sizeof(command));
		sql_message_tail_section // XXX
	}
	torx_free((void*)&message);
	return val;
}

int sql_update_message(const int n,const int i)
{ // Update a saved message (for example: after status changed when it is sent, or to manipulate the saved message)
	const int p_iter = getter_int(n,i,-1,offsetof(struct message_list,p_iter));
	if(p_iter < 0)
	{
		error_simple(0,"Message's p_iter is <0 which indicates it is deleted or buggy.2");
		breakpoint();
		return -1; // message is deleted or buggy
	}
	pthread_rwlock_rdlock(&mutex_protocols);
	const uint16_t protocol = protocols[p_iter].protocol;
	const uint8_t logged = protocols[p_iter].logged;
	const uint32_t signature_len = protocols[p_iter].signature_len;
	const uint8_t file_offer = protocols[p_iter].file_offer;
	const uint8_t group_pm = protocols[p_iter].group_pm;
	pthread_rwlock_unlock(&mutex_protocols);
	if(logged == 0 || !log_check(n,group_pm,protocol))
		return 0; // do not log these.
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	const uint8_t stat = getter_uint8(n,i,-1,offsetof(struct message_list,stat));

	char command[512]; // size is somewhat arbitrary
	snprintf(command,sizeof(command),"UPDATE OR ABORT message SET (stat,protocol,message_txt) = (%d,%d,?) WHERE time = %lld AND nstime = %lld AND peer_index = %d;",stat,protocol,(long long)time,(long long)nstime,peer_index);
	const int val = sql_exec_msg(n,i,command); // Update message
	sodium_memzero(command,sizeof(command));
	uint32_t message_len;
	char *message = getter_string(&message_len,n,i,-1,offsetof(struct message_list,message));
	sql_message_tail_section // XXX
	torx_free((void*)&message);
	return val;
}

int sql_update_peer(const int n)
{ // XXX WARNING: passing sign_sk or peer_sign_pk as NULL will render them null in the database.
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
	char privkey[88+1];
	getter_array(&privkey,sizeof(privkey),n,INT_MIN,-1,offsetof(struct peer_list,privkey));
	char peeronion[56+1];
	getter_array(&peeronion,sizeof(peeronion),n,INT_MIN,-1,offsetof(struct peer_list,peeronion));
	char command[1024]; // size is arbitrary
	snprintf(command,sizeof(command),"UPDATE OR ABORT peer SET (owner,status,peerversion,privkey,peeronion,peernick) = (%u,%u,%u,'%s','%s',?) WHERE peer_index = %d;",owner,status,peerversion,privkey,peeronion,peer_index);
	sodium_memzero(privkey,sizeof(privkey));
	sodium_memzero(peeronion,sizeof(peeronion));
	uint32_t peernick_len;
	char *peernick = getter_string(&peernick_len,n,INT_MIN,-1,offsetof(struct peer_list,peernick));
	const int val = sql_exec(&db_encrypted,command,peernick,peernick_len-1); // don't include null byte in the count
	torx_free((void*)&peernick);
	sodium_memzero(command,sizeof(command));
	unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
	getter_array(&sign_sk,sizeof(sign_sk),n,INT_MIN,-1,offsetof(struct peer_list,sign_sk));
	unsigned char peer_sign_pk[crypto_sign_PUBLICKEYBYTES];
	getter_array(&peer_sign_pk,sizeof(peer_sign_pk),n,INT_MIN,-1,offsetof(struct peer_list,peer_sign_pk));
	unsigned char invitation[crypto_sign_BYTES];
	getter_array(&invitation,sizeof(invitation),n,INT_MIN,-1,offsetof(struct peer_list,invitation));
	sql_update_blob(&db_encrypted,"peer","sign_sk",peer_index,0,0,sign_sk,crypto_sign_SECRETKEYBYTES);
	sql_update_blob(&db_encrypted,"peer","peer_sign_pk",peer_index,0,0,peer_sign_pk,crypto_sign_PUBLICKEYBYTES);
	sql_update_blob(&db_encrypted,"peer","invitation",peer_index,0,0,invitation,crypto_sign_BYTES);
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
	pthread_mutex_lock(&mutex_sql_messages); // better to put this before we get the earliest_time
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
		pthread_mutex_unlock(&mutex_sql_messages);
		return 0; // no messages to retrieve
	}
	sqlite3_stmt *stmt;
	char command[512]; // size is somewhat arbitrary
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
	int val = sqlite3_prepare_v2(db_messages,command, len, &stmt, NULL); // XXX passing length + null terminator for testing because sqlite is weird
	sodium_memzero(command,sizeof(command));
	if(val != SQLITE_OK)
	{
		error_printf(0, "Can't prepare message statement: %s. Not loading messages. Report this.",sqlite3_errmsg(db_messages));
		pthread_mutex_unlock(&mutex_sql_messages);
		return 0;
	}
	int offset = 0;
	if(reverse)
	{ // Need to calculate the offset and appropriately expand the struct.
		int i = min_i;
		while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			i--;
			offset--;
			uint8_t expanded = 0;
			torx_write(n) // 🟥🟥🟥
			if(peer[n].message[i].p_iter == -1 && i % 10 == 0 && (i + 10 > peer[n].max_i + 1 || i - 10 < peer[n].min_i - 1))
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
	//	error_simple(0,"Checkpoint load more IS BROKEN (memory issue). Bailing out until we can fix it. 2025/01/21. Be sure to reduce show_log_messages. Problem may be related to increment_i, or "); // TODO TODO TODO FOR TESTING ONLY, REMOVE
	//	pthread_mutex_unlock(&mutex_sql_messages); // TODO TODO TODO FOR TESTING ONLY, REMOVE
	//	return 0; // TODO TODO TODO FOR TESTING ONLY, REMOVE
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
		pthread_rwlock_rdlock(&mutex_protocols);
		const uint8_t logged = protocols[p_iter].logged;
		const uint32_t null_terminated_len = protocols[p_iter].null_terminated_len;
		const uint8_t file_offer = protocols[p_iter].file_offer;
		const uint8_t file_checksum = protocols[p_iter].file_checksum;
		const uint8_t group_msg = protocols[p_iter].group_msg;
		pthread_rwlock_unlock(&mutex_protocols);
		if(null_terminated_len == 0 && logged)
			column = 6;
		else
			column = 5;
		const char *message = (const char *)sqlite3_column_text(stmt, column);
		uint32_t message_len = (uint32_t)sqlite3_column_bytes(stmt, column);
		const unsigned char *signature = sqlite3_column_blob(stmt, 7);
		const size_t signature_length = (size_t)sqlite3_column_bytes(stmt, 7);
		const char *extraneous;
		uint32_t extraneous_len = (uint32_t)sqlite3_column_bytes(stmt, 8);
		if(protocol == ENUM_PROTOCOL_FILE_PAUSE || protocol == ENUM_PROTOCOL_FILE_CANCEL)
		{ // Probably important to verify !offset
			if(offset)
				continue; // This highly likely will screw up a file's status, so we must ignore it.
			int file_n = n;
			int f = -1;
			if(owner == ENUM_OWNER_GROUP_PEER)
			{ // First check if its a PM transfer
				f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN-1);
				if(f < 0)
				{ // Second, assume it's a group transfer
					const int g = set_g(n,NULL);
					file_n = getter_group_int(g,offsetof(struct group_list,n));
					if(file_n < 0)
					{ // TODO 2024/05/13 hit this issue, not sure what is going on yet.
						error_printf(0,"We tried to load a file offer for a group that has no group_n. There is a logic error here: %d %u",file_n,protocol);
						continue;
					}
					f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN);
				}
			}
			else
				f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN);
			process_pause_cancel(file_n,f,n,protocol,message_stat);
		}
		if(extraneous_len)
		{
			int file_n = n;
			int f = -1;
			if(file_checksum && message && message_stat != ENUM_MESSAGE_RECV)
			{ // handle outbound file related messages
				if(protocol == ENUM_PROTOCOL_FILE_REQUEST) // check if PM or group transfer (pm is f > -1)
					f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN-1);
				if(f < 0 && (protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP || protocol == ENUM_PROTOCOL_FILE_OFFER_GROUP_DATE_SIGNED || protocol == ENUM_PROTOCOL_FILE_REQUEST))
				{ // do NOT make else if
					if(owner == ENUM_OWNER_CTRL)
					{ // TODO 2024/12/24 hit this issue. The file doesn't exist. Related messages are deleted. Not sure why this one didn't get deleted when history was cleared. This message should be deleted
						error_printf(0,"Bunk message should probably be deleted: %d %u",file_n,protocol);
						continue; // TODO delete instead
					}
					const int g = set_g(n,NULL);
					file_n = getter_group_int(g,offsetof(struct group_list,n));
					if(file_n < 0)
					{ // TODO 2024/05/13 hit this issue, not sure what is going on yet.
						error_printf(0,"We tried to load a file offer for a group that has no group_n. There is a logic error here: %d %u",file_n,protocol);
						continue;
					}
					f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN);
				}
				else if(f < 0)
					f = set_f(file_n,(const unsigned char *)message,CHECKSUM_BIN_LEN);
			}
			if(file_offer || protocol == ENUM_PROTOCOL_FILE_REQUEST)
			{ // Retrieve file_path /* goat */
				extraneous = NULL;
				const char *file_path = (const char *)sqlite3_column_blob(stmt, 8);
				torx_write(file_n) // 🟥🟥🟥
				peer[file_n].file[f].file_path = torx_secure_malloc(extraneous_len+1);
				memcpy(peer[file_n].file[f].file_path,file_path,extraneous_len);
				peer[file_n].file[f].file_path[extraneous_len] = '\0';
				const uint8_t split_progress_exists = peer[file_n].file[f].split_progress ? 1 : 0;
				torx_unlock(file_n) // 🟩🟩🟩
				extraneous_len = 0; // MUST because related to callback
				const int file_status = file_status_get(file_n,f);
				if(protocol == ENUM_PROTOCOL_FILE_REQUEST && file_status != ENUM_FILE_INACTIVE_CANCELLED && (file_status != ENUM_FILE_INACTIVE_AWAITING_ACCEPTANCE_INBOUND || !split_progress_exists))
				{
					initialize_split_info(file_n,f);
					torx_read(file_n) // 🟧🟧🟧
					if(peer[file_n].file[f].splits == 0 && peer[file_n].file[f].split_progress && peer[file_n].file[f].split_progress[0] == 0)
					{ // 2024/05/12 Setting transferred amount according to file size. This might be depreciated (2025/01/13).
						torx_unlock(file_n) // 🟩🟩🟩
						const uint64_t size_on_disk = get_file_size(file_path);
						torx_write(file_n) // 🟥🟥🟥
						if(peer[file_n].file[f].split_progress) // sanity check
							peer[file_n].file[f].split_progress[0] = size_on_disk;
					//	printf("Checkpoint file_status=%d splits=%u size=%lu size_on_disk=%lu\n",file_status,peer[file_n].file[f].splits,peer[file_n].file[f].size,size_on_disk); // should only initialize if not complete
						if(size_on_disk == peer[file_n].file[f].size) // Note: we don't need to check the split file itself because splits==0
							torx_free((void*)&peer[file_n].file[f].split_path);
					}
					torx_unlock(file_n) // 🟩🟩🟩
				}
			}
			else
				extraneous = (const char *)sqlite3_column_blob(stmt, 8);
		}
		const int i = load_messages_struc(offset,n,time,nstime,message_stat,p_iter,message,message_len,signature,signature_length);
		if(i != INT_MIN && !(message_stat != ENUM_MESSAGE_RECV && group_msg && owner == ENUM_OWNER_GROUP_PEER))
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
	pthread_mutex_unlock(&mutex_sql_messages);
	return (int)loaded;
}

void message_extra(const int n,const int i,const void *data,const uint32_t data_len)
{ // Save some extra data related to a message, which will be retrievable via message_extra_cb when loading the message
	const int peer_index = getter_int(n,INT_MIN,-1,offsetof(struct peer_list,peer_index));
	const time_t time = getter_time(n,i,-1,offsetof(struct message_list,time));
	const time_t nstime = getter_time(n,i,-1,offsetof(struct message_list,nstime));
	sql_update_blob(&db_messages,"message","extraneous",peer_index,time,nstime,data,(int)data_len);
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
	pthread_mutex_lock(&mutex_message_loading); // must be BEFORE messages_loaded != 0
	if(messages_loaded != 0)
	{ // This occurs after restarting Tor. We don't necessarily need to load from disk.
		pthread_mutex_unlock(&mutex_message_loading);
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
//	pthread_mutex_lock(&mutex_sql_encrypted);
	const char command[] = "SELECT *FROM peer";
	int val = sqlite3_prepare_v2(db_encrypted,command,(int)strlen(command), &stmt, NULL);
	if(val != SQLITE_OK)
	{
//		pthread_mutex_unlock(&mutex_sql_encrypted);
		pthread_mutex_unlock(&mutex_message_loading);
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
			//	printf("\n\nCheckpoint pre-load_onion p_i==%d n==%d owner==%d\npeernick==%s\npeeronion==%s\nprivkey==%s\n\n\n",peer_index,n,owner,peernick,peeronion,privkey);
				load_onion(n);
				inline_load_messages(owner,peer_index,n,local_show_log_messages);
				if(owner == ENUM_OWNER_GROUP_CTRL)
				{
					const int g = set_g(n,NULL);
					const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
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
				//		printf("Checkpoint PRIVATE group_n: %s group_n_pk: %s\n",peer[n].onion,b64_encode(ed25519_pk,sizeof(ed25519_pk)));
				//	else
				//		printf("Checkpoint PUBLIC group_n: %s group_n_pk: %s\n",peer[n].onion,b64_encode(ed25519_pk,sizeof(ed25519_pk)));
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
		{ // handle pending outgoing	PEER		load struct + peer_init()
			if((n = load_peer_struc(peer_index,owner,status,privkey,peerversion,peeronion,peernick,sign_sk,peer_sign_pk,invitation)) == -1)
				continue;
			torx_read(n) // 🟧🟧🟧
			pthread_t *thrd_send = &peer[n].thrd_send;
			torx_unlock(n) // 🟩🟩🟩
			if(pthread_create(thrd_send,&ATTR_DETACHED,&peer_init,itovp(n))) // TODO 2023/01/17 issue: this must not be run on re-loads (when start_tor() restarts tor)
				error_simple(-1,"Failed to create thread1");
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
//		pthread_mutex_unlock(&mutex_sql_encrypted);
		pthread_mutex_unlock(&mutex_message_loading);
		error_printf(3, "Can't retrieve data: %s",sqlite3_errmsg(db_messages));
		return -1;
	}
	sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
//	pthread_mutex_unlock(&mutex_sql_encrypted);
	pthread_rwlock_wrlock(&mutex_global_variable);
	lockout = 0;
	pthread_rwlock_unlock(&mutex_global_variable);
	login_cb(0); //.... this check COULD be moved to login_cb itself if we have a reason for it to be
	pthread_rwlock_rdlock(&mutex_expand_group);
	for(int g = 0 ; group[g].n > -1 || !is_null(group[g].id,GROUP_ID_SIZE); g++)
	{
		pthread_rwlock_unlock(&mutex_expand_group);
		message_sort(g);
		pthread_rwlock_rdlock(&mutex_expand_group);
	}
	pthread_rwlock_unlock(&mutex_expand_group);
	messages_loaded = 1; // must be at the end
	pthread_mutex_unlock(&mutex_message_loading); // must be AFTER messages_loaded = 1;
	return 0;
}

unsigned char *sql_retrieve(size_t *data_len,const int force_plaintext,const char *query)
{ // WARNING: only returns the FIRST match
	size_t setting_value_len = 0;
	unsigned char *data = NULL;
	if(query == NULL || strlen(query) == 0)
		goto fail;
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
	pthread_mutex_lock(mutex);
	while(cycles--)
	{
		const size_t allocated = strlen(query) + 64;
		char *command = torx_secure_malloc(allocated); // size is somewhat arbitrary
		if(force_plaintext)
			snprintf(command,allocated,"SELECT *FROM setting_clear WHERE setting_name = '%s'",query);
		else if(cycles)
			snprintf(command,allocated,"SELECT *FROM setting_global WHERE setting_name = '%s'",query);
		else
			snprintf(command,allocated,"SELECT *FROM setting_peer WHERE setting_name = '%s'",query);
		int val = sqlite3_prepare_v2(*db,command,(int)strlen(command), &stmt, NULL);
		torx_free((void*)&command);
		if(val != SQLITE_OK)
		{
			error_printf(0, "Can't prepare populate setting statement: %s",sqlite3_errmsg(*db));
			pthread_mutex_unlock(mutex);
			goto fail;
		}
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
			data = torx_secure_malloc(setting_value_len+1);
			memcpy(data,setting_value,setting_value_len);
			data[setting_value_len] = '\0';
		}
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	}
	pthread_mutex_unlock(mutex);
	fail: {}
	if(data_len)
		*data_len = setting_value_len;
	return data;
}

void sql_populate_setting(const int force_plaintext)
{
	#define sanity_check if(peer_index < 0) \
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
	pthread_mutex_lock(mutex);
	uint8_t attempt_login = 0;
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
			pthread_mutex_unlock(mutex);
			return;
		}
		while ((val = sqlite3_step(stmt)) == SQLITE_ROW)
		{ // Retrieve data here using sqlite3_column_* functions,
			int peer_index = -1;
			const char *setting_name;
			const char *setting_value;
			size_t setting_value_len;
			if(force_plaintext || cycles) // (force_plaintext)
			{ // TODO 2024/03/09 consider using sqlite3_column_blob for setting_value
				setting_name = (const char *)sqlite3_column_text(stmt, 1);
				setting_value = (const char *)sqlite3_column_text(stmt, 2);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 2);
			}
			else  /* encrypted */
			{
				peer_index = sqlite3_column_int(stmt, 1);
				setting_name = (const char *)sqlite3_column_text(stmt, 2);
				setting_value = (const char *)sqlite3_column_text(stmt, 3);
				setting_value_len = (size_t)sqlite3_column_bytes(stmt, 3);
			}
		//	int bytes = sqlite3_column_bytes(stmt, 0);
			if(force_plaintext)
			{
				error_printf(2,"Plaintext Setting: %s",setting_name);
				pthread_rwlock_wrlock(&mutex_global_variable);
				if(!strncmp(setting_name,"salt",4) && setting_value_len == sizeof(saltbuffer))
					memcpy(saltbuffer,setting_value,sizeof(saltbuffer));
				else if(!strncmp(setting_name,"crypto_pwhash_OPSLIMIT",22))
					crypto_pwhash_OPSLIMIT = strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"crypto_pwhash_MEMLIMIT",22))
					crypto_pwhash_MEMLIMIT = strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"crypto_pwhash_ALG",17))
					crypto_pwhash_ALG = (int)strtoll(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"tor_location",12))
				{
					torx_free((void*)&tor_location);
					tor_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(tor_location,setting_value,setting_value_len);
					tor_location[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"snowflake_location",18))
				{
					torx_free((void*)&snowflake_location);
					snowflake_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(snowflake_location,setting_value,setting_value_len);
					snowflake_location[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"lyrebird_location",17))
				{
					torx_free((void*)&lyrebird_location);
					lyrebird_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(lyrebird_location,setting_value,setting_value_len);
					lyrebird_location[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"conjure_location",16))
				{
					torx_free((void*)&conjure_location);
					conjure_location = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(conjure_location,setting_value,setting_value_len);
					conjure_location[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"censored_region",15))
					censored_region = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"decryption_key",14))
				{
					if(!keyed && setting_value_len > 0 && setting_value_len <= sizeof(decryption_key))
					{
						memcpy(decryption_key,setting_value,sizeof(decryption_key));
						attempt_login = 1;
					}
				}
				else
				{
					pthread_rwlock_unlock(&mutex_global_variable);
					const size_t len = strlen(setting_name);
					char *setting_name_allocated = torx_secure_malloc(len+1);
					snprintf(setting_name_allocated,len+1,"%s",setting_name);
					char *setting_value_allocated = torx_secure_malloc(setting_value_len+1);
					memcpy(setting_value_allocated,setting_value,setting_value_len);
					setting_value_allocated[setting_value_len] = '\0';
					custom_setting_cb(peer_index,setting_name_allocated,setting_value_allocated,setting_value_len,1);
					pthread_rwlock_rdlock(&mutex_global_variable); // yes rdlock is correct here, because we have no more actions upon it
				}
				pthread_rwlock_unlock(&mutex_global_variable);
			}
			else /* encrypted */
			{
				error_printf(3,"Encrypted Setting: peer_index=%d %s",peer_index,setting_name);
				if(peer_index < 0) // global variable
					pthread_rwlock_wrlock(&mutex_global_variable);
				if(!strncmp(setting_name,"download_dir",12))
				{
					torx_free((void*)&download_dir);
					download_dir = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(download_dir,setting_value,setting_value_len);
					download_dir[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"torrc",5))
				{
					torx_free((void*)&torrc_content);
					torrc_content = torx_secure_malloc(setting_value_len+1); // could free on shutdown
					memcpy(torrc_content,setting_value,setting_value_len);
					torrc_content[setting_value_len] = '\0';
				}
				else if(!strncmp(setting_name,"shorten_torxids",15))
					shorten_torxids = (uint8_t)strtoull(setting_value, NULL, 10); // A bunch of casts here is not wonderful but should not be harmful either since we control
				else if(!strncmp(setting_name,"suffix_length",13))
					suffix_length = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"global_threads",14))
					global_threads = (uint32_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"global_log_messages",19))
					global_log_messages = (uint8_t)strtoull(setting_value, NULL, 10); // SIGNED
				else if(!strncmp(setting_name,"sing_expiration_days",20))
					sing_expiration_days = (uint32_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"mult_expiration_days",20))
					mult_expiration_days = (uint32_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"auto_accept_mult",16))
					auto_accept_mult = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"destroy_input",13))
					destroy_input = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"reduced_memory",14))
					reduced_memory = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"auto_resume_inbound",19))
					auto_resume_inbound = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"log_last_seen",13))
					log_last_seen = (uint8_t)strtoull(setting_value, NULL, 10);
				else if(!strncmp(setting_name,"last_seen",9))
				{
					sanity_check
					const int n = set_n(peer_index,NULL);
					const time_t last_seen = strtoll(setting_value, NULL, 10);
					setter(n,INT_MIN,-1,offsetof(struct peer_list,last_seen),&last_seen,sizeof(last_seen));
				}
				else if(!strncmp(setting_name,"logging",7))
				{
					sanity_check
					const int n = set_n(peer_index,NULL);
					const int8_t log_messages = (int8_t)strtoll(setting_value, NULL, 10);
					setter(n,INT_MIN,-1,offsetof(struct peer_list,log_messages),&log_messages,sizeof(log_messages));
				}
				else if(!strncmp(setting_name,"group_id",8))
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
				else if(!strncmp(setting_name,"invite_required",15))
				{ // DO NOT assume any specific group setting will be read before any other
					sanity_check
					const int ctrl_n = set_n(peer_index,NULL);
					const uint8_t owner = ENUM_OWNER_GROUP_CTRL;
					setter(ctrl_n,INT_MIN,-1,offsetof(struct peer_list,owner),&owner,sizeof(owner)); // XXX HAVE TO set this because set_g relies on it
					const int g = set_g(ctrl_n,NULL); // reserved
					const uint8_t invite_required = (uint8_t)strtoull(setting_value, NULL, 10);
					setter_group(g,offsetof(struct group_list,invite_required),&invite_required,sizeof(invite_required));
				}
				else if(!strncmp(setting_name,"group_peer",10))
				{ // Onion of a peer, associated with peer_index XXX NOTE: can only compare first 10 letters. what follows is peer_index of the GROUP_PEER, for uniqueness // XXX do use setting_value, its trash XXX
					sanity_check
					const int ctrl_n = set_n(peer_index,NULL); // this is group_n's peer_index, not group_peer's
					const uint8_t owner = ENUM_OWNER_GROUP_CTRL;
					setter(ctrl_n,INT_MIN,-1,offsetof(struct peer_list,owner),&owner,sizeof(owner)); // XXX HAVE TO set this because set_g relies on it
					const int g = set_g(ctrl_n,NULL); // reserved
					const int stripped_peer_index = (int)strtoull(&setting_name[10], NULL, 10);
					const int peer_n = set_n(stripped_peer_index,NULL); // XXX do use setting_value, its trash XXX
					pthread_rwlock_wrlock(&mutex_expand_group); // XXX
					if(group[g].peerlist)
						group[g].peerlist = torx_realloc(group[g].peerlist,((size_t)group[g].peercount+1)*sizeof(int));
					else
						group[g].peerlist = torx_insecure_malloc(((size_t)group[g].peercount+1)*sizeof(int));
					group[g].peerlist[group[g].peercount] = peer_n;
					group[g].peercount++; // so, this grows as we load more
				//	printf("Checkpoint sql_populate_setting g==%d peercount==%u\n",g,group[g].peercount);
					pthread_rwlock_unlock(&mutex_expand_group); // XXX
				}
				else
				{ // Send unrecognized settings to UI
					if(peer_index < 0) // prevent potential for deadlock by unpredictable contents of custom_setting_cb
						pthread_rwlock_unlock(&mutex_global_variable);
					const int n = set_n(peer_index,NULL); // XXX WARNING: N could be negative, indicating a global value
					const size_t len = strlen(setting_name);
					char *setting_name_allocated = torx_secure_malloc(len+1);
					snprintf(setting_name_allocated,len+1,"%s",setting_name);
					char *setting_value_allocated = torx_secure_malloc(setting_value_len+1);
					memcpy(setting_value_allocated,setting_value,setting_value_len);
					setting_value_allocated[setting_value_len] = '\0';
					custom_setting_cb(n,setting_name_allocated,setting_value_allocated,setting_value_len,0);
					if(peer_index < 0) // prevent potential for deadlock by unpredictable contents of custom_setting_cb
						pthread_rwlock_rdlock(&mutex_global_variable); // yes rdlock is correct here, because we have no more actions upon it
				}
				if(peer_index < 0) // global variable
					pthread_rwlock_unlock(&mutex_global_variable);
			}
		}
		if(val != SQLITE_DONE)
			error_printf(3, "Can't retrieve data: %s",sqlite3_errmsg(*db));
		sqlite3_finalize(stmt); // XXX: this frees ALL returned data from anything regarding stmt, so be sure it has been copied before this XXX
	}
	pthread_mutex_unlock(mutex);
	if(force_plaintext)
	{
		hash_password();
		pthread_rwlock_rdlock(&mutex_global_variable);
		const char *tor_location_local_pointer = tor_location;
		pthread_rwlock_unlock(&mutex_global_variable);
		if(tor_location_local_pointer && attempt_login)
			login_start("");
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
	char command[strlen(setting_name)+256+2]; // size is somewhat arbitrary
	if(force_plaintext)
		snprintf(command,sizeof(command),"DELETE FROM setting_clear WHERE setting_name = '%s';",setting_name);
	else if(peer_index == -1)
		snprintf(command,sizeof(command),"DELETE FROM setting_global WHERE setting_name = '%s';",setting_name);
	else // encrypted
		snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d AND setting_name = '%s';",peer_index,setting_name);
	int val;
	if(force_plaintext)
		val = sql_exec(&db_plaintext,command,NULL,0);
	else
		val = sql_exec(&db_encrypted,command,NULL,0);
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
	char command[256]; // size is somewhat arbitrary
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // delete all the associated GROUP_PEER messages
		const int g = set_g(n,NULL);
		const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t p = 0; p < g_peercount; p++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int specific_peer = group[g].peerlist[p];
			pthread_rwlock_unlock(&mutex_expand_group);
			const int peer_index_other = getter_int(specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d AND time = %lld AND nstime = %lld;",peer_index_other,(long long)time,(long long)nstime);
			sql_exec(&db_messages,command,NULL,0);
		}
	}
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d AND time = %lld AND nstime = %lld;",peer_index,(long long)time,(long long)nstime);
	return sql_exec(&db_messages,command,NULL,0);
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
	char command[256]; // size is somewhat arbitrary
	const uint8_t owner = getter_uint8(n,INT_MIN,-1,offsetof(struct peer_list,owner));
	if(owner == ENUM_OWNER_GROUP_CTRL)
	{ // delete all the associated GROUP_PEER message history first
		const int g = set_g(n,NULL);
		const uint32_t g_peercount = getter_group_uint32(g,offsetof(struct group_list,peercount));
		for(uint32_t p = 0; p < g_peercount; p++)
		{
			pthread_rwlock_rdlock(&mutex_expand_group);
			const int specific_peer = group[g].peerlist[p];
			pthread_rwlock_unlock(&mutex_expand_group);
			const int peer_index_other = getter_int(specific_peer,INT_MIN,-1,offsetof(struct peer_list,peer_index));
			snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index_other);
			sql_exec(&db_messages,command,NULL,0);
		}
	}
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index);
	return sql_exec(&db_messages,command,NULL,0);
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
	char command[256]; // size is somewhat arbitrary
	snprintf(command,sizeof(command),"DELETE FROM message WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_messages,command,NULL,0);
	snprintf(command,sizeof(command),"DELETE FROM setting_peer WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_encrypted,command,NULL,0);
	snprintf(command,sizeof(command),"DELETE FROM peer WHERE peer_index = %d;",peer_index);
	val = sql_exec(&db_encrypted,command,NULL,0);
	return val;
}
