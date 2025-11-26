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

/* XXX This is ONLY for single-threaded front-end UIs that can't handle async callbacks from other threads because it requires constant polling XXX
 *	What it does:
 *	It aims to put callback results in a buffer for UI to poll (~60 times per second, or whatever phone frame rate is)
 *	Events MUST be returned by cb_buffer() IN ORDER to the UI or bad things WILL occur.
 *	TODO Remember to free passed void *in UI

XXX WARNING: If the function signature changes, ie different data types are being returned, change the ENUM_ value to a new unused random echo $((RANDOM % 256)) for safety XXX
*/

static int8_t async_callbacks_initialized = 0;

static pthread_mutex_t mutex_set_c = PTHREAD_MUTEX_INITIALIZER;

#define size_cb_info 100000 // arbitrary, should never get anywhere near this number. If it does, things will be lost, which could cause overflows in UI (ex: if struct is not expanded)

static volatile int pending = 0; // is wrapped in mutex_set_c to prevent data races and other such

static void (*async_notifier_registered)(void) = NULL;

struct cb_info cb_info[size_cb_info] = {0};

void initialize_n_cb_async(const int n);
void initialize_i_cb_async(const int n,const int i);
void initialize_g_cb_async(const int g);
void shrinkage_cb_async(const int n,const int shrinkage);
void expand_message_struc_cb_async(const int n,const int i);
void expand_peer_struc_cb_async(const int n);
void expand_group_struc_cb_async(const int g);
void change_password_cb_async(const int value);
void incoming_friend_request_cb_async(const int n);
void onion_deleted_cb_async(const uint8_t owner,const int n);
void peer_online_cb_async(const int n);
void peer_offline_cb_async(const int n);
void peer_new_cb_async(const int n);
void onion_ready_cb_async(const int n);
void tor_log_cb_async(char *message);
void error_cb_async(char *error_message);
void fatal_cb_async(char *error_message);
void stream_cb_async(const int n,const int p_iter,char *data,const uint32_t len);
void custom_setting_cb_async(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext);
void login_cb_async(const int value);
void cleanup_cb_async(const int sig_num);
void message_new_cb_async(const int n,const int i);
void message_modified_cb_async(const int n,const int i);
void message_deleted_cb_async(const int n,const int i);
void peer_loaded_cb_async(const int n);
void message_extra_cb_async(const int n,const int i,unsigned char *data,const uint32_t data_len);
void message_more_cb_async(const int loaded,int *loaded_array_n,int *loaded_array_i);
void unknown_cb_async(const int n,const uint16_t protocol,char *data,const uint32_t len);
#ifndef NO_FILE_TRANSFER
void initialize_f_cb_async(const int n,const int f);
void expand_file_struc_cb_async(const int n,const int f);
void transfer_progress_cb_async(const int n,const int f,const uint64_t transferred);
#endif // NO_FILE_TRANSFER
#ifndef NO_AUDIO_CALL
void initialize_peer_call_cb_async(const int call_n,const int call_c);
void expand_call_struc_cb_async(const int call_n,const int call_c);
void call_update_cb_async(const int call_n,const int call_c);
void audio_cache_add_cb_async(const int participant_n);
#endif // NO_AUDIO_CALL

static inline void async_notifier_setter(void (*callback)(void))
{ // Could integrate into intitialize_async_callbacks
	if(async_notifier_registered == NULL || IS_ANDROID) // refuse to set twice, for security, except on android because their lifecycle requires re-setting after .detach
		async_notifier_registered = callback;
}

void intitialize_async_callbacks(void (*callback)(void))
{ // Can put anything specific that needs to be initialized here // Function is safe to run multiple times
	if(async_callbacks_initialized == 0)
	{ // Utilizing setter functions instead of direct setting (ex: stream_registered = stream_cb_async;) for typechecking
		initialize_n_setter(initialize_n_cb_async);
		initialize_i_setter(initialize_i_cb_async);
		initialize_g_setter(initialize_g_cb_async);
		shrinkage_setter(shrinkage_cb_async);
		expand_message_struc_setter(expand_message_struc_cb_async);
		expand_peer_struc_setter(expand_peer_struc_cb_async);
		expand_group_struc_setter(expand_group_struc_cb_async);
		change_password_setter(change_password_cb_async);
		incoming_friend_request_setter(incoming_friend_request_cb_async);
		onion_deleted_setter(onion_deleted_cb_async);
		peer_online_setter(peer_online_cb_async);
		peer_offline_setter(peer_offline_cb_async);
		peer_new_setter(peer_new_cb_async);
		onion_ready_setter(onion_ready_cb_async);
		tor_log_setter(tor_log_cb_async);
		error_setter(error_cb_async);
		fatal_setter(fatal_cb_async);
		stream_setter(stream_cb_async);
		custom_setting_setter(custom_setting_cb_async);
		login_setter(login_cb_async);
		cleanup_setter(cleanup_cb_async);
		message_new_setter(message_new_cb_async);
		message_modified_setter(message_modified_cb_async);
		message_deleted_setter(message_deleted_cb_async);
		peer_loaded_setter(peer_loaded_cb_async);
		message_extra_setter(message_extra_cb_async);
		message_more_setter(message_more_cb_async);
		unknown_setter(unknown_cb_async);
		#ifndef NO_FILE_TRANSFER
		initialize_f_setter(initialize_f_cb_async);
		expand_file_struc_setter(expand_file_struc_cb_async);
		transfer_progress_setter(transfer_progress_cb_async);
		#endif // NO_FILE_TRANSFER
		#ifndef NO_AUDIO_CALL
		initialize_peer_call_setter(initialize_peer_call_cb_async);
		expand_call_struc_setter(expand_call_struc_cb_async);
		audio_cache_add_setter(audio_cache_add_cb_async);
		call_update_setter(call_update_cb_async);
		#endif // NO_AUDIO_CALL
		if(callback)
			async_notifier_setter(callback);
	}
	async_callbacks_initialized = 1;
}

void *cb_buffer(void) // Remember to torx_free((void*)arg) and any pointers within
{ // Returns pointer to next dataset ready for handling ( called by UI )
	pthread_mutex_lock(&mutex_set_c);
	if(pending == 0)
	{
		pthread_mutex_unlock(&mutex_set_c);
		return NULL;
	}
	int c = 0;
	while(c < size_cb_info && cb_info[c].cb_args == NULL) // oldest will be first
		c++;
	if(cb_info[c].cb_args)
	{
		pending--;
		struct cb_info *cb_page = torx_insecure_malloc(sizeof(struct cb_info));
		cb_page->cb_type = cb_info[c].cb_type;
		cb_page->cb_args = cb_info[c].cb_args; // struct callback_args
		cb_info[c].cb_type = 0; // Remove from struct
		cb_info[c].cb_args = NULL; // Remove from struct
		pthread_mutex_unlock(&mutex_set_c);
		return cb_page; // XXX remember to free
	}
	else
	{
		pthread_mutex_unlock(&mutex_set_c);
		error_simple(0,"Hit error in cb_buffer, possibly caused by insufficient mutex. Report this.");
		return NULL; // nothing to process. this is an error, should not occur
	}
}

static inline void queue_callback(const uint8_t cb_type,struct callback_args *cb_args)
{ // Set c for writing. XXX DO NOT USE ERROR_ IN THIS FUNCTION or it will start eternal loop
	int c = 0;
	pthread_mutex_lock(&mutex_set_c);
	for(int found = 0; c < size_cb_info && (cb_info[c].cb_args != NULL || found < pending); c++)
	{ // find first open space, after all pending
		if(cb_info[c].cb_args != NULL)
			found++;
	}
	if(c != size_cb_info) // if it was equal, it would be bad. Would result in lost callback info.
	{
		cb_info[c].cb_type = cb_type;
		cb_info[c].cb_args = cb_args;
		pending++;
	}
	pthread_mutex_unlock(&mutex_set_c);
	if(async_notifier_registered)
		async_notifier_registered();
}

#ifndef NO_FILE_TRANSFER
void initialize_f_cb_async(const int n,const int f)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_a = f;
	queue_callback(ENUM_INITIALIZE_F,struct_p);
}

void expand_file_struc_cb_async(const int n,const int f)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = f;
	queue_callback(ENUM_EXPAND_FILE_STRUC,struct_p);
}

void transfer_progress_cb_async(const int n,const int f,const uint64_t transferred)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = f;
	struct_p->mem_uint64 = transferred;
	queue_callback(ENUM_TRANSFER_PROGRESS,struct_p);
}
#endif // NO_FILE_TRANSFER

#ifndef NO_AUDIO_CALL
void initialize_peer_call_cb_async(const int call_n,const int call_c)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = call_n;
	struct_p->mem_int_b = call_c;
	queue_callback(ENUM_INITIALIZE_PEER_CALL,struct_p);
}

void expand_call_struc_cb_async(const int call_n,const int call_c)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = call_n;
	struct_p->mem_int_b = call_c;
	queue_callback(ENUM_EXPAND_CALL_STRUC,struct_p);
}

void call_update_cb_async(const int call_n,const int call_c)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = call_n;
	struct_p->mem_int_b = call_c;
	queue_callback(ENUM_CALL_UPDATE,struct_p);
}

void audio_cache_add_cb_async(const int participant_n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = participant_n;
	queue_callback(ENUM_AUDIO_CACHE_ADD,struct_p);
}
#endif // NO_AUDIO_CALL

void initialize_n_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_INITIALIZE_N,struct_p);
}

void initialize_i_cb_async(const int n,const int i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	queue_callback(ENUM_INITIALIZE_I,struct_p);
}

void initialize_g_cb_async(const int g)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = g;
	queue_callback(ENUM_INITIALIZE_G,struct_p);
}

void shrinkage_cb_async(const int n,const int shrinkage)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = shrinkage;
	queue_callback(ENUM_SHRINKAGE,struct_p);
}

void expand_message_struc_cb_async(const int n,const int i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	queue_callback(ENUM_EXPAND_MESSAGE_STRUC,struct_p);
}

void expand_peer_struc_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_EXPAND_PEER_STRUC,struct_p);
}

void expand_group_struc_cb_async(const int g)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = g;
	queue_callback(ENUM_EXPAND_GROUP_STRUC,struct_p);
}

void change_password_cb_async(const int value)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = value;
	queue_callback(ENUM_CHANGE_PASSWORD,struct_p);
}

void incoming_friend_request_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_INCOMING_FRIEND_REQUEST,struct_p);
}

void onion_deleted_cb_async(const uint8_t owner,const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_uint8 = owner;
	struct_p->mem_int_a = n;
	queue_callback(ENUM_ONION_DELETED,struct_p);
}

void peer_online_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_PEER_ONLINE,struct_p);
}

void peer_offline_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_PEER_OFFLINE,struct_p);
}

void peer_new_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_PEER_NEW,struct_p);
}

void onion_ready_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_ONION_READY,struct_p);
}

void tor_log_cb_async(char *message)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_charp_a = message;
	queue_callback(ENUM_TOR_LOG,struct_p);
}

void error_cb_async(char *error_message)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_charp_a = error_message;
	queue_callback(ENUM_ERROR,struct_p);
}

void fatal_cb_async(char *error_message)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_charp_a = error_message;
	queue_callback(ENUM_FATAL,struct_p);
}

void stream_cb_async(const int n,const int p_iter,char *data,const uint32_t len)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = p_iter;
	struct_p->mem_charp_a = data;
	struct_p->mem_uint32 = len;
	queue_callback(ENUM_STREAM,struct_p);
}

void custom_setting_cb_async(const int n,char *setting_name,char *setting_value,const size_t setting_value_len,const int plaintext)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_charp_a = setting_name;
	struct_p->mem_charp_b = setting_value;
	struct_p->mem_size = setting_value_len;
	struct_p->mem_int_b = plaintext;
	queue_callback(ENUM_CUSTOM_SETTING,struct_p);
}

void login_cb_async(const int value)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = value;
	queue_callback(ENUM_LOGIN,struct_p);
}

void cleanup_cb_async(const int sig_num)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = sig_num;
	queue_callback(ENUM_CLEANUP,struct_p);
}

void message_new_cb_async(const int n,const int i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	queue_callback(ENUM_MESSAGE_NEW,struct_p);
}

void message_modified_cb_async(const int n,const int i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	queue_callback(ENUM_MESSAGE_MODIFIED,struct_p);
}

void message_deleted_cb_async(const int n,const int i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	queue_callback(ENUM_MESSAGE_DELETED,struct_p);
}

void peer_loaded_cb_async(const int n)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	queue_callback(ENUM_PEER_LOADED,struct_p);
}

void message_extra_cb_async(const int n,const int i,unsigned char *data,const uint32_t data_len)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_int_b = i;
	struct_p->mem_ucharp = data;
	struct_p->mem_uint32 = data_len;
	queue_callback(ENUM_MESSAGE_EXTRA,struct_p);
}

void message_more_cb_async(const int loaded,int *loaded_array_n,int *loaded_array_i)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = loaded;
	struct_p->mem_intp_a = loaded_array_n;
	struct_p->mem_intp_b = loaded_array_i;
	queue_callback(ENUM_MESSAGE_MORE,struct_p);
}

void unknown_cb_async(const int n,const uint16_t protocol,char *data,const uint32_t len)
{
	struct callback_args *struct_p = torx_insecure_malloc(sizeof(struct callback_args));
	struct_p->mem_int_a = n;
	struct_p->mem_uint16 = protocol;
	struct_p->mem_charp_a = data;
	struct_p->mem_uint32 = len;
	queue_callback(ENUM_UNKNOWN,struct_p);
}
