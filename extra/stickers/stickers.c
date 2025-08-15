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

static inline int8_t sticker_invalid(const int s)
{ // Sanity check
	int8_t ret = 0;
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	if(s < 0 || (uint32_t)s >= torx_allocation_len(sticker)/sizeof(struct sticker_list))
		ret = -1;
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	return ret;
}

int set_s(const unsigned char checksum[CHECKSUM_BIN_LEN])
{ // Formerly called ui_sticker_set
	if(!checksum)
	{
		error_simple(0,"Null passed to set_sticker. Coding error. Report this.");
		breakpoint();
		return -1;
	}
	int s = 0;
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	while((uint32_t)s < torx_allocation_len(sticker)/sizeof(struct sticker_list) && memcmp(sticker[s].checksum,checksum,CHECKSUM_BIN_LEN))
		s++;
	if((uint32_t)s == torx_allocation_len(sticker)/sizeof(struct sticker_list))
		s = -1; // Sticker not found.
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	return s;
}

void sticker_save(const int s)
{
	if(sticker_invalid(s))
		return;
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	if(sticker[s].saved || !sticker[s].data)
	{
		pthread_rwlock_unlock(&mutex_sticker); // 🟩
		error_simple(0,"Cannot save sticker. Already saved or no data exists. Coding error. Report this.");
		breakpoint();
		return;
	}
	unsigned char* data_copy = torx_copy(NULL,sticker[s].data); // copying rather than wrapping sql_setting with a mutex
	char *encoded = b64_encode(sticker[s].checksum,sizeof(sticker[s].checksum));
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	char setting_name[256];
	snprintf(setting_name,sizeof(setting_name),"sticker-gif-%s",encoded);
	torx_free((void*)&encoded);
	sql_setting(0,-1,setting_name,(const char*)data_copy,torx_allocation_len(data_copy));
	sodium_memzero(setting_name,sizeof(setting_name));
	torx_free((void*)&data_copy);
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥
	sticker[s].saved = 1;
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
}

void sticker_delete(const int s)
{
	if(sticker_invalid(s))
		return;
	char setting_name[256];
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	char *encoded = b64_encode(sticker[s].checksum,sizeof(sticker[s].checksum));
	snprintf(setting_name,sizeof(setting_name),"sticker-gif-%s",encoded);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	torx_free((void*)&encoded);
	sql_delete_setting(0,-1,setting_name);
	sodium_memzero(setting_name,sizeof(setting_name));
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥
	torx_free((void*)&sticker[s].data);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
}

int sticker_register(const unsigned char *data,const size_t data_len)
{ // Run on startup (remember to set .saved=1) and when receiving new sticker data. Will not save sticker automatically.
	unsigned char checksum[CHECKSUM_BIN_LEN];
	if(!data || !data_len || b3sum_bin(checksum,NULL,data,0,data_len) != data_len)
	{
		sodium_memzero(checksum,sizeof(checksum));
		return -1; // bug
	}
	int s = 0;
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥
	while((uint32_t)s < torx_allocation_len(sticker)/sizeof(struct sticker_list) && memcmp(sticker[s].checksum,checksum,CHECKSUM_BIN_LEN))
		s++;
	if((uint32_t)s == torx_allocation_len(sticker)/sizeof(struct sticker_list))
	{ // Register new sticker
		if(sticker)
			sticker = torx_realloc(sticker,torx_allocation_len(sticker) + sizeof(struct sticker_list));
		else
			sticker = torx_secure_malloc(sizeof(struct sticker_list));
		memcpy(sticker[s].checksum,checksum,sizeof(checksum));
		sticker[s].data = torx_secure_malloc(data_len);
		memcpy(sticker[s].data,data,data_len);
		sticker[s].peers = NULL; // should be already initialized
		sticker[s].saved = 0; // should be already initialized TODO must subsequently set if we just loaded from disk
	}
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	sodium_memzero(checksum,sizeof(checksum));
	if(threadsafe_read_uint8(&mutex_global_variable,&stickers_offload_all))
		sticker_offload(s);
	return s;
}

uint8_t sticker_retrieve_saved(const int s)
{ // UI helper function. TODO Consider returning instead from sticker_retrieve_data (as a uint8_t*).
	if(sticker_invalid(s))
		return 0;
	uint8_t saved;
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	saved = sticker[s].saved;
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	return saved;
}

char *sticker_retrieve_checksum(const int s)
{ // UI helper function, size will always be CHECKSUM_BIN_LEN or 0 in case of error
	if(sticker_invalid(s))
		return NULL;
	char *checksum = torx_secure_malloc(CHECKSUM_BIN_LEN);
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	memcpy(checksum,sticker[s].checksum,CHECKSUM_BIN_LEN);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	return checksum;
}

unsigned char *sticker_retrieve_data(size_t *len_p,const int s)
{ // First check if we already loaded it, then retrieve if from SQL if we don't. UI should follow this call with a call to sticker_offload if it don't desire library to cache, or set stickers_offload_all=1.
	if(sticker_invalid(s))
	{
		error_simple(0,"Unable to retrieve invalid sticker");
		if(len_p)
			*len_p = 0;
		return NULL;
	}
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	if(!sticker[s].data)
	{ // Load from SQL
		char *p = b64_encode(sticker[s].checksum,CHECKSUM_BIN_LEN);
		pthread_rwlock_unlock(&mutex_sticker); // 🟩
		char query[256]; // somewhat arbitrary size
		snprintf(query,sizeof(query),"sticker-gif-%s",p);
		torx_free((void*)&p);
		unsigned char *setting_value = sql_retrieve(NULL,0,query);
		sodium_memzero(query,sizeof(query));
		pthread_rwlock_wrlock(&mutex_sticker); // 🟥
		sticker[s].data = setting_value;
	}
	const size_t len = torx_allocation_len(sticker[s].data);
	unsigned char *data_copy = torx_secure_malloc(len);
	memcpy(data_copy,sticker[s].data,len);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	if(threadsafe_read_uint8(&mutex_global_variable,&stickers_offload_all))
		sticker_offload(s);
	if(len_p)
		*len_p = len;
	return data_copy;
}

uint32_t sticker_retrieve_count(void)
{
	uint32_t count;
	pthread_rwlock_rdlock(&mutex_sticker); // 🟧
	count = torx_allocation_len(sticker)/sizeof(struct sticker_list);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
	return count;
}

void sticker_offload(const int s)
{ // Does not clear checksum, does not clear peers list.
	if(sticker_invalid(s))
	{
		error_simple(0,"Unable to offload invalid sticker");
		return;
	}
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥
	torx_free((void*)&sticker[s].data);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
}

void sticker_offload_saved(void)
{ // Rapidly offload all saved stickers. Useful to save RAM when minimizing or going to the background.
	pthread_rwlock_wrlock(&mutex_sticker); // 🟥
	for(uint32_t s = 0; s < torx_allocation_len(sticker)/sizeof(struct sticker_list); s++)
		if(sticker[s].saved)
			torx_free((void*)&sticker[s].data);
	pthread_rwlock_unlock(&mutex_sticker); // 🟩
}
