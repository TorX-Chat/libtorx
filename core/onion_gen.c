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
/*
	// TODO any references to ENUM_OWNER_GROUP_PEER can be removed because we no longer use generate_onion for it (we just create a fake string for PK)
		note: do a group handshake first with some debug lines to verify that we never call this with owner == GROUP_PEER

	Regarding migrating to openssl, it is not possible yet: https://github.com/openssl/openssl/issues/13630

	// TODO consider using setpriority(PRIO_PROCESS, 0, 19), but can we do this specific to one pthread?
*/

struct thread_data { // XXX Do not sodium_malloc structs unless they contain sensitive arrays XXX
	size_t suffix_length_local;
	uint32_t thrd_num;
	uint8_t *winner;
	unsigned char *ed25519_pk;
	unsigned char *ed25519_sk;
	unsigned char *expanded_sk;
};
struct serv_strc { // Sodium malloc this struct due to sensitive arrays
	uint8_t owner;
	char privkey[88+1];
	char onion[56+1];
	char *peernick;
	int8_t in_pthread;
};

void generate_onion_simple(char onion[56+1],char privkey[88+1])
{ // Simple utility function.
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES]; // zero'd when sensitive
	unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES]; // zero'd when sensitive
	unsigned char expanded_sk[crypto_hash_sha512_BYTES]; // zero'd when sensitive
	crypto_sign_keypair(ed25519_pk,ed25519_sk);
	char *p;
	if(onion)
	{
		if((p = onion_from_ed25519_pk(ed25519_pk)))
		{
			memcpy(onion,p,56+1);
			torx_free((void*)&p);
		}
	}
	if(privkey)
	{
		crypto_hash_sha512(expanded_sk,ed25519_sk,32);
		expanded_sk[0] &= 248;
		expanded_sk[31] &= 63;
		expanded_sk[31] |= 64;
		if((p = b64_encode(expanded_sk,crypto_hash_sha512_BYTES)))
		{
			memcpy(privkey,p,88+1);
			torx_free((void*)&p);
		}
	}
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	sodium_memzero(expanded_sk,sizeof(expanded_sk));
}

/* static void increment(unsigned char *array,const size_t size)
{ // not using sodium_increment because it does something else. This function is tested and true. XXX do not delete until perfecting Method 2
	for(size_t reverse = 1; reverse <= size; reverse++)
		if(array[size-reverse]++ != UINT8_MAX)
			break;
} */

static void *generate_suffix_ed25519(void *arg)
{  // Base32 encoding function could be replaced with a more efficient one, or with bin2hex BDEF7=(XXXX) (lessor bottleneck)
  // However, on our CPU, single thread, base32 method gets 28,000 per second. Hex gets about 28,000 per second also. Identical speeds.
  // this is 1.1% of the speed of mkp224o on the same hardware. Hypothetically, with optimization, we can shave another character or two off.
/* TODO calling crypto_sign_keypair thousands of times is inefficient. Advanced onion generators do not do this. (MAIN BOTTLENECK)
	Method 2 seems to:
		(a) trigger "Critical private key conversion issue" frequently
		(b) increase speed so dramatically that race conditions occur
*/
	struct thread_data *thread_data = (struct thread_data*) arg; // Casting passed struct
	const size_t suffix_length_local = thread_data->suffix_length_local;
	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES]; // zero'd when sensitive
	unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES]; // zero'd when sensitive
	unsigned char expanded_sk[crypto_hash_sha512_BYTES]; // zero'd when sensitive
	char ed25519_pk_b32[56+1]; // zero'd when sensitive
	size_t len = 0;
//	randombytes_buf(ed25519_sk,sizeof(ed25519_sk)); // XXX METHOD 2 EXCLUSIVE XXX
//	size_t cycles = 0; // TODO cycles remove
//	int time_start = time(NULL); // TODO cycles remove
	do
	{
	//	increment(ed25519_sk,sizeof(ed25519_sk)); // XXX METHOD 2 EXCLUSIVE XXX
	//	crypto_sign_ed25519_sk_to_pk(ed25519_pk,ed25519_sk);  // XXX METHOD 2 EXCLUSIVE XXX
		crypto_sign_keypair(ed25519_pk,ed25519_sk);  // XXX METHOD 1 EXCLUSIVE XXX
		len = base32_encode((unsigned char*)ed25519_pk_b32,ed25519_pk,sizeof(ed25519_pk));
	//	cycles++; // TODO cycles remove
	//	if(cycles % 1000 == 0) // TODO cycles remove
	//		printf("Checkpoint cycles==%lu len==%lu sll=%lu\n",cycles,len,suffix_length_local); // TODO cycles remove
//		if(!strncmp(&ed25519_pk_b32[52-(suffix_length_local-1)],"QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",suffix_length_local-1)) // TODO cycles remove
//			printf("%ld %s\n",cycles,&ed25519_pk_b32[52-suffix_length_local-2]); // TODO cycles remove
		if(*thread_data->winner) // Keep this last // 2022/11/22 getting an invalid read here in some threads. perhaps some threads hit this after this value is free'd?
		{
			torx_free((void*)&arg);
			pthread_exit(NULL);
		}
	}
	while(len != 56 || strncmp(&ed25519_pk_b32[52-suffix_length_local],"QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",suffix_length_local));
	pthread_mutex_lock(&mutex_onion);
	if(*thread_data->winner == 0)
	{
		crypto_hash_sha512(expanded_sk,ed25519_sk,32);
		expanded_sk[0] &= 248;
		expanded_sk[31] &= 63;
		expanded_sk[31] |= 64;
		memcpy(thread_data->ed25519_pk,ed25519_pk,sizeof(ed25519_pk));
		memcpy(thread_data->ed25519_sk,ed25519_sk,sizeof(ed25519_sk));
		memcpy(thread_data->expanded_sk,expanded_sk,sizeof(expanded_sk));
		*thread_data->winner = 1; // STOP OTHER THREADS
//		printf("Checkpoint %d in %ld cycles in %ld seconds\n",suffix_length_local,cycles,time(NULL)-time_start); // TODO cycles remove
		error_printf(5,"Generated: %s",ed25519_pk_b32);
	}
	pthread_mutex_unlock(&mutex_onion);
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
	sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
	sodium_memzero(expanded_sk,sizeof(expanded_sk));
	sodium_memzero(ed25519_pk_b32,sizeof(ed25519_pk_b32));
	torx_free((void*)&arg);
	return 0;
}

void gen_truncated_sha3(unsigned char *truncated_checksum,unsigned char *ed25519_pk)
{
	uint8_t data[48]; // zero'd
	uint8_t digest[32] = {0}; // zero'd
	memcpy(data,".onion checksum",15); // strcpy(string,".onion checksum"); throws a warning on some compilers due to destination not being char*
	for(int i = 0; i < 32; ++i)
		data[15 + i] = ed25519_pk[i]; // 15 is following the ".onion checksum" prefix
	data[47] = 0x03; // adds version byte
	sha3_hash(digest,48,data);
	truncated_checksum[0] = digest[0];
	truncated_checksum[1] = digest[1];
	sodium_memzero(data,sizeof(data));
	sodium_memzero(digest,sizeof(digest));
}

static void *onion_gen(void *arg)
{ // For SING/MULT generation, call with pthread_create. THIS IS A BACKEND FUNCTION ONLY. // Note: TorX-ID length will be [52-suffix_length]
	setcanceltype(TORX_PHTREAD_CANCEL_TYPE,NULL); // TODO not utilized. Need to track then pthread_cleanup_push + pop + thread_kill
	struct serv_strc *serv_strc = (struct serv_strc*) arg; // Casting passed struct
	if((serv_strc->owner == ENUM_OWNER_SING || serv_strc->owner == ENUM_OWNER_MULT) && (serv_strc->peernick == NULL || strlen(serv_strc->peernick) < 1))
	{
		torx_free((void*)&serv_strc->peernick);
		if(default_peernick == NULL)
			error_simple(-1,"Default peernick is null. Coding error. Report this.");
		pthread_rwlock_rdlock(&mutex_global_variable);
		const size_t allocation_len = strlen(default_peernick)+1;
		serv_strc->peernick = torx_secure_malloc(allocation_len);
		snprintf(serv_strc->peernick,allocation_len,"%s",default_peernick);
		pthread_rwlock_unlock(&mutex_global_variable);
	}
	pthread_rwlock_rdlock(&mutex_global_variable);
	size_t suffix_length_local = (size_t)suffix_length;
	const uint8_t local_shorten_torxids = shorten_torxids;
	const uint32_t local_global_threads = global_threads;
	pthread_rwlock_unlock(&mutex_global_variable);
	if(serv_strc->owner == ENUM_OWNER_CTRL || serv_strc->owner == ENUM_OWNER_GROUP_CTRL || local_shorten_torxids == 0) // TODO consider utilizing in_pthread
		suffix_length_local = 0; // this should cause quick returns for CTRL, which we require

	unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES] = {0}; // zero'd
	unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES] = {0}; // zero'd
	unsigned char expanded_sk[crypto_hash_sha512_BYTES] = {0}; // zero'd
	uint32_t threads_local = 0;
	int8_t generating = 0;
	int8_t return_privkey = 0;
	int8_t regenerate = 0;
	while(1)
	{ // not a real loop, just replacing goto
		if(regenerate || strlen(serv_strc->privkey) != 88)
		{
			if(!regenerate) // TODO 2023/07/17 this if might not be necessary, but to comply with the existing logic (since we don't want to do testing right now) we put it for safety
				generating = 1;
	//		regenerate: {}
			uint8_t winner = 0;
			if(serv_strc->owner == ENUM_OWNER_CTRL || serv_strc->owner == ENUM_OWNER_GROUP_CTRL || serv_strc->owner == ENUM_OWNER_GROUP_PEER || local_global_threads < 2 || local_shorten_torxids == 0) // TODO consider utilizing in_pthread
			{
				threads_local = 1;
				struct thread_data *thread_data = torx_insecure_malloc(sizeof(struct thread_data));
				thread_data->suffix_length_local = suffix_length_local;
				thread_data->thrd_num = 1;
				thread_data->winner = &winner;
				thread_data->ed25519_pk = ed25519_pk;
				thread_data->ed25519_sk = ed25519_sk;
				thread_data->expanded_sk = expanded_sk;
				generate_suffix_ed25519((void*)thread_data);
			}
			else
			{
				threads_local = local_global_threads;
				uint32_t running_threads = 0;
				while(running_threads < threads_local)
				{ // We probably need a mutex or something to prevent a race condition where something could return at same time? if that happens, it will fail and regen though
					running_threads++;
					error_printf(4,"Creating thread: %u",running_threads);
					struct thread_data *thread_data = torx_insecure_malloc(sizeof(struct thread_data));
					thread_data->suffix_length_local = suffix_length_local;
					thread_data->thrd_num = running_threads;
					thread_data->winner = &winner;
					thread_data->ed25519_pk = ed25519_pk;
					thread_data->ed25519_sk = ed25519_sk;
					thread_data->expanded_sk = expanded_sk;
					pthread_t thrd; // XXX no need to track these threads because they don't interact with global variables/struct, so no risk of segfault on shutdown
					if(pthread_create(&thrd,&ATTR_DETACHED,&generate_suffix_ed25519,(void*)thread_data))
						error_simple(-1,"Failed to create thread for onion_generation");
				}
				struct timespec tim;
				tim.tv_sec = 0;
				tim.tv_nsec = 50000000L; // 50 ms
				while(!winner)
					nanosleep(&tim, NULL); //  slows down checks to save CPU. effectively sets minimum time for generating len > 0 // TODO XXX should break up onion_gen and use a internal _cb or signal instead
			}
			char *p = b64_encode(expanded_sk,crypto_hash_sha512_BYTES);
			snprintf(serv_strc->privkey,88+1,"%s",p);
			torx_free((void*)&p);
		}
		else // This is if privkey is provided to function. (ex: by custom_input )
		{
			return_privkey = 1;
			if(b64_decode(expanded_sk,sizeof(expanded_sk),serv_strc->privkey) != 64)
			{
				error_simple(0,"Invalid base64 privkey passed to onion_gen(). Bailing out.");
				torx_free((void*)&serv_strc->peernick);
				return 0;
			}
			memcpy(ed25519_sk,expanded_sk,32);
			crypto_scalarmult_ed25519_base(ed25519_pk,ed25519_sk); // XXX the fact that this is being done to custom_input means that hs_ files have already had crypto_hash_sha512() applied to them, meaning the ed25519 SK is FOREVER LOST
		}
		sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
		sodium_memzero(expanded_sk,sizeof(expanded_sk));
		char *p = onion_from_ed25519_pk(ed25519_pk);
		snprintf(serv_strc->onion,56+1,"%s",p);
		torx_free((void*)&p);
		serv_strc->onion[56] = '\0'; // should be unnecessary
		xstrlwr(serv_strc->onion);
		unsigned char x25519_pk[32] = {0}; // zero'd // crypto_scalarmult_curve25519_BYTES
		if(strlen(serv_strc->onion) != 56 || serv_strc->onion[55] != 'd')
		{
			if(generating == 1)
			{ // (OLD COMMENT) this error is caused by us or by our encoder requiring null termination, not a failure of libsodium, ms7821 thinks?
				error_simple(0,"Onion generation failed. Trying again."); // TODO on 2023/05/20, we hit this in a loop real hard
				regenerate = 1;
				continue;
			}
			else
			{
				error_simple(0,"Probably invalid privkey provided to us (could only be caused by not enough bytes/un-decodable base64)."); // goto retry;
				if(serv_strc->in_pthread == 1)
				{
					torx_free((void*)&serv_strc->peernick);
					torx_free((void*)&serv_strc);
				}
				return 0; 
			}
		}
		else if(crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk) < 0)
		{ // this check was implemented due to v3auth keys occassionally coming up short and being invalid for unknown reasons, possibly bad keys, possibly our base32 encoder XXX
			error_simple(0,"Critical private key conversion issue in onion_gen. Trying again.");
			regenerate = 1;
			continue;
		}
		else 
		{
			char ed25519_pk_b32[56+1];
			const size_t len = base32_encode((unsigned char*)ed25519_pk_b32,x25519_pk,32);
			if(len != 56)
			{ // this was implemented due to v3auth keys occassionally coming up short and being invalid for unknown reasons, possibly bad keys, possibly our base32 encoder XXX
				error_printf(0,"Generated key cannot be converted to v3Auth (came up short: %lu). Trying again.",len);
				regenerate = 1;
				continue;
			}
			else
				sodium_memzero(ed25519_pk_b32,sizeof(ed25519_pk_b32));
		}
		sodium_memzero(x25519_pk,sizeof(x25519_pk));
		break;
	}
	sodium_memzero(ed25519_pk,sizeof(ed25519_pk));

	error_printf(3,"Generated onion: %s",serv_strc->onion);
	error_printf(4,"Expanded PrivKey: %s",serv_strc->privkey);

	if(serv_strc->owner == ENUM_OWNER_SING || serv_strc->owner == ENUM_OWNER_MULT || serv_strc->owner == ENUM_OWNER_GROUP_CTRL || serv_strc->owner == ENUM_OWNER_GROUP_PEER)
	{ // We don't automatically load ctrl. We will probably work that in, in the future. We would have to make sure that automatically_accept_mult is on.
		time_t expiration = 0;
		pthread_rwlock_rdlock(&mutex_global_variable);
		if(serv_strc->owner == ENUM_OWNER_SING && sing_expiration_days > 0)
			expiration = (60*60*24*sing_expiration_days+time(NULL));
		else if(serv_strc->owner == ENUM_OWNER_MULT && mult_expiration_days > 0)
			expiration = (60*60*24*mult_expiration_days+time(NULL));
		pthread_rwlock_unlock(&mutex_global_variable);
		int peer_index = sql_insert_peer(serv_strc->owner,ENUM_STATUS_FRIEND,99,serv_strc->privkey,serv_strc->onion,serv_strc->peernick,(int)expiration);
		int n;
		if(serv_strc->owner == ENUM_OWNER_GROUP_CTRL)
		{
//			unsigned char ed25519_pk[crypto_sign_PUBLICKEYBYTES]; // zero'd when sensitive
//			unsigned char ed25519_sk[crypto_sign_SECRETKEYBYTES]; // zero'd when sensitive
			crypto_sign_keypair(ed25519_pk,ed25519_sk);
			n = load_peer_struc(peer_index,serv_strc->owner,ENUM_STATUS_FRIEND,serv_strc->privkey,99,serv_strc->onion,serv_strc->peernick,ed25519_sk,NULL,NULL);
			sodium_memzero(ed25519_pk,sizeof(ed25519_pk));
			sodium_memzero(ed25519_sk,sizeof(ed25519_sk));
			sql_update_peer(n);
		}
		else
			n = load_peer_struc(peer_index,serv_strc->owner,ENUM_STATUS_FRIEND,serv_strc->privkey,99,serv_strc->onion,serv_strc->peernick,NULL,NULL,NULL);
		setter(n,INT_MIN,-1,offsetof(struct peer_list,peer_index),&peer_index,sizeof(peer_index));
		if(!return_privkey && n > -1 && serv_strc->owner != ENUM_OWNER_GROUP_PEER) // sanity check of n returned by load_peer_struc
		{
			load_onion(n);
			if(serv_strc->owner == ENUM_OWNER_SING || serv_strc->owner == ENUM_OWNER_MULT)
				onion_ready_cb(n);
		}
	}
	else if(serv_strc->owner == ENUM_OWNER_CTRL && serv_strc->in_pthread == 0)
	{ //  2023/01/02, new functionality for syncronous use of generate_onion(), not fully tested. some things might be wrong. bad data should later be overwritten when load_onion is called by subsequent process.
	//	int n = 
		load_peer_struc(-1,serv_strc->owner,99,serv_strc->privkey,99,serv_strc->onion,serv_strc->peernick,NULL,NULL,NULL);
	} // XXX NOTE: the 000... is just to beat our sanity check. This may not be an ideal long term solution.
	if(serv_strc->in_pthread == 1)
	{
		torx_free((void*)&serv_strc->peernick);
		torx_free((void*)&serv_strc);
	}
	return 0; // could return n to generate_onion to avoid having to set_n() but thats lower priority
}

int generate_onion(const uint8_t owner,char *privkey,const char *peernick)
{// Privkey doesn't need to be passed unless generating from priv key custom_input(). Generates and saves (only saves if SING/MULT)
/* NOTE: To determine the validity of a privkey, can use b64_decoded_size() rather than this function */
	struct serv_strc *serv_strc = torx_secure_malloc(sizeof(struct serv_strc)); // torx_free((void*)&)'d
	serv_strc->owner = owner;  // just making sure these are null terminated.
	int8_t return_privkey = 0;
	if(privkey != NULL)
	{ // in case it is provided for conversion to onion
		if(owner != ENUM_OWNER_SING && owner != ENUM_OWNER_MULT)
			return_privkey = 1; // we don't return the privkey for generated onions of SING/MULT (this check is to prevent returning on call from custom_input())
		snprintf(serv_strc->privkey,88+1,"%s",privkey);
	}
	else
		sodium_memzero(serv_strc->privkey,88+1);
	sodium_memzero(serv_strc->onion,56+1);
	if(peernick)
	{
		const size_t allocation_len = strlen(peernick)+1;
		serv_strc->peernick = torx_secure_malloc(allocation_len);
		snprintf(serv_strc->peernick,allocation_len,"%s",peernick);
	}
	if((owner == ENUM_OWNER_SING || owner == ENUM_OWNER_MULT) && threadsafe_read_int8(&mutex_global_variable,(int8_t*)&shorten_torxids) == 1 && privkey == NULL) // NOTE: This must be the same as above UID:271231
	{ // Nonblocking operation (relies on callback)
		serv_strc->in_pthread = 1;
		pthread_t thrd_onion_gen; // TODO 2024/03/25 track this thread somehow? questionable utility.
		if(pthread_create(&thrd_onion_gen,&ATTR_DETACHED,&onion_gen,(void*)serv_strc))
			error_simple(-1,"Failed to create thread3");
		return 0;
	}
	else
	{ // Blocking operation
		serv_strc->in_pthread = 0;
		onion_gen(serv_strc);
		if(return_privkey == 1)
			snprintf(privkey,88+1,"%s",serv_strc->privkey);
		torx_free((void*)&serv_strc->peernick);
		if(serv_strc->onion[0] == '\0')
		{ // BAD PRIVKEY, cannot be decoded. Probably passed from custom_input()
			torx_free((void*)&serv_strc); // otherwise free'd in pthread
			return -1;
		}
		const int n = set_n(-1,serv_strc->onion);
		torx_free((void*)&serv_strc); // otherwise free'd in pthread
		return n;
	}
}
