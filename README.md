<img alt="Logo" width="256" height="256" src="https://raw.githubusercontent.com/TorX-Chat/torx-gtk4/main/other/scalable/apps/logo-torx-symbolic.svg" align="right" style="position: relative; top: 0; left: 0;">

### TorX Library (libtorx)
This page is for developers and contributors. If you are simply looking to download and run TorX, go to [TorX.Chat](https://torx.chat/#download)

#### Build Instructions:
See the proof-of-concept UI clients or help improve our CMakeLists.txt to allow independent building of the library's .so/.dll files.

#### Contribution Agreement:
All ideas, suggestions, issues, pull requests, contributions of any kind, etc, are gifted to the original TorX developer without condition nor consideration, for the purpose of improving the software, for the benefit of all users, current and future.

#### Legacy TODO List (needs review / cleanup)
2024/05/04 Need a red team building malicious or buggy client/library, which will send undersized/oversized messages, spam attacks, etc
<br>2024/03/06 streaming a group message is going to be a message struct bloat issue because, unlike other stream messages, upon outbound send it is not deleted from group_ctrl (the group_ctrl n,i is not zero_i'd). The solution is to somehow track when all the attempts are done (perhaps in message_send) and then zero_i it.
<br>2024/05/06 is --keygen/--key-expiration only for relays? OfflineMasterKey/SigningKeyLifetime
<br>2024/05/06 Takedown_onion must call disconnect_forever in a threadsafe manner. We've tried everything (evbuffer_lock, event_base_once, etc) and can't find a way.
<br>2024/05/03 Consider moving the message size and protocol behind the .message pointer (so we can avoid copying moving message when signing)
<br>2024/04/30 Implement _from_i functions in Gtk/Lib

###### ALL TASKS LAST REVIEWED: 2023/12/03
2023/11/22 (possibly outdated? test in debugger before investing time) illegal reads could result if we have >10 group files, since null checks and other shit may occur on peer[n].file[f].?? of group_peer_n, which won't be allocated. Must prevent null checks on .filename or .size == 0 checks
<br>2023/10/25 Broadcast should be added to queue if checksum (single int) is not in sent list. Queue should take note of how many broadcasts came from each user, and should store an integer hash of each sent broadcast to avoid repitition. It should also be rate limited (random rate, random delays) to avoid facilitating mapping of the network. Broadcast thread should run perpetually if there is anything in the queue, otherwise close. Broadcasts exceeding queue should be discarded? undecided.
<br>2023/07/03 ??? ENUM_GROUP_OFFER_ACCEPT_REPLY always signs / issues an invitation... is this a problem? if ENUM_GROUP_OFFER_ACCEPT_REPLY is utilized during every handshake then its a problem because not just the inviter will sign but everyone... meaning that people can spoof who actually invited them
<br>2023/05/24 file descriptor leaks and limitations. ulimit -n shows we can only have 1024 file descriptors open at once. thats going to limit the potential of group chats. If we get near the limit, we should shed outbound connections and rely on inbound connections (1 per group). except when sending when we would have to open them up again?
<br>2023/??/?? in CMakeLists.txt of libtorx, set(SSL_ARCH linux-x86_64) is hardcoded, except on android. will be issues on *pi, postmarketOS, macbooks, etc
<br>2023/??/?? multiple offers of the same file to the same peer is undefined behavior, especially when changing filename. Test it.
<br>2023/??/?? Bug: load_onions() occurs when restarting Tor, causing a few things to be loaded twice.

###### Threadsafety
2024/02/01 Certain pointers such as peer[n].message[i].message could be subject to race conditions in limited circumstances (ie, if it were to be modified at the same time it is being saved), which is unlikely. The circumstances that could cause this occur where it is passed to a function without wrapping the function in torx_read/torx_unlock. Currently we just pass tmp_message, which is a copy of the message location. The only 100% certain solution is to copy (malloc), but its probably unnecessary, so do nothing for now. (solution: implement getter_string)

###### Security:
2024/04/26 *** HIGHEST PRIORITY: Group PM messages are STILL going to the wrong person sometimes. Cause is unknown. Displays as "fail" with right recipient name, but the wrong person receives it.
<br>2023/??/?? Throughout libevent, we should be careful not to cause reads beyond message length (event_strc->buffer_len)
<br>2023/??/?? Cascade deletion of messages and peer specific settings untested
<br>2023/09/10 Invites need to be one-time-use (they are not) and non-transferrable (i presume they are non-transferrable, but check)

###### Post release:
2024/03/30 man atexit. May be useful. Note: doesn't trigger on signals (ie ctrl + c). Not sure why this would be useful since we handle all exit() calls.
<br>2024/03/30 We don't have library protection against running twice. We implement "running" check in GTK. For now, this is ideal. No reason to change this.
<br>2024/03/29 To reveal 1300+ thread-unsafe reads, remove -Wno-unsafe-buffer-usage
<br>2024/03/25 *** IPHONE/Orbot: We need to re-write tor_call so that all calls are on a single connection and ADD_ONION does not utilize "Detached". See Tor's control-spec.txt. That will enable us to run safely without control_password.
<br>2024/03/24 GROUP FILE TRANSFER Documentation: Outbound uses peer_n fd for disk reads, Inbound uses group_ctrl fd for disk writes. When receiving file request, it appears we store outbound date in the group_peer_n. This needs to be documented/understood. When changing file status in process_pause_cancel, we might need to iterate through the relevant group_peer_n and set their status too? idk if we store status there or only transfer amount.
<br>2024/03/23 broadcast_threaded should ONLY message_send WHEN WE ARE CONNECTED, otherwise it will queue up all our messages and then send them all at once when we get online... totally defeating the purpose of a queue. This is easy to implement for ENUM_OWNER_CTRL (we can just check online status), but harder to implement with GROUP_CTRL.
<br>2024/03/01 !v3auth is NO LONGER CONFIRMED SAFE -- appears to be operating full duplex. If !v3auth, utilize auth pipes. Then we can tear out some legacy code. Need to test with an old tor binary though. 
<br>2024/03/20 If there is any file transfer corruption caused by repeated pauses and restarts, it is due to races on ].fd_out_
<br>2024/03/14 *** When requesting group files (in message_prep currently and select_peer, both), we should request a *random* largest section (+/- 1), rather than the first available one, to help the spread of the file into the network
<br>2024/03/15 If a peer pauses or cancels, or otherwise ignores file requests, some sections may end up unrequested until restart. We are NOT a dedicated file sharing software!
<br>2024/03/11 Utilizing the return of message_insert(), we could permit the modification of messages ... but only group messages, its dumb
<br>2024/03/05 see: sfaoij2309fjfw
<br>2024/02/26 Should probably have a "doing checksum" spinner or something for file transfers, so people don't add more than once
<br>2023/??/?? Tor not dying is a major issue that keeps onions online after crash. Consider the viability of a Tor Killer process that will kill Tor if TorX's PID dies. It could just be a wait() kill() process, being forked from TorX with possession of both Tor and TorX PIDs. This would be useful to ensure that Tor and its hidden services aren't left hanging if TorX crashes or is improperly closed. NOTE: probably better to use just not use detached?
<br>2023/??/?? After a file is cancelled, a peer can keep sending data or re-start sending data and we receive/disgard it. This could be exploited to monitor a peer. Need to somehow notify a peer that such packets are still inbound (or any bunk packets, for that matter)
<br>2023/??/?? 2023/06/13 search for ]; and ] = { then ensure zero'd
<br>2023/??/?? Multi-Device / Blinded keys. Use the nonce method to generate blinded keys. Do it using onion_gen.c Upload it using HSPOST. See src/feature/hs/hs_common.c for creation of blinded keys. See any mentions of "blind" "period" "time" in the src. I think HSPOST is somehow combined with ADD_ONION to publish? Unsure and will need to ask #tor-dev
<br>2023/??/?? accept_automatically. Can either be a toggle or a size slider. size_t is probably most logical. Could have a list of accepted filetypes too. NOTE: Enabling this option will require a check for a default download directory. Also, this option should could be DANGEROUS for insecure platforms like Windows/OSX/iOS/Android, where CSAM scanning exists.
<br>2023/??/?? 2023/10/18 We can't support uint64_t file sizes because ftell/fseek only support long int. Unsure what to do about this. It affects our file transfer protocols. Tried ftello/fseeko with no change???
<br>2023/??/?? Implement killcode handling options (Delete or Disable options). Disable should 'Block' and MUST change the priv/onion/peeronion to some fakes, but retain message data and name.
<br>2023/??/?? Sodium memory management overhead -- Check for compile-time flags that could disable the wasted pages except on debug builds. sodium_malloc() wastes too much memory by allocating 4kb of space. This should be a togglable option, or perhaps we only utilize sodium_malloc() for password, .onions, and privkeys. If doing so, perhaps make it toggleable with a wrapper around malloc/free HAVE_PAGE_PROTECTION http://10.8.88.11/libsodium.git/tree/src/libsodium/sodium/utils.c .... what we should really do is make a custom malloc that will put the size then return [location+2] or whatever is right after the size, with zero'd space or at least one null terminating byte.
<br>2023/11/09 use timezone info to determine default torrc? (this could really be a UI thing, though we do have the censored_region variable in lib)
<br>2023/08/16 implement run_binary with optional STDIN string, for verify_config (requires stdin), which, hash_password, get_tor_version, etc
<br>2023/08/10 for GROUP_PEER, .message and .message_len could be double pointer + pointer, respectively. unsure if viable and how we would re-structure our message struct for that. this can be ignored for now so long as we aren't having bugs.
<br>2023/??/?? ENUM_PROPOSE_UPGRADE is an untested message type, i believe. Removing support for legacy tor might be worth considering, or enabling auth pipes for full duplex support
<br>2023/??/?? file_init() calculates a checksum every time it offers a file. We have modification time now but we don't use it for anything.
<br>2023/??/?? Seems like old file descriptors get closed. If nothing is written in a long time, fd might get closed. Do we have any long-term fd?
<br>2023/??/?? atoi() should be replaced by something that doesn't suck such as strtol (arg, NULL, 10);, but that returns 64 bit int. it sends invalid input to null and returns 0 if bad input.
<br>2024/03/01 consider replacing fork() exec() with posix_spawn(). Note: Cannot replace with thread, execl replaces the parent process, so it doesnt waste memory and cant be used on pthreads

###### Minor ideas, perhaps dumb, low priority (post release considerations):
2023/??/?? Hash is written to disk in plaintext for our .split file, perhaps we should encrypt or salt + rehash it (not all hashes, just this hash written to .split file). The reason we don't is because the file itself is written next to it, so what is the security in having the hash salted? We do attempt to securely delete .split files
<br>2023/10/25 is_valid_b32_input( and b64_isvalidchar( in conjunction can determine whether a string is peer/group/trash, for use with 'Search' or invalid input when adding peer
<br>2023/10/25 consider having UTF8 validator shift forward over any non-utf8 bytes, for use in libevent.c and perhaps message_send (to avoid sql issues), rather than discarding whole messages
<br>2023/10/30 if a split_folder exists, files inside should be labelled via truncated checksum rather than filename
<br>2023/10/26 *** Requesting a 1 byte file in full duplex causes an integer overflow / request of a 18446744073709551615 byte file, causing offerer to crash *** Need a sanity check that requests are not > file size
<br>2023/10/25 Public Groups could hypothetically also be shortened in length (pointless), or allow external generation (pointless)
<br>2023/09/05 Add a counter or bunch of counters that increment every time a malloc occurs, so we can know how many leaks we got. (and optionally in what areas)
