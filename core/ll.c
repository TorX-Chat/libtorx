/* TODO:
	Step 1:	Need to provide access to sub-elements of an element

*/

/* XXX
Benefits of linked-list (ie LLTEST)
	OOP/Abstraction benefits
	Currently, mirroring array-of-struct index numbers can't be easily implemented in Flutter for negative numbers.
		Its only not an issue because we don't have t_message in Flutter.
		Note: We could work around it by having a list + a "negative list" where 0 is -1, 1 is -2, etc.
	Elimination of min_i/max_i and associated potential for races
	Eliminates need to manage struct realloc (increase and decrease in size)

Detrements (ie benefits of current array-of-struct)
	Probably 30% re-write of our codebase
	We don't need splicing, except in groups where we already utilize linked lists.
	Deleting messages is currently fairly simple. UI clients need only recognize that p_iter <0 is deleted.
	Will not solve show_log_messages group issue (message times)

*/

/* XXX
How will we handle t_peer, t_file, t_message?
	Without an index number, this is complex.
	Would need a unique message identifier for each message (per peer), then in UI we would have to maintain a list of unique message identifiers, along with whatever else, and would need to constantly iterate through the list.
*/

/* XXX
Message for #C/ChatGPT: Help me find more solutions.

Background: I've got a chat software library, in C. Currently it utilizes an array of struct to store chat messages (say, 50 on startup and then growing every send/receive). If the UI client wants to load additional historical messages after startup, then they get loaded by the library into the array-of-struct with an index of <0, so all messages remain in chronological order within the array-of-struct. The index number of each message is static, so UI clients (can) mirror the index # to store UI related info about each message in their own array of struct (etc).

Now: I'm considering switching to a linked-list instead of array-of-struct, primarily because it will be easier to onload/offload messages from disk, to minimize ram usage (because mobile users), to minimize realloc operations, and for the benefits of OOP/abstraction.

Issue: There will no longer be a static index number for each message, which UI clients currently rely upon.

Solution 1:
	Create a unique message identifier from time/nstime in the library, then in the UI we would have to iterate through a list until finding a match. However, that is inefficient.

Solution 2:
	???
*/