<img alt="Logo" width="200" height="200" src="https://raw.githubusercontent.com/TorX-Chat/torx-gtk4/main/other/scalable/apps/logo-torx-symbolic.svg" align="right" style="position: relative; top: 0; left: 0;">

### TorX Library (libtorx)
This page is primarily for developers and contributors.
<br>If you are simply looking to download and run TorX, go to [Download](https://torx.chat/#download)
<br>If you want to contribute, see [Contribute](https://torx.chat/#contribute) and our [TODO Lists](https://torx.chat/todo.html)

#### Build Instructions:
##### Linux:
<br>If you want to try on a LiveCD, <a href="https://get.debian.org/images/weekly-live-builds/amd64/iso-hybrid/">here are some suitable liveCDs</a>

###### Install build dependencies:
`sudo apt install git build-essential cmake libsodium-dev libevent-dev libsqlcipher-dev libpng-dev`

###### Install runtime dependencies:
`sudo apt install tor snowflake-client obfs4proxy`

###### Clone the repository
`git clone https://github.com/TorX-Chat/libtorx && cd libtorx`

###### For building TorX for static linking:
`cmake -B build && cd build && make`

###### For building TorX for shared linking:
`cmake -D BUILD_SHARED_LIBS=1 -B build && cd build && make`

###### For building TorX with debug symbols:
`cmake -D CMAKE_BUILD_TYPE=Debug -B build && cd build && make`

###### For installing TorX (after building):
`sudo make install`

###### For uninstalling TorX (after installing):
`sudo xargs rm < install_manifest.txt`

#### Voluntary Contribution Licensing Agreement:
Subject to implicit consent: Ownership of all ideas, suggestions, issues, pull requests, contributions of any kind, etc, are non-exclusively gifted to the original TorX developer without condition nor consideration, for the purpose of improving the software, for the benefit of all users, current and future. Any contributor who chooses not to apply this licensing agreement may make an opt-out statement when making their contribution.
Note: The purpose of this statement is so that TorX can one day be re-licensed as GPLv2, GPLv4, AGPL, MIT, BSD, CC0, etc, in the future, if necessary. If you opt-out, your contributions will need to be stripped if we one day need to re-license and we're unable to contact you for your explicit consent. You may opt-out, but please don't.
