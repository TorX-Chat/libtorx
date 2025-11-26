cmake_minimum_required(VERSION 3.14)

project(torx LANGUAGES C) # removed VERSION 2.0 # because we probably will forget to update it

set(CMAKE_POLICY_VERSION_MINIMUM 3.10)	## Suppresses warnings on Windows

include(GNUInstallDirs)
include(FetchContent)
include(ExternalProject)
set(CMAKE_C_STANDARD 11)
set(CMAKE_TLS_VERIFY TRUE)
# set(CMAKE_BUILD_TYPE Release)
## Double setting because policy CMP0077
option(EVENT__DISABLE_SAMPLES ON)
option(EVENT__DISABLE_OPENSSL ON)
option(EVENT__DISABLE_MBEDTLS ON)
option(EVENT__DISABLE_TESTS ON)
option(EVENT__DISABLE_BENCHMARK ON)
option(SODIUM_DISABLE_TESTS ON)
option(SODIUM_LIBRARY_MINIMAL ON)
option(PNG_TESTS OFF)
set(PNG_TESTS OFF)
set(EVENT__DISABLE_SAMPLES ON)
set(EVENT__DISABLE_OPENSSL ON)
set(EVENT__DISABLE_MBEDTLS ON)
set(EVENT__DISABLE_TESTS ON)
set(EVENT__DISABLE_BENCHMARK ON)
set(SODIUM_DISABLE_TESTS ON)
set(SODIUM_LIBRARY_MINIMAL ON)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

## We should allow some way to override this, https://cmake.org/cmake/help/latest/envvar/CMAKE_BUILD_PARALLEL_LEVEL.html https://cmake.org/cmake/help/latest/module/ProcessorCount.html
include(ProcessorCount)
ProcessorCount(CPU_COUNT)

if(LAN_REPO)
	message(STATUS "${PROJECT_NAME} using LAN repository: ${LAN_REPO}")
	set(REPO_SODIUM "${LAN_REPO}/libsodium.git")
	set(REPO_SSL "${LAN_REPO}/openssl.git")
	set(REPO_ZLIB "${LAN_REPO}/zlib.git")
	set(REPO_SQLCIPHER "${LAN_REPO}/sqlcipher.git")
	set(REPO_EVENT "${LAN_REPO}/libevent.git")
	set(REPO_PNG "${LAN_REPO}/libpng.git")
else()
	message(STATUS "${PROJECT_NAME} using default remote repositories.")
	set(REPO_SODIUM "https://github.com/jedisct1/libsodium")
	set(REPO_SSL "https://github.com/openssl/openssl")
	set(REPO_ZLIB "https://github.com/madler/zlib")
	set(REPO_SQLCIPHER "https://github.com/sqlcipher/sqlcipher")
	set(REPO_EVENT "https://github.com/libevent/libevent.git")
	set(REPO_PNG "https://github.com/glennrp/libpng")
endif()

## START BLOCK: Try to keep this the same in torx-gtk4 and libtorx. XXX It WILL be passed to libtorx, but libtorx also has a default in case of independent build. XXX
	#### C90 crap: -Wvla -Wdeclaration-after-statement
	#### Unimportant: -Waggregate-return
	#### Heavily CPU + RAM + time intensive junk static analyzer that throws mainly "possible null dereference" warnings (requires 9+gb ram): -fanalyzer
	#### other static analyzer binaries: cppcheck clang-tidy
if(NOT DEFINED CMAKE_C_FLAGS OR CMAKE_C_FLAGS STREQUAL "")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug") ## XXX Dev builds can add either of: -fsanitize=thread -fsanitize=address
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=0 -O0")
		if(NOT WIN32)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fsanitize=float-cast-overflow -fsanitize=float-divide-by-zero")
		endif()
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2")
	endif()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fwrapv -mshstk -Wstrict-overflow=5 -Wshadow -Wpedantic -Wcast-qual -Wno-overlength-strings -Wwrite-strings -Wnull-dereference -Wstrict-prototypes -Wstrict-aliasing -Wmissing-prototypes -Wmissing-declarations -fstack-protector-strong -Wconversion -Wformat-security")
	string(FIND ${CMAKE_C_COMPILER} "clang" found_clang)
	if(found_clang GREATER -1)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-align -Weverything -Wno-missing-variable-declarations -Wno-declaration-after-statement -Wno-cast-function-type-strict -Wno-reserved-identifier -Wno-padded -Wno-vla -Wno-used-but-marked-unused -Wno-disabled-macro-expansion -Wno-documentation -Wno-documentation-unknown-command -Wno-double-promotion -Wno-unsafe-buffer-usage -Wno-pre-c11-compat -Wno-switch-enum -Wno-covered-switch-default")
	else() # GCC
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-align=strict -Wformat-signedness") # Dropped -fwhole-program because it caused linking errors when passed to libtorx. Likely responsible for other linking abnormalities.
	endif()
endif()
message(STATUS "${PROJECT_NAME} C_FLAGS being set to: ${CMAKE_C_FLAGS}")
## END BLOCK

## _ARGS taken from https://gitlab.torproject.org/tpo/core/tor/-/issues/33624 _ADDITIONAL are extras to remove bloat
#set(SSL_CONFIG_ARGS shared enable-ec_nistp_64_gcc_128 no-ssl2 no-ssl3 no-dso no-weak-ssl-ciphers no-dtls)
### set(SSL_CONFIG_ADDITIONAL no-asm no-stdio no-tests no-external-tests no-fuzz-libfuzzer no-fuzz-afl) # do more https://security.stackexchange.com/questions/71499/build-only-openssl-crypto
#set(SSL_CONFIG_ADDITIONAL no-asm no-tests no-external-tests no-fuzz-libfuzzer no-fuzz-afl no-comp no-hw no-engine)
# set(SSL_CONFIG_ARGS --debug no-asm no-tests no-libapp no-external-tests no-fuzz-libfuzzer no-fuzz-afl no-comp no-hw no-engine no-dso no-weak-ssl-ciphers no-dtls no-idea no-camellia no-seed no-bf no-cast no-rc2 no-rc4 no-rc5 no-md2 no-md4 no-ecdh no-sock no-ssl2 no-ssl3 no-dsa no-dh no-ec no-ecdsa no-tls1 no-rfc3779 no-whirlpool no-srp no-mdc2 no-ecdh no-engine no-srtp) # -fPIC -fstack-protector-all
set(SSL_CONFIG_ARGS no-legacy no-ssl3 no-weak-ssl-ciphers no-dtls no-dso no-comp no-ec2m no-psk no-srp no-camellia no-idea no-md2 no-md4 no-mdc2 no-rc2 no-rc4 no-rc5 no-rmd160 no-whirlpool no-ui-console no-unit-test no-tests no-external-tests no-fuzz-libfuzzer no-fuzz-afl ) # removed temp: no-asm no-comp no-stdio, removed permanent (tor requires): no-engine no-deprecated. NOTE: some of these might be needed by sqlcipher but not tor.
## XXX XXX REMOVED enable-ec_nistp_64_gcc_128 because it overrides no-comp. It MIGHT BE NECESSARY FOR TOR XXX XXX
if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
	add_definitions(-D__USE_GNU=1) # __USE_GNU is necessary for libevent for android otherwise we get pipe2 issues upon rebuild
	option(EVENT__HAVE_SIGNALFD OFF) # this is not being detected when building... perhaps we need to pass --sysroot if our manual "OFF" is insufficient
	set(EVENT__HAVE_SIGNALFD OFF)
##	set(CLANG_BINARY_PATH $ENV{ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang)
##	set(CLANGPP_BINARY_PATH $ENV{ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++)
	set(ENV{PATH} $ENV{ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$ENV{PATH}) # CRITICALLY IMPORTANT for openssl
#	set(ENV{ANDROID_NDK_ROOT} $ENV{ANDROID_NDK_HOME}) # XXX testing for openssl
	option(CMAKE_PLATFORM_NO_VERSIONED_SONAME TRUE) # WORKS for libevent, not for sodium
	set(CMAKE_PLATFORM_NO_VERSIONED_SONAME TRUE) # 
	if("${ANDROID_ABI}" STREQUAL "arm64-v8a")
		set(SODIUM_BLD_CMD cmake -E env LIBSODIUM_FULL_BUILD=1 NDK_PLATFORM=android-${ANDROID_PLATFORM} ./dist-build/android-armv8-a.sh)
		set(SODIUM_OUT_BIN_DIR libsodium-android-armv8-a+crypto/lib)
		set(SSL_ARCH android-arm64)
		set(SSL_CONFIG_ADDITIONAL enable-ec_nistp_64_gcc_128)
		set(SQLCIPHER_ARCH aarch64-linux-android)
	elseif("${ANDROID_ABI}" STREQUAL "armeabi-v7a")
		set(SODIUM_BLD_CMD cmake -E env LIBSODIUM_FULL_BUILD=1 NDK_PLATFORM=android-${ANDROID_PLATFORM} ./dist-build/android-armv7-a.sh)
		set(SODIUM_OUT_BIN_DIR libsodium-android-armv7-a/lib)
		set(SSL_ARCH android-arm)
		set(SQLCIPHER_ARCH arm-linux-androideabi)
	elseif("${ANDROID_ABI}" STREQUAL "x86")
		set(SODIUM_BLD_CMD cmake -E env LIBSODIUM_FULL_BUILD=1 NDK_PLATFORM=android-${ANDROID_PLATFORM} ./dist-build/android-${ANDROID_ABI}.sh)
		set(SODIUM_OUT_BIN_DIR libsodium-android-i686/lib)
		set(SSL_ARCH android-x86)
		set(SQLCIPHER_ARCH i686-linux-android)
	elseif("${ANDROID_ABI}" STREQUAL "x86_64")
		set(SODIUM_BLD_CMD cmake -E env LIBSODIUM_FULL_BUILD=1 NDK_PLATFORM=android-${ANDROID_PLATFORM} ./dist-build/android-${ANDROID_ABI}.sh)
		set(SODIUM_OUT_BIN_DIR libsodium-android-westmere/lib)
		set(SSL_ARCH android-x86_64)
		set(SSL_CONFIG_ADDITIONAL enable-ec_nistp_64_gcc_128)
		set(SQLCIPHER_ARCH x86_64-linux-android)
	else()
		message("CHECKPOINT: Failed to match any known android arch: ${ANDROID_ABI}")
	endif()
	set(SSL_MAKE_ARGS SHLIB_VERSION_NUMBER= SHLIB_EXT=_1_1.so)

## XXX WORKS but NEED to manually append PATH with ndk tools /bin/ folder (outside of cmake, in the shell that calls it)
	set(SSL_CONFIG_CMD export PATH=$ENV{ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$ENV{PATH} && export CC=${CLANG_BINARY} && export CXX=${CLANGPP_BINARY} && ./Configure ${SSL_ARCH} -D__ANDROID_API__=${ANDROID_PLATFORM} ${SSL_CONFIG_ARGS} ${SSL_CONFIG_ADDITIONAL})
## XXX FAILS due to bug in OpenSSL build for android, where CC= and CXX= are ignored or misused
##	set(SSL_CONFIG_CMD export CC=${CLANG_BINARY} && export CXX=${CLANGPP_BINARY} && ./Configure ${SSL_ARCH} ${SSL_CONFIG_ARGS} ${SSL_CONFIG_ADDITIONAL})
##	set(SSL_CONFIG_CMD export CC=${CLANG_BINARY} && export CXX=${CLANGPP_BINARY} && ./Configure ${SSL_ARCH} -D__ANDROID_API__=${CMAKE_SYSTEM_VERSION} ${SSL_CONFIG_ARGS} ${SSL_CONFIG_ADDITIONAL})
## XXX works static only
#set(SSL_CONFIG_CMD export CC=${CLANG_BINARY_PATH} && export CXX=${CLANGPP_BINARY_PATH} && ./Configure cc ${SSL_CONFIG_ARGS} ${SSL_CONFIG_ADDITIONAL})
	set(SQLCIPHER_CONFIG_CMD export PATH=$ENV{ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$ENV{PATH} && export CC=${CLANG_BINARY} && export CXX=${CLANGPP_BINARY} && ./configure --host=${SQLCIPHER_ARCH} ) # removed --target=${SQLCIPHER_ARCH} --build=${SQLCIPHER_ARCH} because they are wrong and unhelpful
else()
	set(SSL_ARCH linux-x86_64) # TODO do not hardcode this
	set(SODIUM_OUT_BIN_DIR src/libsodium/.libs)
	set(SODIUM_BLD_CMD cmake -E env LIBSODIUM_FULL_BUILD=1 make -j${CPU_COUNT})
	set(SSL_CONFIG_ADDITIONAL enable-ec_nistp_64_gcc_128) # NOTE: only necessary on 64bit
	set(SSL_CONFIG_CMD ./Configure ${SSL_ARCH} ${SSL_CONFIG_ARGS} ${SSL_CONFIG_ADDITIONAL})
	set(SQLCIPHER_CONFIG_CMD ./configure)
endif()

set(SODIUM_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/${SODIUM_OUT_BIN_DIR})
set(Z_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/zlib-download-prefix/src/zlib/)
if(BUILD_SHARED_LIBS)
#	set(enable_shared yes) # might work for libpng
#	set(enable_static no)
	option(PNG_SHARED ON)
	option(PNG_STATIC OFF)
	set(PNG_SHARED ON)
	set(PNG_STATIC OFF)
	option(EVENT__LIBRARY_TYPE SHARED)
	set(EVENT__LIBRARY_TYPE SHARED)
	set(Z_BUILD_BYPRODUCT ${Z_LIB_DIR}/zlib.so)
	set(SODIUM_BUILD_BYPRODUCT ${SODIUM_LIB_DIR}/libsodium.so)
	set(SODIUM_CONFIG_ARGS --disable-static --enable-shared) # XXX NOTE: .a files are still built unless --enable-minimal is passed, but then we get warnings related to crypto_scalarmult_ed25519_base
	if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
		option(EVENT__LIBRARY_TYPE BOTH) # because our tor binary needs static depends
		set(EVENT__LIBRARY_TYPE BOTH) # because our tor binary needs static depends
	else()
		option(EVENT__LIBRARY_TYPE SHARED)
		set(EVENT__LIBRARY_TYPE SHARED)
	endif()
	set(SSL_CONFIG_TYPE shared) # no-static is not available in 1.1.1
	set(SSL_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libssl.so)
	set(CRYPTO_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.so)
	set(SQLCIPHER_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/sqlcipher-download-prefix/src/sqlcipher-download/.libs/libsqlcipher.so)
	if(${CMAKE_SYSTEM_NAME} STREQUAL "Android") # XXX we static link libcrypto to avoid having to include it. We could soft link it if we use libcrypto elsewhere... With Tor, it ssl MUST be statically linked for android (because tor is executable), but for OpenSSL it is optional
		set(SQLCIPHER_CONFIG_ARGS --enable-static=no LDFLAGS=${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.a LIBS=-llog)#--oldincludedir=/tmp )
	else() # TODO we can't get it to build even on linux as .so, for reasons unexplained. give up.
		set(SQLCIPHER_CONFIG_ARGS --enable-static=no LDFLAGS=${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.a ) #causes error, not the only error: LIBS=-llog)
	#	set(SQLCIPHER_CONFIG_ARGS --enable-static=no LDFLAGS=${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.so ) #LDFLAGS=-lcrypto )
	endif()
else()
	option(PNG_SHARED OFF)
	option(PNG_STATIC ON)
	set(PNG_SHARED OFF)
	set(PNG_STATIC ON)
#	set(enable_shared no) # might work for libpng
#	set(enable_static yes)
	set(Z_BUILD_BYPRODUCT ${Z_LIB_DIR}/zlib.a)
	set(SODIUM_BUILD_BYPRODUCT ${SODIUM_LIB_DIR}/libsodium.a)
	set(SODIUM_CONFIG_ARGS --disable-shared --enable-static)
	option(EVENT__LIBRARY_TYPE STATIC)
	set(EVENT__LIBRARY_TYPE STATIC)
	set(SSL_CONFIG_TYPE no-shared) # DO NOT use -static because it disables threads
	set(SSL_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libssl.a )
	set(CRYPTO_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.a)
	set(SQLCIPHER_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/sqlcipher-download-prefix/src/sqlcipher/libsqlcipher.a)
	set(SQLCIPHER_CONFIG_ARGS --enable-shared=no LDFLAGS=${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/libcrypto.a )#--oldincludedir=/tmp ) # link .a from ssl
endif()

add_compile_definitions(SQLITE_HAS_CODEC SECURE_MALLOC)

if(NO_ASYNC_CALLBACKS)
	message(STATUS "${PROJECT_NAME} building with NO_ASYNC_CALLBACKS")
	add_compile_definitions(NO_ASYNC_CALLBACKS) # necessary, not redundant
else()
	set(ASYNC_CALLBACKS_SRC extra/async_callbacks/async.c)
endif()
if(NO_QR_GENERATOR)
	message(STATUS "${PROJECT_NAME} building with NO_QR_GENERATOR")
	add_compile_definitions(NO_QR_GENERATOR) # necessary, not redundant
else()
	set(QR_GENERATOR_SRC extra/qr_generator/torx_qr.c)
endif()
if(NO_AUDIO_CALL)
	message(STATUS "${PROJECT_NAME} building with NO_AUDIO_CALL")
	add_compile_definitions(NO_AUDIO_CALL) # necessary, not redundant
else()
	set(AUDIO_CALL_SRC extra/audio_call/audio_call.c)
endif()
if(NO_STICKERS)
	message(STATUS "${PROJECT_NAME} building with NO_STICKERS")
	add_compile_definitions(NO_STICKERS) # necessary, not redundant
else()
	set(STICKERS_SRC extra/stickers/stickers.c)
endif()
if(NO_FILE_TRANSFER)
	message(STATUS "${PROJECT_NAME} building with NO_FILE_TRANSFER")
	add_compile_definitions(NO_FILE_TRANSFER) # necessary, not redundant
else()
	set(FILE_TRANSFER_SRC extra/file_transfer/file.c)
endif()

add_library(${PROJECT_NAME} core/torx_core.c core/broadcast.c core/sql.c core/client_init.c core/onion_gen.c core/thread_safety.c core/blake3.c core/libevent.c core/serv_init.c core/base32.c core/cpucount.c core/socks.c core/sha3.c core/utf8-validate.c ${ASYNC_CALLBACKS_SRC} ${QR_GENERATOR_SRC} ${AUDIO_CALL_SRC} ${STICKERS_SRC} ${FILE_TRANSFER_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 2.0.36) # Do not set SOVERSION because it will already be set, if unset, to VERSION. Note: SOVERSION will be ignored on Android because CMAKE_PLATFORM_NO_VERSIONED_SONAME=true

if(BUILD_TORX_DEPS)
	include_directories( # These cannot be target_ because they dont exist in time for target_
		PUBLIC
		${CMAKE_CURRENT_BINARY_DIR}/_deps/png-src/
		${CMAKE_CURRENT_BINARY_DIR}/_deps/png-build/
	##	${CMAKE_CURRENT_BINARY_DIR}/_deps/event-src/include
	##	${CMAKE_CURRENT_BINARY_DIR}/_deps/event-build/include
		${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/include
	#	${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/include/crypto
		${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/include
		${CMAKE_CURRENT_BINARY_DIR}/sqlcipher-download-prefix/src/sqlcipher-download/include
	#no	${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/${SODIUM_OUT_BIN_DIR}/include # redundant
		PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/include/sodium
	)
	ExternalProject_Add( # https://asim.ihsan.io/flutter-ffi-libsodium/
		sodium-download # ExternalProject(s) ignores the crosscompile request and ignores the NDK, so we let sodium handle the build, but then we have to link
	##	PREFIX ${CMAKE_BINARY_DIR}/sodium
		BUILD_IN_SOURCE TRUE
		GIT_REPOSITORY ${REPO_SODIUM}
		GIT_TAG stable 		# necessary to choose a release or it wont have ./configure (master has autogen instead)
		UPDATE_COMMAND ""
		PATCH_COMMAND ""
	##	CMAKE_ARGS -DCMAKE_C_STANDARD=11 # not functional
	#	CMAKE_ARGS -D CMAKE_BUILD_TYPE=Release
		CONFIGURE_COMMAND ./autogen.sh -s -f && ./configure ${SODIUM_CONFIG_ARGS} # --disable-pie # ./configure ${EXTRA_CONFIG_OPTIONS_FOR_ANDROID} # --enable-minimal
		BUILD_COMMAND ${SODIUM_BLD_CMD}
	##	INSTALL_COMMAND cp -R ${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/include/sodiu* ${CMAKE_CURRENT_SOURCE_DIR}/include
	##	INSTALL_COMMAND cp -R ${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/include/sodium ${CMAKE_CURRENT_SOURCE_DIR}/include
		INSTALL_COMMAND ""
		BUILD_BYPRODUCTS ${SODIUM_BUILD_BYPRODUCT}
	)
	ExternalProject_Add(
		openssl-download
		GIT_REPOSITORY ${REPO_SSL}
	#	GIT_TAG OpenSSL_1_1_1-stable
		GIT_TAG openssl-3.5.2
		BUILD_IN_SOURCE TRUE
	#	DOWNLOAD_COMMAND git clone ${REPO_SSL} --branch OpenSSL_1_1_1-stable openssl-download ## --depth=1 XXX dual placing, this is to force not building submodules. TODO Enable --depth=1 if using HTTPS.
		DOWNLOAD_COMMAND git clone ${REPO_SSL} --branch openssl-3.5.2 openssl-download ## --depth=1 XXX dual placing, this is to force not building submodules. TODO Enable --depth=1 if using HTTPS.
		UPDATE_COMMAND ""
		CONFIGURE_COMMAND ${SSL_CONFIG_CMD} ${SSL_CONFIG_TYPE}
		BUILD_COMMAND make -j${CPU_COUNT} ${SSL_MAKE_ARGS}
		INSTALL_COMMAND ""
		BUILD_BYPRODUCTS ${SSL_BUILD_BYPRODUCT} ${CRYPTO_BUILD_BYPRODUCT}
	)
	ExternalProject_Add(
		zlib-download
		GIT_REPOSITORY ${REPO_ZLIB}
		GIT_TAG master
		BUILD_IN_SOURCE 1
		UPDATE_COMMAND ""
		CONFIGURE_COMMAND export CC=${CLANG_BINARY_PATH} && export CXX=${CLANGPP_BINARY_PATH} && ./configure
		BUILD_COMMAND make -j${CPU_COUNT}
		INSTALL_COMMAND ""
# 		BUILD_BYPRODUCTS ${Z_BUILD_BYPRODUCT} # first we need to get it to be .so
	)
	set(SQLCIPHER_CFLAGS "-DSQLITE_HAS_CODEC -DSQLCIPHER_CRYPTO_OPENSSL -I${CMAKE_CURRENT_BINARY_DIR}/openssl-download-prefix/src/openssl-download/include")
	ExternalProject_Add(
		sqlcipher-download
		GIT_REPOSITORY ${REPO_SQLCIPHER}
		GIT_TAG v4.5.6 # probably best to use a release. master could risk corruption.
		BUILD_IN_SOURCE TRUE
		UPDATE_COMMAND mkdir -p include/sqlcipher
		CONFIGURE_COMMAND ${SQLCIPHER_CONFIG_CMD} ${SQLCIPHER_CONFIG_ARGS} --with-crypto-lib=none --enable-tempstore=yes CFLAGS=${SQLCIPHER_CFLAGS}
		BUILD_COMMAND make -j${CPU_COUNT}
		INSTALL_COMMAND ${CMAKE_COMMAND} -E make_directory include/sqlcipher && ${CMAKE_COMMAND} -E copy sqlite3.h include/sqlcipher/
	#	INSTALL_COMMAND cp *.h include/sqlcipher/
		BUILD_BYPRODUCTS ${SQLCIPHER_BUILD_BYPRODUCT}
	)
	FetchContent_Declare( # TODO building unnecessary things here like _extra and they get linked
		event
		GIT_REPOSITORY ${REPO_EVENT}
		GIT_TAG master # release-2.2.1-alpha
		UPDATE_DISCONNECTED TRUE
		OVERRIDE_FIND_PACKAGE
	)
	FetchContent_MakeAvailable(event)
	FetchContent_Declare( # TODO set some env variable to define when this should build .a/.so. by default it seems to link .a at late stages and .so at early stages. Bad either way. MUST BE FIXED FOR GTK
		png
		GIT_REPOSITORY ${REPO_PNG}
		GIT_TAG c22ef3b2e342bdfe3140b7e94879996d0e18c95b # DO NOT GO TO MASTER. They broke android builds somewhere after this commit.
		UPDATE_DISCONNECTED TRUE
		OVERRIDE_FIND_PACKAGE
	)
	FetchContent_MakeAvailable(png)
	if(BUILD_SHARED_LIBS) # https://cmake.org/cmake/help/latest/guide/tutorial/Selecting%20Static%20or%20Shared%20Libraries.html
#no use		set(PNG_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/_deps/png-build/libpng16.so)
		add_library(sodium SHARED IMPORTED)
		add_library(openssl SHARED IMPORTED)
		add_library(crypto SHARED IMPORTED)
	#	add_library(png SHARED IMPORTED)
# 		add_library(zlib SHARED IMPORTED)
		add_library(sqlcipher SHARED IMPORTED)
	else()
#no use		set(PNG_BUILD_BYPRODUCT ${CMAKE_CURRENT_BINARY_DIR}/_deps/png-build/libpng16.a)
		add_library(sodium STATIC IMPORTED)
		add_library(openssl STATIC IMPORTED)
		add_library(crypto STATIC IMPORTED)
	#	add_library(png STATIC IMPORTED)
# 		add_library(zlib STATIC IMPORTED)
		add_library(sqlcipher STATIC IMPORTED)
	endif()
	set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${SODIUM_BUILD_BYPRODUCT})
	set_target_properties(openssl PROPERTIES IMPORTED_LOCATION ${SSL_BUILD_BYPRODUCT})
	set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${SSL_BUILD_BYPRODUCT})
#no use	set_target_properties(png PROPERTIES IMPORTED_LOCATION ${PNG_BUILD_BYPRODUCT})
# 	set_target_properties(zlib PROPERTIES IMPORTED_LOCATION ${Z_BUILD_BYPRODUCT})
	set_target_properties(sqlcipher PROPERTIES IMPORTED_LOCATION ${SQLCIPHER_BUILD_BYPRODUCT})
#	if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
#		set_target_properties(png PROPERTIES PREFIX "lib") ## attempt work-around for libpng/commit/70fda1837d5de802ce5f7e04be239192b6a74d92
#	endif()
	add_dependencies(${PROJECT_NAME} sodium sqlcipher) # sqlcipher
	add_dependencies(sodium sodium-download )
# 	add_dependencies(zlib zlib-download )
# 	add_dependencies(openssl-download zlib )
	add_dependencies(crypto openssl-download )
	add_dependencies(openssl openssl-download )
	add_dependencies(sqlcipher sqlcipher-download)
	add_dependencies(sqlcipher-download openssl crypto)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
	include_directories( # These cannot be target_ because they dont exist in time for target_
		PUBLIC
		${CMAKE_CURRENT_BINARY_DIR}/_deps/png-src/
		${CMAKE_CURRENT_BINARY_DIR}/_deps/png-build/
		${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/include
		${CMAKE_CURRENT_BINARY_DIR}/_deps/event-build/include
		${CMAKE_CURRENT_BINARY_DIR}/sqlcipher-download-prefix/src/sqlcipher-download/include
	)
	add_library(event_core SHARED IMPORTED)
	add_library(event_pthreads SHARED IMPORTED)
	add_library(png SHARED IMPORTED)
	add_library(sodium SHARED IMPORTED)
	add_library(sqlcipher SHARED IMPORTED)
	set_target_properties(event_core PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/_deps/event-build/lib/libevent_core-2.2.so)
	set_target_properties(event_pthreads PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/_deps/event-build/lib/libevent_pthreads-2.2.so)
	set_target_properties(png PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/_deps/png-build/libpng16.so)
	set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/sodium-download-prefix/src/sodium-download/src/libsodium/.libs/libsodium.so)
	set_target_properties(sqlcipher PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/sqlcipher-download-prefix/src/sqlcipher-download/.libs/libsqlcipher.so)
else()
	find_package(Sodium REQUIRED)
	find_package(LibEvent REQUIRED COMPONENTS core pthreads)
	find_package(PNG REQUIRED)
	if(BUILD_SHARED_LIBS)
	#	add_library(event SHARED IMPORTED)
		add_library(event_core_shared SHARED IMPORTED)
		add_library(event_pthreads_shared SHARED IMPORTED)
		set_target_properties(event_core_shared PROPERTIES IMPORTED_LOCATION ${LIBEVENT_CORE})
		set_target_properties(event_pthreads_shared PROPERTIES IMPORTED_LOCATION ${LIBEVENT_THREAD})
	else()
	#	add_library(event STATIC IMPORTED)
		add_library(event_core_static STATIC IMPORTED)
		add_library(event_pthreads_static STATIC IMPORTED)
		set_target_properties(event_core_static PROPERTIES IMPORTED_LOCATION ${LIBEVENT_CORE})
		set_target_properties(event_pthreads_static PROPERTIES IMPORTED_LOCATION ${LIBEVENT_THREAD})
	endif()
#	set_target_properties(event PROPERTIES IMPORTED_LOCATION ${LIBEVENT_CORE})
endif()
target_include_directories(
	${PROJECT_NAME}
	PUBLIC ##	SYSTEM # not sure if helpful
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>		# to get torx.h
		$<INSTALL_INTERFACE:include>			# this MIGHT make it work when distributed https://cmake.org/cmake/help/latest/manual/cmake-packages.7.html#creating-relocatable-packages
	PRIVATE
		${PNG_INCLUDE_DIRS}				# probably not useful, i think this is bunk. see include_directories()
##		${CMAKE_CURRENT_BINARY_DIR}/_deps/event-src/include
		${CMAKE_CURRENT_SOURCE_DIR}/core	# Necessary so that audio_call.c can find torx_internal.h
)

if(WIN32)
target_link_libraries(
	${PROJECT_NAME}
	PRIVATE	# Currently, all of these links are meaningless on Windows. The links really only occur when building the UI.
		sodium
	#	event
		event_core
	#	event_pthreads
		png
		sqlcipher
		Ws2_32
)
else()
target_link_libraries(
	${PROJECT_NAME}
	PRIVATE
		sodium
	#	event
		event_core
		event_pthreads
		png
		sqlcipher
)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/include/torx.h)
install(TARGETS ${PROJECT_NAME} COMPONENT RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}) # COMPONENT RUNTIME installs both the PUBLIC_HEADER and RUNTIME appropriately.
