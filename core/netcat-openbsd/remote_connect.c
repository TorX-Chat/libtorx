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
/* Some modifications have been made for integration into the TorX project
 */

/* $OpenBSD: netcat.c,v 1.217 2020/02/12 14:46:36 schwarze Exp $ */
/*
 *Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 *Copyright (c) 2015 Bob Beck.  All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions
 *are met:
 *
 *1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *3. The name of the author may not be used to endorse or promote products
 *  derived from this software without specific prior written permission.
 *
 *THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *Re-written nc(1) for OpenBSD. Original implementation by
 **Hobbit* <hobbit@avian.org>.
 */


static const int Iflag = SOCKET_SO_RCVBUF;	//TorX mod		/* TCP receive buffer size */
static const int Oflag = SOCKET_SO_SNDBUF;	//TorX mod		/* TCP send buffer size */
static const int Sflag = 1;			//TorX mod		/* TCP MD5 signature option */ // unsure if this does anything for us
static const int TCP_MD5SIG_ignore = 1;				// unknown. Default was 0 but seems to work with 1 so lets enable it for lulz https://man.openbsd.org/tcp https://blog.habets.se/2019/11/TCP-MD5.html

static inline void set_common_sockopts(evutil_socket_t proxyfd)
{ // TODO 2024/03/03 SO_RCVBUF/SO_SNDBUF are overwritten by Disable_nagle and set to SOCKET_SO_SNDBUF, so setting them here is pointless.
	const int x = 1;
	if(Sflag)
		if(setsockopt(SOCKET_CAST_OUT proxyfd, IPPROTO_TCP, TCP_MD5SIG_ignore, OPTVAL_CAST &x, sizeof(x)) == -1)
			error_simple(0, "set_common_sockopts() error: non-fatal TCP_MD5SIG error");
	if(Iflag)
		if(setsockopt(SOCKET_CAST_OUT proxyfd, SOL_SOCKET, SO_RCVBUF, OPTVAL_CAST &Iflag, sizeof(Iflag)) == -1)
			error_simple(0, "set_common_sockopts() error: set TCP receive buffer size");
	if(Oflag)
		if(setsockopt(SOCKET_CAST_OUT proxyfd, SOL_SOCKET, SO_SNDBUF, OPTVAL_CAST &Oflag, sizeof(Oflag)) == -1)
			error_simple(0, "set_common_sockopts() error: set TCP send buffer size");
}

static inline int timeout_connect(evutil_socket_t proxyfd, const struct sockaddr *name,const size_t namelen)
{
	#ifdef WIN32
	WSAPOLLFD pfd = {0};
	#else
	struct pollfd pfd = {0};
	#endif
	int optval = 0;
	int ret;
	if((ret = connect(SOCKET_CAST_OUT proxyfd, name, (socklen_t)namelen)) != 0) // && errno == EINPROGRESS
	{
		pfd.fd = SOCKET_CAST_OUT proxyfd;
		pfd.events = POLLOUT;
		#ifdef WIN32
		ret = WSAPoll(&pfd, 1, MESSAGE_TIMEOUT);
		#else
		ret = poll(&pfd, 1, MESSAGE_TIMEOUT);
		#endif
		if(ret == 1)
		{
			socklen_t optlen = sizeof(optval);
			if((ret = getsockopt(SOCKET_CAST_OUT proxyfd, SOL_SOCKET, SO_ERROR, (char *) &optval, &optlen)) == 0) // This occurs on startup with optval == 0, if connections get attempted before sockets are up. Not a big deal. // errno = optval;
				ret = -1; // 2023/08/13 put this instead of ret = optval == 0 ? 0 : -1;
		}
		else if(ret == 0)
		{
			error_simple(0, "timeout_connect error: timeout");
			ret = -1;
		} 
		else
		{
			error_simple(0, "timeout_connect error: poll failed");
			ret = -1;
		}
	}
	return ret;
}

evutil_socket_t remote_connect(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0 = {0};
	evutil_socket_t proxyfd = -1;
	int error = 1;//, save_errno;

	if((error = getaddrinfo(host, port, &hints, &res0)) != 0)
	{ // DNS lookup
		error_printf(0,"getaddrinfo for host %s port %s: %s",host,port,gai_strerror(error)); // return value is const, cannot be freed, so leave it as is
		return -1;
	}

	for (res = res0; res; res = res->ai_next)
	{ // this for NOT a loop
		if((proxyfd = SOCKET_CAST_IN socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
		{
			error_simple(0,"Checkpoint remote_connect failed to bind.");
			continue;
		}
		#ifndef WIN32
		{
			const int one = 1;
			setsockopt(SOCKET_CAST_OUT proxyfd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_CAST &one, sizeof(one));
		}
		#endif
		set_common_sockopts(proxyfd);

		if(timeout_connect(proxyfd, res->ai_addr, res->ai_addrlen) == 0)
			break; // connected!
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 12112");
	}
	freeaddrinfo(res0);
	return proxyfd;
}
