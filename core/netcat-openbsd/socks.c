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
 *Specifically, anything non-socks5 related was stripped out, and anything
 *that was unnecessary for connecting to .onions was stripped out.
 */

/*	$OpenBSD: socks.c,v 1.30 2019/11/04 17:33:28 millert Exp $	*/
/*
 *Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 *Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions
 *are met:
 *1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
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
/* $OpenBSD: atomicio.c,v 1.11 2012/12/04 02:24:47 deraadt Exp $ */
/*
 *Copyright (c) 2006 Damien Miller. All rights reserved.
 *Copyright (c) 2005 Anil Madhavapeddy. All rights reserved.
 *Copyright (c) 1995,1999 Theo de Raadt.  All rights reserved.
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions
 *are met:
 *1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
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

#define SOCKS_V5	5
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3

//#define vwrite (ssize_t (*)(int, void *, size_t))write

/*
 *Error strings taken almost directly from RFC 1928.
 *//*
static inline const char *socks5_strerror(int e)
{
	switch (e) 
	{
		case 0:
			return "Succeeded";
		case 1:
			return "General SOCKS server failure";
		case 2:
			return "Connection not allowed by ruleset";
		case 3:
			return "Network unreachable";
		case 4:
			return "Host unreachable";
		case 5:
			return "Connection refused";
		case 6:
			return "TTL expired";
		case 7:
			return "Command not supported";
		case 8:
			return "Address type not supported";
		default:
			return "Unknown error";
	}
} */

static inline int decode_addrport(const char *h, const char *p, struct sockaddr *addr,const size_t addrlen,const int numeric)
{
	struct addrinfo hints, *res = {0};
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_STREAM;
	int r = getaddrinfo(h, p, &hints, &res); // DNS lookup
	if(r != 0) 
	{ // Don't fatal when attempting to convert a numeric address
		if(!numeric)
			error_printf(0, "getaddrinfo(%s, %s): %s",h,p,gai_strerror(r)); // return value is const, cannot be freed, so leave it as is
		return -1;
	}
	if(addrlen < res->ai_addrlen) 
	{
		freeaddrinfo(res);
		error_simple(0,"decode_addrport() internal error: addrlen < res->ai_addrlen");
		return -1;
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

/*
 *ensure all of data on socket comes through. f==read || f==vwrite
 */
static inline size_t atomicio(const short int pollin_or_pollout,const evutil_socket_t fd,void *_s,const size_t n)
{
	char *s = _s;
	size_t pos = 0;
	#ifdef WIN32
	WSAPOLLFD pfd = {0};
	#else
	struct pollfd pfd = {0};
	#endif
	pfd.fd = SOCKET_CAST_OUT fd;
	pfd.events = pollin_or_pollout;
	while (n > pos)
	{
		ssize_t res;
		if(pollin_or_pollout == POLLIN)
			res = recv(SOCKET_CAST_OUT fd, s + pos, SOCKET_WRITE_SIZE (n - pos),0);
		else if(pollin_or_pollout == POLLOUT)
			res = send(SOCKET_CAST_OUT fd, s + pos, SOCKET_WRITE_SIZE (n - pos),0);
		else
		{
			error_simple(-1,"Coding error in atomicio. Report this.");
			return 0;
		}
		switch (res)
		{
			case -1:
				#ifdef WIN32
				if (WSAGetLastError() == WSAEINTR)
					continue;
				if ((WSAGetLastError() == WSAEWOULDBLOCK) || (WSAGetLastError() == WSAENOBUFS))
				{
					(void)WSAPoll(&pfd, 1, -1);
					continue;
				}
				#else
				if(errno == EINTR)
					continue;
				if((errno == EAGAIN) || (errno == ENOBUFS))
				{
					(void)poll(&pfd, 1, -1);
					continue;
				}
				#endif
				return 0;
			case 0:
				#ifdef WIN32
				WSASetLastError(WSAESHUTDOWN);
				#else
				errno = EPIPE;
				#endif
				return pos;
			default:
				pos += (size_t)res;
		}
	}
	return pos;
}

evutil_socket_t socks_connect(const char *host, const char *port)
{
	if(!port || strtoll(port, NULL, 10) < 1025)
	{
		error_printf(0,"Attempted socks_connect to invalid port: %s. Report this.",port);
		return -1;
	}
	if(!host || strlen(host) != (56+6))
	{
		error_simple(0,"Attempted socks_connect to null or invalid host. Report this.");
		return -1;
	}
	char proxyport[6];
	pthread_rwlock_rdlock(&mutex_global_variable);
	snprintf(proxyport,sizeof(proxyport),"%d",tor_socks_port);
	pthread_rwlock_unlock(&mutex_global_variable);
	struct addrinfo hints = {0};
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_STREAM;
	struct sockaddr_storage addr = {0};
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	if(decode_addrport("127.0.0.1", port, (struct sockaddr *)&addr, sizeof(addr), 1) == -1)
	{ // TorX Note: Unsure what this does here but it breaks if we remove it. TODO
		error_simple(0,"Proxy port not specified to socks_connect");
		return -1;
	}
	in_port_t serverport = in4->sin_port;
	evutil_socket_t proxyfd;
	if((proxyfd = remote_connect(TOR_CTRL_IP, proxyport, hints)) < 0) // Contains DNS lookup
		return -1;
//	addr.ss_family = 0;
	unsigned char buf[1024] = {0};
	buf[0] = SOCKS_V5;
	buf[1] = 1;
	buf[2] = SOCKS_NOAUTH;
	size_t cnt = atomicio(POLLOUT, proxyfd, buf, 3);
	if(cnt != 3)
	{ // TODO 2023/05 Seems to occur when a tor instance is running but not being killed (ie, after a crash + deletion of pid file) TODO
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 124125"); // 2024/12/25 Occurs frequently on restart of Tor
		else
			error_simple(0,"Bingo. 124125");
		return -1;
	}
	cnt = atomicio(POLLIN, proxyfd, buf, 2);
	if(cnt != 2)
	{
		error_simple(0,"socks_connect error: read failed1");
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 524255");
		return -1;
	}
	if(buf[1] == SOCKS_NOMETHOD)
	{
		error_simple(0,"socks_connect error: authentication failed1");
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 6222125");
		return -1;
	}
	size_t wlen = 0;
	size_t hlen = 0;
	if((hlen = strlen(host)) != 62)
	{
		error_printf(0,"Host name wrong size to be onion: %lu. Should be 62 chars including domain. Something is very wrong.",hlen);
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 52115");
		return -1; // THIS IS BAD.
	}
	buf[0] = SOCKS_V5;
	buf[1] = SOCKS_CONNECT;
	buf[2] = 0;
	buf[3] = SOCKS_DOMAIN;
	buf[4] = (unsigned char)hlen; // looks bad but should be ok due to prior check
	memcpy(buf + 5, host, hlen);
	memcpy(buf + 5 + hlen, &serverport, sizeof serverport);
	wlen = 7 + hlen;
	cnt = atomicio(POLLOUT, proxyfd, buf, wlen);
	if(cnt != wlen)
	{
		error_simple(0,"socks_connect error: write failed2");
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 3526323");
		return -1;
	}
	cnt = atomicio(POLLIN, proxyfd, buf, 4);
	if(cnt != 4 || buf[1] != 0) // XXX XXX THIS TRIGGERS WHEN tor_pid is killed
	{ // All good, we hit this all the time on shutdown
	//	error_simple(0,"Read failed, probably due to tor being killed, or we are starting too fast.");
		if(proxyfd > 0 && evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 142535");
		return -1;
	}
	if(buf[3] == SOCKS_IPV4)
	{
		cnt = atomicio(POLLIN, proxyfd, buf + 4, 6);
		if(cnt != 6)
		{ // Occured on 2024/02/21 when taking down a group peer.
			error_simple(0,"read failed, this will probably never occur because we don't use ipv6"); // occurred 2025/01/16 when doing nothing, then reconnected just fine.
			if(evutil_closesocket(proxyfd) == -1)
				error_simple(0,"Failed to close socket. 95324"); // Occured on 2024/09/28 when repeatedly blocking/unblocking.
			return -1;
		}
	}
	else
	{
		error_simple(0, "Connection failed, unsupported address type. This should never occur."); // occured 2024/02/26 when deleting some group peers, occurs 2024/12/27 frequently, occurred 2025/01/16 when doing nothing, then reconnected just fine.
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket. 841231"); // Occured overnight on 2023/11/02
		return -1;
	}
	return proxyfd;
}
