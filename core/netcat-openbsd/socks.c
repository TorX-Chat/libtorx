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

void DisableNagle(const evutil_socket_t sendfd)
{ // Might slightly reduce latency. As far as we can see, it is having no effect at all, because the OS or something is still implementing Nagle.
	const int on = 1;
	if(setsockopt(SOCKET_CAST_OUT sendfd, IPPROTO_TCP, TCP_NODELAY, OPTVAL_CAST &on, sizeof(on)) == -1)
	{
		error_simple(0,"Error in DisableNagle setting TCP_NODELAY. Report this.");
		perror("getsockopt");
	}
	const int sndbuf_size = SOCKET_SO_SNDBUF;
	const int recvbuf_size = SOCKET_SO_RCVBUF;
	if(sndbuf_size)
		if(setsockopt(SOCKET_CAST_OUT sendfd, SOL_SOCKET, SO_SNDBUF, OPTVAL_CAST &sndbuf_size, sizeof(sndbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
	if(recvbuf_size)
		if(setsockopt(SOCKET_CAST_OUT sendfd, SOL_SOCKET, SO_RCVBUF, OPTVAL_CAST &recvbuf_size, sizeof(recvbuf_size)) == -1)
		{ // set socket recv buff size (operating system)
			error_simple(0,"Error in DisableNagle setting SO_SNDBUF. Report this.");
			perror("getsockopt");
		}
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

static inline evutil_socket_t socks_establish(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res = {0}, *res0 = {0};
	evutil_socket_t proxyfd = -1;
	const int error = getaddrinfo(host, port, &hints, &res0); // essentially DNS query of TOR_SOCKS_IP
	if(error)
	{
		error_printf(0,"getaddrinfo for host %s port %s: %s",host,port,gai_strerror(error)); // return value is const, cannot be freed, so leave it as is
		return -1;
	}
	uint8_t success = 0;
	for (res = res0; res; res = res->ai_next)
	{ // XXX This for NOT a loop for our purposes because "DNS queries" of TOR_SOCKS_IP return a maximum of one res. There will be no res->ai_next.
		if((proxyfd = SOCKET_CAST_IN socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
		{
			error_simple(0,"socks_establish failed to bind.");
			continue;
		}
		#ifndef WIN32
		{
			const int one = 1;
			setsockopt(SOCKET_CAST_OUT proxyfd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_CAST &one, sizeof(one));
		}
		#endif
		if(timeout_connect(proxyfd, res->ai_addr, res->ai_addrlen) == 0)
		{ // Connected
			success = 1;
			DisableNagle(proxyfd);
			break;
		}
		if(evutil_closesocket(proxyfd) == -1)
			error_simple(0,"Failed to close socket in socks_establish.");
	}
	freeaddrinfo(res0);
	if(success)
		return proxyfd;
	return -1; // NOTE: This occurs when Tor isn't running yet or is being restarted
}

static inline int decode_addrport(const char *host, const char *port, struct sockaddr *addr,const size_t addrlen)
{ // Decode address of TOR_SOCKS_IP
	struct addrinfo hints = {0}, *res = {0};
	hints.ai_family = PF_INET;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_STREAM;
	const int error = getaddrinfo(host, port, &hints, &res); // essentially DNS query of TOR_SOCKS_IP
	if(error)
	{
		error_printf(0,"getaddrinfo for host %s port %s: %s",host,port,gai_strerror(error)); // return value is const, cannot be freed, so leave it as is
		return -1;
	}
	if(addrlen < res->ai_addrlen) 
	{
		freeaddrinfo(res);
		error_simple(0,"decode_addrport internal error: addrlen < res->ai_addrlen");
		return -1;
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

static inline size_t atomicio(const short int pollin_or_pollout,const evutil_socket_t fd,void *_s,const size_t n)
{ // ensure all of data on socket comes through. f==read || f==vwrite
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
	size_t hlen;
	if(!port || strtoll(port, NULL, 10) < 1025)
	{
		error_printf(0,"Attempted socks_connect to invalid port: %s. Report this.",port);
		return -1;
	}
	if(!host || (hlen = strlen(host)) != (56+6))
	{ // includes .onion
		error_simple(0,"Attempted socks_connect to null or invalid host. Should be 62 chars including domain. Report this.");
		return -1;
	}
	char proxyport[6];
	snprintf(proxyport,sizeof(proxyport),"%d",threadsafe_read_uint16(&mutex_global_variable,&tor_socks_port));
	struct addrinfo hints = {0};
	hints.ai_family = PF_INET;
	hints.ai_flags = 0;
	hints.ai_socktype = SOCK_STREAM;
	struct sockaddr_storage addr = {0};
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	if(decode_addrport(TOR_SOCKS_IP, port, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
		error_simple(0,"Proxy port not specified to socks_connect");
		return -1;
	}
	in_port_t serverport = in4->sin_port;
	evutil_socket_t proxyfd;
	if((proxyfd = socks_establish(TOR_SOCKS_IP, proxyport, hints)) < 0)
		return -1;
//	addr.ss_family = 0;
	unsigned char buf[5 + hlen + sizeof(serverport)]; // 5+62+2
	buf[0] = SOCKS_V5;
	buf[1] = 1;
	buf[2] = SOCKS_NOAUTH;
	if(atomicio(POLLOUT, proxyfd, buf, 3) != 3 || atomicio(POLLIN, proxyfd, buf, 2) != 2)
	{
		error_simple(0,"socks_connect read or write failed");
		goto error;
	}
	if(buf[1] == SOCKS_NOMETHOD)
	{
		error_simple(0,"socks_connect authentication failed");
		goto error;
	}
	buf[0] = SOCKS_V5;
	buf[1] = SOCKS_CONNECT;
	buf[2] = 0;
	buf[3] = SOCKS_DOMAIN;
	buf[4] = (unsigned char)hlen; // looks bad but should be ok due to prior check
	memcpy(buf + 5, host, hlen);
	memcpy(buf + 5 + hlen, &serverport, sizeof(serverport));
	if(atomicio(POLLOUT, proxyfd, buf, sizeof(buf)) != sizeof(buf))
	{
		error_simple(0,"socks_connect write failed");
		goto error;
	}
	if(atomicio(POLLIN, proxyfd, buf, 4) != 4 || buf[1] != 0)
	{
		error_simple(5,"Read failed. Could be a 120 second timeout, or Tor has been restarted / shutdown"); // or we attempted a connection before Tor came up.
		goto error;
	}
	if(buf[3] != SOCKS_IPV4)
	{
		error_simple(0, "Connection failed, unsupported address type. This should never occur."); // occured 2024/02/26 when deleting some group peers, occurs 2024/12/27 frequently, occurred 2025/01/16 when doing nothing, then reconnected just fine.
		goto error;
	}
	if(atomicio(POLLIN, proxyfd, buf + 4, 6) != 6)
	{ // Occured on 2024/02/21 when taking down a group peer.
		error_simple(0,"Read failed, this will probably never occur because we don't use ipv6"); // occurred 2025/01/16 when doing nothing, then reconnected just fine.
		goto error;
	}
	return proxyfd;
	error: {}
	if(evutil_closesocket(proxyfd) == -1)
		error_simple(0,"Failed to close socket in socks_connect."); // Might already be closed?
	return -1;
}
