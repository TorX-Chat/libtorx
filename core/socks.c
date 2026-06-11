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

#include "torx_internal.h"

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

int socks_build_tor_sockaddr(struct sockaddr_in *out)
{ // Fill *out for connect()/bufferevent_socket_connect() to Tor's SOCKS port. TOR_SOCKS_IP is an IP literal; no DNS.
	if(!out)
		return -1;
	sodium_memzero(out,sizeof(*out));
	out->sin_family = AF_INET;
	out->sin_port = htobe16(threadsafe_read_uint16(&mutex_global_variable,&tor_socks_port));
	if(evutil_inet_pton(AF_INET,TOR_SOCKS_IP,&out->sin_addr) != 1)
	{
		error_simple(0,"socks_build_tor_sockaddr: evutil_inet_pton failed for TOR_SOCKS_IP. Report this.");
		return -1;
	}
	return 0;
}

size_t socks_build_greeting(unsigned char buf[3])
{
	buf[0] = SOCKS_V5;
	buf[1] = 1;
	buf[2] = SOCKS_NOAUTH;
	return 3;
}

int socks_validate_method(const unsigned char buf[2])
{
	if(buf[0] != SOCKS_V5)
		return -1;
	if(buf[1] == SOCKS_NOMETHOD)
		return -1;
	return 0;
}

size_t socks_build_connect(unsigned char *buf,size_t buflen,const char *host,const char *port)
{ // Build [V5, CONNECT, 0, DOMAIN, hlen, host..., be16(port)] into buf. Returns total bytes written, or 0 on failure.
	if(!buf || !host || !port)
		return 0;
	const size_t hlen = strlen(host);
	if(hlen != (56+6)) // expecting "<56-char-onion>.onion"
	{
		error_simple(0,"socks_build_connect: invalid host length. Report this.");
		return 0;
	}
	const long long portll = strtoll(port,NULL,10);
	if(portll < 1025 || portll > 65535)
	{
		error_printf(0,"socks_build_connect: invalid port: %s. Report this.",port);
		return 0;
	}
	const size_t total = 5 + hlen + sizeof(uint16_t);
	if(buflen < total)
		return 0;
	const uint16_t port_be = htobe16((uint16_t)portll);
	buf[0] = SOCKS_V5;
	buf[1] = SOCKS_CONNECT;
	buf[2] = 0;
	buf[3] = SOCKS_DOMAIN;
	buf[4] = (unsigned char)hlen;
	memcpy(buf + 5,host,hlen);
	memcpy(buf + 5 + hlen,&port_be,sizeof(port_be));
	return total;
}

int socks_validate_reply_header(const unsigned char buf[4])
{
	if(buf[0] != SOCKS_V5)
		return -1;
	if(buf[1] != 0) // 0 == success
		return -1;
	if(buf[3] != SOCKS_IPV4)
		return -1;
	return 0;
}

