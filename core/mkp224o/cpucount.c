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
/* From https://github.com/cathugger/mkp224o/blob/master/cpucount.c
cpucount.c is licensed as CC0 by cathugger
*/

#ifndef BSD
#  ifndef __linux__
// FreeBSD
#    ifdef __FreeBSD__
#      undef BSD
#      define BSD
#    endif
// OpenBSD
#    ifdef __OpenBSD__
#      undef BSD
#      define BSD
#    endif
// NetBSD
#    ifdef __NetBSD__
#      undef BSD
#      define BSD
#    endif
// DragonFly
#    ifdef __DragonFly__
#      undef BSD
#      define BSD
#    endif
#  endif // __linux__
// sys/param.h may have its own define
#  ifdef BSD
#    undef BSD
#    include <sys/param.h>
#    define SYS_PARAM_INCLUDED
#    ifndef BSD
#      define BSD
#    endif
#  endif
#endif // BSD

#ifdef BSD
#  ifndef SYS_PARAM_INCLUDED
#    include <sys/param.h>
#  endif
#  include <sys/sysctl.h>
#endif

#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#else
#define UNICODE 1
#include <windows.h>
#endif

#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
static inline int parsecpuinfo(void)
{
	unsigned char cpubitmap[128];

	memset(cpubitmap,0,sizeof(cpubitmap));

	FILE *f = fopen("/proc/cpuinfo","r");
	if (!f)
		return -1;

	char buf[8192];
	while (fgets(buf,sizeof(buf),f)) {
		// we don't like newlines
		for (char *p = buf;*p;++p) {
			if (*p == '\n') {
				*p = 0;
				break;
			}
		}
		// split ':'
		char *v = 0;
		for (char *p = buf;*p;++p) {
			if (*p == ':') {
				*p = 0;
				v = p + 1;
				break;
			}
		}
		// key padding
		size_t kl = strlen(buf);
		while (kl > 0 && (buf[kl - 1] == '\t' || buf[kl - 1] == ' ')) {
			--kl;
			buf[kl] = 0;
		}
		// space before value
		if (v) {
			while (*v && (*v == ' ' || *v == '\t'))
				++v;
		}
		// check what we need
		if (strcasecmp(buf,"processor") == 0 && v) {
			char *endp = 0;
			long n = strtol(v,&endp,10);
			if (endp && endp > v && n >= 0 && (size_t)n < sizeof(cpubitmap) * 8)
				cpubitmap[n / 8] |= (unsigned char)(1 << (n % 8));
		}
	}

	fclose(f);

	// count bits in bitmap
	int ncpu = 0;
	for (size_t n = 0;n < sizeof(cpubitmap) * 8;++n)
		if (cpubitmap[n / 8] & (1 << (n % 8)))
			++ncpu;

	return ncpu;
}
#endif

int cpucount(void)
{
	int ncpu;
#ifdef _SC_NPROCESSORS_ONLN
	ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu > 0)
		return ncpu;
#endif
#ifdef __linux__
	// try parsing /proc/cpuinfo
	// NOTE seems cygwin can provide this too, idk if need tho
	ncpu = parsecpuinfo();
	if (ncpu > 0)
		return ncpu;
#endif
#ifdef BSD
	const int ctlname[2] = {CTL_HW,HW_NCPU};
	size_t ctllen = sizeof(ncpu);
	if (sysctl(ctlname,2,&ncpu,&ctllen,0,0) < 0)
		ncpu = -1;
	if (ncpu > 0)
		return ncpu;
#endif
#ifdef _WIN32
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	ncpu = (int)sysinfo.dwNumberOfProcessors;
	if (ncpu > 0)
		return ncpu;
#endif
	(void) ncpu;
	return -1;
}
