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
#include <stdint.h>
#include <string.h>
#include "blake3.h"

#define CHUNK_START	(1u << 0)
#define CHUNK_END	(1u << 1)
#define PARENT		(1u << 2)
#define ROOT		(1u << 3)

static uint32_t iv[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static void
compress(uint32_t *out, const uint32_t m[static 16], const uint32_t h[static 8], uint64_t t, uint32_t b, uint32_t d)
{
	static const unsigned char s[][16] = {
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
		{3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
		{10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
		{12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
		{9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
		{11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
	};
	uint32_t v[16] = {
		h[0], h[1], h[2], h[3],
		h[4], h[5], h[6], h[7],
		iv[0], iv[1], iv[2], iv[3],
		(uint32_t)t, (uint32_t)(t >> 32), b, d, // XXX bad cast
	};
	unsigned i;

#define G(i, j, a, b, c, d) \
	a = a + b + m[s[i][j * 2]]; \
	d = d ^ a; \
	d = d >> 16 | d << 16; \
	c = c + d; \
	b = b ^ c; \
	b = b >> 12 | b << 20; \
	a = a + b + m[s[i][j * 2 + 1]]; \
	d = d ^ a; \
	d = d >> 8 | d << 24; \
	c = c + d; \
	b = b ^ c; \
	b = b >> 7 | b << 25;

#define ROUND(i) \
	G(i, 0, v[0], v[4], v[8],  v[12]) \
	G(i, 1, v[1], v[5], v[9],  v[13]) \
	G(i, 2, v[2], v[6], v[10], v[14]) \
	G(i, 3, v[3], v[7], v[11], v[15]) \
	G(i, 4, v[0], v[5], v[10], v[15]) \
	G(i, 5, v[1], v[6], v[11], v[12]) \
	G(i, 6, v[2], v[7], v[8],  v[13]) \
	G(i, 7, v[3], v[4], v[9],  v[14])

	ROUND(0) ROUND(1) ROUND(2) ROUND(3)
	ROUND(4) ROUND(5) ROUND(6)

#undef G
#undef ROUND

	if (d & ROOT)
		for (i = 8; i < 16; ++i)
			out[i] = v[i] ^ h[i - 8];
	for (i = 0; i < 8; ++i)
		out[i] = v[i] ^ v[i + 8];
}

#pragma GCC diagnostic push // TODO actually fix this
#pragma GCC diagnostic ignored "-Wstrict-overflow"
static void
load(uint32_t d[static 16], const unsigned char s[static 64]) {
	for (uint32_t *end = d + 16; d < end; ++d, s += 4) {
		*d = (uint32_t)s[0]       | (uint32_t)s[1] <<  8
		   | (uint32_t)s[2] << 16 | (uint32_t)s[3] << 24;
	}
}
#pragma GCC diagnostic pop
/* // TODO possible fix here, untested
static void
load(uint32_t d[static 16], const unsigned char s[static 64]) {
	for (int i = 0; i < 16; ++i) {
		const unsigned char *sp = s + i * 4;
		d[i] = (uint32_t)sp[0] | (uint32_t)sp[1] << 8 |
		(uint32_t)sp[2] << 16 | (uint32_t)sp[3] << 24;
	}
}
*/

static void
block(struct blake3 *ctx, const unsigned char *buf)
{
	uint32_t m[16], flags, *cv = ctx->cv;

	flags = 0;
	switch (ctx->block) {
	case 0:  flags |= CHUNK_START; break;
	case 15: flags |= CHUNK_END;   break;
	}
	load(m, buf);
	compress(cv, m, cv, ctx->chunk, 64, flags);
	if (++ctx->block == 16) {
		ctx->block = 0;
		for (uint64_t t = ++ctx->chunk; (t & 1) == 0; t >>= 1) {
			cv -= 8;
			compress(cv, cv, iv, 0, 64, PARENT);
		}
		cv += 8;
		memcpy(cv, iv, sizeof(iv));
	}
	ctx->cv = cv;
}

void
blake3_init(struct blake3 *ctx)
{
	ctx->bytes = 0;
	ctx->block = 0;
	ctx->chunk = 0;
	ctx->cv = ctx->cv_buf;
	memcpy(ctx->cv, iv, sizeof(iv));
}

void
blake3_update(struct blake3 *ctx, const void *buf, size_t len)
{
	const unsigned char *pos = buf;

	if (ctx->bytes) {
		uint32_t n = 64 - ctx->bytes;
		if (len < n)
			n = (uint32_t)len; // XXX bad cast
		memcpy(ctx->input + ctx->bytes, pos, n);
		pos += n;
		len -= n;
		ctx->bytes += n;
		if (!len)
			return;
		block(ctx, ctx->input);
	}
	for (; len > 64; pos += 64, len -= 64)
		block(ctx, pos);
	ctx->bytes = (uint32_t)len; // XXX bad cast
	memcpy(ctx->input, pos, len);
}

void
blake3_out(struct blake3 *ctx, unsigned char *restrict out, size_t len)
{
	uint32_t flags, b, x, *in, *cv, m[16], root[16];
	x = 0;

	cv = ctx->cv;
	memset(ctx->input + ctx->bytes, 0, 64 - ctx->bytes);
	load(m, ctx->input);
	flags = CHUNK_END;
	if (ctx->block == 0)
		flags |= CHUNK_START;
	if (cv == ctx->cv_buf) {
		b = ctx->bytes;
		in = m;
	} else {
		compress(cv, m, cv, ctx->chunk, ctx->bytes, flags);
		flags = PARENT;
		while ((cv -= 8) != ctx->cv_buf)
			compress(cv, cv, iv, 0, 64, flags);
		b = 64;
		in = cv;
		cv = (uint32_t *)iv;
	}
	flags |= ROOT;
	for (size_t i = 0; i < len; ++i, ++out, x >>= 8) {
		if ((i & 63) == 0)
			compress(root, in, cv, i >> 6, b, flags);
		if ((i & 3) == 0)
			x = root[i >> 2 & 15];
		*out = x & 0xff;
	}
}
/*
int
blake3_test(void)
{
	static const struct {
		size_t len;
		const char hash[65];
	} tests[] = {
		{0,      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
		{1,      "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
		{2,      "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"},
		{3,      "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"},
		{4,      "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"},
		{5,      "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"},
		{6,      "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"},
		{7,      "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"},
		{8,      "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"},
		{63,     "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"},
		{64,     "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"},
		{65,     "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"},
		{127,    "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"},
		{128,    "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"},
		{129,    "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"},
		{1023,   "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
		{1024,   "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
		{1025,   "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
		{2048,   "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
		{2049,   "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"},
		{3072,   "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"},
		{3073,   "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"},
		{4096,   "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"},
		{4097,   "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"},
		{5120,   "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"},
		{5121,   "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"},
		{6144,   "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"},
		{6145,   "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"},
		{7168,   "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"},
		{7169,   "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"},
		{8192,   "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"},
		{8193,   "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"},
		{16384,  "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"},
		{31744,  "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"},
		{102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"},
	};
	static const unsigned char hex[] = "0123456789abcdef";
	struct blake3 ctx;
	unsigned char input[251], hash[32];
	char hash_str[65];
	size_t j, len;
	int fail = 0;

	for (uint8_t i = 0; i < sizeof(input); ++i)
		input[i] = i;
	for (uint8_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		len = tests[i].len;
		printf("test length %zu...", len);
		blake3_init(&ctx);
		for (; len > sizeof(input); len -= sizeof(input))
			blake3_update(&ctx, input, sizeof(input));
		blake3_update(&ctx, input, len);
		blake3_out(&ctx, hash, 32);
		for (j = 0; j < sizeof(hash); ++j) {
			hash_str[j * 2] = (char)hex[hash[j] >> 4];
			hash_str[j * 2 + 1] = (char)hex[hash[j] & 0xf];
		}
		hash_str[64] = 0;
		if (strcmp(hash_str, tests[i].hash) == 0) {
			printf("\tPASS\n");
		} else {
			printf("\tFAIL\n\twant %s\n\tgot  %s\n", tests[i].hash, hash_str);
			++fail;
		}
	}
	return fail;
}
*/
