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

#include "torx_internal.h"
#include <zlib.h>
#include "qrcodegen.h"
#include "qrcodegen.c"

struct qr_data *qr_bool(const char *text,const size_t multiplier)
{
	if(!text)
	{
		error_simple(0,"Called qr_bool() for NULL text. Coding error. Report this.");
		return NULL;
	}
	size_t height,width = 0;
	enum qrcodegen_Ecc errCorLvl = qrcodegen_Ecc_LOW;  // Error correction level
	// Make and print the QR Code symbol
	uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
	uint8_t tempBuffer[qrcodegen_BUFFER_LEN_MAX];
	bool ok = qrcodegen_encodeText(text, tempBuffer, qrcode, errCorLvl,
		qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);
	sodium_memzero(tempBuffer,sizeof(tempBuffer));
	if(ok)
	{ // Print QR code as UTF8 blocks
		int size = qrcodegen_getSize(qrcode);
		int border = 1;
		height = width = multiplier *(size_t)(border*2 + size);
		struct qr_data *qr_data = torx_secure_malloc(sizeof(struct qr_data));
		qr_data->size_allocated = height*width+1; // +1 might not be necessary here
		bool *pixels = torx_secure_malloc(qr_data->size_allocated); // verified correct allocation though not sure we need the +1 for nullptr
		int pixelIndex = 0;
		for (int y = -border; y < size + border; y++)
			for (size_t j = 0; j < multiplier; j++)
				for (int x = -border; x < size + border; x++)
					for (size_t i = 0; i < multiplier; i++) // expands width
						pixels[pixelIndex++] = (qrcodegen_getModule(qrcode, x, y) ? 0 : 1); // 1 is black, 0 is white
	//	error_printf(0,"Checkpoint qr_bool pixels=%d allocated=%lu",pixelIndex,qr_data->size_allocated);
		qr_data->data = pixels;
		qr_data->height = height;
		qr_data->width = width;
		qr_data->multiplier = multiplier;
		sodium_memzero(qrcode,sizeof(qrcode));
		return qr_data;
	}
	sodium_memzero(qrcode,sizeof(qrcode));
	return NULL;
}

char *qr_utf8(const struct qr_data *arg)
{
	const struct qr_data *qr_data = (const struct qr_data*) arg; // Casting passed struct
	if(!qr_data->height)
		return NULL;
	const size_t allocated = qr_data->multiplier*qr_data->multiplier*((sizeof("⬛")-1)*(qr_data->height*qr_data->width)+(qr_data->height)+1);
	char *result = torx_secure_malloc(allocated); 
	size_t written = 0;
	const size_t character_size = sizeof("⬜")-1; // no need the null terminator
	for (size_t y = 0; y < qr_data->height; y++)
	{
		for (size_t x = 0; x < qr_data->width; x++)
		{
			qr_data->data[y *qr_data->width + x] ? memcpy(&result[written],"⬜",character_size) : memcpy(&result[written],"⬛",character_size) ;
			written += character_size;
		}
		result[written++] = '\n';
	}
	result[written] = '\0';
//	error_printf(0,"Checkpoint qr_utf8 allocated=%lu written=%lu",allocated,written);
	return result;
}

static inline void put_chunk(uint8_t *out, size_t *pos, const char *type, const uint8_t *data, size_t len)
{ // append one PNG chunk: length, type, data, CRC(type+data)
	uint32_t trash = htobe32((uint32_t)len);
	memcpy(out + *pos,&trash,sizeof(trash));
	*pos += 4;
	memcpy(out + *pos, type, 4);
	*pos += 4;
	if(len)
	{
		memcpy(out + *pos, data, len);
		*pos += len;
	}
	uLong crc = crc32(0L, (const uint8_t *)type, 4);
	if(len)
		crc = crc32(crc, data, (uInt)len);
	trash = htobe32((uint32_t)crc);
	memcpy(out + *pos, &trash, sizeof(trash));
	*pos += 4;
}

void *return_png(const struct qr_data *qr_data)
{
	// Build the raw image in 1-bit grayscale, sample 0 = black and 1 = white.
	const size_t rowbytes = (qr_data->width + 7) / 8;
	const size_t raw_len = (size_t)qr_data->height * (1 + rowbytes);
	uint8_t *raw = torx_secure_malloc(raw_len); // NOTE: Requires a malloc that zeros after allocation
	for(size_t y = 0; y < qr_data->height; y++)
	{
		uint8_t *row = raw + (size_t)y * (1 + rowbytes);
		for(size_t x = 0; x < qr_data->width; x++)
			if(qr_data->data[y * qr_data->width + x])
				row[1 + (x >> 3)] |= (uint8_t)(0x80 >> (x & 7));
	}
	// Compress with zlib. compress2() emits a complete zlib stream
	uLongf zl = compressBound(raw_len);
	uint8_t *compressed = torx_secure_malloc(zl);
	if(compress2(compressed, &zl, raw, raw_len, Z_BEST_COMPRESSION) != Z_OK)
	{
		torx_free((void*)&compressed);
		torx_free((void*)&raw);
		return NULL;
	}
	// Append signature, IHDR, IDAT, IEND into one big output buffer. 8-byte signature + (12-byte chunk overhead each) + payloads, with plenty of slack so we never have to grow it.
	uint8_t *out = torx_secure_malloc(8 + 3 * 12 + 13 + zl);
	static const uint8_t sig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
	memcpy(out, sig, 8);
	const uint8_t ihdr[13] = {
		(qr_data->width >> 24) & 0xff, (qr_data->width >> 16) & 0xff, (qr_data->width >> 8) & 0xff, qr_data->width & 0xff,
		(qr_data->height >> 24) & 0xff, (qr_data->height >> 16) & 0xff, (qr_data->height >> 8) & 0xff, qr_data->height & 0xff,
		1, /* bit depth */
		0, /* color type : 0 = grayscale */
		0, /* compression : 0 = deflate */
		0, /* filter : 0 = adaptive */
		0 /* interlace : 0 = none */
	};
	size_t pos = 8; // since we already appended sig
	put_chunk(out, &pos, "IHDR", ihdr, sizeof(ihdr));
	put_chunk(out, &pos, "IDAT", compressed, zl);
	put_chunk(out, &pos, "IEND", NULL, 0);

	torx_free((void*)&raw);
	torx_free((void*)&compressed);
	return out; // holds `pos` bytes of finished PNG.
}

size_t write_bytes(const char *filename,const void *png_data,const size_t length)
{ /* This will TRUNCATE any file. It is only intended as a helper function for saving a small QR Code */ // NOTE: Could write these bytes direcly in flutter. Search .asTypedList for how to get bytes to something usable with a writeToFile function that works with ByteData (which is lists of Uint8)
	if(!length)
		return 0;
	FILE *fp = fopen(filename, "wb");
	if(!fp)
		return 0;
	const size_t bytes_written = fwrite(png_data,1,length,fp);
	fclose(fp); fp = NULL;
	return bytes_written;
}
