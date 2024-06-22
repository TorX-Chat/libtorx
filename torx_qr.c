//#ifdef QR_GENERATOR	TODO implement this conditional in torx.c and torx.h
/*	 // we can cut our PNG file sizes by about 70% if we get this bitwise operation working right? it seems like with compression libpng already puts us below what bitwise would be
	png_set_IHDR(png, info, width, height, 1, PNG_COLOR_TYPE_GRAY,
		PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

	png_write_info(png, info);

	// Determine rows
	for (int y = 0; y < height; y++) {
		png_byte row[width];
		int bits = 0;
		int bytes = 0;
		for (int x = 0; x < width; x++) {
			if(bits == 8)
				bits = 0; 
			row[bytes] = pixel_array[y *width + x] ? 0x00 << bits : 0xFF << bits;
			bits++;
		}
		png_write_row(png, row);
	} */

static pthread_mutex_t mutex_png_workaround = PTHREAD_MUTEX_INITIALIZER;

static volatile size_t png_size_global = 0; // should not be global, but is ok. has been worked around via mutex_png_workaround

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
	//	printf("Checkpoint qr_bool pixels=%d allocated=%lu\n",pixelIndex,qr_data->size_allocated);
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
//	printf("Checkpoint qr_utf8 allocated=%lu written=%lu\n",allocated,written);
	return result;
}

static inline void png_raw(png_structp png_ptr, png_bytep data, png_size_t length)
{
	void** png_data_ptr = (void**)png_get_io_ptr(png_ptr);
	void* png_data = *png_data_ptr;
	png_size_t new_size = png_size_global + length;
	if(png_data)
		png_data = torx_realloc(png_data,new_size); // NOTE: this can get big because it is uncompressed. One byte per pixel.
	else
		png_data = torx_secure_malloc(new_size);
	memcpy((char*)png_data + png_size_global, data, length);
// printf("Checkpoint png_size: %d new_size: %d\n",png_size_global,new_size);
	png_size_global = new_size;
	*png_data_ptr = png_data;
}

void *return_png(size_t *size_ptr,const struct qr_data *arg)
{
	const struct qr_data *qr_data = (const struct qr_data*) arg; // Casting passed struct
	png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(!png)
		return NULL;
	png_infop info = png_create_info_struct(png);
	if(!info)
	{
		png_destroy_write_struct(&png, NULL);
		return NULL;
	}
	if(setjmp(png_jmpbuf(png)))
	{
		png_destroy_write_struct(&png, &info);
		return NULL;
	}
	void* png_data = NULL;
	png_size_global = 0;
	pthread_mutex_lock(&mutex_png_workaround);
	png_set_write_fn(png, &png_data, png_raw, NULL);
//	png_init_io(png, fp);
	// XXX Note these (png_uint_32) casts aren't ideal but shouldn't matter since we'll never be generating a QR of the size that would matter
	png_set_IHDR(png, info,(png_uint_32)qr_data->width,(png_uint_32)qr_data->height, 8, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);
	png_write_info(png, info);
	for (size_t y = 0; y < qr_data->height; y++)
	{
		png_byte row[qr_data->width];
		for (size_t x = 0; x < qr_data->width; x++)
			row[x] = qr_data->data[y *qr_data->width + x] ? 0xFF : 0x00;
		png_write_row(png, row);
	}
	png_write_end(png, NULL);
	if(size_ptr)
		*size_ptr = png_size_global;
	pthread_mutex_unlock(&mutex_png_workaround);
	return png_data;
// To destroy: 	png_destroy_write_struct(&png, &info);
// To write:	FILE *fp = fopen(filename, "wb");
//		fwrite(png_data,1,png_size_global,fp);
//		fclose(fp);
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

//#endif
