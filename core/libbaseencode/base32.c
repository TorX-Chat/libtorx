// base32_encode allocates memory that must be freed after calling.
// TODO replace err with simple NULL return checks

#define BITS_PER_BYTE		8
#define BITS_PER_B32_BLOCK	5
// 64 MB should be more than enough
#define MAX_ENCODE_INPUT_LEN	64*1024*1024 // if 64 MB of data is encoded than it should be also possible to decode it. That's why a bigger input is allowed for decoding
#define MAX_DECODE_BASE32_INPUT_LEN ((MAX_ENCODE_INPUT_LEN * 8 + 4) / 5)

static const unsigned char b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// The encoding process represents 40-bit groups of input bits as output strings of 8 encoded characters.
size_t base32_encode(unsigned char *encoded_data,const unsigned char *user_data,const size_t data_len)
{ // DO NOT allocate memory in this function. This function has to be FAST for onion generation.
	if(!encoded_data)
		return 0;
	if(!user_data || data_len == 0 || data_len > MAX_ENCODE_INPUT_LEN)
	{ // this is important
		encoded_data[0] = '\0';
		return 0;
	}

	size_t user_data_chars = data_len;
	size_t total_bits = 8*data_len;
	size_t num_of_equals = 0;

	switch (total_bits % 40)
	{
		case 8:
			num_of_equals = 6;
			break;
		case 16:
			num_of_equals = 4;
			break;
		case 24:
			num_of_equals = 3;
			break;
		case 32:
			num_of_equals = 1;
			break;
		default:
			break;
	}

	size_t output_length = (user_data_chars * 8 + 4) / 5;

	uint64_t first_octet, second_octet, third_octet, fourth_octet, fifth_octet;
	uint64_t quintuple;
	for (size_t i = 0, j = 0; i < user_data_chars;)
	{
		first_octet = i < user_data_chars ? user_data[i++] : 0;
		second_octet = i < user_data_chars ? user_data[i++] : 0;
		third_octet = i < user_data_chars ? user_data[i++] : 0;
		fourth_octet = i < user_data_chars ? user_data[i++] : 0;
		fifth_octet = i < user_data_chars ? user_data[i++] : 0;
		quintuple =
				((first_octet >> 3) << 35) +
				((((first_octet & 0x7) << 2) | (second_octet >> 6)) << 30) +
				(((second_octet & 0x3F) >> 1) << 25) +
				((((second_octet & 0x01) << 4) | (third_octet >> 4)) << 20) +
				((((third_octet & 0xF) << 1) | (fourth_octet >> 7)) << 15) +
				(((fourth_octet & 0x7F) >> 2) << 10) +
				((((fourth_octet & 0x3) << 3) | (fifth_octet >> 5)) << 5) +
				(fifth_octet & 0x1F);

		encoded_data[j++] = b32_alphabet[(quintuple >> 35) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 30) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 25) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 20) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 15) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 10) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 5) & 0x1F];
		encoded_data[j++] = b32_alphabet[(quintuple >> 0) & 0x1F];
	}

	for (size_t i = 0; i < num_of_equals; i++)
		encoded_data[output_length + i] = '=';
	encoded_data[output_length + num_of_equals] = '\0';

	return output_length + num_of_equals; // length of output, less null byte
}

static inline int is_valid_b32_input(const char *user_data, size_t data_len)
{
	size_t found = 0, b32_alphabet_len = sizeof(b32_alphabet);
	for (size_t i = 0; i < data_len; i++)
	{
		if(user_data[i] == '\0')
		{
			found++;
			break;
		}
		for(size_t j = 0; j < b32_alphabet_len; j++)
		{
			if(user_data[i] == b32_alphabet[j] || user_data[i] == '=')
			{
				found++;
				break;
			}
		}
	}
	if(found != data_len)
		return 0;
	else
		return 1;
}

static inline int get_char_index(unsigned char c)
{
	for (int i = 0; i < (int)sizeof(b32_alphabet); i++)
		if(b32_alphabet[i] == c)
			return i;
	return -1;
}

static inline size_t strip_char(char *str,const char strip)
{
	size_t found = 0;
	char *p, *q;
	for (q = p = str; *p; p++)
	{
		if (*p != strip)
			*q++ = *p;
		else
			found++;
	}
	*q = '\0';
	return found;
}

static inline void check_input(const unsigned char *user_data, size_t data_len, size_t max_len, baseencode_error_t *err)
{
	if (user_data == NULL || (data_len == 0 && user_data[0] != '\0'))
	{
		*err = INVALID_INPUT;
		return;
	}
	else if (user_data[0] == '\0')
	{
		*err = EMPTY_STRING;
		return;
	}

	if (data_len > max_len)
	{
		*err = INPUT_TOO_BIG;
		return;
	}

	*err = SUCCESS;
}

unsigned char *base32_decode(const char *user_data_untrimmed, size_t data_len, baseencode_error_t *err)
{ // TODO move this to stack, remove *err, have it return the length
	if(!user_data_untrimmed)
		return NULL;
	baseencode_error_t error;
	check_input((const unsigned char *)user_data_untrimmed, data_len, MAX_DECODE_BASE32_INPUT_LEN, &error);
	if(error != SUCCESS)
	{
		*err = error;
		return NULL;
	}

	char user_data[data_len+1];
	memcpy(user_data,user_data_untrimmed,data_len);
	user_data[data_len] = '\0'; // should be redundant if using sodium_malloc or calloc equiv, or strings

	data_len -= strip_char(user_data, ' ');

	if(!is_valid_b32_input(user_data, data_len))
	{
		*err = INVALID_B32_DATA;
		torx_free((void*)&user_data);
		return NULL;
	}

	double user_data_chars = 0;
	for (size_t i = 0; i < data_len; i++)
	{
		// As it's not known whether data_len is with or without the +1 for the null byte, a manual check is required.
		if(user_data[i] != '=' && user_data[i] != '\0')
			user_data_chars += 1;
	}

	size_t output_length = (size_t)((user_data_chars + 1.6 + 1) / 1.6);  // round up
	unsigned char *decoded_data = torx_secure_malloc(output_length + 1);
	if(decoded_data == NULL)
	{
		*err = MEMORY_ALLOCATION;
		torx_free((void*)&user_data);
		return NULL;
	}

	uint8_t mask = 0, current_byte = 0;
	int bits_left = 8;
	for (size_t i = 0, j = 0; i < (size_t)user_data_chars; i++) {
		int char_index = get_char_index((unsigned char)user_data[i]);
		if(bits_left > BITS_PER_B32_BLOCK) {
			mask = (uint8_t) (char_index << (bits_left - BITS_PER_B32_BLOCK));
			current_byte = (uint8_t) (current_byte | mask);
			bits_left -= BITS_PER_B32_BLOCK;
		} else {
			mask = (uint8_t) (char_index >> (BITS_PER_B32_BLOCK - bits_left));
			current_byte = (uint8_t) (current_byte | mask);
			decoded_data[j++] = current_byte;
			current_byte = (uint8_t) (char_index << (BITS_PER_BYTE - BITS_PER_B32_BLOCK + bits_left));
			bits_left += BITS_PER_BYTE - BITS_PER_B32_BLOCK;
		}
	}
	decoded_data[output_length] = '\0';

	sodium_memzero(user_data,sizeof(user_data));

	*err = SUCCESS;
	return decoded_data;
}
