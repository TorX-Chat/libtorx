#define DIGEST 32 // 256-bit digest in bytes.

#define ROUNDS 24 // Number of KECCAK rounds to perform for SHA3-256.
#define WIDTH 200 // 1600-bit width in bytes.
#define RATE 136 // 1600-bit width - 512-bit capacity in bytes.

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

/*** Constants. ***/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
    5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(uint8_t bytes[WIDTH]) {
  uint64_t* a = (uint64_t*)(void*)bytes;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  for (int i = 0; i < 24; i++) {
    // Theta
    FOR5(x, 1,
         b[x] = 0;
         FOR5(y, 5,
              b[x] ^= a[x + y]; ))
    FOR5(x, 1,
         FOR5(y, 5,
              a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
    // Rho and pi
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]];
             a[pi[x]] = rol(t, rho[x]);
             t = b[0];
             x++; )
    // Chi
    FOR5(y,
       5,
       FOR5(x, 1,
            b[x] = a[y + x];)
       FOR5(x, 1,
            a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
    // Iota
    a[0] ^= RC[i];
  }
}

static int absorb(const uint64_t len, const uint8_t data[len], uint8_t bytes[WIDTH]) {
	int absorbed = 0;
	for (uint64_t i = 0; i < len; i++) {
		bytes[absorbed++] ^= data[i];
		if (absorbed == RATE) {
			keccakf(bytes);
			absorbed = 0;
		}
	}
	return absorbed;
}

static void squeeze(uint8_t digest[DIGEST], int padpoint, uint8_t bytes[WIDTH]) {
	bytes[padpoint] ^= 0x06;
	bytes[RATE - 1] ^= 0x80;
	keccakf(bytes);
	for (int i = 0; i < DIGEST; i++) {
		digest[i] = bytes[i];
	}
}

void sha3_hash(uint8_t digest[DIGEST], const uint64_t len, const uint8_t data[len]) {
	uint8_t bytes[WIDTH] = {0};
	int padpoint = absorb(len, data, bytes);
	squeeze(digest, padpoint, bytes);
}
