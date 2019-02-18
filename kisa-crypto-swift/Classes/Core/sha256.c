#include <stdlib.h>
#include "sha256.h"
#include <string.h>


#ifdef KISA_WINMO_32
#define PUT64(n) n##ui64
#else
#define PUT64(n) n##ULL
#endif

#define MIN(x, y) ( ((x)<(y))?(x):(y) )

#ifdef KISA_WINMO_32
#define RORc(x, y)    _lrotr((x), (y))
#define ROLc(x, y)    _lrotl((x), (y))
#else
#define ROLc(x, y) ((((unsigned int)(x)<<(unsigned int)((y)&31)) | (((unsigned int)(x)&0xFFFFFFFFU)>>(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFU)
#define RORc(x, y) (((((unsigned int)(x)&0xFFFFFFFFU)>>(unsigned int)((y)&31)) | ((unsigned int)(x)<<(unsigned int)(32-((y)&31)))) & 0xFFFFFFFFU)
#endif

#define OR(x,y)			(x|y)
#define AND(x,y)		(x&y)
#define XOR(x,y)		(x^y)

#define S(x, n)         RORc((x),(n))
#define R(x, n)         ((uint64_t)((x)>>(n)))

#define SHR(x, n)   \
	((((x)>>((uint64_t)((n)&PUT64(63)))) | \
	((x)<<((uint64_t)(64-((n)&PUT64(63)))))))

#define ROTR(x, n)         (((uint64_t))((x)>>n))

#define WORK_VAR(a,b,c,d,e,f,g,h,i)                    \
	t0 = h + (SHR(e, 14) ^ SHR(e, 18) ^ SHR(e, 41)) + F(e, f, g) + K_512[i] + W[i];   \
	t1 = (SHR(a, 28) ^ SHR(a, 34) ^ SHR(a, 39)) + H(a, b, c);                  \
	d += t0; \
	h  = t0 + t1;

#define F(x,y,z)		(XOR(z,(AND(x,(XOR(y,z))))))
#define G(x,y,z)		(XOR(x,XOR(y,z)))
#define H(x,y,z)		(OR(AND(x,y),AND(z,OR(x,y))))

#define SHA256_BLOCK_SIZEx8		512
	
static const uint32_t SHA256_K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};


static int SHA256_compute(KISA_SHA256 *sha256, uint8_t *data);



int KISA_SHA256_init(KISA_SHA256 *sha256) {
	
	if(sha256 == NULL) 
		return 0;
	
	sha256->l1 = 0;
	sha256->l2 = 0;
	sha256->data[0] = 0x6A09E667UL;
	sha256->data[1] = 0xBB67AE85UL;
	sha256->data[2] = 0x3C6EF372UL;
	sha256->data[3] = 0xA54FF53AUL;
	sha256->data[4] = 0x510E527FUL;
	sha256->data[5] = 0x9B05688CUL;
	sha256->data[6] = 0x1F83D9ABUL;
	sha256->data[7] = 0x5BE0CD19UL;

	return 1;
}

int KISA_SHA256_update(KISA_SHA256 *sha256, const uint8_t *data, uint32_t length) {

	uint32_t n;

	if (sha256->l2 > SHA256_BLOCK_SIZE)
		return 0;

	while (length > 0) {
		
		if (!sha256->l2 && length >= SHA256_BLOCK_SIZE) {
			
			if (!(SHA256_compute(sha256, (uint8_t *)data))) 
				return 0;
			
			sha256->l1 += SHA256_BLOCK_SIZEx8;
			data += SHA256_BLOCK_SIZE;
			length -= SHA256_BLOCK_SIZE;

		} else {
			
			n = MIN((SHA256_BLOCK_SIZE - sha256->l2), length);                       
			memcpy(sha256->buf + sha256->l2, data, n);
			data += n;
			sha256->l2 += n;
			length -= n;

			if (sha256->l2 == SHA256_BLOCK_SIZE) {
				if (!(SHA256_compute(sha256, sha256->buf)))
					return 0;

				sha256->l2 = 0;
				sha256->l1 += SHA256_BLOCK_SIZEx8;
			}
		}
	}
	return 1;
}

int KISA_SHA256_final(KISA_SHA256 *sha256, uint8_t *out) {
	
	int i;
	int off = 0;

	if(sha256->l2 >= SHA256_BLOCK_SIZE) 
		return 0;
	

	sha256->l1 += sha256->l2 << 3;
	sha256->buf[sha256->l2++] = (uint8_t)0x80;

	if(sha256->l2 > 56) {
		memset(sha256->buf+sha256->l2, 0, 64 - (sha256->l2));
		sha256->l2 = SHA256_BLOCK_SIZE;
		SHA256_compute(sha256, sha256->buf);
		sha256->l2 = 0;
	}

	while(sha256->l2 < 56)
		sha256->buf[sha256->l2++] = 0;

	sha256->buf[56] = (uint8_t)(sha256->l1>>56); 			
	sha256->buf[57] = (uint8_t)(sha256->l1>>48); 			
	sha256->buf[58] = (uint8_t)(sha256->l1>>40); 		
	sha256->buf[59] = (uint8_t)(sha256->l1>>32); 	
	sha256->buf[60] = (uint8_t)(sha256->l1>>24); 
	sha256->buf[61] = (uint8_t)(sha256->l1>>16); 	
	sha256->buf[62] = (uint8_t)(sha256->l1>>8); 
	sha256->buf[63] = (uint8_t)(sha256->l1); 

	SHA256_compute(sha256, sha256->buf);

	for(i = 0; i < 8; i++) {
		off = i << 2;
		(out+off)[3] = (uint8_t)(sha256->data[i]);
		(out+off)[2] = (uint8_t)(sha256->data[i]>>8);
		(out+off)[1] = (uint8_t)(sha256->data[i]>>16);
		(out+off)[0] = (uint8_t)(sha256->data[i]>>24);
	}
	return 1;
}

static int SHA256_compute(KISA_SHA256 *sha256, uint8_t *data) {
	
	int i;
	uint32_t data_temp[8], W[64];
	uint32_t temp, t1, temp2;
	int off = 0;

	data_temp[0] = sha256->data[0];
	data_temp[1] = sha256->data[1];
	data_temp[2] = sha256->data[2];
	data_temp[3] = sha256->data[3];
	data_temp[4] = sha256->data[4];
	data_temp[5] = sha256->data[5];
	data_temp[6] = sha256->data[6];
	data_temp[7] = sha256->data[7];

	for(i = 0; i < 16; i++) {
		off = i<<2;
		W[i] = (((uint32_t)((data+off)[0]<<24)) | 
			((uint32_t)((data+off)[1]<<16)) | 
			((uint32_t)((data+off)[2]<<8))  | 
			((uint32_t)((data+off)[3]))); 
	}

	for(i = 16; i < 64; i++)
		W[i] = (S(W[i - 2], 17) ^ S(W[i - 2], 19) ^ R(W[i - 2], 10)) + 
		W[i - 7] + (S(W[i - 15], 7) ^ S(W[i - 15], 18) ^ R(W[i - 15], 3)) + W[i - 16];

	for(i = 0; i < 64; ++i) {
		t1 = data_temp[7] + (S(data_temp[4], 6) ^ S(data_temp[4], 11) ^ S(data_temp[4], 25))
			+ F(data_temp[4], data_temp[5], data_temp[6]) + SHA256_K[i] + W[i];
		temp2 = (S(data_temp[0], 2) ^ S(data_temp[0], 13) ^ S(data_temp[0], 22))
			+ H(data_temp[0], data_temp[1], data_temp[2]);
		data_temp[3] += t1;
		data_temp[7] = t1 + temp2;

		temp = data_temp[7]; 
		data_temp[7] = data_temp[6]; 
		data_temp[6] = data_temp[5]; 
		data_temp[5] = data_temp[4]; 
		data_temp[4] = data_temp[3];
		data_temp[3] = data_temp[2]; 
		data_temp[2] = data_temp[1]; 
		data_temp[1] = data_temp[0]; 
		data_temp[0] = temp;
	}  

	sha256->data[0] += data_temp[0];
	sha256->data[1] += data_temp[1];
	sha256->data[2] += data_temp[2];
	sha256->data[3] += data_temp[3];
	sha256->data[4] += data_temp[4];
	sha256->data[5] += data_temp[5];
	sha256->data[6] += data_temp[6];
	sha256->data[7] += data_temp[7];

	return 1;
}

int KISA_SHA256_MD(unsigned char *in, int len, unsigned char *out)
{
	KISA_SHA256 has;
	if(!KISA_SHA256_init(&has))
		return 0;

	if(!KISA_SHA256_update(&has,in,len))
		return 0;

	if(!KISA_SHA256_final(&has,out))
		return 0;

	return SHA256_DIGEST_LENGTH;
}
