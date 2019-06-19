#include <stdio.h>
#include <time.h>
#include "hightcbc.h"
#include <string.h>

unsigned char F0[256] = {
		0, 134, 13, 139, 26, 156, 23, 145, 52, 178, 57, 191, 46, 168, 35, 165, 
		104, 238, 101, 227, 114, 244, 127, 249, 92, 218, 81, 215, 70, 192, 75, 205, 
		208, 86, 221, 91, 202, 76, 199, 65, 228, 98, 233, 111, 254, 120, 243, 117, 
		184, 62, 181, 51, 162, 36, 175, 41, 140, 10, 129, 7, 150, 16, 155, 29, 
		161, 39, 172, 42, 187, 61, 182, 48, 149, 19, 152, 30, 143, 9, 130, 4, 
		201, 79, 196, 66, 211, 85, 222, 88, 253, 123, 240, 118, 231, 97, 234, 108, 
		113, 247, 124, 250, 107, 237, 102, 224, 69, 195, 72, 206, 95, 217, 82, 212, 
		25, 159, 20, 146, 3, 133, 14, 136, 45, 171, 32, 166, 55, 177, 58, 188, 
		67, 197, 78, 200, 89, 223, 84, 210, 119, 241, 122, 252, 109, 235, 96, 230, 
		43, 173, 38, 160, 49, 183, 60, 186, 31, 153, 18, 148, 5, 131, 8, 142, 
		147, 21, 158, 24, 137, 15, 132, 2, 167, 33, 170, 44, 189, 59, 176, 54, 
		251, 125, 246, 112, 225, 103, 236, 106, 207, 73, 194, 68, 213, 83, 216, 94, 
		226, 100, 239, 105, 248, 126, 245, 115, 214, 80, 219, 93, 204, 74, 193, 71, 
		138, 12, 135, 1, 144, 22, 157, 27, 190, 56, 179, 53, 164, 34, 169, 47, 
		50, 180, 63, 185, 40, 174, 37, 163, 6, 128, 11, 141, 28, 154, 17, 151, 
		90, 220, 87, 209, 64, 198, 77, 203, 110, 232, 99, 229, 116, 242, 121, 255};

unsigned char F1[256] = {
		0, 88, 176, 232, 97, 57, 209, 137, 194, 154, 114, 42, 163, 251, 19, 75, 
		133, 221, 53, 109, 228, 188, 84, 12, 71, 31, 247, 175, 38, 126, 150, 206, 
		11, 83, 187, 227, 106, 50, 218, 130, 201, 145, 121, 33, 168, 240, 24, 64, 
		142, 214, 62, 102, 239, 183, 95, 7, 76, 20, 252, 164, 45, 117, 157, 197, 
		22, 78, 166, 254, 119, 47, 199, 159, 212, 140, 100, 60, 181, 237, 5, 93, 
		147, 203, 35, 123, 242, 170, 66, 26, 81, 9, 225, 185, 48, 104, 128, 216, 
		29, 69, 173, 245, 124, 36, 204, 148, 223, 135, 111, 55, 190, 230, 14, 86, 
		152, 192, 40, 112, 249, 161, 73, 17, 90, 2, 234, 178, 59, 99, 139, 211, 
		44, 116, 156, 196, 77, 21, 253, 165, 238, 182, 94, 6, 143, 215, 63, 103, 
		169, 241, 25, 65, 200, 144, 120, 32, 107, 51, 219, 131, 10, 82, 186, 226, 
		39, 127, 151, 207, 70, 30, 246, 174, 229, 189, 85, 13, 132, 220, 52, 108, 
		162, 250, 18, 74, 195, 155, 115, 43, 96, 56, 208, 136, 1, 89, 177, 233, 
		58, 98, 138, 210, 91, 3, 235, 179, 248, 160, 72, 16, 153, 193, 41, 113, 
		191, 231, 15, 87, 222, 134, 110, 54, 125, 37, 205, 149, 28, 68, 172, 244, 
		49, 105, 129, 217, 80, 8, 224, 184, 243, 171, 67, 27, 146, 202, 34, 122, 
		180, 236, 4, 92, 213, 141, 101, 61, 118, 46, 198, 158, 23, 79, 167, 255};


unsigned char Delta[128] ={
		0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41, 0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
		0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c, 0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
		0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50, 0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
		0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29, 0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
		0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
		0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e, 0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
		0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01, 0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
		0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68, 0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a
};

void KISA_HIGHT_init(const unsigned char *userkey, KISA_HIGHT_KEY *ks)
{
	unsigned char i, j;

	ks->user_key[0] = userkey[0]; ks->user_key[1] = userkey[1];
	ks->user_key[2] = userkey[2]; ks->user_key[3] = userkey[3];
	ks->user_key[4] = userkey[4]; ks->user_key[5] = userkey[5];
	ks->user_key[6] = userkey[6];  ks->user_key[7] = userkey[7];
	ks->user_key[8] = userkey[8];  ks->user_key[9] = userkey[9];
	ks->user_key[10] = userkey[10]; ks->user_key[11] = userkey[11];
	ks->user_key[12] = userkey[12]; ks->user_key[13] = userkey[13];
	ks->user_key[14] = userkey[14]; ks->user_key[15] = userkey[15];

	for(i=0 ; i < 8 ; i++)
	{
		for(j=0 ; j < 8 ; j++)
			ks->key_data[ 16*i + j ] = ks->user_key[(j-i)&7    ] + Delta[ 16*i + j ];

		for(j=0 ; j < 8 ; j++)
			ks->key_data[ 16*i + j + 8 ] = ks->user_key[((j-i)&7)+8] + Delta[ 16*i + j + 8 ];
	}
}


#define EncIni_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)	\
	t0 = x0 + mk0;										\
	t2 = x2 ^ mk1;										\
	t4 = x4 + mk2;										\
	t6 = x6 ^ mk3; 

#define EncFin_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)	\
	out[0] = x0 + mk0;										\
	out[2] = x2 ^ mk1;										\
	out[4] = x4 + mk2;										\
	out[6] = x6 ^ mk3; 

#define Round(x7,x6,x5,x4,x3,x2,x1,x0)				\
	x1 += (F1[x0] ^ key[0]);				\
	x3 ^= (F0[x2] + key[1]);				\
	x5 += (F1[x4] ^ key[2]);				\
	x7 ^= (F0[x6] + key[3]);


void KISA_HIGHT_encrypt_block(const unsigned char *in, unsigned char *out, const KISA_HIGHT_KEY *ks)
{
	register unsigned char t0, t1, t2, t3, t4, t5, t6, t7;
	unsigned char *key, *key2;

	key = ks->key_data;
	key2 = ks->user_key;
	
	t1 = in[1]; t3 = in[3]; t5 = in[5]; t7 = in[7];
	EncIni_Transformation(in[0],in[2],in[4],in[6],key2[12],key2[13],key2[14],key2[15]);	// Initial Transformation

	Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;
	Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;
	Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;
	Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;
	Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;
	Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;
	Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;
	Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;
	Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;
	Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;
	Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;
	Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;
	Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;
	Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;
	Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;
	Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;
	Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;
	Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;
	Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;
	Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;
	Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;
	Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;
	Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;
	Round(t0,t7,t6,t5,t4,t3,t2,t1);key += 4;
	Round(t7,t6,t5,t4,t3,t2,t1,t0);key += 4;
	Round(t6,t5,t4,t3,t2,t1,t0,t7);key += 4;
	Round(t5,t4,t3,t2,t1,t0,t7,t6);key += 4;
	Round(t4,t3,t2,t1,t0,t7,t6,t5);key += 4;
	Round(t3,t2,t1,t0,t7,t6,t5,t4);key += 4;
	Round(t2,t1,t0,t7,t6,t5,t4,t3);key += 4;
	Round(t1,t0,t7,t6,t5,t4,t3,t2);key += 4;
	Round(t0,t7,t6,t5,t4,t3,t2,t1);

	EncFin_Transformation(t1,t3,t5,t7,key2[0],key2[1],key2[2],key2[3]);	// Final Transformation

	out[1] = t2; out[3] = t4; out[5] = t6; out[7] = t0;
}


#define DecIni_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)	\
	t0 = x0 - mk0;										\
	t2 = x2 ^ mk1;										\
	t4 = x4 - mk2;										\
	t6 = x6 ^ mk3; 

#define DecFin_Transformation(x0,x2,x4,x6,mk0,mk1,mk2,mk3)	\
	out[0] = x0 - mk0;										\
	out[2] = x2 ^ mk1;										\
	out[4] = x4 - mk2;										\
	out[6] = x6 ^ mk3; 


#define DRound(x7,x6,x5,x4,x3,x2,x1,x0)				\
	x1 = x1 - (F1[x0] ^ key[0]);				\
	x3 = x3 ^ (F0[x2] + key[1]);				\
	x5 = x5 - (F1[x4] ^ key[2]);				\
	x7 = x7 ^ (F0[x6] + key[3]); 


void KISA_HIGHT_decrypt_block(const unsigned char *in, unsigned char *out, const KISA_HIGHT_KEY *ks)
{
	register unsigned char t0, t1, t2, t3, t4, t5, t6, t7;
	unsigned char *key, *key2;

	key = &(ks->key_data[124]);
	key2 = ks->user_key;
	
	t1 = in[1]; t3 = in[3]; t5 = in[5]; t7 = in[7];
	DecIni_Transformation(in[0],in[2],in[4],in[6],key2[0], key2[1], key2[2], key2[3] );	// Initial Transformation

	DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
	DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
	DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
	DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
	DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
	DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
	DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
	DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
	DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
	DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
	DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
	DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
	DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
	DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
	DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
	DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
	DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
	DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
	DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
	DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
	DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
	DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
	DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
	DRound(t6,t5,t4,t3,t2,t1,t0,t7);key -= 4;
	DRound(t7,t6,t5,t4,t3,t2,t1,t0);key -= 4;
	DRound(t0,t7,t6,t5,t4,t3,t2,t1);key -= 4;
	DRound(t1,t0,t7,t6,t5,t4,t3,t2);key -= 4;
	DRound(t2,t1,t0,t7,t6,t5,t4,t3);key -= 4;
	DRound(t3,t2,t1,t0,t7,t6,t5,t4);key -= 4;
	DRound(t4,t3,t2,t1,t0,t7,t6,t5);key -= 4;
	DRound(t5,t4,t3,t2,t1,t0,t7,t6);key -= 4;
	DRound(t6,t5,t4,t3,t2,t1,t0,t7);

	DecFin_Transformation(t7, t1, t3, t5,key2[12],key2[13],key2[14],key2[15]);	// Final Transformation

	out[1] = t0; out[3] = t2; out[5] = t4; out[7] = t6;
}

void internal_hight_process_blocks(const KISA_HIGHT_KEY *hight_key, int encrypt, const unsigned char *ivec, const unsigned char *in, unsigned int inl, unsigned char *out)
{
	unsigned int i;
	unsigned int inlength = inl;
	unsigned char tmp[HIGHT_BLOCK_SIZE];
	const unsigned char *iv = ivec;

	if(encrypt)
	{
		while (inlength >= HIGHT_BLOCK_SIZE)
		{
			out[0] = in[0] ^ iv[0];
			out[1] = in[1] ^ iv[1];
			out[2] = in[2] ^ iv[2];
			out[3] = in[3] ^ iv[3];
			out[4] = in[4] ^ iv[4];
			out[5] = in[5] ^ iv[5];
			out[6] = in[6] ^ iv[6];
			out[7] = in[7] ^ iv[7];

			KISA_HIGHT_encrypt_block(out, out, hight_key);
			iv = out;
			inlength -= HIGHT_BLOCK_SIZE;
			in  += HIGHT_BLOCK_SIZE;
			out += HIGHT_BLOCK_SIZE;
		}
		if (inlength)
		{
			for (i = 0; i < inlength; ++i)
				out[i] = in[i] ^ iv[i];
			for (i = inlength; i < HIGHT_BLOCK_SIZE; ++i)
				out[i] = iv[i];
			KISA_HIGHT_encrypt_block(out, out, hight_key);
			iv = out;
		}
        //*memcpy(void *__dst, const void *__src, size_t __n);
		memcpy(ivec, iv, HIGHT_BLOCK_SIZE);
	}
	else if (in != out) {
		while (inlength >= HIGHT_BLOCK_SIZE)
		{
			KISA_HIGHT_decrypt_block(in, out, hight_key);

			out[0] ^= iv[0];
			out[1] ^= iv[1];
			out[2] ^= iv[2];
			out[3] ^= iv[3];
			out[4] ^= iv[4];
			out[5] ^= iv[5];
			out[6] ^= iv[6];
			out[7] ^= iv[7];

			iv = in;
			inlength -= HIGHT_BLOCK_SIZE;
			in  += HIGHT_BLOCK_SIZE;
			out += HIGHT_BLOCK_SIZE;
		}
		if (inlength)
		{
			KISA_HIGHT_decrypt_block(in, tmp, hight_key);
			for (i = 0; i < inlength; ++i)
				out[i] = tmp[i] ^ iv[i];
			iv = in;
		}
		memcpy(ivec, iv, HIGHT_BLOCK_SIZE);
	}
	else {
		while (inlength >= HIGHT_BLOCK_SIZE)
		{
			memcpy(tmp, in, HIGHT_BLOCK_SIZE);
			KISA_HIGHT_decrypt_block(in, out, hight_key);

			out[0] ^= iv[0];
			out[1] ^= iv[1];
			out[2] ^= iv[2];
			out[3] ^= iv[3];
			out[4] ^= iv[4];
			out[5] ^= iv[5];
			out[6] ^= iv[6];
			out[7] ^= iv[7];

			memcpy(ivec, tmp, HIGHT_BLOCK_SIZE);
			inlength -= HIGHT_BLOCK_SIZE;
			in  += HIGHT_BLOCK_SIZE;
			out += HIGHT_BLOCK_SIZE;
		}
		if (inlength)
		{
			memcpy(tmp, in, HIGHT_BLOCK_SIZE);
			KISA_HIGHT_decrypt_block(tmp, tmp, hight_key);
			for (i = 0; i < inlength; ++i)
				out[i] = tmp[i] ^ iv[i];
			memcpy(ivec, tmp, HIGHT_BLOCK_SIZE);
		}
	}
}


int KISA_HIGHT_CBC_init(KISA_HIGHT_CBC_INFO *info, int encrypt, unsigned char *user_key ,unsigned char *iv)
{	
	if((info==NULL)||(user_key==NULL)||(iv==NULL)) return 0;

	KISA_HIGHT_init(user_key,&(info->hight_key));
	memcpy(info->ivec,iv,HIGHT_BLOCK_SIZE);
	info->encrypt = encrypt;
	info->last_block_flag = info->buffer_length = 0;
	return 1;
}


int internal_hight_cbc_process_enc(KISA_HIGHT_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	unsigned int templen = inLen&(0x07);

	if(info->buffer_length == 0 && templen == 0)
	{		
		internal_hight_process_blocks(&(info->hight_key),info->encrypt,info->ivec,in,inLen,out);
		*outLen=inLen;
		return 1;
	}

	if (info->buffer_length != 0)
	{
		if (info->buffer_length+inLen < HIGHT_BLOCK_SIZE)
		{
			memcpy(&(info->cbc_buffer[info->buffer_length]),in,inLen);
			info->buffer_length += inLen;
			*outLen=0;
			return 1;
		}
		else
		{
			int length;
			length=HIGHT_BLOCK_SIZE-info->buffer_length;
			memcpy(&(info->cbc_buffer[info->buffer_length]),in,length);
			internal_hight_process_blocks(&(info->hight_key),info->encrypt,info->ivec,info->cbc_buffer,HIGHT_BLOCK_SIZE,out);

			inLen -= length;
			in += length;
			out += HIGHT_BLOCK_SIZE;
			*outLen = HIGHT_BLOCK_SIZE;

			templen = inLen&(0x07);
		}
	}
	else
		*outLen = 0;

	inLen -= templen;
	if (inLen > 0)
	{
		internal_hight_process_blocks(&(info->hight_key),info->encrypt,info->ivec,in,inLen,out);
		*outLen += inLen;
	}

	if (templen > 0)
		memcpy(info->cbc_buffer,&(in[inLen]),templen);

	info->buffer_length = templen;
	return 1;
}

int internal_hight_cbc_process_dec(KISA_HIGHT_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	int updated_len;

	if(info->last_block_flag)
	{
		memcpy(out, info->cbc_last_block, HIGHT_BLOCK_SIZE);
		out += HIGHT_BLOCK_SIZE;
		updated_len = 1;	
	}
	else
		updated_len = 0;

	internal_hight_cbc_process_enc(info,in,inLen,out,outLen);

	if (!info->buffer_length)
	{
		*outLen -= HIGHT_BLOCK_SIZE;
		info->last_block_flag = 1;
		memcpy(info->cbc_last_block,&out[*outLen],HIGHT_BLOCK_SIZE);
	}
	else
		info->last_block_flag = 0;

	if(updated_len)
		*outLen += HIGHT_BLOCK_SIZE;

	return 1;
}

int KISA_HIGHT_CBC_process(KISA_HIGHT_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	if(inLen <= 0)
	{
		return 0;
	}

	if(info->encrypt)
	{
		return internal_hight_cbc_process_enc(info,in,inLen,out,outLen);
	}	
	else
	{
		return internal_hight_cbc_process_dec(info,in,inLen,out,outLen);
	}
}

int KISA_HIGHT_CBC_close(KISA_HIGHT_CBC_INFO *info, unsigned char *out, int *outLen)
{	
	unsigned int i, padlen, padvalue;

	if(info->encrypt)
	{
		padlen=HIGHT_BLOCK_SIZE-(info->buffer_length);

		for (i=(info->buffer_length); i<HIGHT_BLOCK_SIZE; ++i)
			info->cbc_buffer[i] = (unsigned char)padlen;

		internal_hight_process_blocks(&(info->hight_key),info->encrypt,info->ivec,info->cbc_buffer,HIGHT_BLOCK_SIZE,out);

		*outLen=HIGHT_BLOCK_SIZE;

		return 1;
	}
	else
	{
		*outLen=0;

		padlen = HIGHT_BLOCK_SIZE-(info->cbc_last_block[HIGHT_BLOCK_SIZE-1]);

		if(padlen > HIGHT_BLOCK_SIZE)
			return 0;

		if(padlen > 1)
		{
			i = info->cbc_last_block[HIGHT_BLOCK_SIZE-1];
			padvalue = info->cbc_last_block[HIGHT_BLOCK_SIZE-1];
			while(i>0)
			{
				if(padvalue != info->cbc_last_block[HIGHT_BLOCK_SIZE-i])
					return 0;
				i--;
			}
		}

		for (i=0; i<padlen; ++i)
			out[i]=info->cbc_last_block[i];

		*outLen=padlen;

		return 1;
	}
}

int KISA_HIGHT_CBC_ENCRYPT(unsigned char *user_key, unsigned char *iv, unsigned char *in,unsigned int len,unsigned char *out)
{
	int interlen = 0;
	int padlen = 0;
	KISA_HIGHT_CBC_INFO cbc;

	if(!KISA_HIGHT_CBC_init(&cbc,HIGHT_ENCRYPT,user_key,iv))
	{
		return 0;
	}

	if(!KISA_HIGHT_CBC_process(&cbc,in,len,out,&interlen))
	{
		return 0;
	}

	if(!KISA_HIGHT_CBC_close(&cbc,out+interlen,&padlen))
	{
		return 0;
	}

	memset(&cbc, 0x00, sizeof(KISA_HIGHT_CBC_INFO));

	return interlen + padlen;
}

int KISA_HIGHT_CBC_DECRYPT(unsigned char *user_key,unsigned char *iv,unsigned char *in,unsigned int len,unsigned char *out)
{
	int interlen = 0;
	int padlen = 0;
	KISA_HIGHT_CBC_INFO cbc;

	if(!KISA_HIGHT_CBC_init(&cbc,HIGHT_DECRYPT,user_key,iv))
	{
		return 0;
	}

	if(!KISA_HIGHT_CBC_process(&cbc,in,len,out,&interlen))
	{
		return 0;
	}

	if(!KISA_HIGHT_CBC_close(&cbc,out+interlen,&padlen))
	{
		return 0;
	}

	memset(&cbc, 0x00, sizeof(KISA_HIGHT_CBC_INFO));

	return interlen + padlen;
}
