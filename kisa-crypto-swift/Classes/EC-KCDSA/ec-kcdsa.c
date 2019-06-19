#define _CRT_SECURE_NO_WARNINGS
#include "ec-kcdsa.h"
#include "sha224.h"
#include "sha256.h"
#include "type.h"

void Byte_to_Prime_Field(unsigned char *C, unsigned long *Field, int Byte_length, int Field_length)
{
	int i;
	unsigned char Converted_C[100] = { 0, };

	for (i = 0; i < Byte_length; i++)
	{
		Converted_C[i] = C[Byte_length - 1 - i];
	}

	for (i = 0; i < Field_length; i++)
		Field[i] = Converted_C[i * 4] ^ Converted_C[i * 4 + 1] << 8 ^ Converted_C[i * 4 + 2] << 16 ^ Converted_C[i * 4 + 3] << 24;

}

void Word_to_Byte(unsigned long *W, unsigned char *C, int W_length, int char_length)
{
	int i;

	unsigned char TEMP[100] = { 0, };

	for (i = 0; i < W_length; i++)
	{
		TEMP[i * 4] = W[i] & 0xFF;
		TEMP[i * 4 + 1] = W[i] >> 8 & 0xFF;
		TEMP[i * 4 + 2] = W[i] >> 16 & 0xFF;
		TEMP[i * 4 + 3] = W[i] >> 24 & 0xFF;
	}

	for (i = 0; i < char_length; i++)
	{
		C[i] = TEMP[char_length - i - 1];
	}

}

void Point_to_Byte(unsigned long *W, unsigned char *C, int W_length, const int Temp_char_length)
{
	int i;
	unsigned char TEMP[100] = { 0, };

	for (i = 0; i < W_length; i++)
	{
		TEMP[i * 4] = W[i] & 0xFF;
		TEMP[i * 4 + 1] = W[i] >> 8 & 0xFF;
		TEMP[i * 4 + 2] = W[i] >> 16 & 0xFF;
		TEMP[i * 4 + 3] = W[i] >> 24 & 0xFF;
	}

	for (i = 0; i < Temp_char_length; i++)
	{
		C[i] = TEMP[Temp_char_length - i - 1];
	}

}

void
eckcdsa_gfp(const ECC_POINT Private, const ECC_PARAMS SELECTED_CURVE, unsigned long *secret, const unsigned int ECC_ID, 
	const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len, unsigned char signature[])
{
	int i, added_len = 0, added_len2 = 0;
	unsigned int t, u, u2, K_Word_length;
	SHA224_ALG_INFO AlgInfo_224;
	SHA256_ALG_INFO AlgInfo_256;
	unsigned char KKEY_VAL_[32];

	unsigned char Hash_out_r[MAX_GF_BUF_LEN], Hash_out_v[MAX_GF_BUF_LEN];
	ECC_POINT kG;
	ECC_POINT Q;

	ULONG kG_x_dat[MAX_GF_BUF_LEN], kG_y_dat[MAX_GF_BUF_LEN];
	ULONG e_dat[MAX_GF_BUF_LEN] = { 0, }, s_dat[MAX_GF_BUF_LEN], k_e_dat[MAX_GF_BUF_LEN];
	unsigned char r_xor_v_dat[MAX_GF_BUF_LEN] = { 0, };

	unsigned long d_inv_dat[MAX_GF_BUF_LEN];
	unsigned char char_cQ_x[100] = { 0, }, char_cQ_y[100] = { 0, }, c_Q_M[200] = { 0, }, char_kG_x[100] = { 0, }, Temp_char_length;
	int count; // HASH_OUTPUT_LENGTH와 Temp_char_length의 차이로 발생하는 r,v 문제를 해결하기 위함
	unsigned long KVAL_dat[100] = { 0, }, K_dat[100] = { 0, };
	unsigned char KVAL_char_dat[500] = { 0, };
	MPZ K, KVAL;
	MPZ d_inv, d;
	MPZ e, s, r_xor_v, k_e;

	int HASH_INPUT_LENGTH = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH, HASH_OUTPUT_LENGTH;
	int KKEY_VAL_len;

	switch (ECC_ID) {
		case SECP224r:
			t = 224, u = 223;
			break;
		case SECP256r:
			t = 256, u = 255;
			break;
		default:
			return;
	}

	K_Word_length = SELECTED_CURVE.order.len;

	u2 = u * 2;

	if (t % 8)
		added_len = 1;
	if (u2 % 8)
		added_len2 = 1;

	// KKEY 생성
	KKEY_VAL_len = t / 8;
	srand((unsigned)time(NULL));
	for (i = 0; i < KKEY_VAL_len; i++)
		KKEY_VAL_[i] = rand();

	/*curve = secp224r, SHA-224 test vector*/
	/*curve = secp224r, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0xF2;	KKEY_VAL_[1] = 0x34;	KKEY_VAL_[2] = 0xBC;	KKEY_VAL_[3] = 0xCE;
	KKEY_VAL_[4] = 0x04;	KKEY_VAL_[5] = 0x43;	KKEY_VAL_[6] = 0xAE;	KKEY_VAL_[7] = 0x32;
	KKEY_VAL_[8] = 0x20;	KKEY_VAL_[9] = 0xDC;	KKEY_VAL_[10] = 0xE2;	KKEY_VAL_[11] = 0xC5;
	KKEY_VAL_[12] = 0x95;	KKEY_VAL_[13] = 0x4A;	KKEY_VAL_[14] = 0xF3;	KKEY_VAL_[15] = 0xA2;
	KKEY_VAL_[16] = 0x6C;	KKEY_VAL_[17] = 0x64;	KKEY_VAL_[18] = 0x50;	KKEY_VAL_[19] = 0x63;
	KKEY_VAL_[20] = 0x84;	KKEY_VAL_[21] = 0x98;	KKEY_VAL_[22] = 0x7F;	KKEY_VAL_[23] = 0x8C;
	KKEY_VAL_[24] = 0xF1;	KKEY_VAL_[25] = 0x61;	KKEY_VAL_[26] = 0xE1;	KKEY_VAL_[27] = 0x54;
	KKEY_VAL_len = 28;*/

	/*curve = secp256r, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0xFA;	KKEY_VAL_[1] = 0x77;	KKEY_VAL_[2] = 0x02;	KKEY_VAL_[3] = 0xD7;
	KKEY_VAL_[4] = 0xE8;	KKEY_VAL_[5] = 0x39;	KKEY_VAL_[6] = 0x2C;	KKEY_VAL_[7] = 0x53;
	KKEY_VAL_[8] = 0xCB;	KKEY_VAL_[9] = 0xC9;	KKEY_VAL_[10] = 0x12;	KKEY_VAL_[11] = 0x1E;
	KKEY_VAL_[12] = 0x33;	KKEY_VAL_[13] = 0x74;	KKEY_VAL_[14] = 0x9E;	KKEY_VAL_[15] = 0x0C;
	KKEY_VAL_[16] = 0xF4;	KKEY_VAL_[17] = 0xD5;	KKEY_VAL_[18] = 0xD4;	KKEY_VAL_[19] = 0x9F;
	KKEY_VAL_[20] = 0xD4;	KKEY_VAL_[21] = 0xA4;	KKEY_VAL_[22] = 0x59;	KKEY_VAL_[23] = 0x7E;
	KKEY_VAL_[24] = 0x35;	KKEY_VAL_[25] = 0xCF;	KKEY_VAL_[26] = 0x32;	KKEY_VAL_[27] = 0x22;
	KKEY_VAL_[28] = 0xF4;	KKEY_VAL_[29] = 0xCC;	KKEY_VAL_[30] = 0xCF;	KKEY_VAL_[31] = 0xD3;
	KKEY_VAL_len = 32;*/

	// KVAL = KKEY
	// SNGF(KVAL, 2u) 생성
	if (HASH_FUNCTION == SHA224)
		PRNG_ECKCDSA_SHA224(KKEY_VAL_, KKEY_VAL_len, KVAL_char_dat, u2);
	else if (HASH_FUNCTION == SHA256)
		PRNG_ECKCDSA_SHA256(KKEY_VAL_, KKEY_VAL_len, KVAL_char_dat, u2);
	else
		return;
	
	// k = SNGF(KVAL, 2u) mod n 계산
	Byte_to_Prime_Field(KVAL_char_dat, KVAL_dat, u2 / 8 + added_len2, K_Word_length * 2);

	MAC_INIT_MPZ(K, K_dat, MPCONST_POS_SIG);
	MAC_INIT_MPZ(KVAL, KVAL_dat, MPCONST_POS_SIG);

	KVAL.len = K_Word_length * 2;
	K.len = K_Word_length;

	MPZ_mod(&KVAL, &SELECTED_CURVE.order, &K);

	if (HASH_FUNCTION == SHA224)
		HASH_OUTPUT_LENGTH = SHA224_OUT_BYTE_LENGTH;
	else if (HASH_FUNCTION == SHA256)
		HASH_OUTPUT_LENGTH = SHA256_OUT_BYTE_LENGTH;

	// k * G = (x_1, y_1) 계산
	kG.pfield_point.x.dat = kG_x_dat;
	kG.pfield_point.y.dat = kG_y_dat;
	GFP_smul_ECPT_AC(&SELECTED_CURVE.pfield.curve, &K, &SELECTED_CURVE.pfield.base, &kG.pfield_point);

	// r = HASH(x_1) 계산
	Temp_char_length = EC_POINT_LENGTH(ECC_ID);

	Point_to_Byte(kG.pfield_point.x.dat, char_kG_x, kG.pfield_point.x.len, Temp_char_length);

	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, char_kG_x, Temp_char_length);
		SHA224_Final(&AlgInfo_224, Hash_out_r);
		memcpy(signature, Hash_out_r, HASH_OUTPUT_LENGTH);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, char_kG_x, Temp_char_length);
		SHA256_Final(&AlgInfo_256, Hash_out_r);
		memcpy(signature, Hash_out_r + (HASH_OUTPUT_LENGTH - KKEY_VAL_len), KKEY_VAL_len);
	}

	// C_Q = MSB(X_Q || Y_Q, L) 계산
	MAC_INIT_MPZ(d, secret, MPCONST_POS_SIG);
	d.len = SELECTED_CURVE.order.len;

	Q.pfield_point.x.dat = Private.pfield_point.x.dat;
	Q.pfield_point.y.dat = Private.pfield_point.y.dat;
	Q.pfield_point.x.len = SELECTED_CURVE.order.len;
	Q.pfield_point.y.len = SELECTED_CURVE.order.len;
	Q.pfield_point.x.sig = 1;
	Q.pfield_point.y.sig = 1;

	Point_to_Byte(Q.pfield_point.x.dat, char_cQ_x, Q.pfield_point.x.len, Temp_char_length);
	Point_to_Byte(Q.pfield_point.y.dat, char_cQ_y, Q.pfield_point.x.len, Temp_char_length);

	for (i = 0; i < Temp_char_length; i++)
	{
		c_Q_M[i] = char_cQ_x[i];
		c_Q_M[i + Temp_char_length] = char_cQ_y[i];
	}
	for (i = Temp_char_length * 2; i < HASH_INPUT_LENGTH; i++)	c_Q_M[i] = 0;
	for (i = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH; i < HASH_INPUT_LENGTH + MSG_len; i++)	c_Q_M[i] = Message[i - HASH_INPUT_LENGTH];

	// v = HASH(C_Q || M) 계산
	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA224_Final(&AlgInfo_224, Hash_out_v);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA256_Final(&AlgInfo_256, Hash_out_v);
	}

	// (r, v) mod 2 ^ 8w 계산
	count = HASH_OUTPUT_LENGTH - Temp_char_length;
	if (count > 0) {
		for (i = 0; i < count; i++) {
			Hash_out_r[i] = 0x00;
			Hash_out_v[i] = 0x00;
		}
	}

	// e = r ^ v mod n 계산
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)		r_xor_v_dat[i] = Hash_out_r[i] ^ Hash_out_v[i];

	MAC_INIT_MPZ(r_xor_v, r_xor_v_dat, MPCONST_POS_SIG);

	r_xor_v.len = HASH_OUTPUT_LENGTH / 4;

	Byte_to_Prime_Field(r_xor_v_dat, r_xor_v.dat, HASH_OUTPUT_LENGTH, r_xor_v.len);

	MAC_INIT_MPZ(e, e_dat, MPCONST_POS_SIG);
	e.len = SELECTED_CURVE.order.len;

	MPZ_mod(&r_xor_v, &SELECTED_CURVE.order, &e);

	// t = d(k - e) mod n = s
	MAC_INIT_MPZ(k_e, k_e_dat, MPCONST_POS_SIG);
	k_e.len = SELECTED_CURVE.order.len;

	MPZ_sub_mod(&K, &e, &SELECTED_CURVE.order, &k_e);

	MAC_INIT_MPZ(s, s_dat, MPCONST_POS_SIG);
	MPZ_mul_mod(&k_e, &d, &SELECTED_CURVE.order, &s);

	Point_to_Byte(s.dat, signature + KKEY_VAL_len, s.len, Temp_char_length);
}

void
eckcdsa_gf2n(const ECC_POINT Private, const ECC_PARAMS SELECTED_CURVE, unsigned long *secret, const unsigned int ECC_ID,
	const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len, unsigned char signature[])
{
	int i, added_len = 0, added_len2 = 0;
	unsigned int t, u, u2, K_Word_length;
	int count;
	int Nbyte, N;
	SHA256_ALG_INFO AlgInfo_256;
	SHA224_ALG_INFO AlgInfo_224;
	unsigned char KKEY_VAL_[36];

	unsigned char Hash_out_r[MAX_GF_BUF_LEN], Hash_out_v[MAX_GF_BUF_LEN];

	ECC_POINT kG;
	ECC_POINT Q;

	ULONG kG_x_dat[MAX_GF_BUF_LEN] = { 0, }, kG_y_dat[MAX_GF_BUF_LEN] = { 0, }, xx_dat[MAX_GF_BUF_LEN] = { 0, }, yy_dat[MAX_GF_BUF_LEN] = { 0, };
	ULONG Q_x_dat[MAX_GF_BUF_LEN], Q_y_dat[MAX_GF_BUF_LEN];
	ULONG e_dat[MAX_GF_BUF_LEN] = { 0, }, s_dat[MAX_GF_BUF_LEN], k_e_dat[MAX_GF_BUF_LEN];

	unsigned char r_xor_v_char_dat[MAX_GF_BUF_LEN] = { 0, };

	unsigned long r_xor_v_dat[MAX_GF_BUF_LEN], KVAL_dat[100] = { 0, }, K_dat[100] = { 0, };
	unsigned char char_cQ_x[100] = { 0, }, char_cQ_y[100] = { 0, }, c_Q_M[200] = { 0, }, char_kG_x[100] = { 0, }, Temp_char_length = 0;

	unsigned int v_c = 1;
	unsigned char KVAL_char_dat[500] = { 0, };

	MPZ K, KVAL;
	MPZ d;
	MPZ e, s, r_xor_v, k_e;

	int HASH_INPUT_LENGTH = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH, HASH_OUTPUT_LENGTH;
	int KKEY_VAL_len;

	switch (ECC_ID) {
		case SECT233k:
			t = 232, u = 231, N = 232;
			break;
		case SECT233r:
			t = 233, u = 232, N = 233;
			break;
		case SECT283k:
			t = 281, u = 280, N = 283;
			break;
		case SECT283r:
			t = 282, u = 281, N = 283;
			break;
		default:
			return;
	}

	K_Word_length = SELECTED_CURVE.order.len;

	u2 = u * 2;

	if (t % 8)
		added_len = 1;
	if (u2 % 8)
		added_len2 = 1;

	// KKEY 생성
	i = 0;
	srand((unsigned)time(NULL));
	if (added_len) {
		if(ECC_ID == SECT233r || ECC_ID == SECT283k)
			KKEY_VAL_[i] = 0x01;
		else if (ECC_ID == SECT283r)
			KKEY_VAL_[i] = 0x03;
	}
	for (i = i; i < t / 8 + added_len; i++)
		KKEY_VAL_[i] = rand();
	KKEY_VAL_len = t / 8 + added_len;

	// t / 8 + added_len = 232 / 8 + 1 = 30
	/*curve = sect233r, SHA-224 test vector*/
	/*curve = sect233r, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0x01;	KKEY_VAL_[1] = 0x9B;	KKEY_VAL_[2] = 0x62;	KKEY_VAL_[3] = 0x34;
	KKEY_VAL_[4] = 0xBC;	KKEY_VAL_[5] = 0xCE;	KKEY_VAL_[6] = 0xC1;	KKEY_VAL_[7] = 0x13;
	KKEY_VAL_[8] = 0x95;	KKEY_VAL_[9] = 0xC0;	KKEY_VAL_[10] = 0xB2;	KKEY_VAL_[11] = 0xFE;
	KKEY_VAL_[12] = 0x46;	KKEY_VAL_[13] = 0x65;	KKEY_VAL_[14] = 0x4A;	KKEY_VAL_[15] = 0x25;
	KKEY_VAL_[16] = 0x81;	KKEY_VAL_[17] = 0xFD;	KKEY_VAL_[18] = 0xD5;	KKEY_VAL_[19] = 0xCE;
	KKEY_VAL_[20] = 0x4E;	KKEY_VAL_[21] = 0x34;	KKEY_VAL_[22] = 0xBF;	KKEY_VAL_[23] = 0xB8;
	KKEY_VAL_[24] = 0xAF;	KKEY_VAL_[25] = 0x31;	KKEY_VAL_[26] = 0xC1;	KKEY_VAL_[27] = 0x70;
	KKEY_VAL_[28] = 0x8A;	KKEY_VAL_[29] = 0xC4;
	KKEY_VAL_len = 30;*/

	// t / 8 + added_len = 232 / 8 + 0 = 29
	/*curve = sect233k, SHA-224 test vector*/
	/*curve = sect233k, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0x8B;	KKEY_VAL_[1] = 0x62;	KKEY_VAL_[2] = 0x34;	KKEY_VAL_[3] = 0xBC;
	KKEY_VAL_[4] = 0xCE;	KKEY_VAL_[5] = 0xC1;	KKEY_VAL_[6] = 0x13;	KKEY_VAL_[7] = 0x95;	
	KKEY_VAL_[8] = 0xC0;	KKEY_VAL_[9] = 0xB2;	KKEY_VAL_[10] = 0xFE;	KKEY_VAL_[11] = 0x46;	
	KKEY_VAL_[12] = 0x65;	KKEY_VAL_[13] = 0x4A;	KKEY_VAL_[14] = 0x25;	KKEY_VAL_[15] = 0x81;	
	KKEY_VAL_[16] = 0xFD;	KKEY_VAL_[17] = 0xD5;	KKEY_VAL_[18] = 0xCE;	KKEY_VAL_[19] = 0x4E;	
	KKEY_VAL_[20] = 0x34;	KKEY_VAL_[21] = 0xBF;	KKEY_VAL_[22] = 0xB8;	KKEY_VAL_[23] = 0xAF;	
	KKEY_VAL_[24] = 0x31;	KKEY_VAL_[25] = 0xC1;	KKEY_VAL_[26] = 0x70;	KKEY_VAL_[27] = 0x8A;	
	KKEY_VAL_[28] = 0xC4;
	KKEY_VAL_len = 29;*/

	// t / 8 + added_len = 282 / 8 + 1 = 36 
	/*curve = sect283r, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0x03;	KKEY_VAL_[1] = 0x4D;	KKEY_VAL_[2] = 0xB6;	KKEY_VAL_[3] = 0xE7;
	KKEY_VAL_[4] = 0x51;	KKEY_VAL_[5] = 0x83;	KKEY_VAL_[6] = 0x88;	KKEY_VAL_[7] = 0x16;
	KKEY_VAL_[8] = 0x77;	KKEY_VAL_[9] = 0x42;	KKEY_VAL_[10] = 0xBE;	KKEY_VAL_[11] = 0x85;
	KKEY_VAL_[12] = 0xA4;	KKEY_VAL_[13] = 0x89;	KKEY_VAL_[14] = 0xEB;	KKEY_VAL_[15] = 0x93;
	KKEY_VAL_[16] = 0x31;	KKEY_VAL_[17] = 0x6B;	KKEY_VAL_[18] = 0xD3;	KKEY_VAL_[19] = 0xAF;
	KKEY_VAL_[20] = 0x9C;	KKEY_VAL_[21] = 0x12;	KKEY_VAL_[22] = 0xB4;	KKEY_VAL_[23] = 0xAA;
	KKEY_VAL_[24] = 0x1F;	KKEY_VAL_[25] = 0x8B;	KKEY_VAL_[26] = 0xE8;	KKEY_VAL_[27] = 0x1B;
	KKEY_VAL_[28] = 0xD3;	KKEY_VAL_[29] = 0xBF;	KKEY_VAL_[30] = 0xE3;	KKEY_VAL_[31] = 0xA5;
	KKEY_VAL_[32] = 0xA3;	KKEY_VAL_[33] = 0x13;	KKEY_VAL_[34] = 0x47;	KKEY_VAL_[35] = 0xEA;
	KKEY_VAL_len = 36;*/

	// t / 8 + added_len = 283 / 8 + 1 = 36 
	/*curve = sect283k, SHA-256 test vector*/
	/*KKEY_VAL_[0] = 0x01;	KKEY_VAL_[1] = 0x4D;	KKEY_VAL_[2] = 0xB6;	KKEY_VAL_[3] = 0xE7;
	KKEY_VAL_[4] = 0x51;	KKEY_VAL_[5] = 0x83;	KKEY_VAL_[6] = 0x88;	KKEY_VAL_[7] = 0x16;
	KKEY_VAL_[8] = 0x77;	KKEY_VAL_[9] = 0x42;	KKEY_VAL_[10] = 0xBE;	KKEY_VAL_[11] = 0x85;
	KKEY_VAL_[12] = 0xA4;	KKEY_VAL_[13] = 0x89;	KKEY_VAL_[14] = 0xEB;	KKEY_VAL_[15] = 0x93;
	KKEY_VAL_[16] = 0x31;	KKEY_VAL_[17] = 0x6B;	KKEY_VAL_[18] = 0xD3;	KKEY_VAL_[19] = 0xAF;
	KKEY_VAL_[20] = 0x9C;	KKEY_VAL_[21] = 0x12;	KKEY_VAL_[22] = 0xB4;	KKEY_VAL_[23] = 0xAA;
	KKEY_VAL_[24] = 0x1F;	KKEY_VAL_[25] = 0x8B;	KKEY_VAL_[26] = 0xE8;	KKEY_VAL_[27] = 0x1B;
	KKEY_VAL_[28] = 0xD3;	KKEY_VAL_[29] = 0xBF;	KKEY_VAL_[30] = 0xE3;	KKEY_VAL_[31] = 0xA5;
	KKEY_VAL_[32] = 0xA3;	KKEY_VAL_[33] = 0x13;	KKEY_VAL_[34] = 0x47;	KKEY_VAL_[35] = 0xEA;
	KKEY_VAL_len = 36;*/

	// KVAL = KKEY
	// SNGF(KVAL, 2u) 생성
	if (HASH_FUNCTION == SHA224)
		PRNG_ECKCDSA_SHA224(KKEY_VAL_, KKEY_VAL_len, KVAL_char_dat, u2);
	else if (HASH_FUNCTION == SHA256)
		PRNG_ECKCDSA_SHA256(KKEY_VAL_, KKEY_VAL_len, KVAL_char_dat, u2);
	else
		return;

	// k = SNGF(KVAL, 2u) mod n 계산
	Byte_to_Prime_Field(KVAL_char_dat, KVAL_dat, u2 / 8 + added_len2, K_Word_length * 2);

	MAC_INIT_MPZ(K, K_dat, MPCONST_POS_SIG);
	MAC_INIT_MPZ(KVAL, KVAL_dat, MPCONST_POS_SIG);

	KVAL.len = K_Word_length * 2;
	K.len = K_Word_length;

	MPZ_mod(&KVAL, &SELECTED_CURVE.order, &K);

	if (HASH_FUNCTION == SHA224)
		HASH_OUTPUT_LENGTH = SHA224_OUT_BYTE_LENGTH;
	else if (HASH_FUNCTION == SHA256)
		HASH_OUTPUT_LENGTH = SHA256_OUT_BYTE_LENGTH;

	Nbyte = N / 8 + 1;

	// k * G = (x_1, y_1) 계산
	kG.c2field_point.x = xx_dat;
	kG.c2field_point.y = yy_dat;
	GF2N_smul_ECPT_AC(&SELECTED_CURVE.c2field.curve, &K, &SELECTED_CURVE.c2field.base, &kG.c2field_point);

	// r = HASH(x_1) 계산
	Temp_char_length = EC_POINT_LENGTH(ECC_ID);

	Point_to_Byte(kG.c2field_point.x, char_kG_x, SELECTED_CURVE.order.len, Nbyte);

	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, char_kG_x, Nbyte);
		SHA224_Final(&AlgInfo_224, Hash_out_r);
		memcpy(signature, Hash_out_r, HASH_OUTPUT_LENGTH);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, char_kG_x, Nbyte);
		SHA256_Final(&AlgInfo_256, Hash_out_r);
		if(N == 233 || N == 232)
			memcpy(signature, Hash_out_r + (HASH_OUTPUT_LENGTH - KKEY_VAL_len), KKEY_VAL_len);
		else
			memcpy(signature, Hash_out_r, HASH_OUTPUT_LENGTH);
	}

	// C_Q = MSB(X_Q || Y_Q, L) 계산
	MAC_INIT_MPZ(d, secret, MPCONST_POS_SIG);
	d.len = SELECTED_CURVE.order.len;

	Q.c2field_point.x = Q_x_dat;
	Q.c2field_point.y = Q_y_dat;

	for (i = 0; i < SELECTED_CURVE.order.len; i++)
	{
		Q.c2field_point.x[i] = Private.c2field_point.x[i];
		Q.c2field_point.y[i] = Private.c2field_point.y[i];
	}

	Point_to_Byte(Q.c2field_point.x, char_cQ_x, SELECTED_CURVE.order.len, Nbyte);
	Point_to_Byte(Q.c2field_point.y, char_cQ_y, SELECTED_CURVE.order.len, Nbyte);

	for (i = 0; i < Nbyte; i++)		c_Q_M[i] = char_cQ_x[i];
	for (i = Nbyte; i < Nbyte * 2; i++)		c_Q_M[i] = char_cQ_y[i - Nbyte];
	for (i = Nbyte * 2; i < HASH_INPUT_LENGTH; i++)	c_Q_M[i] = 0;
	for (i = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH; i < HASH_INPUT_LENGTH + MSG_len; i++)	c_Q_M[i] = Message[i - HASH_INPUT_LENGTH];

	// v = HASH(C_Q || M) 계산
	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA224_Final(&AlgInfo_224, Hash_out_v);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA256_Final(&AlgInfo_256, Hash_out_v);
	}

	// (r, v) mod 2 ^ 8w 계산
	count = HASH_OUTPUT_LENGTH - (N/8);
	if ((N % 8) != 0) count--;
	if (count > 0) {
		for (i = 0; i < count; i++) {
			Hash_out_r[i] = 0x00;
			Hash_out_v[i] = 0x00;
		}
	}

	// e = r ^ v mod n 계산
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)	r_xor_v_char_dat[i] = Hash_out_r[i] ^ Hash_out_v[i];

	MAC_INIT_MPZ(r_xor_v, r_xor_v_dat, MPCONST_POS_SIG);
	r_xor_v.len = HASH_OUTPUT_LENGTH / 4;

	Byte_to_Prime_Field(r_xor_v_char_dat, r_xor_v.dat, HASH_OUTPUT_LENGTH, r_xor_v.len);

	MAC_INIT_MPZ(e, e_dat, MPCONST_POS_SIG);
	e.len = SELECTED_CURVE.order.len;

	MPZ_mod(&r_xor_v, &SELECTED_CURVE.order, &e);

	// t = d(k - e) mod n = s
	MAC_INIT_MPZ(k_e, k_e_dat, MPCONST_POS_SIG);
	k_e.len = SELECTED_CURVE.order.len;

	MPZ_sub_mod(&K, &e, &SELECTED_CURVE.order, &k_e);

	MAC_INIT_MPZ(s, s_dat, MPCONST_POS_SIG);
	MPZ_mul_mod(&k_e, &d, &SELECTED_CURVE.order, &s);

	Point_to_Byte(s.dat, signature + Temp_char_length, s.len, Temp_char_length);
}

int eckcdsa_gfp_verify(const ECC_POINT Private, unsigned char signature[], const ECC_PARAMS SELECTED_CURVE,
	const unsigned int ECC_ID, const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len)
{
	int count;
	int i;
	SHA256_ALG_INFO AlgInfo_256;
	SHA224_ALG_INFO AlgInfo_224;
	unsigned char Hash_out_r[MAX_GF_BUF_LEN], Hash_out_v[MAX_GF_BUF_LEN];
	ECC_POINT Q;
	ULONG Q_x_dat[MAX_GF_BUF_LEN], Q_y_dat[MAX_GF_BUF_LEN];
	ULONG e_dat[MAX_GF_BUF_LEN] = { 0, }, s_dat[MAX_GF_BUF_LEN];
	unsigned char r_xor_v_dat[MAX_GF_BUF_LEN] = { 0, };
	unsigned char rr_dat[100] = { 0x00, };
	unsigned long ss_dat[100] = { 0x00, };

	unsigned char char_cQ_x[100] = { 0, }, char_cQ_y[100] = { 0, }, c_Q_M[200] = { 0, }, char_kG_x[100] = { 0, }, char_sQ_eG[100] = { 0, };
	int Temp_char_length;

	MPZ e, s, r_xor_v;
	ECC_POINT sQ_eG, sQ, eG;

	ULONG sQ_x_dat[MAX_GF_BUF_LEN], sQ_y_dat[MAX_GF_BUF_LEN];
	ULONG eG_x_dat[MAX_GF_BUF_LEN], eG_y_dat[MAX_GF_BUF_LEN];
	ULONG sQ_eG_x_dat[MAX_GF_BUF_LEN], sQ_eG_y_dat[MAX_GF_BUF_LEN];

	int HASH_INPUT_LENGTH = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH, HASH_OUTPUT_LENGTH;

	if (HASH_FUNCTION == SHA224)
		HASH_OUTPUT_LENGTH = SHA224_OUT_BYTE_LENGTH;
	else if (HASH_FUNCTION == SHA256)
		HASH_OUTPUT_LENGTH = SHA256_OUT_BYTE_LENGTH;
	else
		return -1;

	// C_Q = MSB(X_Q || Y_Q, L) 계산
	Q.pfield_point.x.dat = Q_x_dat;
	Q.pfield_point.y.dat = Q_y_dat;
	Q.pfield_point.x.len = SELECTED_CURVE.order.len;
	Q.pfield_point.y.len = SELECTED_CURVE.order.len;
	Q.pfield_point.x.sig = 1;
	Q.pfield_point.y.sig = 1;

	for (i = 0; i < 100; i++)
	{
		Q.pfield_point.x.dat[i] = Private.pfield_point.x.dat[i];
		Q.pfield_point.y.dat[i] = Private.pfield_point.y.dat[i];
	}

	Temp_char_length = EC_POINT_LENGTH(ECC_ID);

	Point_to_Byte(Q.pfield_point.x.dat, char_cQ_x, Q.pfield_point.x.len, Temp_char_length);
	Point_to_Byte(Q.pfield_point.y.dat, char_cQ_y, Q.pfield_point.x.len, Temp_char_length);

	Temp_char_length = EC_POINT_LENGTH(ECC_ID);

	for (i = 0; i < Temp_char_length; i++)
	{
		c_Q_M[i] = char_cQ_x[i];
		c_Q_M[i + Temp_char_length] = char_cQ_y[i];
	}
	for (i = Temp_char_length * 2; i < HASH_INPUT_LENGTH; i++)	c_Q_M[i] = 0;
	for (i = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH; i < HASH_INPUT_LENGTH + MSG_len; i++)	c_Q_M[i] = Message[i - HASH_INPUT_LENGTH];

	// v' = HASH(C_Q || M') 계산
	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA224_Final(&AlgInfo_224, Hash_out_v);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA256_Final(&AlgInfo_256, Hash_out_v);
	}

	// (r', v') mod 2 ^ 8w 계산
	memcpy(rr_dat, signature, HASH_OUTPUT_LENGTH);

	count = HASH_OUTPUT_LENGTH - Temp_char_length;
	if (count > 0) {
		for (i = 0; i < count; i++)		Hash_out_v[i] = 0x00;
		for (i = HASH_OUTPUT_LENGTH - 1; i >= count; i--)	rr_dat[i] = rr_dat[i - count];
		for (; i >= 0; i--)		rr_dat[i] = 0x00;
	}

	// (r', v') mod 2 ^ 8w 계산
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)	r_xor_v_dat[i] = rr_dat[i] ^ Hash_out_v[i];

	MAC_INIT_MPZ(r_xor_v, r_xor_v_dat, MPCONST_POS_SIG);
	r_xor_v.len = HASH_OUTPUT_LENGTH / 4;

	Byte_to_Prime_Field(r_xor_v_dat, r_xor_v.dat, HASH_OUTPUT_LENGTH, r_xor_v.len);

	MAC_INIT_MPZ(e, e_dat, MPCONST_POS_SIG);
	e.len = SELECTED_CURVE.order.len;

	MPZ_mod(&r_xor_v, &SELECTED_CURVE.order, &e);

	// (x_2, y_2) = t'Q + e'G
	MAC_INIT_MPZ(s, s_dat, MPCONST_POS_SIG);
	Byte_to_Prime_Field(signature + Temp_char_length, ss_dat, Temp_char_length, SELECTED_CURVE.order.len);
	for (i = 0; i < SELECTED_CURVE.order.len; i++)		s.dat[i] = ss_dat[i];

	s.len = SELECTED_CURVE.order.len;

	eG.pfield_point.x.dat = eG_x_dat;
	eG.pfield_point.y.dat = eG_y_dat;

	sQ.pfield_point.x.dat = sQ_x_dat;
	sQ.pfield_point.y.dat = sQ_y_dat;

	sQ_eG.pfield_point.x.dat = sQ_eG_x_dat;
	sQ_eG.pfield_point.y.dat = sQ_eG_y_dat;

	GFP_smul_ECPT_AC(&SELECTED_CURVE.pfield.curve, &e, &SELECTED_CURVE.pfield.base, &eG.pfield_point);
	GFP_smul_ECPT_AC(&SELECTED_CURVE.pfield.curve, &s, &Q.pfield_point, &sQ.pfield_point);

	GFP_add_ECPT_AC(&SELECTED_CURVE.pfield.curve, &eG.pfield_point, &sQ.pfield_point, &sQ_eG.pfield_point);

	Point_to_Byte(sQ_eG.pfield_point.x.dat, char_sQ_eG, SELECTED_CURVE.order.len, Temp_char_length);

	// Hash(x_2')
	if(HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, char_sQ_eG, Temp_char_length);
		SHA224_Final(&AlgInfo_224, Hash_out_r);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, char_sQ_eG, Temp_char_length);
		SHA256_Final(&AlgInfo_256, Hash_out_r);
	}

	// Hash(x_2') mod 2 ^ 8w 계산
	count = HASH_OUTPUT_LENGTH - Temp_char_length;
	if (count > 0) {
		for (i = 0; i < count; i++)		Hash_out_r[i] = 0x00;
	}

	// Hash(x_2') = r' 여부 확인
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)
	{
		if (rr_dat[i] != Hash_out_r[i]) 
			return -1;
	}

	return 0;
}

int eckcdsa_gf2n_verify(const ECC_POINT Private, unsigned char signature[], const ECC_PARAMS SELECTED_CURVE,
	const unsigned int ECC_ID, const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len)
{
	int count;
	int N = 0, Nbyte = 0, added_len = 0;

	int i;
	SHA256_ALG_INFO AlgInfo_256;
	SHA224_ALG_INFO AlgInfo_224;

	unsigned char Hash_out_r[MAX_GF_BUF_LEN], Hash_out_v[MAX_GF_BUF_LEN];

	ECC_POINT Q;
	ULONG Q_x_dat[MAX_GF_BUF_LEN], Q_y_dat[MAX_GF_BUF_LEN];
	ULONG e_dat[MAX_GF_BUF_LEN] = { 0, }, s_dat[MAX_GF_BUF_LEN];
	ULONG sQ_x_dat[MAX_GF_BUF_LEN], sQ_y_dat[MAX_GF_BUF_LEN];
	ULONG eG_x_dat[MAX_GF_BUF_LEN], eG_y_dat[MAX_GF_BUF_LEN];
	ULONG sQ_eG_x_dat[MAX_GF_BUF_LEN], sQ_eG_y_dat[MAX_GF_BUF_LEN];

	unsigned char r_xor_v_char_dat[MAX_GF_BUF_LEN] = { 0, };
	unsigned char rr_dat[100] = { 0x00, };
	unsigned long ss_dat[100] = { 0x00, };

	unsigned long r_xor_v_dat[MAX_GF_BUF_LEN];
	unsigned char char_cQ_x[100] = { 0, }, char_cQ_y[100] = { 0, }, c_Q_M[200] = { 0, }, char_kG_x[100] = { 0, }, char_sQ_eG[100] = { 0, };
	int Temp_char_length = 0;
	unsigned int v_c = 1;

	MPZ e, s, r_xor_v;
	ECC_POINT sQ_eG, sQ, eG;

	int HASH_INPUT_LENGTH = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH, HASH_OUTPUT_LENGTH;

	if (HASH_FUNCTION == SHA224)
		HASH_OUTPUT_LENGTH = SHA224_OUT_BYTE_LENGTH;
	else if (HASH_FUNCTION == SHA256)
		HASH_OUTPUT_LENGTH = SHA256_OUT_BYTE_LENGTH;
	else
		return -1;

	switch (ECC_ID)
	{
		case SECT233r:
			N = 233;
			break;
		case SECT233k:
			N = 232;
			break;
		case SECT283r:
			N = 283;
			break;
		case SECT283k:
			N = 283;
			break;
		default:
			return -1;
	}

	Nbyte = N / 8 + 1;

	if (N % 8)
		added_len = 1;

	// C_Q = MSB(X_Q || Y_Q, L) 계산
	Q.c2field_point.x = Q_x_dat;
	Q.c2field_point.y = Q_y_dat;

	for (i = 0; i < SELECTED_CURVE.order.len; i++)
	{
		Q.c2field_point.x[i] = Private.c2field_point.x[i];
		Q.c2field_point.y[i] = Private.c2field_point.y[i];
	}

	Temp_char_length = EC_POINT_LENGTH(ECC_ID);

	Point_to_Byte(Q.c2field_point.x, char_cQ_x, SELECTED_CURVE.order.len, Nbyte);
	Point_to_Byte(Q.c2field_point.y, char_cQ_y, SELECTED_CURVE.order.len, Nbyte);

	for (i = 0; i < Nbyte; i++)		c_Q_M[i] = char_cQ_x[i];
	for (i = Nbyte; i < Nbyte * 2; i++)		c_Q_M[i] = char_cQ_y[i - Nbyte];
	for (i = Temp_char_length * 2; i < HASH_INPUT_LENGTH; i++)		c_Q_M[i] = 0;
	for (i = EC_KCDSA_HAS160_INPUT_BYTE_LENGTH; i < HASH_INPUT_LENGTH + MSG_len; i++)	c_Q_M[i] = Message[i - HASH_INPUT_LENGTH];

	// v' = HASH(C_Q || M') 계산
	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA224_Final(&AlgInfo_224, Hash_out_v);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, c_Q_M, HASH_INPUT_LENGTH + MSG_len);
		SHA256_Final(&AlgInfo_256, Hash_out_v);
	}

	// (r', v') mod 2 ^ 8w 계산
	memcpy(rr_dat, signature, HASH_OUTPUT_LENGTH);

	count = HASH_OUTPUT_LENGTH - (N/8);
	if ((N % 8) != 0) count--;
	if (count > 0) {
		for (i = 0; i < count; i++)	Hash_out_v[i] = 0x00;
		for (i = HASH_OUTPUT_LENGTH - 1; i >= count; i--)	rr_dat[i] = rr_dat[i - count];
		for (; i >= 0; i--)	rr_dat[i] = 0x00;
	}

	// e' = r' ^ v' mod n 계산
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)	r_xor_v_char_dat[i] = rr_dat[i] ^ Hash_out_v[i];

	MAC_INIT_MPZ(r_xor_v, r_xor_v_dat, MPCONST_POS_SIG);
	r_xor_v.len = HASH_OUTPUT_LENGTH / 4;

	Byte_to_Prime_Field(r_xor_v_char_dat, r_xor_v.dat, HASH_OUTPUT_LENGTH, r_xor_v.len);

	MAC_INIT_MPZ(e, e_dat, MPCONST_POS_SIG);
	e.len = SELECTED_CURVE.order.len;

	MPZ_mod(&r_xor_v, &SELECTED_CURVE.order, &e);

	// (x_2, y_2) = t'Q + e'G
	MAC_INIT_MPZ(s, s_dat, MPCONST_POS_SIG);
	Byte_to_Prime_Field(signature + Temp_char_length, ss_dat, Temp_char_length, SELECTED_CURVE.order.len);
	for (i = 0; i < SELECTED_CURVE.order.len; i++)		s.dat[i] = ss_dat[i];

	s.len = SELECTED_CURVE.order.len;

	eG.c2field_point.x = eG_x_dat;
	eG.c2field_point.y = eG_y_dat;

	sQ.c2field_point.x = sQ_x_dat;
	sQ.c2field_point.y = sQ_y_dat;

	sQ_eG.c2field_point.x = sQ_eG_x_dat;
	sQ_eG.c2field_point.y = sQ_eG_y_dat;

	GF2N_smul_ECPT_AC(&SELECTED_CURVE.c2field.curve, &e, &SELECTED_CURVE.c2field.base, &eG.c2field_point);
	GF2N_smul_ECPT_AC(&SELECTED_CURVE.c2field.curve, &s, &Q.c2field_point, &sQ.c2field_point);

	GF2N_add_ECPT_AC(&SELECTED_CURVE.c2field.curve, &eG.c2field_point, &sQ.c2field_point, &sQ_eG.c2field_point);

	Point_to_Byte(sQ_eG.c2field_point.x, char_sQ_eG, SELECTED_CURVE.order.len, Temp_char_length);

	// Hash(x_2')
	if (HASH_FUNCTION == SHA224)
	{
		SHA224_Init(&AlgInfo_224);
		SHA224_Update(&AlgInfo_224, char_sQ_eG, Nbyte);
		SHA224_Final(&AlgInfo_224, Hash_out_r);
	}
	else if (HASH_FUNCTION == SHA256)
	{
		SHA256_Init(&AlgInfo_256);
		SHA256_Update(&AlgInfo_256, char_sQ_eG, Nbyte);
		SHA256_Final(&AlgInfo_256, Hash_out_r);
	}

	// Hash(x_2') mod 2 ^ 8w 계산
	count = HASH_OUTPUT_LENGTH - (N/8);
	if ((N % 8) != 0) count--;
	if (count > 0) {
		for (i = 0; i < count; i++)	Hash_out_r[i] = 0x00;
	}

	// Hash(x_2') = r' 여부 확인
	for (i = 0; i < HASH_OUTPUT_LENGTH; i++)
	{
		if (rr_dat[i] != Hash_out_r[i])
			return -1;
	}

	return 0;
}

void Private_Key_generator(MPZ *Private_key, ECC_PARAMS SELECTED_CURVE, const ECC_ID ecc_id, const int HASH_FUNCTION, unsigned char *URAND_VAL, const int URAND_len)
{
	unsigned long tmp_XKEY[9] = { 0x00, };
	unsigned long XSEED_dat[9] = { 0x00, }, final_KEY_dat[100] = { 0, };
	unsigned long XVAL_dat[9] = { 0x00, }, G_XVAL_2u_dat[100] = { 0, };
	MPZ XKEY, XSEED, XVAL;
	MPZ final_KEY, G_XVAL_2u;
	int added_len = 0, added_len2 = 0, i;

	unsigned char G_XVAL_2u_char_dat[500] = { 0, };
	unsigned char XVAL_char_dat[36] = { 0x00, };
	unsigned char XSEED_char_dat[36] = { 0x00, };

	int t, u, u2, finalkey_Word_length;

	switch (ecc_id) {
		case SECT233k:
			t = 232, u = 231;
			break;
		case SECT233r:
			t = 233, u = 232;
			break;
		case SECT283k:
			t = 281, u = 280;
			break;
		case SECT283r:
			t = 282, u = 281;
			break;
		case SECP224r:
			t = 224, u = 223;
			break;
		case SECP256r:
			t = 256, u = 255;
			break;
		default:
			return;
	}

	Private_key->dat = (ULONG*)malloc(100 * sizeof(ULONG));

	finalkey_Word_length = SELECTED_CURVE.order.len;

	u2 = u * 2;

	if (t % 8)
		added_len = 1;
	if (u2 % 8)
		added_len2 = 1;

	// XKEY 생성
	srand((unsigned)time(NULL));
	for (i = 0; i < t / 8; i++)
		((unsigned char*)tmp_XKEY)[i] = rand();
	if (added_len) {
		if (ecc_id == SECT233r || ecc_id == SECT283k)
			((unsigned char*)tmp_XKEY)[i] = 0x01;
		else if (ecc_id == SECT283r)
			((unsigned char*)tmp_XKEY)[i] = 0x03;
	}
	
	/*curve = secp224r, SHA-224 test vector*/
	/*curve = secp224r, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0xf3455554;
	tmp_XKEY[1] = 0x3ab87f8c;
	tmp_XKEY[2] = 0xffc640ee;
	tmp_XKEY[3] = 0x9ddaf3a2;
	tmp_XKEY[4] = 0xeeefe2c5;
	tmp_XKEY[5] = 0xe4432fcb;
	tmp_XKEY[6] = 0xf788eebb;*/

	/*curve = secp256r, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0xE61DF084;
	tmp_XKEY[1] = 0x9C167272;
	tmp_XKEY[2] = 0xCDD11E9D;
	tmp_XKEY[3] = 0xFF698F61;
	tmp_XKEY[4] = 0xEF574961;
	tmp_XKEY[5] = 0xDC8E6683;
	tmp_XKEY[6] = 0x14D67E2D;
	tmp_XKEY[7] = 0xFF67D6BF;*/

	/*curve = sect233r, SHA-224 test vector*/
	/*curve = sect233r, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0x91EAF894;
	tmp_XKEY[1] = 0x36817EE1;
	tmp_XKEY[2] = 0x603C21CE;
	tmp_XKEY[3] = 0x0A3B5553;
	tmp_XKEY[4] = 0x2BDE3877;
	tmp_XKEY[5] = 0x50846A7C;
	tmp_XKEY[6] = 0x9D507305;
	tmp_XKEY[7] = 0x01AA;*/

	/*curve = sect233k, SHA-224 test vector*/
	/*curve = sect233k, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0x91EAF894;
	tmp_XKEY[1] = 0x36817EE1;
	tmp_XKEY[2] = 0x603C21CE;
	tmp_XKEY[3] = 0x0A3B5553;
	tmp_XKEY[4] = 0x2BDE3877;
	tmp_XKEY[5] = 0x50846A7C;
	tmp_XKEY[6] = 0x9D507305;
    tmp_XKEY[7] = 0x008A;*/

	/*curve = sect283r, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0xB3CFB7BD;
	tmp_XKEY[1] = 0x67337C7E;
	tmp_XKEY[2] = 0xB3883CB4;
	tmp_XKEY[3] = 0xB3F2ABDE;
	tmp_XKEY[4] = 0x1CA97BA0;
	tmp_XKEY[5] = 0xF89E8FB9;
	tmp_XKEY[6] = 0x8B9FE86A;
	tmp_XKEY[7] = 0x5697ADA5;
	tmp_XKEY[8] = 0x0392DD3B;*/

	/*curve = sect283k, SHA-256 test vector*/
	/*tmp_XKEY[0] = 0xB3CFB7BD;
	tmp_XKEY[1] = 0x67337C7E;
	tmp_XKEY[2] = 0xB3883CB4;
	tmp_XKEY[3] = 0xB3F2ABDE;
	tmp_XKEY[4] = 0x1CA97BA0;
	tmp_XKEY[5] = 0xF89E8FB9;
	tmp_XKEY[6] = 0x8B9FE86A;
	tmp_XKEY[7] = 0x5697ADA5;
	tmp_XKEY[8] = 0x0192DD3B;*/

	// XSEED = SNGF(user_provided_random_input, 224) 생성
	if (HASH_FUNCTION == SHA224)
		PRNG_ECKCDSA_SHA224(URAND_VAL, URAND_len, XSEED_char_dat, t);
	else if (HASH_FUNCTION == SHA256)
		PRNG_ECKCDSA_SHA256(URAND_VAL, URAND_len, XSEED_char_dat, t);
	else
		return;

	Byte_to_Prime_Field(XSEED_char_dat, XSEED_dat, t / 8 + added_len, finalkey_Word_length);

	MAC_INIT_MPZ(XSEED, XSEED_dat, MPCONST_POS_SIG);
	XSEED.len = finalkey_Word_length;
	MAC_INIT_MPZ(XKEY, tmp_XKEY, MPCONST_POS_SIG);
	XKEY.len = finalkey_Word_length;

	MAC_INIT_MPZ(XVAL, XVAL_dat, MPCONST_POS_SIG);
	XVAL.len = finalkey_Word_length + 1;

	// XVAL = (XKEY + XSEED) mod 2 ^ b
	MPZ_add(&XSEED, &XKEY, &XVAL);
	Bit_Truncation(XVAL.dat, t);

	Word_to_Byte(XVAL.dat, XVAL_char_dat, finalkey_Word_length, t / 8 + added_len);

	// SNGF(XVAL, 2u) 생성
	if (HASH_FUNCTION == SHA224)
		PRNG_ECKCDSA_SHA224(XVAL_char_dat, t / 8 + added_len, G_XVAL_2u_char_dat, u2);
	else if (HASH_FUNCTION == SHA256)
		PRNG_ECKCDSA_SHA256(XVAL_char_dat, t / 8 + added_len, G_XVAL_2u_char_dat, u2);
	else
		return;

	Byte_to_Prime_Field(G_XVAL_2u_char_dat, G_XVAL_2u_dat, u2 / 8 + added_len2, finalkey_Word_length * 2);

	MAC_INIT_MPZ(final_KEY, final_KEY_dat, MPCONST_POS_SIG);
	MAC_INIT_MPZ(G_XVAL_2u, G_XVAL_2u_dat, MPCONST_POS_SIG);

	G_XVAL_2u.len = finalkey_Word_length * 2;
	final_KEY.len = finalkey_Word_length;
	
	// d = SNGF(XVAL, 2u) mod n 생성
	MPZ_mod(&G_XVAL_2u, &SELECTED_CURVE.order, &final_KEY);

	memcpy(Private_key->dat, final_KEY.dat, sizeof(ULONG) * final_KEY.len);
	Private_key->len = final_KEY.len;
	Private_key->sig = final_KEY.sig;
}

void Public_Key_generator_gfp(ECC_POINT *Public_point, unsigned long *Private_key, ECC_PARAMS SELECTED_CURVE)
{
	int a;
	unsigned long d_inv_dat[MAX_GF_BUF_LEN] = { 0, };

	MPZ d_inv, d;

	Public_point->pfield_point.x.dat = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
	Public_point->pfield_point.y.dat = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
	Public_point->pfield_point.x.len = SELECTED_CURVE.pfield.base.x.len;
	Public_point->pfield_point.y.len = SELECTED_CURVE.pfield.base.y.len;
	
	// d ^ -1 mod n
	MAC_INIT_MPZ(d, Private_key, MPCONST_POS_SIG);
	d.len = SELECTED_CURVE.order.len;

	MAC_INIT_MPZ(d_inv, d_inv_dat, MPCONST_POS_SIG);
	d_inv.len = SELECTED_CURVE.order.len;

	MPZ_mul_inv_mod(&d, &SELECTED_CURVE.order, &d_inv);

	a = d_inv.len;
	
	// Q = (d ^ -1) * G = (X_Q, Y_Q)
	GFP_smul_ECPT_AC(&SELECTED_CURVE.pfield.curve, &d_inv, &SELECTED_CURVE.pfield.base, &Public_point->pfield_point);
}

void Public_Key_generator_gf2n(ECC_POINT *Public_point, unsigned long *Private_key, ECC_PARAMS SELECTED_CURVE)
{
	unsigned long d_inv_dat[MAX_GF_BUF_LEN] = { 0, };
	MPZ d_inv, d;

	Public_point->c2field_point.x = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
	Public_point->c2field_point.y = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));

	// d ^ -1 mod n
	MAC_INIT_MPZ(d, Private_key, MPCONST_POS_SIG);
	d.len = SELECTED_CURVE.order.len;

	MAC_INIT_MPZ(d_inv, d_inv_dat, MPCONST_POS_SIG);
	d_inv.len = SELECTED_CURVE.order.len;

	MPZ_mul_inv_mod(&d, &SELECTED_CURVE.order, &d_inv);

	// Q = (d ^ -1) * G = (X_Q, Y_Q)
	GF2N_smul_ECPT_AC(&SELECTED_CURVE.c2field.curve, &d_inv, &SELECTED_CURVE.c2field.base, &Public_point->c2field_point);
}

void Public_Key_generator(ECC_POINT *Public_point, unsigned long *Private_key, ECC_PARAMS SELECTED_CURVE) {
	if (SELECTED_CURVE.field_type == ECC_PRIME_FIELD) {
		Public_Key_generator_gfp(Public_point, Private_key, SELECTED_CURVE);
	}
	else if (SELECTED_CURVE.field_type == ECC_CHAR2_FIELD) {
		Public_Key_generator_gf2n(Public_point, Private_key, SELECTED_CURVE);
	}
	else
		return;
}

void EC_KCDSA_sign(const ECC_POINT Public_point, const ECC_PARAMS SELECTED_CURVE, unsigned long *secret, const unsigned int ECC_ID,
	const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len, unsigned char signature[]) {
	if (SELECTED_CURVE.field_type == ECC_PRIME_FIELD) {
		eckcdsa_gfp(Public_point, SELECTED_CURVE, secret, ECC_ID, HASH_FUNCTION, Message, MSG_len, signature);
	}
	else if (SELECTED_CURVE.field_type == ECC_CHAR2_FIELD) {
		eckcdsa_gf2n(Public_point, SELECTED_CURVE, secret, ECC_ID, HASH_FUNCTION, Message, MSG_len, signature);
	}
	else
		return;
}

int EC_KCDSA_verify(const ECC_POINT Public_point, unsigned char signature[], const ECC_PARAMS SELECTED_CURVE,
	const unsigned int ECC_ID, const unsigned int HASH_FUNCTION, unsigned char Message[], const int MSG_len) {
	if (SELECTED_CURVE.field_type == ECC_PRIME_FIELD) {
		return eckcdsa_gfp_verify(Public_point, signature, SELECTED_CURVE, ECC_ID, HASH_FUNCTION, Message, MSG_len);
	}
	else if (SELECTED_CURVE.field_type == ECC_CHAR2_FIELD) {
		return eckcdsa_gf2n_verify(Public_point, signature, SELECTED_CURVE, ECC_ID, HASH_FUNCTION, Message, MSG_len);
	}
	else
		return - 1;
}

void Public_Key_set_params(ECC_POINT *Public_point, const ECC_PARAMS SELECTED_CURVE, const unsigned int *x_Q, int x_Q_len, const unsigned int *y_Q, int y_Q_len)
{
	if (SELECTED_CURVE.field_type == ECC_PRIME_FIELD) {
		Public_point->pfield_point.x.dat = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
		Public_point->pfield_point.y.dat = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
		Public_point->pfield_point.x.len = SELECTED_CURVE.pfield.base.x.len;
		Public_point->pfield_point.y.len = SELECTED_CURVE.pfield.base.y.len;

		Public_point->pfield_point.is_O = 0;
		Public_point->pfield_point.x.sig = 1;
		Public_point->pfield_point.y.sig = 1;

		for (int i = 0; i < x_Q_len; ++i) Public_point->pfield_point.x.dat[i] = x_Q[i];
		for (int i = 0; i < y_Q_len; ++i) Public_point->pfield_point.y.dat[i] = y_Q[i];
	}
	else if (SELECTED_CURVE.field_type == ECC_CHAR2_FIELD) {
		Public_point->c2field_point.x = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));
		Public_point->c2field_point.y = (unsigned long*)malloc(MAX_GF_BUF_LEN * sizeof(unsigned long));

		Public_point->c2field_point.is_O = 0;
		
		for (int i = 0; i < x_Q_len; ++i) Public_point->c2field_point.x[i] = x_Q[i];
		for (int i = 0; i < y_Q_len; ++i) Public_point->c2field_point.y[i] = y_Q[i];
	}
	else
		return;
}