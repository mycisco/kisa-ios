#ifndef _ECC_H_
#define _ECC_H_

#include "sysconf.h"
#include "ec_gf2n.h"
#include "ec_gfp.h"
#include "mpz.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef	SINT ECC_FIELD_TYPE;
#define ECC_PRIME_FIELD 0 /* pfield */
#define ECC_CHAR2_FIELD 1 /* c2field */
#define EC_KCDSA_HAS160_INPUT_BYTE_LENGTH 64
#define SHA224_OUT_BYTE_LENGTH 28
#define SHA256_OUT_BYTE_LENGTH 32

#define MAX_GF_BUF_LEN (( MAX_GF2N_BUF_LEN >= MAX_GFP_BUF_LEN ) ? MAX_GF2N_BUF_LEN : MAX_GFP_BUF_LEN ) 

typedef GFP_ECPT_AC GFP_EC_POINT;
typedef GF2N_ECPT_AC GF2N_EC_POINT;

typedef struct _ECC_POINT{
	union {
		GFP_EC_POINT pfield_point;
		GF2N_EC_POINT c2field_point;
	};
}ECC_POINT;

typedef struct _ECCP_PFIELD{
	GFP_EC_CTX	curve;
	GFP_EC_POINT base;
}ECCP_PFIELD;

typedef struct _ECCP_C2FIELD{
	GF2N_EC_CTX	curve;
	GF2N_EC_POINT base;
}ECCP_C2FIELD;


typedef struct _ECC_PARAMS{
	ECC_FIELD_TYPE	field_type;
	union {
		ECCP_PFIELD pfield;/* prime field */
		ECCP_C2FIELD c2field;/* characteristic-two field */
	};
	MPZ order;
	MPZ cofactor;
} ECC_PARAMS;


#define MAX_ECC_GRP_ORD_BUF_LEN 150
typedef struct _ECC_PARAMS_BUF{
	ULONG modulo_dat[MAX_GF_BUF_LEN];/* prime or irr */
	ULONG coef1_dat[MAX_GF_BUF_LEN]; /* (a or a2) */
	ULONG coef2_dat[MAX_GF_BUF_LEN]; /* (b or a6) */
	ULONG base_x_dat[MAX_GF_BUF_LEN];
	ULONG base_y_dat[MAX_GF_BUF_LEN];
	ULONG order_dat[MAX_ECC_GRP_ORD_BUF_LEN];
	ULONG cofactor_dat[MAX_ECC_GRP_ORD_BUF_LEN];
} ECC_PARAMS_BUF;


typedef	SINT ECC_ID;

typedef struct _ECC_PARAMS_TAB{
	SINT field_type; /* ECC_PRIME_FIELD or ECC_CHAR2_FIELD */
	ECC_PARAMS_BUF ecc_params_buf;
	SINT field_len;
	SINT order_len;
	SINT cofactor_len;
	SINT gf2n_top;
	SINT gf2n_fbits;
}ECC_PARAMS_TAB;

#define SECT233k  0
#define SECT233r  1
#define SECT283k  2
#define SECT283r  3
#define SECP224r  4
#define SECP256r  5

    /******************************************************/
    /*                                                    */
	/*          SEC2 : Domain parameter table             */
    /*                                                    */
    /******************************************************/

static const ECC_PARAMS_TAB ecc_params_tab[6]={
	/******0******/
	/* SECT233k  */
	/*************/
	{
		/* field type */ ECC_CHAR2_FIELD,
		{
			/* f (x) = x233+x74 +1 */
			/* modulo */{0x00400000,0x00000000,0x00000000,0x00000001,0x00000000,0x00000000,
						0x00000000,0x80000000,},
			/*  a   */{0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,},
			/*  b   */{0X00000001,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,},
			/*base_x*/{0XEFAD6126,0X0A4C9D6E,0X19C26BF5,0X149563A4,0X29F22FF4,0X7E731AF1,
					   0X32BA853A,0X00000172,},
			/*base_y*/{0X56FAE6A3,0X56E0C110,0XF18AEB9B,0X27A8CD9B,0X555A67C4,0X19B7F70F,
					   0X537DECE8,0X000001DB,},
			/*order */{0XF173ABDF,0X6EFB1AD5,0XB915BCD4,0X00069D5B,0X00000000,0X00000000,
					   0X00000000,0X00000080,},
			/* cofactor */{0x04,}
		},
		/* field_len */ 8,
		/* order_len */ 8,
		/* cofactor_len */ 1,
		/*GF2N_top*/    7,
		/*GF2N_fbits*/  10
	},

	/******1******/
	/* SECT233r  */
	/*************/
	{
		/* field type */ ECC_CHAR2_FIELD,
		{
			/* f (x) = x233+x74 +1 */
			/* modulo */{0x00400000,0x00000000,0x00000000,0x00000001,0x00000000,0x00000000,
						0x00000000,0x80000000,},
			/*  a   */{0X00000001,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,},
			/*  b   */{0X7D8F90AD,0X81FE115F,0X20E9CE42,0X213B333B,0X0923BB58,0X332C7F8C,
					   0X647EDE6C,0X00000066,},
			/*base_x*/{0X71FD558B,0XF8F8EB73,0X391F8B36,0X5FEF65BC,0X39F1BB75,0X8313BB21,
					   0XC9DFCBAC,0X000000FA,},
			/*base_y*/{0X01F81052,0X36716F7E,0XF867A7CA,0XBF8A0BEF,0XE58528BE,0X03350678,
					   0X6A08A419,0X00000100,},
			/*order */{0X03CFE0D7,0X22031D26,0XE72F8A69,0X0013E974,0X00000000,0X00000000,
					   0X00000000,0X00000100,},
			/* cofactor */{0x04,}
		},
		/* field_len */ 8,
		/* order_len */ 8,
		/* cofactor_len */ 1,
		/*GF2N_top*/    7,
		/*GF2N_fbits*/  10
	},

	/******2******/
	/* SECT283k  */
	/*************/
	{
		/* field type */ ECC_CHAR2_FIELD,
		{
			/* f (x) = x283+x12 +x7+x5+1 */
			/* modulo */{0x00010a10,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
						0x00000000,0x00000000,0x80000000,},
			/*  a   */{0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,0X00000000,},
			/*  b   */{0X00000001,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,0X00000000,},
			/*base_x*/{0X58492836,0XB0C2AC24,0X16876913,0X23C1567A,0X53CD265F,0X62F188E5,
					   0X3F1A3B81,0X78CA4488,0X0503213F,},
			/*base_y*/{0X77DD2259,0X4E341161,0XE4596236,0XE8184698,0XE87E45C0,0X07E5426F,
					   0X8D90F95D,0X0F1C9E31,0X01CCDA38,},
			/*order */{0X1E163C61,0X94451E06,0X265DFF7F,0X2ED07577,0XFFFFE9AE,0XFFFFFFFF,
					   0XFFFFFFFF,0XFFFFFFFF,0X01FFFFFF,},
			/* cofactor */{0x04,}
		},
		/* field_len */ 9,
		/* order_len */ 9,
		/* cofactor_len */ 1,
		/*GF2N_top*/    8,
		/*GF2N_fbits*/  28
	},

	/******3******/
	/* SECT283r  */
	/*************/
	{
		/* field type */ ECC_CHAR2_FIELD,
		{
			/* f (x) = x283+x12 +x7+x5+1 */
			/* modulo */{0x00010a10,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,
						0x00000000,0x00000000,0x80000000,},
			/*  a   */{0X00000001,0X00000000,0X00000000,0X00000000,0X00000000,0X00000000,
					   0X00000000,0X00000000,0X00000000,},
			/*  b   */{0X3B79A2F5,0XF6263E31,0XA581485A,0X45309FA2,0XCA97FD76,0X19A0303F,
					   0XA5A4AF8A,0XC8B8596D,0X027B680A,},
			/*base_x*/{0X86B12053,0XF8CDBECD,0X80E2E198,0X557EAC9C,0X2EED25B8,0X70B0DFEC,
					   0XE1934F8C,0X8DB7DD90,0X05F93925,},
			/*base_y*/{0XBE8112F4,0X13F0DF45,0X826779C8,0X350EDDB0,0X516FF702,0XB20D02B4,
					   0XB98FE6D4,0XFE24141C,0X03676854,},
			/*order */{0XEFADB307,0X5B042A7C,0X938A9016,0X399660FC,0XFFFFEF90,0XFFFFFFFF,
					   0XFFFFFFFF,0XFFFFFFFF,0X03FFFFFF,},
			/* cofactor */{0x02,}
		},
		/* field_len */ 9,
		/* order_len */ 9,
		/* cofactor_len */ 1,
		/*GF2N_top*/    8,
		/*GF2N_fbits*/  28
	},

	/******4******/
	/* SECP224r  */
	/*************/
	{
		/* field type */ ECC_PRIME_FIELD,
		{
			/* field size 224 */
			/*modulo*/{0X00000001,0X00000000,0X00000000,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,},
			/*  a   */{0XFFFFFFFE,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFE,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,},
			/*  b   */{0X2355FFB4,0X270B3943,0XD7BFD8BA,0X5044B0B7,0XF5413256,0X0C04B3AB,0XB4050A85,},
			/*base_x*/{0X115C1D21,0X343280D6,0X56C21122,0X4A03C1D3,0X321390B9,0X6BB4BF7F,0XB70E0CBD,},
			/*base_y*/{0X85007E34,0X44D58199,0X5A074764,0XCD4375A0,0X4C22DFE6,0XB5F723FB,0XBD376388,},
			/*order */{0X5C5C2A3D,0X13DD2945,0XE0B8F03E,0XFFFF16A2,0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,},
			/* cofactor */{0x01,}
		},
		/* field_len */ 7,
		/* order_len */ 7,
		/* cofactor_len */ 1,
		/*GF2N_top*/    -1,
		/*GF2N_fbits*/  -1
	},

	/******5******/
	/* SECP256r  */
	/*************/
	{
		/* field type */ ECC_PRIME_FIELD,
		{
			/* field size 256 */
			/*modulo*/{0XFFFFFFFF,0XFFFFFFFF,0XFFFFFFFF,0X00000000,0X00000000,0X00000000,
					   0X00000001,0XFFFFFFFF,},
			/*  a   */{0XFFFFFFFC,0XFFFFFFFF,0XFFFFFFFF,0X00000000,0X00000000,0X00000000,
					   0X00000001,0XFFFFFFFF,},
			/*  b   */{0X27D2604B,0X3BCE3C3E,0XCC53B0F6,0X651D06B0,0X769886BC,0XB3EBBD55,
					   0XAA3A93E7,0X5AC635D8,},
			/*base_x*/{0XD898C296,0XF4A13945,0X2DEB33A0,0X77037D81,0X63A440F2,0XF8BCE6E5,
					   0XE12C4247,0X6B17D1F2,},
			/*base_y*/{0X37BF51F5,0XCBB64068,0X6B315ECE,0X2BCE3357,0X7C0F9E16,0X8EE7EB4A,
					   0XFE1A7F9B,0X4FE342E2,},
			/*order */{0XFC632551,0XF3B9CAC2,0XA7179E84,0XBCE6FAAD,0XFFFFFFFF,0XFFFFFFFF,
					   0X00000000,0XFFFFFFFF,},
			/* cofactor */{0x01,}
		},
		/* field_len */ 8,
		/* order_len */ 8,
		/* cofactor_len */ 1,
		/*GF2N_top*/    -1,
		/*GF2N_fbits*/  -1
	}
};

extern SINT EC_POINT_LENGTH(int Curve_number);

/* ECC Domain Parameters Setting */
SINT ECC_init_params(ECC_FIELD_TYPE	ftype, ECC_PARAMS *ecc_params, const unsigned int ECC_ID);
SINT ECC_set_params(ECC_ID ecc_id,ECC_PARAMS *ecc_params);

SINT Bit_Truncation(unsigned long *IN, const int Truncater_bit_loc);
void PRNG_ECKCDSA_SHA256(const unsigned char *SEED, const SINT SEED_char_LENGTH, unsigned char *output, const SINT output_bit_LENGTH);  // output should be initialized
void PRNG_ECKCDSA_SHA224(const unsigned char *SEED, const SINT SEED_char_LENGTH, unsigned char *output, const SINT output_bit_LENGTH);  // output should be initialized

#ifdef __cplusplus
}
#endif

#endif
