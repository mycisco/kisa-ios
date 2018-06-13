/*!
 * \file ctr_drbg.h
 * \brief CTR-DRBG 알고리즘 구현 (NIST 800-90)
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */

#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#ifdef  __cplusplus
extern "C" {
#endif

//------------------------------------------------
#define ALGO_SEED								1
#define ALGO_ARIA128							2
#define ALGO_ARIA192							3
#define ALGO_ARIA256							4

//------------------------------------------------
#define ALGO_SEED_OUTLEN_IN_BYTES				16
#define ALGO_ARIA128_OUTLEN_IN_BYTES			16
#define ALGO_ARIA192_OUTLEN_IN_BYTES			16
#define ALGO_ARIA256_OUTLEN_IN_BYTES			16

//------------------------------------------------
#define ALGO_SEED_KEYLEN_IN_BYTES				16
#define ALGO_ARIA128_KEYLEN_IN_BYTES			16
#define ALGO_ARIA192_KEYLEN_IN_BYTES			24
#define ALGO_ARIA256_KEYLEN_IN_BYTES			32

//------------------------------------------------
#define ALGO_SEED_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES	24
#define ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES	32

//------------------------------------------------
#define ALGO_SEED_SEEDLEN_IN_BYTES				ALGO_SEED_OUTLEN_IN_BYTES + ALGO_SEED_KEYLEN_IN_BYTES
#define ALGO_ARIA128_SEEDLEN_IN_BYTES			ALGO_ARIA128_OUTLEN_IN_BYTES + ALGO_ARIA128_KEYLEN_IN_BYTES
#define ALGO_ARIA192_SEEDLEN_IN_BYTES			ALGO_ARIA192_OUTLEN_IN_BYTES + ALGO_ARIA192_KEYLEN_IN_BYTES
#define ALGO_ARIA256_SEEDLEN_IN_BYTES			ALGO_ARIA256_OUTLEN_IN_BYTES + ALGO_ARIA256_KEYLEN_IN_BYTES

//------------------------------------------------
#define MAX_V_LEN_IN_BYTES						16
#define MAX_Key_LEN_IN_BYTES					32
#define MAX_SEEDLEN_IN_BYTES					ALGO_ARIA256_SEEDLEN_IN_BYTES

//------------------------------------------------
#define MIN_ENTROPY_INPUT_LEN_IN_BYTES			// Depends on SECURITY_STRENGTH of each algorithm

//------------------------------------------------
#define MAX_NUM_INPUT_OF_BYTES_PER_REQUEST		0x10000			// 2^19 bits

//------------------------------------------------
// The following values are too huge to apply on the current architectures,
// thus we do not consider the maximum length of either input or entropy.
#define MAX_ENTROPY_INPUT_LEN_IN_BYTES			0x100000000		// 2^35 bits
#define MAX_PERSONALIZED_STRING_LEN_IN_BYTES	0x100000000		// 2^35 bits
#define MAX_ADDITIONAL_INPUT_LEN_IN_BYTES		0x100000000		// 2^35 bits
#define NUM_OF_REQUESTS_BETWEEN_RESEEDS			0x1000000000000UL// 2^48 bits

#define STATE_INITIALIZED_FLAG					0xFE12DC34

//------------------------------------------------
// The following values define either using derivation-function or not
// when KISA_CTR_DRBG_Instantiate(..., unsigned char derivation_function_flag) is called.
#define NON_DERIVATION_FUNCTION					0x00
#define USE_DERIVATION_FUNCTION					0xFF


#ifdef WIN32
	typedef unsigned __int64	uint64;
#else
	typedef unsigned long long	uint64;
#endif

	/*!
	 * \brief
	 * CTR DRBG 구현을 위한 내부 변수 구조체 (STATE)
	 */
	typedef struct ctr_drbg_state{
		unsigned char	algo; /*!< ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 */
		unsigned char	V[MAX_V_LEN_IN_BYTES];
		int				Vlen;
		unsigned char	Key[MAX_Key_LEN_IN_BYTES];
		int				Keylen;
		int				seedlen;
		uint64			reseed_counter;
		int				security_strength;		
		int				initialized_flag;		  // If initialized_flag = STATE_INITIALIZED_FLAG, state is already initialized.
		unsigned char	derivation_function_flag; // 0x00 : non-df ,  0xFF : use df
	}KISA_CTR_DRBG_STATE;


	
	/*!
	 * \brief
	 * CTR DRBG 초기화 함수. 랜덤 생성을 위해서는 반드시 초기화가 필요
	 * 
	 * \param state
	 * 정보를 담고 있는 KISA_CTR_DRBG_STATE 구조체
	 *
	 * \param algo
	 * 내부에서 사용될 대칭키 암호를 지정 (ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 중 택일)
	 *
	 * \param entropy_input
	 * 랜덤 엔진 초기화를 위한 엔트로피 정보 입력
	 * (길이는 사용하는 대칭키 암호의 ALGO_XXX_SECURITY_STRENGTH_IN_BYTES 이상을 입력해야함)
	 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes 이상)
	 * (Derivation Function을 사용하지 않을 경우에는 ALGO_xxx_SEEDLEN_IN_BYTES 이상을 입력해야 함)
	 *
	 * \param entropylen
	 * 입력하는 엔트로피의 길이 (bytes 단위)
	 *
	 * \param nonce
	 * 랜덤 엔진 초기화를 위한 Nonce 입력
	 * (입력 블럭암호의 security strength 절반 이상을 입력해야 함)
	 *
	 * \param noncelen
	 * 입력하는 엔트로피의 길이 (bytes 단위)
	 *
	 * \param personalization_string
	 * 사용자 지정 스트링 입력(옵션). 입력하지 않을 경우 NULL
	 *
	 * \param stringlen
	 * 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
	 *
	 * \param derivation_function_flag
	 * 입력하는 엔트로피 정보가 Full Entropy일 경우 : NON_DERIVATION_FUNCTION / 
	 * 입력하는 엔트로피 정보가 Full Entropy가 아닐 경우 : USE_DERIVATION_FUNCTION
	 * 
	 * \returns
	 * 초기화 성공 (1) / 실패 (0)
	 */
	int KISA_CTR_DRBG_Instantiate(KISA_CTR_DRBG_STATE *state,
		unsigned char algo,
		unsigned char* entropy_input, int entropylen,
		unsigned char* nonce, int noncelen,
		unsigned char* personalization_string, int stringlen,
		unsigned char derivation_function_flag
		);


	
	/*!
	 * \brief
	 * CTR DRBG 랜덤 생성 함수. 반드시 KISA_CTR_DRBG_Instantiate 구동 이후에 실행 가능
	 * 
	 * \param state
	 * 정보를 담고 있는 KISA_CTR_DRBG_STATE 구조체
	 *
	 * \param output
	 * 생성될 랜덤이 입력되는 버퍼
	 *
	 * \param request_num_of_bits
	 * 생성될 랜덤의 길이 (bits) 단위
	 *
	 * \param additional_input
	 * 부가적인 랜덤시드 입력(옵션). 입력하지 않을 경우 NULL
	 *
	 * \param addlen
	 * 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
	 *
	 * 
	 * \returns
	 * 성공 (1) / 실패 (0)
	 */
	int KISA_CTR_DRBG_Generate(KISA_CTR_DRBG_STATE *state,
		unsigned char* output, int request_num_of_bits,
		unsigned char* addtional_input, int addlen	
		);


	/*!
	 * \brief
	 * CTR DRBG 재 초기화 함수(필요시). KISA_CTR_DRBG_Instantiate를 사전에 구동시킨 이후에 사용 가능
	 * 
	 * \param state
	 * 정보를 담고 있는 KISA_CTR_DRBG_STATE 구조체
	 *
	 * \param entropy_input
	 * 랜덤 엔진 초기화를 위한 엔트로피 정보 입력
	 * (길이는 사용하는 대칭키 암호의 ALGO_XXX_SECURITY_STRENGTH_IN_BYTES 이상을 입력해야함)
	 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes 이상)
	 * (Derivation Function을 사용하지 않을 경우에는 ALGO_xxx_SEEDLEN_IN_BYTES 이상을 입력해야 함)
	 *
	 * \param entropylen
	 * 입력하는 엔트로피의 길이 (bytes 단위)
	 *
	 * \param additional_input
	 * 부가적인 랜덤시드 입력(옵션). 입력하지 않을 경우 NULL
	 *
	 * \param addlen
	 * 사용자 지정 스트링의 길이. NULL일 경우 길이를 0으로 입력
	 *
	 * 
	 * \returns
	 * 성공 (1) / 실패 (0)
	 */
	int KISA_CTR_DRBG_Reseed(KISA_CTR_DRBG_STATE *state,
		unsigned char* entropy_input, int entropylen,
		unsigned char* additional_input, int addlen
		);

#ifdef  __cplusplus
}
#endif

#endif