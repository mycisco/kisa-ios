/*!
 * \file seed.h
 * \brief SEED 암호 알고리즘 (관련표준 : TTAS.KO-12.0004 : 128비트 블록암호알고리즘(SEED))
 * \author
 * Copyright (c) 2010 by \<KISA\>
 */
#ifndef KISA_SEED_H
#define KISA_SEED_H

#ifdef  __cplusplus
extern "C" {
#endif

#define SEED_BLOCK_SIZE 16			/*!< SEED 블럭 크기*/
#define SEED_ENCRYPT	1			/*!< SEED 암호화 모드*/
#define SEED_DECRYPT	0			/*!< SEED 복호화 모드*/

	/*!
	 * \brief
	 * SEED 내부 엔진 암호화를 위한 SEED Key 구조체
	 * \remarks
	 * unsigned int key_data[32] 자료형
	 */
	typedef struct kisa_seed_key_st {
		unsigned int key_data[32];
	} KISA_SEED_KEY;

	/*!
	* \brief
	* SEED 초기화를 위한 암호화키 지정 함수
	* \param user_key
	* 사용자가 지정하는 입력 키 (16 bytes)
	* \param ks
	* 사용자가 지정하는 키가 저장되는 키 구조체
	* \remarks
	* const unsigned char *user_key의 크기는 반드시 16 bytes 가 입력되어야 하고 키구조체(KISA_SEED_KEY *ks)는 메모리 할당이 되어있어야 함
	*/
	void KISA_SEED_init(const unsigned char *user_key, KISA_SEED_KEY *ks);

	/*!
	* \brief
	* SEED 알고리즘 단일 블럭 암호화 함수
	* \param in
	* 사용자 입력 평문(16 bytes)
	* \param out
	* 사용자 입력에 대한 출력 암호문(16 bytes)
	* \param ks
	* KISA_SEED_init로 사용자 키가 설정된 KISA_SEED_KEY 구조체
	* \remarks
	* -# 사용자 입력 평문(const unsigned char *in)의 크기는 반드시 16 bytes 를 입력
	* -# 출력 암호문(unsigned char *out)는 16 bytes 이상 메모리 할당이 되어 있어야 하며, 16 bytes 암호문에 저장됨
	*/
	void KISA_SEED_encrypt_block(const unsigned char *in, unsigned char *out, const KISA_SEED_KEY *ks);
	
	/*!
	* \brief
	* SEED 알고리즘 단일 블럭 복호화 함수
	* \param in
	* 사용자 입력 암호문(16 bytes)
	* \param out
	* 사용자 입력에 대한 출력 평문(16 bytes)
	* \param ks
	* KISA_SEED_init로 사용자 키가 설정된 KISA_SEED_KEY 구조체
	* \remarks
	* -# 사용자 입력 암호문(const unsigned char *in)의 크기는 반드시 16 bytes 를 입력
	* -# 출력 평문(unsigned char *out)는 16 bytes 이상 메모리 할당이 되어 있어야 하며, 16 bytes 평문에 저장됨
	*/
	void KISA_SEED_decrypt_block(const unsigned char *in, unsigned char *out, const KISA_SEED_KEY *ks);
		

	/*!
	 * \brief
	 * SEED 암호화 알고리즘 CBC 운영모드 지원을 위한 범용 구조체
	 */
	typedef struct kisa_seed_cbc_info_st {	
		int				encrypt;							/*!< 암호화/복호화 모드 지정자*/
		unsigned char	ivec[SEED_BLOCK_SIZE];				/*!< 초기 벡터*/
		KISA_SEED_KEY	seed_key;							/*!< SEED 암호화 키*/
		unsigned char	cbc_buffer[SEED_BLOCK_SIZE];		/*!< 내부 버퍼*/
		int				buffer_length;						/*!< 내부 버퍼의 길이*/
		unsigned char	cbc_last_block[SEED_BLOCK_SIZE];	/*!< CBC 지원 버퍼*/
		int				last_block_flag;					/*!< CBC 지원 버퍼 사용 여부*/
	} KISA_SEED_CBC_INFO;

	/*!
	* \brief
	* SEED CBC 알고리즘 초기화 함수
	* \param info
	* SEED CBC 알고리즘 운영을 위한 구조체 지정 (미리 메모리가 할당되어 있어야 함)
	* \param enc
	* 알고리즘 암호화 및 복호화 모드 지정 (암호화 : SEED_ENCRYPT / 복호화 : SEED_DECRYPT)
	* \param user_key
	* 사용자가 지정하는 입력 키 (16 bytes)
	* \param iv
	* 사용자가 지정하는 초기화 벡터 (16 bytes)
	* \returns
	* 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
	* \remarks
	* user_key와 iv는 반드시 16 bytes를 그 크기로 갖음
	*/
	int KISA_SEED_CBC_init(KISA_SEED_CBC_INFO *info, int enc, unsigned char *user_key ,unsigned char *iv);

	/*!
	 * \brief
	 * SEED CBC 알고리즘 다중 블럭 암호화 함수
	 * 
	 * \param info
	 * SEED CBC 알고리즘 운영을 위한 구조체 지정 (KISA_SEED_CBC_init 로 초기화 필요)
	 * 
	 * \param in
	 * 사용자 입력 평문/암호문
	 * 
	 * \param inLen
	 * 사용자 입력의 길이 지정
	 * 
	 * \param out
	 * 사용자 입력에 대한 암호문/평문 출력 버퍼
	 * 
	 * \param outLen
	 * 출력 버퍼에 저장된 데이터의 길이
	 * 
	 * \returns
	 * 구동 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
	 * 
	 * \remarks
	 * -# 출력이 되는 버퍼의 크기는 사용자 입력의 길이 보다 크거나 같게 미리 메모리 할당을 해야함
	 * -# outLen은 실제로 출력버퍼 out에 저장된 결과값의 길이를 함수 내부에서 지정함
	 */
	int KISA_SEED_CBC_process(KISA_SEED_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen);

	/*!
	 * \brief
	 * SEED CBC 알고리즘 운영모드 종료 및 패딩(PKCS7) 처리 함수
	 * 
	 * \param info
	 * SEED CBC 알고리즘 운영을 위한 구조체 지정 (KISA_SEED_CBC_init 로 초기화 필요)
	 * 
	 * \param out
	 * 사용자 입력에 대한 최종 출력 블럭이 저장되는 버퍼
	 * 
	 * \param outLen
	 * 출력 버퍼에 저장된 데이터의 길이
	 * 
	 * \returns
	 * 구동 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
	 * 
	 * \remarks
	 * 출력버퍼 out은 SEED 알고리즘의 한블럭(16 bytes) 이상으로 메모리 할당이 되어 있어야 함
	 * 
	 */
	int KISA_SEED_CBC_close(KISA_SEED_CBC_INFO *info, unsigned char *out, int *outLen);

	/*!
	 * \brief
	 * SEED CBC 암호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(16 bytes)
	 * 
	 * \param iv
	 * 사용자 입력 초기 벡터 (16 bytes)
	 * 
	 * \param in
	 * 암호화 하려는 입력
	 * 
	 * \param len
	 * 입력 포인터의 길이
	 * 
	 * \param out
	 * 압호문이 기록될 출력 버퍼
	 * 
	 * \returns
	 * 구동 성공시 : 암호문 출력의 길이 / 메모리가 적절히 할당되지 않았을 경우 (0)
	 * 
	 * \remarks
	 * 출력버퍼 out은 입력버퍼의 길이는 (len+16) bytes 이상 미리 할당되어 있어야 안전함
	 * 
	 */
	int KISA_SEED_CBC_ENCRYPT(unsigned char *userkey,
							  unsigned char *iv,
							  unsigned char *in,
							  unsigned int   len,
							  unsigned char *out);

	/*!
	 * \brief
	 * SEED CBC 복호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(16 bytes)
	 * 
	 * \param iv
	 * 사용자 입력 초기 벡터 (16 bytes)
	 * 
	 * \param in
	 * 복호화 하려는 입력
	 * 
	 * \param len
	 * 입력 포인터의 길이
	 * 
	 * \param out
	 * 복호화된 평문이 기록될 출력 버퍼
	 * 
	 * \returns
	 * 구동 성공시 : 평문 출력의 길이 / 메모리가 적절히 할당되지 않았을 경우 또는 잘못된 암호문 (0)
	 * 
	 * \remarks
	 * 출력버퍼 out은 입력버퍼의 길이 len과 같게 미리 할당되어 있어야 안전함
	 * 
	 */
	int KISA_SEED_CBC_DECRYPT(unsigned char *userkey,
							  unsigned char *iv,
							  unsigned char *in,
							  unsigned int   len,
							  unsigned char *out);

#ifdef  __cplusplus
}
#endif


#endif /* HEADER_SEED_H */