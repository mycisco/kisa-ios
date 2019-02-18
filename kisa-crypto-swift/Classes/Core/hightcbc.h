/*!
 * \file hight.h
 * \brief HIGHT 암호 알고리즘 (관련표준 : KISA - HIGHT 블록암호 알고리즘 사양 및 세부 명세서)
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */
#ifndef HIGHT_H
#define HIGHT_H

#ifdef  __cplusplus
extern "C" {
#endif

#define HIGHT_BLOCK_SIZE 8			/*!< HIGHT 블럭 크기*/
#define HIGHT_ENCRYPT 1				/*!< HIGHT 암호화 모드*/
#define HIGHT_DECRYPT 0				/*!< HIGHT 복호화 모드*/


	/*!
	 * \brief
	 * HIGHT 내부 엔진 암호화를 위한 HIGHT Key 구조체
	 * \remarks
	 * -# unsigned char user_key[16]  자료형
	 * -# unsigned char key_data[128] 자료형
	 */
	typedef struct kisa_hight_key_st {
		unsigned char user_key[16];
		unsigned char key_data[128];
	} KISA_HIGHT_KEY;

	/*!
	 * \brief
	 * HIGHT 초기화를 위한 암호화키 지정 함수
	 * 
	 * \param userkey
	 * 사용자가 지정하는 입력 키 (16 bytes)
	 * 
	 * \param ks
	 * 사용자가 지정하는 키가 저장되는 HIGHT key 구조체
	 * 
	 * \remarks
	 * const unsigned char *user_key의 크기는 반드시 16 bytes 가 입력되어야 하고 키 구조체(KISA_HIGHT_KEY *ks)는 메모리 할당이 되어 있어야 함
	 * 
	 */
	void KISA_HIGHT_init(const unsigned char *userkey, KISA_HIGHT_KEY *ks);


	/*!
	 * \brief
	 * HIGHT 알고리즘 단일 블럭 암호화 함수
	 * 
	 * \param in
	 * 사용자 입력 평문(8 bytes)
	 * 
	 * \param out
	 * 사용자 입력에 대한 출력 암호문(8 bytes)
	 * 
	 * \param ks
	 * KISA_HIGHT_init으로 암호화 키가 설정된 KISA_HIGHT_KEY 구조체
	 * 
	 * \remarks
	 * -# 사용자 입력 평문(const unsigned char *in)의 크기는 반드시 8 bytes 를 입력
	 * -# 출력 암호문(unsigned char *out)은 8 bytes 이상 메모리 할당이 되어 있어야 하며, 출력되는 암호문의 크기는 8 bytes 임
	 */
	void KISA_HIGHT_encrypt_block(const unsigned char *in, unsigned char *out, const KISA_HIGHT_KEY *ks);


	/*!
	 * \brief
	 * HIGHT 알고리즘 단일 블럭 복호화 함수
	 * 
	 * \param in
	 * 사용자 입력 암호문(8 bytes)
	 * 
	 * \param out
	 * 사용자 입력에 대한 출력 평문(8 bytes)
	 * 
	 * \param ks
	 * KISA_HIGHT_init으로 암호화 키가 설정된 KISA_HIGHT_KEY 구조체
	 * 
	 * \remarks
	 * -# 사용자 입력 암호문(const unsigned char *in)의 크기는 반드시 8 bytes 를 입력
	 * -# 출력 평문(unsigned char *out)은 8 bytes 이상 메모리 할당이 되어 있어야 하며, 출력되는 평문의 크기는 8 bytes 임
	 */
	void KISA_HIGHT_decrypt_block(const unsigned char *in, unsigned char *out, const KISA_HIGHT_KEY *ks);
	


	/*!
	 * \brief
	 * HIGHT 암호화 알고리즘의 CBC 운영모드 지원을 위한 범용 구조체
	 */
	typedef struct kisa_hight_cbc_info_st {	
		int			   encrypt;								/*!< 암호화/복호화 모드 지정자*/
		unsigned char  ivec[HIGHT_BLOCK_SIZE];				/*!< 초기 벡터*/
		KISA_HIGHT_KEY hight_key;							/*!< HIGHT 암호화 키*/
		unsigned char  cbc_buffer[HIGHT_BLOCK_SIZE];		/*!< 내부 버퍼*/
		int			   buffer_length;						/*!< 내부 버퍼의 길이*/
		unsigned char  cbc_last_block[HIGHT_BLOCK_SIZE];	/*!< CBC 지원 버퍼*/
		int			   last_block_flag;						/*!< CBC 지원 버퍼 사용 여부*/
	} KISA_HIGHT_CBC_INFO;


	/*!
	 * \brief
	 * HIGHT CBC 알고리즘 초기화 함수
	 * 
	 * \param info
	 * HIGHT CBC 알고리즘 운영을 위한 구조체 지정 (미리 메모리가 할당되어 있어야 함)
	 * 
	 * \param enc
	 * 알고리즘 암호화 및 복호화 모드 지정 (암호화 : HIGHT_ENCRYPT / 복호화 : HIGHT_DECRYPT)
	 * 
	 * \param user_key
	 * 사용자가 지정하는 입력 키 (16 bytes)
	 * 
	 * \param iv
	 * 사용자가 지정하는 초기화 벡터(8 bytes)
	 * 
	 * \returns
	 * 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
	 * 
	 * \remarks
	 * -# user_key의 크기는 반드시 16 bytes 여야 함
	 * -# iv의 크기는 반드시 8 bytes 여야 함
	 */
	int KISA_HIGHT_CBC_init(KISA_HIGHT_CBC_INFO *info, int enc, unsigned char *user_key , unsigned char *iv);


	/*!
	 * \brief
	 * HIGHT CBC 알고리즘 다중 블럭 암호화 함수
	 * 
	 * \param info
	 * HIGHT CBC 알고리즘 운영을 위한 구조체 지정 (KISA_HIGHT_CBC_init으로 초기화 필요)
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
	 * -# 출력되는 버퍼의 크기는 사용자 입력의 길이보다 크거나 같게 미리 메모리 할당을 해야 함
	 * -# outLen의 값은 함수 내부에서 출력 버퍼 out에 저장된 결과값의 길이로 지정됨
	 */
	int KISA_HIGHT_CBC_process(KISA_HIGHT_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen);


	/*!
	 * \brief
	 * HIGHT CBC 알고리즘 운영모드 종료 및 패딩(PKCS7) 처리 함수
	 * 
	 * \param info
	 * HIGHT CBC 알고리즘 운영을 위한 구조체 지정 (KISA_HIGHT_CBC_init으로 초기화 필요)
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
	 * 출력 버퍼 out은 HIGHT 알고리즘의 한블럭 (8 bytes) 이상으로 메모리 할당이 되어 있어야 함
	 */
	int KISA_HIGHT_CBC_close(KISA_HIGHT_CBC_INFO *info, unsigned char *out, int *outLen);

	
	/*!
	 * \brief
	 * HIGHT CBC 암호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(16 bytes)
	 * 
	 * \param iv
	 * 사용자 입력 초기 벡터 (8 bytes)
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
	 * 출력버퍼 out은 입력버퍼의 길이는 (len+8) bytes 이상 미리 할당되어 있어야 안전함
	 * 
	 */
	int KISA_HIGHT_CBC_ENCRYPT(unsigned char *userkey,
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
	 * 사용자 입력 초기 벡터 (8 bytes)
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
	int KISA_HIGHT_CBC_DECRYPT(unsigned char *userkey,
							  unsigned char *iv,
							  unsigned char *in,
							  unsigned int   len,
							  unsigned char *out);

#ifdef  __cplusplus
}
#endif

#endif