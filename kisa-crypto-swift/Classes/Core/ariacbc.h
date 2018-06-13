/*!
 * \file aria.h
 * \brief ARIA 암호 알고리즘 ( 관련표준 :  KS X 1213:2004 )
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */

#ifndef HEADER_ARIA_H
#define HEADER_ARIA_H

#define ARIA_ENCRYPT	1			/*!< ARIA의 암호화*/
#define ARIA_DECRYPT	0			/*!< ARIA의 복호화*/

#define ARIA_BLOCK_SIZE	16			/*!< ARIA의 BLOCK_SIZE*/

#define ARIA128 128
#define ARIA192 192
#define ARIA256 256

#define ARIA128_KEY_SIZE		16					
#define ARIA192_KEY_SIZE		24					
#define ARIA256_KEY_SIZE		32

#define ARIA128_IV_SIZE			ARIA_BLOCK_SIZE		

#define ARIA_MAXKB	32
#define ARIA_MAXNR	16
#define ARIA_WORD_SIZE  4


#ifdef  __cplusplus
extern "C" {
#endif


	/*!
	 * \brief
	 * ARIA Key 구조체
	 */
	typedef struct kisa_aria_key_st {
		unsigned char rk[ARIA_MAXNR * (ARIA_MAXNR+1)];		
		int nr;
	} KISA_ARIA_KEY ;


	/*!
	 * \brief
	 * ARIA 암호화 알고리즘 CBC 운영모드 지원을 위한 범용 구조체
	 */
	typedef struct kisa_aria_cbc_info_st {	
		int				encrypt;							/*!< 암호화/복호화 모드 지정자*/
		unsigned char	ivec[ARIA_BLOCK_SIZE];				/*!< 초기 벡터*/
		KISA_ARIA_KEY	ariakey;
		unsigned char	cbc_buffer[ARIA_BLOCK_SIZE];		/*!< 내부 버퍼*/
		int				buffer_length;						/*!< 내부 버퍼의 길이*/
		unsigned char	cbc_last_block[ARIA_BLOCK_SIZE];	/*!< CBC 지원 버퍼*/
		int				last_block_flag;					/*!< CBC 지원 버퍼 사용 여부*/
	} KISA_ARIA_CBC_INFO;

	
	void KISA_ARIA_encrypt_init(const unsigned char *userkey, int keyBits, KISA_ARIA_KEY *ariakey);
	void KISA_ARIA_decrypt_init(const unsigned char *userkey, int keyBits, KISA_ARIA_KEY *ariakey);
	void KISA_ARIA_process_block(const unsigned char *in, unsigned char *out, KISA_ARIA_KEY *ariakey);

	int KISA_ARIA_CBC_init(KISA_ARIA_CBC_INFO *info, int encrypt, int bits, unsigned char *user_key ,unsigned char *iv);
	int KISA_ARIA_CBC_process(KISA_ARIA_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen);
	int KISA_ARIA_CBC_close(KISA_ARIA_CBC_INFO *info, unsigned char *out, int *outLen);
	

		/*!
	 * \brief
	 * ARIA 128bit CBC 암호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
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
	int KISA_ARIA128_CBC_ENCRYPT(unsigned char *userkey,
							     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);

	/*!
	 * \brief
	 * ARIA 128bit CBC 복호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
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
	int KISA_ARIA128_CBC_DECRYPT(unsigned char *userkey,
					  		     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);

		/*!
	 * \brief
	 * ARIA 192bit CBC 암호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(24 bytes)
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
	int KISA_ARIA192_CBC_ENCRYPT(unsigned char *userkey,
							     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);

	/*!
	 * \brief
	 * ARIA 192bit CBC 복호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(24 bytes)
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
	int KISA_ARIA192_CBC_DECRYPT(unsigned char *userkey,
					  		     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);

		/*!
	 * \brief
	 * ARIA 256bit CBC 암호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(32 bytes)
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
	int KISA_ARIA256_CBC_ENCRYPT(unsigned char *userkey,
							     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);

	/*!
	 * \brief
	 * ARIA 256bit CBC 복호화 함수. 주어진 입력에 대한 암호화를 처리(CBC모드, PKCS패딩)
	 * 
	 * \param userkey
	 * 사용자 입력 키(32 bytes)
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
	int KISA_ARIA256_CBC_DECRYPT(unsigned char *userkey,
					  		     unsigned char *iv,
							     unsigned char *in,
							     unsigned int   len,
							     unsigned char *out);




#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ARIA_H */

