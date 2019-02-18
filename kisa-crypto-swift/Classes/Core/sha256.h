/*!
 * \file sha.h
 * \brief SHA256 Digest 알고리즘 (관련표준 fips-180 - SECURE HASH STANDARD)
 * \author
 * Copyright (c) 2010 by \<KISA\>
 */
#ifndef SHA256_H
#define SHA256_H

#if WIN32 || KISA_WINMO_32
typedef unsigned __int64	uint64_t;
typedef unsigned int		uint32_t;
typedef unsigned int		uint16_t;
typedef unsigned char		uint8_t;
#else
#include <stdint.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_SIZE		64			/*!< SHA256 블럭 크기*/
#define SHA256_DIGEST_LENGTH	32			/*!< SHA256 Digest Output 크기*/


	/*!
	 * \brief
	 * SHA256 Digest를 위한 SHA256 구조체
	 */
	typedef struct sha256_structure {
		uint64_t l1;
		unsigned int l2;
		unsigned long data[8];
		unsigned char buf[SHA256_BLOCK_SIZE];
	} KISA_SHA256;

	
	/*!
	 * \brief
	 * SHA256 Digest를 위한 구조체 초기화 함수
	 * 
	 * \param sha256
	 * SHA256 Digest를 위한 구조체 지정 (미리 메모리가 할당되어 있어야 함)
	 * 
	 * \returns
	 * 초기화 성공 (1) / 메모리가 적절히 할당되지 않았을 경우 (0)
	 */
	int KISA_SHA256_init(KISA_SHA256 *sha256);


	/*!
	 * \brief
	 * SHA256 알고리즘 Digest 함수
	 * 
	 * \param sha256
	 * SHA256 Digest를 위한 구조체 지정 (KISA_SHA256_init으로 초기화 필요)
	 * 
	 * \param data
	 * 사용자 입력 평문
	 * 
	 * \param length
	 * 사용자 입력 평문의 길이
	 * 
	 * \returns
	 * 구동 성공 (1) / 메모리 할당 혹은 초기화가 적절히 이루어지지 않았을 경우 (0)
	 * 
	 * \remarks
	 * 사용자 입력 평문의 길이(length)는 data에 저장된 데이터의 길이와 일치해야 함
	 */
	int KISA_SHA256_update(KISA_SHA256 *sha256, const unsigned char *data, unsigned int length);


	/*!
	 * \brief
	 * SHA256 알고리즘 Digest 완료 함수
	 * 
	 * \param sha256
	 * SHA256 Digest를 위한 구조체 지정 (KISA_SHA256_init으로 초기화 필요)
	 * 
	 * \param md
	 * SHA256 Digest 값이 저장되는 버퍼
	 * 
	 * \returns
	 * 구동 성공 (1) / 메모리 할당 혹은 초기화가 적절히 이루어지지 않았을 경우 (0)
	 * 
	 * \remarks
	 * 출력버퍼 md의 크기는 SHA256 Digest의 한 블럭(32 Bytes) 이상으로 메모리 할당이 되어 있어야 함
	 * 
	 */
	int KISA_SHA256_final(KISA_SHA256 *sha256, unsigned char *md);

	/*!
	 * \brief
	 * SHA256 Digest 처리 함수
	 * 
	 * \param in
	 * 다이제스트 생성을 위한 메시지 입력 버퍼
	 * 
	 * \param len
	 * 입력 버퍼의 길이
	 *
	 * \param out
	 * 해시생성 결과가 입력될 버퍼
	 * 
	 * \returns
	 * 구동 성공 (생성된 해시의 길이) / 메모리 할당 혹은 초기화가 적절히 이루어지지 않았을 경우 (0)
	 *
	 * \remarks
	 * 출력버퍼 out의 크기는 SHA256 Digest의 결과(32 Bytes) 이상으로 메모리 할당이 되어 있어야 함
	 */
	int KISA_SHA256_MD(unsigned char *in, int len, unsigned char *out);

#ifdef  __cplusplus
}
#endif

#endif