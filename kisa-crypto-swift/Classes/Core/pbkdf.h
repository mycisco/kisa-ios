/*!
 * \file pbkdf.h
 * \brief HMAC-SHA2기반 PBKDF2 키 생성 알고리즘 (관련표준 : PKCS #5 v2.1: Password-Based Cryptography Standard )
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */

#ifndef HEADER_PBKDF_H
#define HEADER_PBKDF_H


#ifdef  __cplusplus
extern "C" {
#endif

	/*!
	 * \brief
	 * HMAC-SHA2에 기반한 PBKDF2 패스워드 기반 키생성 함수
	 * 
	 * \param password
	 * 입력될 패스워드
	 *
	 * \param passwordLen
	 * 입력된 패스워드의 길이
	 *
	 * \param salt
	 * 함께 사용될 SALT
	 *
	 * \param saltLen
	 * SALT의 길이
	 *
	 * \param iter
	 * 내부 해시 반복 카운트
	 *
	 * \param key
	 * 생성된 키가 입력될 버퍼
	 *
	 * \param keyLen
	 * 생성할 키의 길이
	 * 
	 * \returns
	 * 성공 (1) / 실패 (0)
	 */
	int KISA_PBKDF2(unsigned char* password,
					int passwordLen,
					unsigned char* salt,
					int saltLen,
					int iter,
					unsigned char* key,
					int keyLen);

#ifdef  __cplusplus
}
#endif
#endif

