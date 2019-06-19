#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "kcdsa.h"

unsigned int ROTL_WORD(unsigned int x, unsigned int n)
{
    return (((unsigned int)x << n) | ((unsigned int)x >> (32-n)));
}

unsigned int ENDIAN_REVERSE_WORD(unsigned int dwS)
{
    return ((ROTL_WORD(dwS, 8) & 0x00ff00ff) | (ROTL_WORD(dwS, 24) & 0xff00ff00));
}

void BIG_W2B(unsigned int W, unsigned int *B)
{
    *B = ENDIAN_REVERSE_WORD(W);
}

unsigned int KISA_KCDSA_CreateObject(KISA_KCDSA	**kcdsa)
{
	int i = 0;
	unsigned int		tt = 0;
	KISA_KCDSA	*BN_Key;

	if (kcdsa == NULL)
		return CTR_INVALID_POINTER;

	*kcdsa = BN_Key = (KISA_KCDSA *)malloc(sizeof(KISA_KCDSA));
	if (BN_Key == NULL)		goto LABEL_END0;
	memset((unsigned char *)BN_Key, 0, sizeof(KISA_KCDSA));

	tt = (BN_MAX_BITS - 1) / BitsInDIGIT + 1;
	if ((BN_Key->KCDSA_P = CreateBigNum(tt + 1)) == NULL)	goto LABEL_END0;
	if ((BN_Key->KCDSA_G = CreateBigNum(tt + 1)) == NULL)	goto LABEL_END0;
	if ((BN_Key->KCDSA_y = CreateBigNum(tt + 1)) == NULL)	goto LABEL_END0;
	for (i = 0; i < (tt + 1); i++)
	{
		BN_Key->KCDSA_P->pData[i] = 0;
		BN_Key->KCDSA_G->pData[i] = 0;
		BN_Key->KCDSA_y->pData[i] = 0;
	}
	tt = (256 - 1) / BitsInDIGIT + 1;
	if ((BN_Key->KCDSA_Q = CreateBigNum(tt + 1)) == NULL)	goto LABEL_END0;
	if ((BN_Key->KCDSA_x = CreateBigNum(tt + 1)) == NULL)	goto LABEL_END0;
	for (i = 0; i < (tt + 1); i++)
	{
		BN_Key->KCDSA_Q->pData[i] = 0;
		BN_Key->KCDSA_x->pData[i] = 0;
	}
	BN_Key->Count = 0;
	BN_Key->SeedLen = MAX_SEED_LEN;

	return CTR_SUCCESS;

LABEL_END0:
	KISA_KCDSA_DestroyObject(kcdsa);
	return CTR_MEMORY_ALLOC_ERROR;
}

unsigned int KCDSA_PRNG_SHA_224(
	SHA224_ALG_INFO	*SHA224_AlgInfo,
	unsigned char		*pbSrc,
	unsigned int		dSrcByteLen,
	unsigned char		*pbDst,
	unsigned int		dDstBitLen)
{
	unsigned char		Count = 0, DigestValue[SHA224_DIGEST_VALUELEN] = { 0, };
	unsigned int		i;
	unsigned int tempLen = dSrcByteLen;
	unsigned char *tempSrc = (unsigned char *)malloc((unsigned char)tempLen);

    for (i = 0; (int)i < (int)dSrcByteLen; i++)
		tempSrc[i] = pbSrc[i];

	i = ((dDstBitLen + 7) & 0xFFFFFFF8) / 8;
    
	for (Count = 0;; Count++) {
		SHA224_Init(SHA224_AlgInfo);
		SHA224_Update(SHA224_AlgInfo, tempSrc, tempLen);
		SHA224_Update(SHA224_AlgInfo, &Count, 1);
		SHA224_Final(SHA224_AlgInfo, DigestValue);
        
		if ((int)i >= SHA224_DIGEST_VALUELEN) {
			i = i-SHA224_DIGEST_VALUELEN;
			memcpy(pbDst + i, DigestValue, SHA224_DIGEST_VALUELEN);
			if ((int)i == 0)	break;
		}
		else {
			memcpy(pbDst, DigestValue + SHA224_DIGEST_VALUELEN - i, i);
			break;
		}
	}

	i = (dDstBitLen&0xffffffff) & 0x07;
	if ((int)i)
		pbDst[0] = (pbDst[0]&0xffffffff) & ((((unsigned int)1 << (int)i)) - 1);
    
	free(tempSrc);

	return CTR_SUCCESS;
}

unsigned int KCDSA_PRNG_SHA_256(
	SHA256_ALG_INFO	*SHA256_AlgInfo,
	unsigned char		*pbSrc,
	unsigned int		dSrcByteLen,
	unsigned char		*pbDst,
	unsigned int		dDstBitLen)
{
	unsigned char		Count = 0, DigestValue[SHA256_DIGEST_VALUELEN] = { 0, };
	unsigned int		i = 0;
	unsigned int tempLen = dSrcByteLen;
	unsigned char *tempSrc = (unsigned char *)malloc((unsigned char)tempLen);

	for (i = 0; i < dSrcByteLen; i++)
		tempSrc[i] = pbSrc[i];

	i = ((dDstBitLen + 7) & 0xFFFFFFF8) / 8;

	for (Count = 0;; Count++) {
		SHA256_Init(SHA256_AlgInfo);
		SHA256_Update(SHA256_AlgInfo, tempSrc, tempLen);
		SHA256_Update(SHA256_AlgInfo, &Count, 1);
		SHA256_Final(SHA256_AlgInfo, DigestValue);

		if (i >= SHA256_DIGEST_VALUELEN) {
			i -= SHA256_DIGEST_VALUELEN;
			memcpy(pbDst + i, DigestValue, SHA256_DIGEST_VALUELEN);
			if (i == 0)	break;
		}
		else {
			memcpy(pbDst, DigestValue + SHA256_DIGEST_VALUELEN - i, i);
			break;
		}
	}
    
    i = (dDstBitLen&0xffffffff) & 0x07;
	if ((int)i)
		pbDst[0] = (pbDst[0]&0xffffffff) & ((((unsigned int)1 << (int)i)) - 1);

	free(tempSrc);

	return CTR_SUCCESS;
}

unsigned int Generate_Random(
	BIGNUM	*XKEY,
	unsigned char *pbSrc,
	unsigned int dSrcByteLen,
	unsigned int *X,
	unsigned int XBitLen,
	KISA_KCDSA	*kcdsa,
	unsigned int HASH)
{
	int i, j;
	unsigned int ret = 0;
	unsigned char *bzTmp1, *bzTmp2;

	BIGNUM *VAL = NULL, *BN_Tmp1 = NULL;
	SHA224_ALG_INFO	SHA224_AlgInfo;
	SHA256_ALG_INFO	SHA256_AlgInfo;

	if (HASH == SHA224)
	{
		bzTmp1 = (unsigned char *)malloc(224 / 8 + 1);
		bzTmp2 = (unsigned char *)malloc(224 / 8 + 1);
		for (j = 0; j < SHA224_DIGEST_VALUELEN / 4; j++)
			SHA224_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j < 4; j++)
			SHA224_AlgInfo.Count[j] = 0;
		for (j = 0; j < SHA224_DIGEST_BLOCKLEN; j++)
			SHA224_AlgInfo.Buffer[j] = 0;
	}
	else if (HASH == SHA256)
	{
		bzTmp1 = (unsigned char *)malloc(256 / 8 + 1);
		bzTmp2 = (unsigned char *)malloc(256 / 8 + 1);
		for (j = 0; j < SHA256_DIGEST_VALUELEN / 4; j++)
			SHA256_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j < 4; j++)
			SHA256_AlgInfo.Count[j] = 0;
		for (j = 0; j < SHA256_DIGEST_BLOCKLEN; j++)
			SHA256_AlgInfo.Buffer[j] = 0;
	}
	else {
		ret = CTR_INVALID_ALG_PARAMS;
		GOTO_END;
	}

	if ((VAL = CreateBigNum(XBitLen / 32)) == NULL)			goto LABEL_END;
	if ((BN_Tmp1 = CreateBigNum(XBitLen / 32)) == NULL)			goto LABEL_END;

	for (j = 0; j < (int)(XBitLen / 32 + 1); j++)
	{
		VAL->pData[j] = 0;
		BN_Tmp1->pData[j] = 0;
	}

	if (HASH == SHA224)
	{
		ret = KCDSA_PRNG_SHA_224(&SHA224_AlgInfo, pbSrc, dSrcByteLen, bzTmp1, XBitLen);			GOTO_END;
	}
	else if (HASH == SHA256)
	{
		ret = KCDSA_PRNG_SHA_256(&SHA256_AlgInfo, pbSrc, dSrcByteLen, bzTmp1, XBitLen);			GOTO_END;
	}

	ret = OS2BN(bzTmp1, XBitLen / 8, BN_Tmp1);	GOTO_END;

	ret = BN_Add(VAL, XKEY, BN_Tmp1);	GOTO_END;

	if (VAL->pData[XBitLen / 32] != 0)
	{
		VAL->pData[XBitLen / 32] = 0;
		VAL->Length -= 1;
		VAL->Space -= 1;
	}

	ret = BN2OS(VAL, VAL->Length * 4, bzTmp1);									GOTO_END;

	if (HASH == SHA224)
	{
		ret = KCDSA_PRNG_SHA_224(&SHA224_AlgInfo, bzTmp1, VAL->Length * 4, bzTmp2, XBitLen);			GOTO_END;
	}
	else
	{
		ret = KCDSA_PRNG_SHA_256(&SHA256_AlgInfo, bzTmp1, VAL->Length * 4, bzTmp2, XBitLen);			GOTO_END;
	}

	ret = OS2BN(bzTmp2, XBitLen / 8, BN_Tmp1);	GOTO_END;

	while (BN_Cmp(BN_Tmp1, kcdsa->KCDSA_Q) >= 0) {
		ret = BN_Sub(BN_Tmp1, BN_Tmp1, kcdsa->KCDSA_Q);			GOTO_END;
	}

	for (i = 0; i < (int)(XBitLen / 32); i++)
		X[i] = BN_Tmp1->pData[i];
	
	free(bzTmp1);
	free(bzTmp2);

LABEL_END:
	if (VAL != NULL)		DestroyBigNum(VAL);
	if (BN_Tmp1 != NULL)	DestroyBigNum(BN_Tmp1);
	return ret;
}

unsigned int KISA_KCDSA_GenerateKeyPair(
	KISA_KCDSA		*KCDSA_Key,
	unsigned char	*pbSrc,
	unsigned int	dSrcByteLen,
	unsigned int	qLen,
	unsigned int	HASH)
{
	unsigned int		i = 0;
	unsigned int		ret = 0;
	BIGNUM		*BN_Tmp1 = NULL;
	BIGNUM		*XKEY = NULL;

	if (KCDSA_Key == NULL)		return CTR_INVALID_POINTER;

	i = KCDSA_Key->KCDSA_P->Length;
	if ((BN_Tmp1 = CreateBigNum(i + 1)) == NULL)	goto LABEL_END;
	if ((XKEY = CreateBigNum(qLen / 32)) == NULL)	goto LABEL_END;
	
	if (KCDSA_Key->KCDSA_x->Length == 0) {
		// b 비트의 임의의 정수 XKEY 생성
		srand((unsigned)time(NULL));
		ret = BN_Rand(XKEY, qLen);			GOTO_END;
		
		/*p = 2048, q = 224, SHA-224 test vector*/
		/*XKEY->pData[0] = 0xa89150be;
		XKEY->pData[1] = 0xeff64b4c;
		XKEY->pData[2] = 0x4b90ffdf;
		XKEY->pData[3] = 0x046d5de1;
		XKEY->pData[4] = 0xd61495ea;
		XKEY->pData[5] = 0x20d9ba54;
		XKEY->pData[6] = 0xf910456a;
		XKEY->Length = 7;
		XKEY->Space = 8;*/

		/*p = 2048, q = 224, SHA-256 test vector*/
		/*XKEY->pData[0] = 0xa89150be;
		XKEY->pData[1] = 0xeff64b4c;
		XKEY->pData[2] = 0x4b90ffdf;
		XKEY->pData[3] = 0x046d5de1;
		XKEY->pData[4] = 0xd61495ea;
		XKEY->pData[5] = 0x20d9ba54;
		XKEY->pData[6] = 0xf910456a;
		XKEY->Length = 7;
		XKEY->Space = 8;*/

		/*p = 2048, q = 256, SHA-256 test vector*/
		/*XKEY->pData[0] = 0xb948da94;
		XKEY->pData[1] = 0xc0a936e2;
		XKEY->pData[2] = 0x2e97da0b;
		XKEY->pData[3] = 0x8b904cf1;
		XKEY->pData[4] = 0x3bf2ab78;
		XKEY->pData[5] = 0x587274d3;
		XKEY->pData[6] = 0xa667cf10;
		XKEY->pData[7] = 0xf0f30814;
		XKEY->Length = 8;
		XKEY->Space = 9;*/

		/*p = 3072, q = 256, SHA-256 test vector*/
		/*XKEY->pData[0] = 0x14dfce52;
		XKEY->pData[1] = 0xf1a369ab;
		XKEY->pData[2] = 0xfa2bb0cd;
		XKEY->pData[3] = 0xc3ca4c8e;
		XKEY->pData[4] = 0xc40e94d7;
		XKEY->pData[5] = 0x47c7ac5b;
		XKEY->pData[6] = 0xd9e9230d;
		XKEY->pData[7] = 0x80f96d39;
		XKEY->Length = 8;
		XKEY->Space = 9;*/

		// 전자서명키 x 생성
		ret = Generate_Random(XKEY, pbSrc, dSrcByteLen, KCDSA_Key->KCDSA_x->pData, qLen, KCDSA_Key, HASH);
		KCDSA_Key->KCDSA_x->Length = qLen / 32;
	}

	ret = BN_ModInv(BN_Tmp1, KCDSA_Key->KCDSA_x, KCDSA_Key->KCDSA_Q);
	GOTO_END;

	// x의 역원 생성
	ret = BN_ModInv(BN_Tmp1, KCDSA_Key->KCDSA_x, KCDSA_Key->KCDSA_Q);	GOTO_END;

	// 전자서명 검증키 y 생성(Y = G^{X^{-1} mod Q} mod P)
	ret = BN_ModExp(KCDSA_Key->KCDSA_y, KCDSA_Key->KCDSA_G, BN_Tmp1, KCDSA_Key->KCDSA_P);				GOTO_END;
	
LABEL_END:
	if (BN_Tmp1 != NULL)		DestroyBigNum(BN_Tmp1);
	if (XKEY != NULL)			DestroyBigNum(XKEY);
	return ret;
}

unsigned int KISA_KCDSA_sign(
	KISA_KCDSA			*kcdsa, 
	unsigned char		*MsgDigest, 
	unsigned int		MsgDigestLen,
	unsigned char		*Signature,
	unsigned int		*SignLen,
	unsigned int		HASH,
	unsigned char		*t_omgri,
	unsigned int		omgri_len)
{
	unsigned char	bzTmp[3072 / 8] = { 0, };
	unsigned char	bzTmp1[64];
	unsigned char	*hashTmp;
	unsigned int	i = 0, j = 0, qByteLen = 0, DigestLen = 0;
	unsigned int	ret;
	BIGNUM		*BN_K = NULL, *BN_Tmp1 = NULL, *KCDSA_s = NULL;
	BIGNUM		*KKEY = NULL;
	SHA224_ALG_INFO	SHA224_AlgInfo;
	SHA256_ALG_INFO	SHA256_AlgInfo;

	if (HASH == SHA224)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA224_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA224_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA224_DIGEST_BLOCKLEN; j++)
			SHA224_AlgInfo.Buffer[j] = 0;
	}
	else if (HASH == SHA256)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA256_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA256_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA256_DIGEST_BLOCKLEN; j++)
			SHA256_AlgInfo.Buffer[j] = 0;
	}
	else {
		ret = CTR_INVALID_ALG_PARAMS;
		GOTO_END;
	}
	
	if (kcdsa == NULL)	return CTR_INVALID_POINTER;

	if (HASH == SHA224)
		DigestLen = SHA224_DIGEST_VALUELEN;
	else if (HASH == SHA256)
		DigestLen = SHA256_DIGEST_VALUELEN;

	qByteLen = (unsigned int)(DIGITSIZE) * (kcdsa->KCDSA_Q->Length); // Q의 바이트단위 길이를 저장

	if (SignLen != NULL) { // 사인의 길이가 입력이 있는경우
		i = *SignLen;
		if((HASH == SHA224 && qByteLen == 28) || (HASH == SHA256 && qByteLen == 32))
			*SignLen = DigestLen + qByteLen;
		else
			*SignLen = qByteLen + qByteLen;
		ret = CTR_BUFFER_TOO_SMALL;
		if ((i != 0) && (i<*SignLen))			goto LABEL_END;
	}
	if (Signature == NULL)	return CTR_INVALID_POINTER; // 사인이 NULL이면 성공적으로 종료

	if (MsgDigest == NULL)	return CTR_INVALID_POINTER; // MsgDigest가 NULL이면 오류

	ret = CTR_MEMORY_ALLOC_ERROR;
	// P의 크기만큼  K와 Tmp1에 공간 할당
	i = kcdsa->KCDSA_P->Length;
	if ((BN_K = CreateBigNum(i + 1)) == NULL)		goto LABEL_END;
	if ((BN_Tmp1 = CreateBigNum(i + 1)) == NULL)	goto LABEL_END;
	// Q의 크기만큼 S에 공간 할당
	i = kcdsa->KCDSA_Q->Length;
	if ((KCDSA_s = CreateBigNum(i + 1)) == NULL)	goto LABEL_END;
	if ((KKEY = CreateBigNum(i + 1)) == NULL)		goto LABEL_END;

	// step 1. 난수 k를 [1, Q-1]에서 임의로 선택한다.
	srand((unsigned)time(NULL));
	ret = BN_Rand(KKEY, 8 * qByteLen);	GOTO_END;
	
	/*p = 2048, q = 224, SHA-224 test vector*/
	/*KKEY->pData[0] = 0xc1fb7222;
	KKEY->pData[1] = 0x71382b7d;
	KKEY->pData[2] = 0xd33ad7fb;
	KKEY->pData[3] = 0x04ac91d7;
	KKEY->pData[4] = 0x74f4f9db;
	KKEY->pData[5] = 0xd5ee4a09;
	KKEY->pData[6] = 0xb7b75e77;
	KKEY->Length = 7;
	KKEY->Space = 8;*/

	/*p = 2048, q = 224, SHA-256 test vector*/
	/*KKEY->pData[0] = 0xc1fb7222;
	KKEY->pData[1] = 0x71382b7d;
	KKEY->pData[2] = 0xd33ad7fb;
	KKEY->pData[3] = 0x04ac91d7;
	KKEY->pData[4] = 0x74f4f9db;
	KKEY->pData[5] = 0xd5ee4a09;
	KKEY->pData[6] = 0xb7b75e77;
	KKEY->Length = 7;
	KKEY->Space = 8;*/

	/*p = 2048, q = 256, SHA-256 test vector*/
	/*KKEY->pData[0] = 0x9475cf69;
	KKEY->pData[1] = 0x3d053f8a;
	KKEY->pData[2] = 0x9f55d297;
	KKEY->pData[3] = 0xb5ef2d93;
	KKEY->pData[4] = 0x59536696;
	KKEY->pData[5] = 0x4b2a759e;
	KKEY->pData[6] = 0xf737ace8;
	KKEY->pData[7] = 0xb2425ced;
	KKEY->Length = 8;
	KKEY->Space = 9;*/

	/*p = 3072, q = 256, SHA-256 test vector*/
	/*KKEY->pData[0] = 0x80804468;
	KKEY->pData[1] = 0x8dad0082;
	KKEY->pData[2] = 0x726b22c0;
	KKEY->pData[3] = 0x1acaa16c;
	KKEY->pData[4] = 0xe4f6028e;
	KKEY->pData[5] = 0x0383e4e9;
	KKEY->pData[6] = 0xc87ae1f6;
	KKEY->pData[7] = 0xa3d070cb;
	KKEY->Length = 8;
	KKEY->Space = 9;*/
		
	ret = Generate_Random(KKEY, t_omgri, omgri_len, BN_K->pData, kcdsa->KCDSA_Q->Length * 32, kcdsa, HASH);
	BN_K->Length = kcdsa->KCDSA_Q->Length;
	BN_K->Space = kcdsa->KCDSA_Q->Length + 1;

	// Q와 K의 길이는 같음.
	// Q와 K의 크기를 비교해서 K가 더 크면 Q을 빼주는 연산을 함.
	if (BN_Cmp(BN_K, kcdsa->KCDSA_Q) >= 0) {
		ret = BN_Sub(BN_K, BN_K, kcdsa->KCDSA_Q);						GOTO_END;
	}

	// step 2. W=G^K mod P를 계산한다.
	ret = BN_ModExp(BN_Tmp1, kcdsa->KCDSA_G, BN_K, kcdsa->KCDSA_P);		GOTO_END;

	//	step 3. 서명의 첫 부분 R=h(W)를 계산한다.
	i = DIGITSIZE * kcdsa->KCDSA_P->Length; // 바이트 단위 길이
	ret = BN2OS(BN_Tmp1, i, bzTmp);									GOTO_END;
	j = i;
	if (HASH == SHA224)
	{
		SHA224_Init(&SHA224_AlgInfo);
		SHA224_Update(&SHA224_AlgInfo, bzTmp, j);
		SHA224_Final(&SHA224_AlgInfo, bzTmp);
		memcpy(Signature, bzTmp, SHA224_DIGEST_VALUELEN);
	}
	else if (HASH == SHA256)
	{
		SHA256_Init(&SHA256_AlgInfo);
		SHA256_Update(&SHA256_AlgInfo, bzTmp, j);
		SHA256_Final(&SHA256_AlgInfo, bzTmp);
		if(qByteLen == 28)
			memcpy(Signature, bzTmp+4, SHA224_DIGEST_VALUELEN);
		else
			memcpy(Signature, bzTmp, SHA256_DIGEST_VALUELEN);
	}

	// step 4. Z = Y mod 2^l(사전에 계산되어 있음)
	// step 5. h = Hash(Z||M)을 계산한다.
	hashTmp = (unsigned char*)malloc((64 + MsgDigestLen) * sizeof(unsigned char));
	i = kcdsa->KCDSA_y->Length;
	kcdsa->KCDSA_y->Length = 512 / BitsInDIGIT;
	ret = BN2OS(kcdsa->KCDSA_y, 512 / 8, bzTmp1);		GOTO_END;
	kcdsa->KCDSA_y->Length = i;
	memcpy(hashTmp, bzTmp1, 64);
	memcpy(hashTmp + 64, MsgDigest, MsgDigestLen);

	if (HASH == SHA224)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA224_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA224_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA224_DIGEST_BLOCKLEN; j++)
			SHA224_AlgInfo.Buffer[j] = 0;
		SHA224_Init(&SHA224_AlgInfo);
		SHA224_Update(&SHA224_AlgInfo, hashTmp, 64 + MsgDigestLen);
		SHA224_Final(&SHA224_AlgInfo, hashTmp);
	}
	else if (HASH == SHA256)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA256_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA256_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA256_DIGEST_BLOCKLEN; j++)
			SHA256_AlgInfo.Buffer[j] = 0;
		SHA256_Init(&SHA256_AlgInfo);
		SHA256_Update(&SHA256_AlgInfo, hashTmp, 64 + MsgDigestLen);
		SHA256_Final(&SHA256_AlgInfo, hashTmp);
	}

	// step 6. E = (R ^ H) mod Q를 계산한다.
	if ((HASH == SHA224 && qByteLen == 28) || (HASH == SHA256 && qByteLen == 32))
		for (i = 0; i < DigestLen; i++)	bzTmp[i] ^= hashTmp[i];
	else
	{
		for (i = 0; i < qByteLen; i++) bzTmp[i + 4] ^= hashTmp[i + 4];
		for (i = 0; i < qByteLen; i++) bzTmp[i] = bzTmp[i + 4];
	}

	free(hashTmp);

	ret = OS2BN(bzTmp, i, BN_Tmp1);							GOTO_END;
	ret = BN_ModRed(BN_Tmp1, BN_Tmp1, kcdsa->KCDSA_Q);		GOTO_END;
	
	//	step 7. S = X(K-E) mod Q를 계산한다.
	ret = BN_ModSub(BN_K, BN_K, BN_Tmp1, kcdsa->KCDSA_Q);			GOTO_END;
	ret = BN_ModMul(KCDSA_s, kcdsa->KCDSA_x, BN_K, kcdsa->KCDSA_Q);	GOTO_END;

	ret = BN2OS(KCDSA_s, qByteLen, Signature + qByteLen);			GOTO_END;
	
	ret = CTR_SUCCESS;
LABEL_END:
	if (BN_K != NULL)		DestroyBigNum(BN_K);
	if (BN_Tmp1 != NULL)	DestroyBigNum(BN_Tmp1);
	if (KCDSA_s != NULL)	DestroyBigNum(KCDSA_s);
	if (KKEY != NULL)		DestroyBigNum(KKEY);
	return ret;
}

unsigned int KISA_KCDSA_verify(
	KISA_KCDSA			*kcdsa,
	unsigned char		*MsgDigest,
	unsigned int		MsgDigestLen,
	unsigned char		*Signature,
	unsigned int		SignLen,
	unsigned int		HASH)
{
	unsigned char	bzTmp[3072 / 8] = { 0, };
	unsigned char	bzTmp1[64];
	unsigned char	*hashTmp;
	unsigned int	i = 0, j = 0, qByteLen = 0, DigestLen = 0;
	unsigned int	ret;
	BIGNUM		*BN_Tmp1 = NULL, *BN_Tmp2 = NULL, *BN_Tmp3 = NULL, *KCDSA_s = NULL;
	SHA224_ALG_INFO	SHA224_AlgInfo;
	SHA256_ALG_INFO	SHA256_AlgInfo;

	if (HASH == SHA224)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA224_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA224_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA224_DIGEST_BLOCKLEN; j++)
			SHA224_AlgInfo.Buffer[j] = 0;
	}
	else if (HASH == SHA256)
	{
		for (j = 0; j<SHA256_DIGEST_VALUELEN / 4; j++)
			SHA256_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j<4; j++)
			SHA256_AlgInfo.Count[j] = 0;
		for (j = 0; j<SHA256_DIGEST_BLOCKLEN; j++)
			SHA256_AlgInfo.Buffer[j] = 0;
	}
	else {
		ret = CTR_INVALID_ALG_PARAMS;
		GOTO_END;
	}

	if ((kcdsa == NULL) || (MsgDigest == NULL) || (Signature == NULL))
		return CTR_INVALID_POINTER;

	if (HASH == SHA224)
		DigestLen = SHA224_DIGEST_VALUELEN;
	else if (HASH == SHA256)
		DigestLen = SHA256_DIGEST_VALUELEN;

	qByteLen = DIGITSIZE * kcdsa->KCDSA_Q->Length;

	if ((SignLen != DigestLen + qByteLen) && (SignLen != qByteLen + qByteLen))	return CTR_INVALID_SIGNATURE_LEN;

	ret = CTR_MEMORY_ALLOC_ERROR;
	i = kcdsa->KCDSA_P->Length;
	if ((BN_Tmp1 = CreateBigNum(i)) == NULL)	goto LABEL_END;
	if ((BN_Tmp2 = CreateBigNum(i)) == NULL)	goto LABEL_END;
	if ((BN_Tmp3 = CreateBigNum(i)) == NULL)	goto LABEL_END;
	i = kcdsa->KCDSA_Q->Length;
	if ((KCDSA_s = CreateBigNum(i)) == NULL)	goto LABEL_END;

	memcpy(bzTmp, Signature, qByteLen);
	ret = OS2BN(Signature + qByteLen, qByteLen, KCDSA_s);				GOTO_END;

	ret = CTR_VERIFY_FAIL;
	if (BN_Cmp(KCDSA_s, kcdsa->KCDSA_G) >= 0)			goto LABEL_END;

	// step 1. 수신된 서명 {R', S'}에 대해 |R'|=LH, 0 < S' < Q 임을 확인한다.
	// step 2. Z = Y mod 2^l(사전에 계산되어 있음)
	// step 3. h = Hash(Z||M)을 계산한다.
	hashTmp = (unsigned char*)malloc((64 + MsgDigestLen) * sizeof(unsigned char));
	i = kcdsa->KCDSA_y->Length;
	kcdsa->KCDSA_y->Length = 512 / BitsInDIGIT;
	ret = BN2OS(kcdsa->KCDSA_y, 512 / 8, bzTmp1);		GOTO_END;
	kcdsa->KCDSA_y->Length = i;
	memcpy(hashTmp, bzTmp1, 64);
	memcpy(hashTmp + 64, MsgDigest, MsgDigestLen);

	if (HASH == SHA224)
	{
		SHA224_Init(&SHA224_AlgInfo);
		SHA224_Update(&SHA224_AlgInfo, hashTmp, 64 + MsgDigestLen);
		SHA224_Final(&SHA224_AlgInfo, hashTmp);
	}
	else if (HASH == SHA256)
	{
		SHA256_Init(&SHA256_AlgInfo);
		SHA256_Update(&SHA256_AlgInfo, hashTmp, 64 + MsgDigestLen);
		SHA256_Final(&SHA256_AlgInfo, hashTmp);
	}

	// step 4. E' = (R' ^ H') mod Q을 계산한다.
	if ((HASH == SHA224 && qByteLen == 28) || (HASH == SHA256 && qByteLen == 32))
		for (i = 0; i < DigestLen; i++)	bzTmp[i] ^= hashTmp[i];
	else
		for (i = 0; i < qByteLen; i++) bzTmp[i] ^= hashTmp[i + 4];

	free(hashTmp);

	ret = OS2BN(bzTmp, i, BN_Tmp1);							GOTO_END;
	ret = BN_ModRed(BN_Tmp1, BN_Tmp1, kcdsa->KCDSA_Q);		GOTO_END;

	// step 5. W' = Y ^ {S'} G ^ {E'} mod P를 계산한다.
	ret = BN_ModExp(BN_Tmp2, kcdsa->KCDSA_y, KCDSA_s, kcdsa->KCDSA_P);				GOTO_END;
	ret = BN_ModExp(BN_Tmp3, kcdsa->KCDSA_G, BN_Tmp1, kcdsa->KCDSA_P);				GOTO_END;
	ret = BN_ModMul(BN_Tmp1, BN_Tmp2, BN_Tmp3, kcdsa->KCDSA_P);						GOTO_END;

	// step 6. h(W') = R'이 성립하는지 확인한다.
	i = DIGITSIZE * kcdsa->KCDSA_P->Length;
	ret = BN2OS(BN_Tmp1, i, bzTmp);							GOTO_END;
	j = i;
	i = 0;
	if (HASH == SHA224)
	{
		SHA224_Init(&SHA224_AlgInfo);
		SHA224_Update(&SHA224_AlgInfo, bzTmp, j);
		SHA224_Final(&SHA224_AlgInfo, bzTmp);

		ret = CTR_VERIFY_FAIL;

		if (memcmp(bzTmp, Signature, SHA224_DIGEST_VALUELEN) != 0)
			goto LABEL_END;
	}
	else if (HASH == SHA256)
	{
		SHA256_Init(&SHA256_AlgInfo);
		SHA256_Update(&SHA256_AlgInfo, bzTmp, j);
		SHA256_Final(&SHA256_AlgInfo, bzTmp);

		ret = CTR_VERIFY_FAIL;

		if (qByteLen == 28)
		{
			if (memcmp(bzTmp + 4, Signature, qByteLen) != 0)
				goto LABEL_END;
		}
		else
		{
			if (memcmp(bzTmp, Signature, SHA256_DIGEST_VALUELEN) != 0)
				goto LABEL_END;
		}
	}

	ret = CTR_SUCCESS;
LABEL_END:
	if (BN_Tmp1 != NULL)	DestroyBigNum(BN_Tmp1);
	if (BN_Tmp2 != NULL)	DestroyBigNum(BN_Tmp2);
	if (BN_Tmp3 != NULL)	DestroyBigNum(BN_Tmp3);
	if (KCDSA_s != NULL)	DestroyBigNum(KCDSA_s);
	return ret;
}

unsigned int KISA_KCDSA_set_params(KISA_KCDSA *kcdsa, unsigned int *p, int plen, unsigned int *q, int qlen, unsigned int *g, int glen, unsigned int *private_key, int private_keylen, unsigned int *public_key, int public_keylen)
{
	int i;

	for (i = 0; i < plen; i++) {
		kcdsa->KCDSA_P->pData[i] = p[i];
	}
	kcdsa->KCDSA_P->Length = plen;
	kcdsa->KCDSA_P->Space = plen + 1;

	for (i = 0; i < qlen; i++) {
		kcdsa->KCDSA_Q->pData[i] = q[i];
	}
	kcdsa->KCDSA_Q->Length = qlen;
	kcdsa->KCDSA_Q->Space = qlen + 1;

	for (i = 0; i < glen; i++) {
		kcdsa->KCDSA_G->pData[i] = g[i];
	}
	kcdsa->KCDSA_G->Length = glen;
	kcdsa->KCDSA_G->Space = glen + 1;

	for (i = 0; i < private_keylen; i++) {
		kcdsa->KCDSA_x->pData[i] = private_key[i];
	}
	kcdsa->KCDSA_x->Length = private_keylen;
	kcdsa->KCDSA_x->Space = private_keylen + 1;

	for (i = 0; i < public_keylen; i++) {
		kcdsa->KCDSA_y->pData[i] = public_key[i];
	}
	kcdsa->KCDSA_y->Length = public_keylen;
	kcdsa->KCDSA_y->Space = public_keylen + 1;

	return 0;
}
unsigned int KISA_KCDSA_GenerateParameters(
	unsigned int	PrimeBits,
	unsigned int	SubPrimeBits,
	KISA_KCDSA		*kcdsa,
	unsigned int	HASH)
{
	int j;
	unsigned char		bzTmp[3072 / 8 + 4] = { 0, };
	unsigned char		tSeed[256 / 8 + 4] = { 0x00, };
	/*p = 2048, q = 224, SHA-224 test vector*/
	//unsigned char		tSeed[256 / 8 + 4] = { 0xc0, 0x52, 0xa2, 0x76, 0x41, 0x00, 0xf0, 0xf4, 0xec, 0x90, 0x6b, 0x9c, 0x5c, 0x6b, 0x10, 0x6e, 0x34, 0x70, 0xdf, 0xc1, 0x36, 0x9f, 0x12, 0xc0, 0x62, 0xf8, 0x0e, 0xe9 };
	/*p = 2048, q = 224, SHA-256 test vector*/
	//unsigned char		tSeed[256 / 8 + 4] = { 0xe1, 0x75, 0xca, 0xd0, 0xea, 0xcb, 0x74, 0xdd, 0xb4, 0x5f, 0x15, 0xf1, 0xf2, 0x57, 0x22, 0xbf, 0x15, 0x56, 0xef, 0x86, 0x0a, 0x0f, 0xe0, 0x31, 0x71, 0x18, 0x44, 0x9b };
	/*p = 2048, q = 256, SHA-256 test vector*/
	//unsigned char		tSeed[256 / 8 + 4] = { 0xf7, 0x5a, 0xbd, 0xa0, 0x03, 0x2c, 0xe2, 0x18, 0xce, 0x04, 0xba, 0xf0, 0xa6, 0xdc, 0x92, 0xc8, 0x7e, 0xb4, 0x6a, 0xa0, 0x56, 0x8c, 0x42, 0x78, 0x2e, 0x64, 0x4c, 0xc2, 0xb8, 0x2e, 0x24, 0x9a };
	/*p = 3072, q = 256, SHA-256 test vector*/
    //unsigned char		tSeed[256 / 8 + 4] = { 0xb8, 0x56, 0x20, 0x16, 0x38, 0x55, 0xa7, 0xc0, 0x05, 0x76, 0x13, 0xdc, 0xd1, 0xf2, 0xae, 0x61, 0x80, 0xc4, 0x34, 0xd0, 0x98, 0x90, 0xea, 0x70, 0x22, 0x00, 0x83, 0xf2, 0x8d, 0x27, 0x54, 0xad };
	unsigned int		i = 0, Count = 0;
	unsigned int		ret;
	unsigned int		g[96];
	/*p = 2048, q = 224, SHA-224 test vector*/
	//unsigned int g[] = { 0x967500f2, 0x4ae06466, 0x8c2eb468, 0xc05a92f8, 0xc314fe16, 0x545cf834, 0x73320013, 0x2024bb80, 0xf8bb047b, 0x66e0db04, 0x629340c6, 0xecd4ec10, 0x046a12e8, 0x806cc64e, 0x59fc0842, 0xc01ad8a8, 0xb5c6285d, 0x3800b9a0, 0x586dd871, 0x9c8c85d0, 0x6e10c0da, 0xceb7b4fa, 0x5ffcb0a8, 0x80cf3ae4, 0x2f30525f, 0x6c1fb75c, 0x376a90e7, 0x6c1af700, 0xf858eca7, 0x12246fc6, 0xba7e782e, 0xf06dbc24, 0xc9888ea8, 0xc031eeba, 0x4568dc7d, 0x582d8950, 0xf9c038b1, 0x764675a0, 0xd85a401d, 0xc8fc9984, 0x462ceac2, 0x5263048e, 0x7354ace8, 0x40d3e2d0, 0x9be0a6db, 0x847b9b84, 0xfb5620bb, 0xc0b23380, 0xf89cd4fc, 0xbe143a82, 0x12609c96, 0x48998c38, 0x5d600a68, 0x00b51688, 0x31982079, 0xf088edf8, 0xca2c4805, 0x4a5e31a0, 0x581ea864, 0xf46c56c0, 0x1e008eaa, 0x9c0f5422, 0x87aca828, 0x8cd78a90 };
	/*p = 2048, q = 224, SHA-256 test vector*/
	//unsigned int g[] = { 0x967500f2, 0x4ae06466, 0x8c2eb468, 0xc05a92f8, 0xc314fe16, 0x545cf834, 0x73320013, 0x2024bb80, 0xf8bb047b, 0x66e0db04, 0x629340c6, 0xecd4ec10, 0x046a12e8, 0x806cc64e, 0x59fc0842, 0xc01ad8a8, 0xb5c6285d, 0x3800b9a0, 0x586dd871, 0x9c8c85d0, 0x6e10c0da, 0xceb7b4fa, 0x5ffcb0a8, 0x80cf3ae4, 0x2f30525f, 0x6c1fb75c, 0x376a90e7, 0x6c1af700, 0xf858eca7, 0x12246fc6, 0xba7e782e, 0xf06dbc24, 0xc9888ea8, 0xc031eeba, 0x4568dc7d, 0x582d8950, 0xf9c038b1, 0x764675a0, 0xd85a401d, 0xc8fc9984, 0x462ceac2, 0x5263048e, 0x7354ace8, 0x40d3e2d0, 0x9be0a6db, 0x847b9b84, 0xfb5620bb, 0xc0b23380, 0xf89cd4fc, 0xbe143a82, 0x12609c96, 0x48998c38, 0x5d600a68, 0x00b51688, 0x31982079, 0xf088edf8, 0xca2c4805, 0x4a5e31a0, 0x581ea864, 0xf46c56c0, 0x1e008eaa, 0x9c0f5422, 0x87aca828, 0x8cd78a90 };
	/*p = 2048, q = 256, SHA-256 test vector*/
	//unsigned int g[] = { 0xe8b24a24, 0xac387aec, 0x8aec08c2, 0x84c12e6c, 0xbe1cd1b6, 0x38463461, 0x6010f000, 0x104068c0, 0x7f5aac40, 0x7c9ff2d4, 0xf4a43f0a, 0x0654781e, 0xd86e34e8, 0xe64c5694, 0xcd8e849d, 0x747db63c, 0x185064a8, 0xd408d05c, 0x4c5b78d0, 0x8a941bd2, 0x1bc25c5b, 0x880abc78, 0x3c18123c, 0x29bc289a, 0x04f91eac, 0x2edc49e6, 0x10300019, 0xc028c020, 0x72e0c0d0, 0x37ca6c57, 0xbc97a2d4, 0x04e877fa, 0x9ea41876, 0xf846c4c8, 0xd68ce56e, 0x45be04d5, 0x308426fc, 0xe8703c38, 0x2c183074, 0x0cd3e504, 0x8594d375, 0x9a159c53, 0x286246d8, 0x76f8aa1e, 0x2147d472, 0x8431e7ec, 0x789cc107, 0xe8e0e010, 0x2040c840, 0x09042f30, 0xefb92ccf, 0xfc8fe9d4, 0xda48e662, 0x36d2b8ce, 0x942d4aa8, 0xebccdd2b, 0xbd2b840d, 0x101cac10, 0x3c901434, 0x8bc4908c, 0xcc4bad84, 0xcd948b7d, 0xb256284b, 0xcfbaee38 };
	/*p = 3072, q = 256, SHA-256 test vector*/
	//unsigned int g[] = { 0xf042e385, 0x287a8c5e, 0x0080c0c0, 0x50004040, 0x3f1d3060, 0x4725c321, 0x9cecba29, 0x2c686420, 0xbcf8f4b0, 0x2fc92360, 0x47e13b55, 0x844c536d, 0xf0e8a018, 0x448840b8, 0x2c5238de, 0xdf354b21, 0x92165a5e, 0x4c86cace, 0x16f82458, 0x0ef092f4, 0xb8e88aec, 0x38787838, 0xb8f8f8b8, 0x80275543, 0x882684a2, 0xa06c8caa, 0x76724894, 0xa502be3a, 0x7da7913b, 0x9af46913, 0x28b0f800, 0x88105860, 0xf1d71cc0, 0xd9bf65cb, 0x56a74db3, 0x488c9002, 0xb8fc00c4, 0x94063834, 0xcd6fd1f3, 0xc090c9eb, 0x00d060b0, 0x0a8040c0, 0xd200ee9c, 0x9ac8b664, 0xc24e9abb, 0x129eeaf6, 0xd00d3a46, 0xa8923ca6, 0x006a147e, 0x5c3810a8, 0xbc040cd4, 0x73e91f34, 0x16bcc7bd, 0xe4b80a30, 0x14e87cd0, 0x7302ac00, 0x2b5d4f01, 0xe31507b9, 0x60f04071, 0xa0308090, 0xbc7ac0d0, 0x7b6917be, 0xae31df4d, 0xbedab652, 0xc4101c62, 0x56d00a38, 0xee68a29c, 0x0ce44f79, 0x2c049cf4, 0xad24bc14, 0x88beb46a, 0x30665c12, 0x027498ba, 0x32c61a2e, 0x29eb4a5e, 0x5263e527, 0x0afcae20, 0x60806000, 0xd0806000, 0x3dbbf940, 0xc543817f, 0x38140907, 0x4824c01c, 0x5834d02c, 0xe923d05a, 0x81bbb56f, 0x3ca4cc07, 0xc860b894, 0x9a60d8f0, 0x02c84e94, 0xd5cb81fc, 0x062a0eb2, 0xf61afea2, 0x28aaec4c, 0xa0226466, 0xcafddcde };
	BIGNUM		*BN_Tmp1 = NULL, *BN_Tmp2 = NULL;
	SHA224_ALG_INFO	SHA224_AlgInfo;
	SHA256_ALG_INFO	SHA256_AlgInfo;
	BIGNUM *KCDSA_J = NULL;
    
	if (kcdsa == NULL)	return CTR_INVALID_POINTER;

	if ((PrimeBits < 2048) || (PrimeBits > 3072) || (PrimeBits % 256))
		return CTR_INVALID_ALG_PARAMS;
	if ((SubPrimeBits < 224) || (SubPrimeBits > 256) || (SubPrimeBits % 32))
		return CTR_INVALID_ALG_PARAMS;

	ret = CTR_MEMORY_ALLOC_ERROR;
	if ((BN_Tmp1 = CreateBigNum(PrimeBits / 32 + 1)) == NULL)			goto LABEL_END;
	if ((BN_Tmp2 = CreateBigNum(PrimeBits / 32 + 1)) == NULL)			goto LABEL_END;
    
	for (j = 0; j < (int)(PrimeBits / 32 + 2); j++)
	{
		BN_Tmp1->pData[j] = 0;
		BN_Tmp2->pData[j] = 0;
	}

	if (HASH == SHA224)
	{
		for (j = 0; j < SHA256_DIGEST_VALUELEN / 4; j++)
			SHA224_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j < 4; j++)
			SHA224_AlgInfo.Count[j] = 0;
		for (j = 0; j < SHA224_DIGEST_BLOCKLEN; j++)
			SHA224_AlgInfo.Buffer[j] = 0;
	}
	else if (HASH == SHA256)
	{
		for (j = 0; j < SHA256_DIGEST_VALUELEN / 4; j++)
			SHA256_AlgInfo.ChainVar[j] = 0;
		for (j = 0; j < 4; j++)
			SHA256_AlgInfo.Count[j] = 0;
		for (j = 0; j < SHA256_DIGEST_BLOCKLEN; j++)
			SHA256_AlgInfo.Buffer[j] = 0;
	}
	else
	{
		ret = CTR_INVALID_ALG_PARAMS;
		GOTO_END;
	}
    
	// 소수 쌍 (P, Q) 생성
LABEL_Start:
	for (;;) {
        // Step 1. 비트 길이 |Q|인 바이트 열 Seed를 생성한다.
		srand((unsigned)time(NULL));
		for (j = 0; j < (signed)(SubPrimeBits / 8); j++) {
			tSeed[j] = rand();
		}
		
		kcdsa->SeedLen = SubPrimeBits / 8;
		
		// Step 2. Seed를 일방향 함수의 입력으로 하여 비트 길이가 n = (|P|-|Q|-4)인 난수 U를 생성한다. (U ← PPGF(Seed, n))
		if (HASH == SHA224)
		{
			ret = KCDSA_PRNG_SHA_224(&SHA224_AlgInfo, tSeed, kcdsa->SeedLen, bzTmp, PrimeBits - SubPrimeBits - 4);			GOTO_END;
		}
		else
		{
			ret = KCDSA_PRNG_SHA_256(&SHA256_AlgInfo, tSeed, kcdsa->SeedLen, bzTmp, PrimeBits - SubPrimeBits - 4);			GOTO_END;
		}
        
		ret = OS2BN(bzTmp, (PrimeBits - SubPrimeBits) / 8, BN_Tmp1);	GOTO_END;

		// Step 3. U의 상위에 4 비트 '1000'을 붙이고 최하위 비트는 1로 만들어 이를 J로 둔다.(J ← 2^|P|-|Q|-1 ∨ U ∨ 1)
		SetBitDIGIT(BN_Tmp1->pData, PrimeBits - SubPrimeBits - 1);
		SetBitDIGIT(BN_Tmp1->pData, 0);

		// Step 4. 강한 소수 판정 알고리즘으로 J를 판정하여 소수가 아니면 Step 1로 이동
		if (MillerRabin(BN_Tmp1) != CTR_SUCCESS)
			goto LABEL_Start;
		break;
	}

	if ((KCDSA_J = CreateBigNum(PrimeBits / 32 + 1)) == NULL);	GOTO_END;

	for (j = BN_Tmp1->Length - 1; j >= 0; j--)
		KCDSA_J->pData[j] = BN_Tmp1->pData[j];
	KCDSA_J->Length = BN_Tmp1->Length;
	KCDSA_J->Space = BN_Tmp1->Space;
    
	// Step 5, 6. Count를 0으로 두고 Count를 1로 증가시킨다.
	for (Count = 1; Count < (1 << 24); Count++) {
		// Step 7. Count > 2^24이면 단계 1로 이동
		if (Count == (1 << 24))	goto LABEL_Start;

		// Step 8. Seed에 Count를 연접한 것을 일방향 함수 PPGF의 입력으로 하여 비트 길이가 |Q|인 난수 U를 생성한다. (U ← PPGF(Seed||Count, |Q|))
		BIG_W2B(Count, (&tSeed[kcdsa->SeedLen]));
		tSeed[kcdsa->SeedLen] = 0;

		if (HASH == SHA224)
		{
			ret = KCDSA_PRNG_SHA_224(&SHA224_AlgInfo, tSeed, kcdsa->SeedLen + 4, bzTmp, SubPrimeBits);			GOTO_END;
		}
		else
		{
			ret = KCDSA_PRNG_SHA_256(&SHA256_AlgInfo, tSeed, kcdsa->SeedLen + 4, bzTmp, SubPrimeBits);			GOTO_END;
		}

		ret = OS2BN(bzTmp, SubPrimeBits / 8, kcdsa->KCDSA_Q);	GOTO_END;

		// Step 9. U의 최상위 및 최하위 비트를 1로 만들어 이를 Q로 둔다. (Q ← 2^|Q|-1 ∨ U ∨ 1)
		SetBitDIGIT(kcdsa->KCDSA_Q->pData, SubPrimeBits - 1);
		SetBitDIGIT(kcdsa->KCDSA_Q->pData, 0);

		// Step 10. P ← (2J|Q| + 1)의 비트 길이가 |P|보다 길면 단계 6으로 이동
		ret = BN_Mul(kcdsa->KCDSA_P, BN_Tmp1, kcdsa->KCDSA_Q);						GOTO_END;
		if (CheckBitDIGIT(kcdsa->KCDSA_P->pData, PrimeBits - 1))
			continue;
		ret = BN_SHL(kcdsa->KCDSA_P, kcdsa->KCDSA_P, 1);					GOTO_END;
		SetBitDIGIT(kcdsa->KCDSA_P->pData, 0);

		// Step 11. 강한 소수 판정 알고리즘으로 Q를 판정하여 소수가 아니면 단계 6으로 이동
		if (MillerRabin(kcdsa->KCDSA_Q) != CTR_SUCCESS)	continue;

		// Step 12. 강한 소수 판정 알고리즘으로 P를 판정하여 소수가 아니면 단계 6으로 이동
		if (MillerRabin(kcdsa->KCDSA_P) == CTR_SUCCESS)	break;
	}

    // Step 13. 소수 P, Q, J와 증거 값 Seed, Count를 출력한다.
	kcdsa->Count = Count;

	ret = BN_SHL(KCDSA_J, KCDSA_J, 1);								GOTO_END;

	// 생성원 g 생성
	for (;;) {
		// Step 1. p보다 작은 임의의 수 h를 생성한다.
		srand((unsigned)time(NULL));
		for (i = 0; i < PrimeBits / 8; i++)
			((unsigned char*)g)[i] = rand();

		for (i = 0; i < PrimeBits / 32; i++)
			BN_Tmp2->pData[i] = g[i];
		BN_Tmp2->Length = PrimeBits / 32;
		BN_Tmp2->Space = PrimeBits / 32 + 1;

		// Step 2. G ← h ^ 2J mod P를 계산한다
		ret = BN_ModExp(kcdsa->KCDSA_G, BN_Tmp2, KCDSA_J, kcdsa->KCDSA_P);						GOTO_END;

		// Step 3. G = 1이면 단계 1로 간다.
		if (BN_Cmp(kcdsa->KCDSA_G, &BN_One) != 0)
			break;
	}
	ret = CTR_SUCCESS;
LABEL_END:
	if (BN_Tmp1 != NULL)	DestroyBigNum(BN_Tmp1);
	if (BN_Tmp2 != NULL)	DestroyBigNum(BN_Tmp2);
	if (KCDSA_J != NULL)	DestroyBigNum(KCDSA_J);
	return ret;
}

unsigned int KISA_KCDSA_DestroyObject(KISA_KCDSA	**kcdsa)
{
	KISA_KCDSA	*BN_Key = *kcdsa;

	if (kcdsa == NULL)	return CTR_INVALID_POINTER;
	if (*kcdsa == NULL)	return CTR_SUCCESS;

	if (BN_Key->KCDSA_P != NULL)		DestroyBigNum(BN_Key->KCDSA_P);
	if (BN_Key->KCDSA_Q != NULL)		DestroyBigNum(BN_Key->KCDSA_Q);
	if (BN_Key->KCDSA_G != NULL)		DestroyBigNum(BN_Key->KCDSA_G);
	if (BN_Key->KCDSA_x != NULL)		DestroyBigNum(BN_Key->KCDSA_x);
	if (BN_Key->KCDSA_y != NULL)		DestroyBigNum(BN_Key->KCDSA_y);

	memset((unsigned char *)BN_Key, 0, sizeof(KISA_KCDSA));
	free(BN_Key);
	*kcdsa = NULL;

	return CTR_SUCCESS;
}