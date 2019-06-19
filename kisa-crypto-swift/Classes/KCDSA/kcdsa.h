#ifdef __cplusplus
extern "C" {
#endif

#include "sha224.h"
#include "sha256.h"
#include "bignum.h"

#define MaxDIGIT		96 //((BN_MAX_BITS-1)/BitsInDIGIT+1)	//	Long #의 최대 자리수

#define GOTO_END		if( ret!=CTR_SUCCESS )	goto LABEL_END

#define CTR_SUCCESS					0

#define KCDSA_SIGN 1
#define KCDSA_VERIFY 0

#define VERIFY_SUCCESS 1
#define VERIFY_FAIL 0

	typedef struct kcdsa_structure {
		BIGNUM 		*KCDSA_P;		//	prime(1024 + 128i bits i=0..8)
		BIGNUM 		*KCDSA_Q;		//	subprime(128 + 32j bits j=0..4)
		BIGNUM 		*KCDSA_G;		//	Base
		BIGNUM 		*KCDSA_x;		//	
		BIGNUM 		*KCDSA_y;		//	
		unsigned int	Count;			//	Prime Type ID
		unsigned int	SeedLen;		//	in BYTEs
	} KISA_KCDSA;
  
    void BIG_W2B(unsigned int W, unsigned int *B);
	unsigned int KISA_KCDSA_CreateObject(KISA_KCDSA	**kcdsa);
	unsigned int KCDSA_PRNG_SHA_224(SHA224_ALG_INFO	*SHA224_AlgInfo, unsigned char *pbSrc, unsigned int dSrcByteLen, unsigned char *pbDst, unsigned int dDstBitLen);
	unsigned int KCDSA_PRNG_SHA_256(SHA256_ALG_INFO	*SHA256_AlgInfo, unsigned char *pbSrc, unsigned int dSrcByteLen, unsigned char *pbDst, unsigned int dDstBitLen);
	unsigned int Generate_Random(BIGNUM	*XKEY, unsigned char *pbSrc, unsigned int dSrcByteLen, unsigned int *X, unsigned int XBitLen, KISA_KCDSA *kcdsa, unsigned int HASH);
	unsigned int KISA_KCDSA_GenerateKeyPair(KISA_KCDSA *KCDSA_Key, unsigned char *pbSrc, unsigned int dSrcByteLen, unsigned int qLen, unsigned int HASH);
	unsigned int KISA_KCDSA_sign(KISA_KCDSA *kcdsa, unsigned char *MsgDigest, unsigned int MsgDigestLen, unsigned char *Signature, unsigned int *SignLen, unsigned int HASH, unsigned char *t_omgri, unsigned int omgri_len);
	unsigned int KISA_KCDSA_verify(KISA_KCDSA *kcdsa, unsigned char *MsgDigest, unsigned int MsgDigestLen, unsigned char *Signature, unsigned int SignLen, unsigned int HASH);
	unsigned int KISA_KCDSA_set_params(KISA_KCDSA *kcdsa, unsigned int *p, int plen, unsigned int *q, int qlen, unsigned int *g, int glen, unsigned int *private_key, int private_keylen, unsigned int *public_key, int public_keylen);
	unsigned int KISA_KCDSA_GenerateParameters(unsigned int PrimeBits, unsigned int SubPrimeBits, KISA_KCDSA *kcdsa, unsigned int HASH);
	unsigned int KISA_KCDSA_DestroyObject(KISA_KCDSA	**kcdsa);

#ifdef __cplusplus
}
#endif
