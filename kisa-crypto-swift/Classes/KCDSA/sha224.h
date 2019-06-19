#ifndef _SHA224_H
#define _SHA224_H

#ifdef  __cplusplus
extern "C" {
#endif
    
    /*************** Definitions **********************************************/
    
#include "type.h"
    
    // SHA-224 상수 정의
#define SHA224_DIGEST_BLOCKLEN    64
#define SHA224_DIGEST_VALUELEN    28
    
#define SHA256_DIGEST_BLOCKLEN    64
#define SHA256_DIGEST_VALUELEN    32
    
    // SHA-224 구조체 정의
    typedef struct {
        DWORD ChainVar[SHA256_DIGEST_VALUELEN / 4];    // 연쇄변수
        DWORD Count[4];                                // 길이변수
        BYTE Buffer[SHA224_DIGEST_BLOCKLEN];        // 메시지 버퍼
    } SHA224_ALG_INFO;
    
    /*************** Functions ************************************************/
    
    // SHA-224 함수 선언
    void SHA224_Init(SHA224_ALG_INFO *AlgInfo);
    void SHA224_Update(SHA224_ALG_INFO *AlgInfo, BYTE *Message, DWORD MessageLen);
    void SHA224_Final(SHA224_ALG_INFO *AlgInfo, BYTE *Digest);
    
    /*************** END OF FILE **********************************************/
#ifdef  __cplusplus
}
#endif

#endif    //    _SHA224_H
