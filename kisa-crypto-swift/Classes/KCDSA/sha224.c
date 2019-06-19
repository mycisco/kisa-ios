#include "sha224.h"

//*********************************************************************************************************************************
// o SHA224_K    : 단계연산에서 사용되는 64개의 상수
//*********************************************************************************************************************************
const DWORD SHA224_K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

//*********************************************************************************************************************************
// o 로테이션 함수
//*********************************************************************************************************************************
#define RR(x, n)        ROTR_DWORD(x, n)

//*********************************************************************************************************************************
// o 쉬프트 함수
//*********************************************************************************************************************************
#define SS(x, n)        (x >> n)

//*********************************************************************************************************************************
// o 단계연산에 사용되는 부울함수
//*********************************************************************************************************************************
#define Ch(x, y, z)        ((x & y) ^ ((~x) & z))
#define Maj(x, y, z)    ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x)        (RR(x,  2) ^ RR(x, 13) ^ RR(x, 22))
#define Sigma1(x)        (RR(x,  6) ^ RR(x, 11) ^ RR(x, 25))

//*********************************************************************************************************************************
// o 메시지 확장에 사용되는 함수
//*********************************************************************************************************************************
#define RHO0(x)            (RR(x,  7) ^ RR(x, 18) ^ SS(x,  3))
#define RHO1(x)            (RR(x, 17) ^ RR(x, 19) ^ SS(x, 10))

//*********************************************************************************************************************************
// o FF    : SHA-224의 단계연산
//*********************************************************************************************************************************
#define FF(a, b, c, d, e, f, g, h, j) {                            \
T1 = h + Sigma1(e) + Ch(e, f, g) + SHA224_K[j] + X[j];    \
d += T1;                                                \
h = T1 + Sigma0(a) + Maj(a, b, c);                        \
}

//*********************************************************************************************************************************
// o SHA224_Transform()    : 512 비트 단위 블록의 메시지를 입력 받아 연쇄변수를 갱신하는 압축 함수로써
//                          4 라운드(64 단계)로 구성되며 8개의 연쇄변수(a, b, c, d, e, f, g, h)를 사용
// o 입력                : Message        - 입력 메시지의 포인터 변수
//                          ChainVar        - 연쇄변수의 포인터 변수
// o 출력                :
//*********************************************************************************************************************************
void SHA224_Transform(DWORD *Message, DWORD *ChainVar)
{
    DWORD a, b, c, d, e, f, g, h, T1, X[64];
    DWORD j;
    
#if defined(BIG_ENDIAN)
#define GetData(x)    x
#else
#define GetData(x)    ENDIAN_REVERSE_DWORD(x)
#endif
    
    // 메시지 확장
    for (j = 0; j < 16; j++)
        X[j] = GetData(Message[j]);
    
    for (j = 16; j < 64; j++)
        X[j] = RHO1(X[j - 2]) + X[j - 7] + RHO0(X[j - 15]) + X[j - 16];
    
    // 연쇄변수 대입
    a = ChainVar[0];
    b = ChainVar[1];
    c = ChainVar[2];
    d = ChainVar[3];
    e = ChainVar[4];
    f = ChainVar[5];
    g = ChainVar[6];
    h = ChainVar[7];
    
    // 단계연산
    for (j = 0; j < 64; j += 8)
    {
        FF(a, b, c, d, e, f, g, h, j + 0);
        FF(h, a, b, c, d, e, f, g, j + 1);
        FF(g, h, a, b, c, d, e, f, j + 2);
        FF(f, g, h, a, b, c, d, e, j + 3);
        FF(e, f, g, h, a, b, c, d, j + 4);
        FF(d, e, f, g, h, a, b, c, j + 5);
        FF(c, d, e, f, g, h, a, b, j + 6);
        FF(b, c, d, e, f, g, h, a, j + 7);
    }
    
    // 연쇄변수 갱신
    ChainVar[0] += a;
    ChainVar[1] += b;
    ChainVar[2] += c;
    ChainVar[3] += d;
    ChainVar[4] += e;
    ChainVar[5] += f;
    ChainVar[6] += g;
    ChainVar[7] += h;
}

//*********************************************************************************************************************************
// o SHA224_Init()        : 연쇄변수와 길이변수를 초기화하는 함수
// o 입력                : AlgInfo        -  SHA-224 구조체의 포인터 변수
// o 출력                :
//*********************************************************************************************************************************
void SHA224_Init(SHA224_ALG_INFO *AlgInfo)
{
    // 연쇄변수 초기화
    AlgInfo->ChainVar[0] = 0xc1059ed8;
    AlgInfo->ChainVar[1] = 0x367cd507;
    AlgInfo->ChainVar[2] = 0x3070dd17;
    AlgInfo->ChainVar[3] = 0xf70e5939;
    AlgInfo->ChainVar[4] = 0xffc00b31;
    AlgInfo->ChainVar[5] = 0x68581511;
    AlgInfo->ChainVar[6] = 0x64f98fa7;
    AlgInfo->ChainVar[7] = 0xbefa4fa4;
    
    // 길이변수 초기화
    AlgInfo->Count[0] = AlgInfo->Count[1] = 0;
}

//*********************************************************************************************************************************
// o SHA224_Update()    : 임의의 길이를 가지는 입력 메시지를 512 비트 블록 단위로 나누어 압축함수를 호출하는 함수
// o 입력                : AlgInfo        - SHA-224 구조체의 포인터 변수
//                          Message        - 입력 메시지의 포인터 변수
//                          MessageLen    - 입력 메시지의 바이트 길이
// o 출력                :
//*********************************************************************************************************************************
void SHA224_Update(SHA224_ALG_INFO *AlgInfo, BYTE *Message, DWORD MessageLen)
{
    DWORD RemainedLen, PartLen;
    
    RemainedLen = (AlgInfo->Count[0] >> 3) % SHA224_DIGEST_BLOCKLEN;
    
    PartLen = SHA224_DIGEST_BLOCKLEN - RemainedLen;
    
    // 메시지 길이 하위 32비트 계산
    if ((AlgInfo->Count[0] += (MessageLen << 3)) < 0)
        AlgInfo->Count[1]++;
    
    // 메시지 길이 상위 32비트 계산
    AlgInfo->Count[1] += (MessageLen >> 29);
    
    // 입력 메시지를 512 비트 블록 단위로 나누어 압축함수를 호출
    //    핵심 updtae 부분
    if( MessageLen>=PartLen ) {
        memcpy(AlgInfo->Buffer+RemainedLen, Message, (int)PartLen);
        SHA224_Transform((DWORD *)AlgInfo->Buffer, AlgInfo->ChainVar);
        
        Message += PartLen;
        MessageLen -= PartLen;
        RemainedLen = 0;
        
        while( MessageLen>=SHA224_DIGEST_BLOCKLEN ) {
            if( (((int)Message)%4)==0 ) {    //    Speed up technique
                SHA224_Transform((DWORD *)Message, AlgInfo->ChainVar);
            }
            else {
                memcpy((BYTE *)AlgInfo->Buffer, Message, (int)SHA224_DIGEST_BLOCKLEN);
                SHA224_Transform((DWORD *)AlgInfo->Buffer, AlgInfo->ChainVar);
            }
            Message += SHA224_DIGEST_BLOCKLEN;
            MessageLen -= SHA224_DIGEST_BLOCKLEN;
        }
    }
    /*
    printf("sha224 - buffer : ");
    for(int i = 0; i < 64; i ++){
        printf("%x ", AlgInfo->Buffer[i]);
    }
    printf("\n");
     */
    
    //    Buffer remaining input
    memcpy((BYTE *)AlgInfo->Buffer+RemainedLen, Message, (int)MessageLen);
}

//*********************************************************************************************************************************
// o SHA224_Final()        : 메시지 덧붙이기와 길이 덧붙이기를 수행한 후 마지막 메시지 블록을 가지고 압축함수를 호출하는 함수
// o 입력                : AlgInfo    - SHA-224 구조체의 포인터 변수
//                          Digest    - SHA-224 해쉬값을 저장할 포인터 변수
// o 출력                :
//*********************************************************************************************************************************
void SHA224_Final(SHA224_ALG_INFO *AlgInfo, BYTE *Digest)
{
    DWORD i, Index, CountL, CountH;
    
    // 메시지 길이 변수 대입
    CountL = AlgInfo->Count[0];
    CountH = AlgInfo->Count[1];
    
    // 메시지 덧붙이기
    Index = (CountL >> 3) % SHA224_DIGEST_BLOCKLEN;
    AlgInfo->Buffer[Index++] = 0x80;
    
    // 덧붙이기로 인해 메시지 블록이 512 비트가 넘으면 압축 함수를 호출
    if (Index > SHA224_DIGEST_BLOCKLEN - 8)
    {
        memset((BYTE *)AlgInfo->Buffer + Index, 0, (int)(SHA224_DIGEST_BLOCKLEN - Index));
        SHA224_Transform((DWORD *)AlgInfo->Buffer, AlgInfo->ChainVar);
        memset((BYTE *)AlgInfo->Buffer, 0, (int)SHA224_DIGEST_BLOCKLEN - 8);
    }
    else
        memset((BYTE *)AlgInfo->Buffer + Index, 0, (int)(SHA224_DIGEST_BLOCKLEN - Index - 8));
    
    // 메시지 길이 변수의 엔디안 변환
#if defined(LITTLE_ENDIAN)
    CountL = ENDIAN_REVERSE_DWORD(CountL);
    CountH = ENDIAN_REVERSE_DWORD(CountH);
#endif
    
    // 메시지 길이 덧붙이기
    ((DWORD *)AlgInfo->Buffer)[SHA224_DIGEST_BLOCKLEN / 4 - 2] = CountH;
    ((DWORD *)AlgInfo->Buffer)[SHA224_DIGEST_BLOCKLEN / 4 - 1] = CountL;
    
    
    // 마지막 메시지 블록으로 압축 함수를 호출
    SHA224_Transform((DWORD *)AlgInfo->Buffer, AlgInfo->ChainVar);
    
    // 계산된 해쉬값을 Digest 변수에 대입
    for (i = 0; i < SHA224_DIGEST_VALUELEN; i += 4)
        BIG_D2B((AlgInfo->ChainVar)[i / 4], &(Digest[i]));
    
    
}
