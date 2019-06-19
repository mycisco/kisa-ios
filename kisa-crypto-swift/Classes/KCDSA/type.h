#ifdef  __cplusplus
extern "C" {
#endif
    
    /*************** Header files *********************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
    
    /*************** Assertions ***********************************************/
    ////////    Define the Endianness    ////////
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN
    
#if defined(USER_BIG_ENDIAN)
    #define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
    #define LITTLE_ENDIAN
#else
    #if 0
        #define BIG_ENDIAN        //    Big-Endian machine with pointer casting
    #elif defined(_MSC_VER)
        #define LITTLE_ENDIAN    //    Little-Endian machine with pointer casting
    #else
        #define LITTLE_ENDIAN
    #endif
#endif
    
    /*************** Macros ***************************************************/
    ////////    rotate by using shift operations    ////////
#if defined(_MSC_VER)
#define ROTL_DWORD(x, n) _lrotl((x), (n))
#define ROTR_DWORD(x, n) _lrotr((x), (n))
#else
#define ROTL_DWORD(x, n) ( (DWORD)((x) << (n)) | (DWORD)((x) >> (32-(n))) )
#define ROTR_DWORD(x, n) ( (DWORD)((x) >> (n)) | (DWORD)((x) << (32-(n))) )
#endif
    
    ////////    reverse the byte order of DWORD(DWORD:4-bytes integer) and WORD.
#define ENDIAN_REVERSE_DWORD(dwS)    ( (ROTL_DWORD((dwS),  8) & 0x00ff00ff)    \
| (ROTL_DWORD((dwS), 24) & 0xff00ff00) )
    
    ////////    move DWORD type to BYTE type and BYTE type to DWORD type
#if defined(BIG_ENDIAN)        ////    Big-Endian machine
#define BIG_B2D(B, D)        D = *(DWORD *)(B)
#define BIG_D2B(D, B)        *(DWORD *)(B) = (DWORD)(D)
#define LITTLE_B2D(B, D)    D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
#define LITTLE_D2B(D, B)    *(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#elif defined(LITTLE_ENDIAN)    ////    Little-Endian machine
#define BIG_B2D(B, D)        D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
#define BIG_D2B(D, B)        *(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#define LITTLE_B2D(B, D)    D = *(DWORD *)(B)
#define LITTLE_D2B(D, B)    *(DWORD *)(B) = (DWORD)(D)
#else
#error ERROR : Invalid DataChangeType
#endif
    
    /*************** New Data Types *******************************************/
    ////////    Determine data types depand on the processor and compiler.
#define BOOL    int                    //    1-bit data type
#define BYTE    unsigned char        //    unsigned 1-byte data type
#define WORD    unsigned short    //    unsigned 2-bytes data type
#define DWORD    unsigned int        //    unsigned 4-bytes data type
#define RET_VAL        DWORD            //    return values
    
    /*
     #if defined(_MSC_VER)
     typedef unsigned _int64 ULLONG;
     typedef ULLONG* ULLOONG_PTR;
     #else
     typedef unsigned long long ULLONG;
     typedef ULLONG* ULLOONG_PTR;
     #endif
     
     typedef unsigned long ULONG;
     typedef ULONG* ULONG_PTR;
     
     typedef signed long SLONG;
     typedef SLONG* SLONG_PTR;
     
     typedef unsigned short USHORT;
     typedef USHORT* USHORT_PTR;
     
     typedef signed short SSHORT;
     typedef SSHORT* SSHORT_PTR;
     
     typedef unsigned int UINT;
     typedef UINT* UINT_PTR;
     
     typedef signed int SINT;
     typedef SINT* SINT_PTR;
     
     typedef unsigned char UCHAR;
     typedef UCHAR* UCHAR_PTR;
     
     typedef char SCHAR;
     typedef SCHAR* SCHAR_PTR;*/
    
    
    /**** Select Hash Function ****/
#define SHA224 1
#define SHA256 2
    
#define INCORRECT_SEED 1000
    
#define MAX_P_LENGTH 3072
#define MAX_Q_LENGTH 256
    
#ifdef  __cplusplus
}
#endif
