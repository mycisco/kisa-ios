#ifndef _BIGNUM_H
#define _BIGNUM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "type.h"

	////////	Define the Endianness	////////
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
#define LITTLE_ENDIAN
#else
#if 0
#define BIG_ENDIAN		//	Big-Endian machine with pointer casting
#elif defined(_MSC_VER)
#define LITTLE_ENDIAN	//	Little-Endian machine with pointer casting
#else
//#error
#endif
#endif

/*************** Definitions / Macros  ************************************/
#define DIGITSIZE			4
#define BitsInDIGIT			32 //(8*DIGITSIZE)

#define BN_MAX_BITS		3072			//	Long #의 최대 비트수 : 512/768/1024/2048//3072
#define MaxDIGIT		96 //((BN_MAX_BITS-1)/BitsInDIGIT+1)	//	Long #의 최대 자리수
#define MAX_SEED_LEN	64	//(512/8) //	in BYTEs

/*************** Macros ***************************************************/
////////	bit control macros	////////
//	bit 반전

//	check k-th bits of A (array of unsigned int)
#define CHECK_BIT_B(A, k)	( 1 & ( (A)[(k)>>3] >> ((k) & ( 8-1)) ) )
//	set k-th bits of A (array of unsigned int)
#define SET_BIT_B(A, k)		(A)[(k)>>3] |= ((unsigned int)1 << ((k) & ( 8-1)) )
#define SET_BIT_D(A, k)		(A)[(k)>>5] |= ((unsigned int)1 << ((k) & (32-1)) )
//	clear k-th bits of A (array of unsigned int)
#define CLEAR_BIT_B(A, k)	(A)[(k)>>3] &= NOT((unsigned int)1 << ((k) & ( 8-1)) )
#define CLEAR_BIT_D(A, k)	(A)[(k)>>5] &= NOT((unsigned int)1 << ((k) & (32-1)) )
//	change k-th bits of A (array of unsigned int)
#define CHANGE_BIT_B(A, k)	(A)[(k)>>3] ^= ((unsigned int)1 << ((k) & ( 8-1)) )
#define CHANGE_BIT_D(A, k)	(A)[(k)>>5] ^= ((unsigned int)1 << ((k) & (32-1)) )

/*************** New Data Types *******************************************/
////////	Determine data types depand on the processor and compiler.
#define BYTE		unsigned char		//	unsigned 1-byte data type


#if defined(_MSC_VER)
#define DWORD	unsigned _int64		//	unsigned 8-bytes data type
#else
#define DWORD	unsigned long long	//	unsigned 8-bytes data type
#endif


#if defined(DWORD)
#define DOUBLE_DIGIT	DWORD
#endif


////	BIGNUM..
	typedef struct {
		unsigned int	Length;		//	유효한 DIGIT의 수를 나타냄
		unsigned int	Space;		//	MUST : MemoryLen>=DataLen+1
		unsigned int	*pData;		//	실제로 데이터가 저장된 주소
	} BIGNUM;

	/*************** Definitions / Macros  ************************************/
#define CTR_SUCCESS					0
#define CTR_VERIFY_FAIL				1
#define CTR_FATAL_ERROR				2
#define CTR_INVALID_POINTER			3
#define CTR_INVALID_ALG_PARAMS		4
#define CTR_MEMORY_ALLOC_ERROR		5
#define CTR_BUFFER_TOO_SMALL		6
#define CTR_INVALID_DATA_LEN		7
#define CTR_INVALID_SIGNATURE_LEN	8

#define ERROR_MemLen1				21	//	input : DataLen<=MemoryLen
#define ERROR_MemLen2				22	//	output : DataLen<=MemoryLen
#define ERROR_OverModulus			23	//	modulus oper. : NO input > modulus
#define CTR_BN_NEGATIVE_RESULT		24	//	음수는 지원하지 않음
    
/*************** Global Variables *****************************************/
	extern BIGNUM	BN_Zero, BN_One, BN_Two;

	/*************** Prototypes ***********************************************/
	//########################################
	//	unsigned int 변수간의 곱셈/나눗셈 함수
	//	unsigned int array의 핵심연산 함수
	//########################################

	//########################################
	//	BIGNUM의 지원 함수 
	//########################################
    
    unsigned int CheckBitDIGIT(unsigned int *A, unsigned int k);
    unsigned int CHECK_BIT_D(unsigned int *A, unsigned int k);
    unsigned int NOT(unsigned x);
    int isEven0(unsigned int *A);
    int isOdd0(unsigned int *A);
    
    void SetBitDIGIT(unsigned int *A, unsigned int k);
    
	//	Create "BIGNUM" data and return the pointer
	BIGNUM	*CreateBigNum(
		unsigned int		dMemoryLen);	//	in unsigned ints

//	Destroy "BIGNUM" data
	void	DestroyBigNum(
		BIGNUM		*BN_Src);		//	pointer of BIGNUM to be destroyed

//
	unsigned int	BN2OS(
		BIGNUM	*BN_Src,	//	Source integer
		unsigned int	dDstLen,	//	Destination Length in BYTEs
		unsigned char	*pbDst);	//	Destination Octet string pointer
	unsigned int	OS2BN(
		unsigned char	*pbSrc,		//	Source Octet string pointer
		unsigned int	dSrcLen,	//	Source Length in BYTEs
		BIGNUM	*BN_Dst);	//	Destination unsigned int array pointer

//	Long Number Copy : BN_Dst <- BN_Src
	unsigned int BN_Copy(BIGNUM *BN_Dst, BIGNUM *BN_Src);

	//	Long Number Compare : return the sign of (BN_Src1 - BN_Src2)
	int BN_Cmp(BIGNUM *BN_Src1, BIGNUM *BN_Src2);

	//	Long Random Number : BN_Dst <- 'BitLen'-unsigned int random long number
	unsigned int BN_Rand(BIGNUM *BN_Dst, unsigned int BitLen);

	//########################################
	//	BIGNUM의 핵심연산 함수
	//########################################

	//	Long Number (NumOfShift)-bits shift left : BN_Dst = BN_Src << NumOfShift
	unsigned int BN_SHL(BIGNUM *BN_Dst, BIGNUM *BN_Src, unsigned int NumOfShift);
	//	Long Number (NumOfShift)-bits shift right : BN_Dst = BN_Src >> NumOfShift
	unsigned int BN_SHR(BIGNUM *BN_Dst, BIGNUM *BN_Src, unsigned int NumOfShift);

	//	Long Nymber Addition : BN_Dst <- BN_Src1 + BN_Src2
	unsigned int BN_Add(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2);
	//	Long Number Subtraction : BN_Dst <- BN_Src1 - BN_Src2
	unsigned int BN_Sub(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2);

	//	Long Number Multiple : BN_Dst <- BN_Src1 * BN_Src2
	//			the most general multiple function
	unsigned int BN_Mul(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2);

	//	Long Number Division : BN_Res <- BN_Dividend div BN_Divisor
	unsigned int BN_Div(BIGNUM *BN_Quotient, BIGNUM *BN_Remainder,
		BIGNUM *BN_Dividend, BIGNUM *BN_Divisor);

	//########################################
	//	BIGNUM의 Modulus 연산 함수
	//########################################

	//	Long Number Modular addtion :
	//				BN_Dst <- BN_Src1 + BN_Src2 mod BN_Modulus
	unsigned int BN_ModAdd(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
		BIGNUM *BN_Modulus);
	//	Long Number Modular subtraction :
	//				BN_Dst <- BN_Src1 - BN_Src2 mod BN_Modulus
	unsigned int BN_ModSub(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
		BIGNUM *BN_Modulus);

	//	Long Number Modular Reduction - Classical Algorithm
	unsigned int BN_ModRed(BIGNUM *BN_Dst, BIGNUM *BN_Src, BIGNUM *BN_Modulus);
	//	Long Number Modular Multiple - Classical Algorithm
	unsigned int BN_ModMul(BIGNUM *BN_Res, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
		BIGNUM *BN_Modulus);

	//	Extended Euclid Algorithm
	//		return CTR_SUCCESS	if gcd(BN_Src,BN_Modulus)==1 :
	//					BN_Dst <- BN_Src^-1 mod BN_Modulus
	//		return !CTR_SUCCESS if gcd(BN_Src,BN_Modulus)!=1 :
	//					BN_Dst <- gcd(BN_Src, BN_Modulus)
	unsigned int BN_ModInv(BIGNUM *BN_Dst, BIGNUM *BN_Src, BIGNUM *BN_Modulus);

	//	Long Number Modular Exponential Algorithm - 
	//		Window Algorithm and Montgomery Reduction Algorithm
	unsigned int BN_ModExp(BIGNUM *BN_Dst, BIGNUM *BN_Base, BIGNUM *BN_Exponent,
		BIGNUM *BN_Modulus);

	//########################################
	//	기타 보조 연산 함수
	//########################################

	//
	unsigned int MillerRabin(
		BIGNUM		*BN_Num);

	/*************** END OF FILE **********************************************/

#ifdef __cplusplus
}
#endif
#endif	//	_BIGNUM_H
