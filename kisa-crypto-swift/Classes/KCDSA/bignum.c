#include "bignum.h"
#include <assert.h>

/*************** Assertions ***********************************************/
#define Kara_Length			9632

/*************** Definitions / Macros  ************************************/
#define GOTO_END		if( ret!=CTR_SUCCESS )	goto LABEL_END

unsigned int CheckBitDIGIT(unsigned int *A, unsigned int k)
{
    return ( 1 & ( (A[k>>5]&0xffffffff) >> (k & (32-1)) ) );
}

unsigned int CHECK_BIT_D(unsigned int *A, unsigned int k)
{
    return ( 1 & ( (A[k>>5]&0xffffffff) >> (k & (32-1)) ) );
}

unsigned int NOT(unsigned x)
{
    return ~(x&0xffffffff);
}

int isEven0(unsigned int *A)
{
    return ((A[0]&1) == 0);
}

int isOdd0(unsigned int *A)
{
    return ((A[0]&1) == 1);
}

/*************** New Data Types *******************************************/

/*************** Global Variables *****************************************/
//	큰 수의 자리수가 Kara_Sqr/mul보다 크면 Karatsuba algorithm 적용
unsigned int Kara_Sqr_Length = Kara_Length / 100;
unsigned int Kara_Mul_Length = Kara_Length % 100;

//
unsigned int bn_Zero[2] = {0, 0};
unsigned int bn_One[2] = {1, 0};
unsigned int bn_Two[2] = {2, 0};
BIGNUM BN_Zero={0, 2, bn_Zero},
		BN_One={1, 2, bn_One},
		BN_Two={1, 2, bn_Two};

/*************** Prototypes ***********************************************/
unsigned int Classical_REDC(unsigned int *L_Dst, unsigned int DstLen,
					   unsigned int *L_Modulus, unsigned int ModLen);
unsigned int Montgomery_Init(unsigned int *L_Modulus, unsigned int ModLen);
unsigned int Montgomery_REDC(unsigned int *L_Dst, unsigned int DstLen,
						unsigned int *L_Modulus, unsigned int ModLen);
unsigned int Montgomery_Zn2RZn(unsigned int *L_Dst, unsigned int *L_Src,
						  unsigned int *L_Modulus, unsigned int ModLen);


//########################################
//	unsigned int 변수간의 곱셈/나눗셈 함수
//########################################

void CheckMostSignificantDIGIT(BIGNUM *BN_Num)
{
    for(; BN_Num->Length > 0; BN_Num->Length--){
        if( (BN_Num->pData[BN_Num->Length-1]&0xffffffff) != 0 )    \
            break;
    }
}

int CheckInput_MemLen(BIGNUM *L)
{
    if( (L->Space&0xffffffff) < (L->Length&0xffffffff) ) return ERROR_MemLen1;
    return -1;
}

int CheckOutput_MemLen(BIGNUM *L)
{
    if( (L->Space&0xffffffff) < (L->Length&0xffffffff) ) return ERROR_MemLen2;
    return -1;
}

void SetBitDIGIT(unsigned int *A, unsigned int k)
{
    A[(unsigned int)k>>5] = (A[(unsigned int)k>>5]&0xffffffff) | ((unsigned int)1 << ((unsigned int)k & (32-1)) );
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static void D_Mul_D(unsigned int *D_Res, unsigned int D_Multiplicand, unsigned int D_Multiplier)
{
	DWORD tmp;
    DWORD GaGb, GaLb, LaGb, LaLb;
	tmp = (D_Multiplicand * D_Multiplier);
	D_Res[0] = (unsigned int) tmp&0xffffffff;
    GaGb = (D_Multiplicand >> (BitsInDIGIT/2)) * (D_Multiplier >> (BitsInDIGIT/2));
    GaLb = (D_Multiplicand >> (BitsInDIGIT/2)) * (D_Multiplier & 0xffff);
    LaGb = (D_Multiplier >> (BitsInDIGIT/2)) * (D_Multiplicand & 0xffff);
    LaLb = (D_Multiplier & 0xffff) * (D_Multiplicand & 0xffff);
    D_Res[1] = GaGb + (GaLb >> (BitsInDIGIT/2)) + (LaGb >> (BitsInDIGIT/2));
    D_Res[1] += (((GaLb & 0xffff) + (LaGb & 0xffff) + (LaLb >> (BitsInDIGIT/2))) >> (BitsInDIGIT/2));
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int DD_Div_D(unsigned int D_Dividend1, unsigned int D_Dividend2, unsigned int D_Divisor)
{
	return (unsigned int)(( (((DWORD)D_Dividend1)<<BitsInDIGIT) + D_Dividend2 )
					 / D_Divisor);
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int DD_Mod_D(unsigned int D_Dividend1, unsigned int D_Dividend2, unsigned int D_Divisor)
{
	return (unsigned int)(( ((((DWORD)D_Dividend1)&0xffffffff)<<BitsInDIGIT) + D_Dividend2 )
					 % D_Divisor);
}

/**************************************************************************
*
*	Function Description
*		DIGIT inverse : return D_Src^{-1} mod (b=2^BitsInDIGIT)
*
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int D_Inv(unsigned int D_Src)
{
	unsigned int	F, G, d, B, C;

	#define XXXX4	3

	C = 1;
	B = 0 - C;
	G = D_Src;
	F = 0 - G;

	for(  ;  ;  ) {
		if( (G&0xffffffff) == 1 )
			break;

		if( ((F&0xffffffff) >> XXXX4) > (G&0xffffffff) ) {
			d = F / G;
			F -= d * G;
			B -= d * C;
		}
		else {
			do {
				F -= G;
				B -= C;
			} while( (F&0xffffffff) > (G&0xffffffff) );
		}

		if( (F&0xffffffff) == 1 ) {
			C = B;
			break;
		}

		if( ((G&0xffffffff) >> XXXX4) > (F&0xffffffff) ) {
			d = G / F;
			G -= d * F;
			C -= d * B;
		}
		else {
			do {
				G -= F;
				C -= B;
			} while( (G&0xffffffff) > (F&0xffffffff) );
		}
	}

	return (unsigned int)C;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int D_Gcd(unsigned int D_Src1, unsigned int D_Src2)
{
	unsigned int		tmp;

	//	assert D_Src1>=D_Src2
	if( (D_Src1&0xffffffff) < (D_Src2&0xffffffff) ) {
		tmp=D_Src1;		D_Src1=D_Src2;	D_Src2=tmp;
	}

	//
	while( (D_Src2&0xffffffff) != 0 ) {
		tmp = (D_Src1&0xffffffff) % (D_Src2&0xffffffff);
		D_Src1 = D_Src2;
		D_Src2 = tmp;
	}

	return D_Src1;
}

//########################################
//	unsigned int array의 핵심연산 함수
//########################################

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_ModD(unsigned int *L_Src, unsigned int SrcLen, unsigned int D_Divisor)
{
	unsigned int	i;
	unsigned int	xx=0;

	for( i=SrcLen-1; i!=(unsigned int)-1; i--) {
		xx = DD_Mod_D(xx, L_Src[i], D_Divisor);
	}

	return xx;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static int bn_Cmp(unsigned int *L_Src1, unsigned int SrcLen1, unsigned int *L_Src2, unsigned int SrcLen2)
{
	unsigned int	i;

	if( (SrcLen1&0xffffffff)>=(SrcLen2&0xffffffff) ) {
		for( i=SrcLen1-1; (i&0xffffffff) != (SrcLen2&0xffffffff)-1; i--)
			if( L_Src1[i]&0xffffffff )		return +1;
	}
	else {
		for( i=SrcLen2-1; (i&0xffffffff) != (SrcLen1&0xffffffff)-1; i--)
			if( L_Src2[i]&0xffffffff )		return -1;
	}

	for(  ; (i&0xffffffff) != (unsigned int)-1; i--) {
		if( (L_Src1[i]&0xffffffff) == (L_Src2[i]&0xffffffff) )		continue;
		else if( (L_Src1[i]&0xffffffff) > (L_Src2[i]&0xffffffff) )	return +1;
		else							return -1;
	}

	return 0;
}

/*************** Function *************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static void bn_Copy(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen)
{
	unsigned int	i;

	for( i=0; (i&0xffffffff) < (SrcLen&0xffffffff); i++)
		L_Dst[i] = L_Src[i];
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_SHL(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen, unsigned int NumOfShift)
{
	unsigned int	i=SrcLen-1;
	unsigned int	ret;

	ret = (L_Src[i]&0xffffffff) >> (BitsInDIGIT-(NumOfShift&0xffffffff));
	for(  ; (i&0xffffffff) != 0; i--)
		L_Dst[i] = ((L_Src[i]&0xffffffff) << (NumOfShift&0xffffffff))
				 ^ ((L_Src[i-1]&0xffffffff) >> (BitsInDIGIT-(NumOfShift&0xffffffff)));
	L_Dst[i] = (L_Src[i]&0xffffffff) << (NumOfShift&0xffffffff);

	return ret;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_SHR(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen, unsigned int NumOfShift)
{
	unsigned int	i=0;
	unsigned int	ret;

	ret = (L_Src[i]&0xffffffff) << ((BitsInDIGIT-(NumOfShift&0xffffffff))&0xffffffff);
	for( i=0; (i&0xffffffff) < (SrcLen&0xffffffff)-1; i++)
		L_Dst[i] = ((L_Src[i]&0xffffffff) >> (NumOfShift&0xffffffff))
				 ^ ((L_Src[i+1]&0xffffffff) << ((BitsInDIGIT-(NumOfShift&0xffffffff))&0xffffffff));
	L_Dst[i] = (L_Src[i]&0xffffffff) >> (NumOfShift&0xffffffff);

	return ret;
}


/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_Add(unsigned int *L_Dst, unsigned int *L_Src1, unsigned int SrcLen1,
						   unsigned int *L_Src2, unsigned int SrcLen2)
{
	unsigned int	i;
	unsigned int	carry, tmp;

	//
	for( carry=i=0; (i&0xffffffff) < (SrcLen2&0xffffffff); i++) {
		if( ((L_Src2[i]&0xffffffff) == ((unsigned int)-1)) && ((carry&0xffffffff)==1) )
			L_Dst[i] = L_Src1[i];
		else {
			tmp = L_Src2[i] + carry;
			L_Dst[i] = L_Src1[i] + tmp;
			carry = ( ((L_Dst[i]&0xffffffff)) < (tmp&0xffffffff) ) ? 1 : 0;
		}
	}

	//
	if( (carry&0xffffffff) == 0 ) {
		if( L_Dst != L_Src1 )
			for(  ; (i&0xffffffff) < (SrcLen1&0xffffffff); i++)
				L_Dst[i] = L_Src1[i];
		return 0;
	}

	//
	for(  ; (i&0xffffffff) < (SrcLen1&0xffffffff); i++)
		if( ((++L_Dst[i])&0xffffffff) != 0 )	return 0;

	return 1;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_Sub(unsigned int *L_Dst, unsigned int *L_Src1, unsigned int SrcLen1,
						   unsigned int *L_Src2, unsigned int SrcLen2)
{
	unsigned int	i;
	unsigned int	carry, tmp;

	for( carry=i=0; (i&0xffffffff)<(SrcLen2&0xffffffff); i++) {
		if( ((L_Src2[i]&0xffffffff)+(carry&0xffffffff))==0 )
			L_Dst[i] = L_Src1[i];
		else {
			tmp = L_Src2[i] + carry;
			L_Dst[i] = L_Src1[i] - tmp;
			carry = ( ((L_Dst[i]&0xffffffff)) > (NOT(tmp)&0xffffffff) ) ? 1 : 0;
		}
	}

	if( (carry&0xffffffff)==0 ) {
		if( L_Dst != L_Src1 )
			for(  ; (i&0xffffffff) < (SrcLen1&0xffffffff); i++)
				L_Dst[i] = L_Src1[i];
		return 0;
	}

	for(  ; (i&0xffffffff) < (SrcLen1&0xffffffff); i++)
		if( (((L_Dst[i]--)&0xffffffff))!=0 )	return 0;

	return 1;
}

/*************** Function *************************************************
*	Long multiple unsigned int ::
*		L_Dst[SrcLen-1..0] = L_Multiplicand[SrcLen-1..0] * D_Multiplier
*			and return the carries
*	** Assume SrcLen>0 **
*/
static unsigned int bn_MulD(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen,
					 unsigned int D_Multiplier)
{
	unsigned int	i;
	unsigned int	La[2], tmp=0;

	for( i=0; i<SrcLen; i++) {
		D_Mul_D(La, D_Multiplier, L_Src[i]);
		La[0] += tmp;
		if( (La[0])<tmp )	La[1]++;
		L_Dst[i] = La[0];
		tmp = La[1];
	}

	return tmp;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int	bn_MulAdd(unsigned int *L_Dst, unsigned int DstLen,
						  unsigned int *L_Src, unsigned int SrcLen, unsigned int D_Multiplier)
{
	unsigned int	i;
	unsigned int	tmp, La[2];

	for( tmp=0, i=0; (i&0xffffffff) < (SrcLen&0xffffffff); i++) {
		D_Mul_D(La, D_Multiplier, L_Src[i]);
		if( ((tmp= (tmp&0xffffffff) +  (La[0]&0xffffffff))&0xffffffff) < (La[0]&0xffffffff) )	La[1]++;
		if( ((L_Dst[i]= (L_Dst[i]&0xffffffff) + (tmp&0xffffffff))&0xffffffff) < (tmp&0xffffffff) )	La[1]++;
		tmp = La[1];
	}

	if( (i&0xffffffff) == (DstLen&0xffffffff) )				return tmp;
	if( ((L_Dst[i]= (L_Dst[i]&0xffffffff) + (tmp&0xffffffff))&0xffffffff) >= (tmp&0xffffffff) )	return 0;

	for( i++; (i&0xffffffff) < (DstLen&0xffffffff); i++)
		if( ((++L_Dst[i])&0xffffffff)!=0 )	return 0;

	return 1;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int	bn_MulSub(unsigned int *L_Dst, unsigned int DstLen,
						  unsigned int *L_Src, unsigned int SrcLen, unsigned int D_Multiplier)
{
	unsigned int	i;
	unsigned int	tmp, La[2];

	for( tmp=0, i=0; (int)i < (int)SrcLen; i++) {
		D_Mul_D(La, D_Multiplier, L_Src[i]);

		tmp = tmp + La[0];
        
		if( (tmp&0xffffffff) < (La[0]&0xffffffff) ) La[1]++;
		if( (L_Dst[i]&0xffffffff) < (tmp&0xffffffff) )  La[1]++;
		L_Dst[i] = L_Dst[i] - tmp;
        
		tmp = La[1];
	}

	if( (int)i == (int)DstLen )				return tmp;

	if( (L_Dst[i]&0xffffffff) >= (tmp&0xffffffff) ) {
		L_Dst[i] = L_Dst[i] - tmp;
		return 0;
	}
	else
		L_Dst[i] = L_Dst[i] - tmp;

	for( i++; (int)i < (int)DstLen; i++)
		if( ((L_Dst[i]--)&0xffffffff) != 0 )	return 0;

	return 1;
}

/*************** Function *************************************************
*	Long square : L_Dst[2*SrcLen-1..0] <- L_Src[SrcLen-1..0] ^ 2
*	** Assume SrcLen>1 **
*/
static void bn_Sqr(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen)
{
	unsigned int	i, j;
	unsigned int	tmp, La[2];

	//	Step 1 : L_Dst[SrcLen-1..0] = 0
	L_Dst[0] = L_Dst[SrcLen+SrcLen-1] = 0;

	//	Step 2 : L_Dst <- Sum_{i<j} L_Src[i]*L_Src[j]*b^{i+j}
	L_Dst[SrcLen] = bn_MulD( L_Dst+1, L_Src+1, SrcLen-1, L_Src[0]);
	for( i=1; (i&0xffffffff) <= (SrcLen&0xffffffff)-2; i++)
		L_Dst[SrcLen+i] = bn_MulAdd(L_Dst+1+i+i, SrcLen-1-i,
									L_Src+1+i, SrcLen-1-i, L_Src[i]);

	//	Step 3 : L_Dst[2n-1..1] <<1 (= C*2) , L_Dst[0] = 0
	bn_SHL(L_Dst, L_Dst, SrcLen+SrcLen, 1);

	//	Step 4 : L_Dst <- L_Dst + Sum_{i=0..SrcLen-1} L_Src[i]^2 * b^{2i}
	for( tmp=i=j=0; (i&0xffffffff) < (SrcLen&0xffffffff); i++,j+=2 ) {
		D_Mul_D(La, L_Src[i], L_Src[i]);
		if( ((La[0] = (La[0]&0xffffffff) + (tmp&0xffffffff))&0xffffffff) < (tmp&0xffffffff) )			La[1]++;
		if( ((L_Dst[j] = (L_Dst[j]&0xffffffff) + (La[0]&0xffffffff))&0xffffffff) < (La[0]&0xffffffff) )	La[1]++;
		if( ((L_Dst[j+1] = (L_Dst[j+1]&0xffffffff) + (La[1]&0xffffffff))&0xffffffff) < (La[1]&0xffffffff) ) tmp = 1;
		else							tmp = 0;
	}
}

/*************** Function *************************************************
*	Long multiple :  L_Dst[SrcLen1+SrcLen2-1..0] = L_Src1[SrcLen1-1..0]
*												 * L_Src2[SrcLen2-1..0]
*	** Assume SrcLen1>=SrcLen2 > 1 **
*/
static void bn_Mul(unsigned int *L_Dst, unsigned int *L_Src1, unsigned int SrcLen1,
						  unsigned int *L_Src2, unsigned int SrcLen2)
{
	unsigned int	La[2], tmp;
	unsigned int	i, j;

	for( i=0; (i&0xffffffff) < (SrcLen1&0xffffffff)+(SrcLen2&0xffffffff); i++)
		L_Dst[i] = 0;

	for( j=0; (j&0xffffffff) < (SrcLen2&0xffffffff); j++) {
		for( tmp=0,i=0; (i&0xffffffff) < (SrcLen1&0xffffffff); i++) {
			D_Mul_D(La, L_Src1[i], L_Src2[j]);
			if( ((tmp = (tmp&0xffffffff) + (La[0]&0xffffffff))&0xffffffff) < (La[0]&0xffffffff) )	La[1]++;
			if( ((L_Dst[i+j] = (L_Dst[i+j]&0xffffffff) + (tmp&0xffffffff))&0xffffffff) < (tmp&0xffffffff) )	La[1]++;
			tmp = La[1];
		}
		L_Dst[i+j] = tmp;
	}
}

/*************** Function *************************************************
*	Long square by Karatsuba algorithm ::
*		L_Dst[2*SrcLen-1..0] <- L_Src[SrcLen-1..0] ^ 2
*	** Assume SrcLen>1 **
*/
static void bn_KaraSqr(unsigned int *L_Dst, unsigned int *L_Src, unsigned int SrcLen)
{
	int	FLAG=0;
	unsigned int	n2=(SrcLen+1)/2, tmp=0;
	unsigned int	S[MaxDIGIT+2];
	unsigned int	T[MaxDIGIT+2];

	if( (SrcLen&0xffffffff)==1 ) {
		D_Mul_D(L_Dst, L_Src[0], L_Src[0]);
		return;
	}

	if( (SrcLen&0xffffffff) < (Kara_Sqr_Length&0xffffffff) ) {
		bn_Sqr(L_Dst, L_Src, SrcLen);
		return;
	}

	if( (SrcLen&0xffffffff)&1 ) {
		tmp = L_Src[SrcLen];
		L_Src[SrcLen] = 0;
		FLAG = 1;
		SrcLen ++;
	}

	if( (bn_Cmp(L_Src+n2, n2, L_Src, n2)&0xffffffff) == 1 )
		bn_Sub(S, L_Src+n2, n2, L_Src, n2);
	else
		bn_Sub(S, L_Src, n2, L_Src+n2, n2);

	bn_KaraSqr(T, S, n2);
	bn_KaraSqr(L_Dst, L_Src, n2);
	bn_KaraSqr(L_Dst+SrcLen, L_Src+n2, n2);

	S[SrcLen] = bn_Add(S, L_Dst, SrcLen, L_Dst+SrcLen, SrcLen);
	bn_Sub(S, S, SrcLen+1, T, SrcLen);
	bn_Add(L_Dst+n2, L_Dst+n2, SrcLen+n2, S, SrcLen+1);

	if( FLAG&0xffffffff ) {
		SrcLen--;
		L_Src[SrcLen] = tmp;
	}
}

/*************** Function *************************************************
*	Long multiple by Karatsuba algorithm ::
*		L_Dst[2*SrcLen-1..0] = L_Src1[SrcLen-1..0] * L_Src2[SrcLen-1..0]
*	** Assume SrcLen > 1 **
*/
static void	bn_KaraMul(unsigned int *L_Dst, unsigned int *L_Src1, unsigned int *L_Src2, unsigned int SrcLen)
{
	int	FLAG=0, SIGN=0;
	unsigned int	n2=(SrcLen+1)/2, tmp1=0, tmp2=0;
	unsigned int	S[MaxDIGIT+2];
	unsigned int	T[MaxDIGIT+2];

#define TempHalf	(MaxDIGIT+2)/2

	if( (int)SrcLen == 1 ) {
		D_Mul_D(L_Dst, L_Src1[0], L_Src2[0]);
		return;
	}
    
	if( (int)SrcLen < (int)Kara_Mul_Length ) {
		bn_Mul( L_Dst, L_Src1, SrcLen, L_Src2, SrcLen);
        
		return;
	}

	if( (SrcLen&0xffffffff) & 1 ) {
		tmp1 = L_Src1[SrcLen];
		L_Src1[SrcLen] = 0;
		tmp2 = L_Src2[SrcLen];
		L_Src2[SrcLen] = 0;
		FLAG = 1;
		SrcLen++;
	}

	if( (int)bn_Cmp(L_Src1+n2, n2, L_Src1, n2) == 1 )
		bn_Sub(S, L_Src1+n2, n2, L_Src1, n2);
	else {
		bn_Sub(S, L_Src1, n2, L_Src1+n2, n2);
		SIGN++;
	}
	if( (int)bn_Cmp(L_Src2+n2, n2, L_Src2, n2) == 1 )
		bn_Sub(S+TempHalf, L_Src2+n2, n2, L_Src2, n2);
	else {
		bn_Sub(S+TempHalf, L_Src2, n2, L_Src2+n2, n2);
		SIGN++;
	}

	bn_KaraMul(T, S, S+TempHalf, n2);
	bn_KaraMul(L_Dst, L_Src1, L_Src2, n2);
	bn_KaraMul(L_Dst+SrcLen, L_Src1+n2, L_Src2+n2, n2);

	S[SrcLen] = bn_Add(S, L_Dst, SrcLen, L_Dst+SrcLen, SrcLen);
	if( (int)SIGN == 1 )
		bn_Add(S, S, SrcLen+1, T, SrcLen);
	else
		bn_Sub(S, S, SrcLen+1, T, SrcLen);
	bn_Add(L_Dst+n2, L_Dst+n2, SrcLen+n2, S, SrcLen+1);

	if( (int)FLAG ) {
		SrcLen --;
		L_Src1[SrcLen] = tmp1;
		L_Src2[SrcLen] = tmp2;
	}
}

/*************** Function *************************************************
*	Long division ::
*		L_Dst[SrcLen1-SrcLen2-1..0] = L_Src1[SrcLen1-1..0]
*									  div L_Src2[SrcLen2-1..0]
*		L_Rem[SrcLen1-1..0] = L_Src1[SrcLen1-1..0]
*							  mod L_Src2[SrcLen2-1..0]
*				& return 0 if remainder equals 0
*/
static unsigned int bn_Div(unsigned int *L_Dst, unsigned int *L_Rem,
					unsigned int *L_Src1, unsigned int SrcLen1,
					unsigned int *L_Src2, unsigned int SrcLen2)
{
	unsigned int	i, q, c, make_MSB;
	unsigned int	C[2*(MaxDIGIT+2)];

	bn_Copy(C, L_Src1, SrcLen1);
	C[SrcLen1] = 0;
	c = SrcLen1 + 1;

	//	Step 1 : Standardize L_Src2 s.t. L_Src2[SrcLen2-1] > b/2
	make_MSB = 0;
	for( i=SrcLen2*BitsInDIGIT-1; !(CheckBitDIGIT(L_Src2,i)); i--,make_MSB++);
	if( make_MSB!=0 ) {
		bn_SHL(C, C, c, make_MSB);
		bn_SHL(L_Src2, L_Src2, SrcLen2, make_MSB);
	}

	//	Step 2 : main part
	for( i=c-SrcLen2-1; i!=(unsigned int)-1; i--) {
		//	Step 2-1 : Estimate q
		if( C[SrcLen2+i]==L_Src2[SrcLen2-1] )
			q = (unsigned int)-1;
		else
			q = DD_Div_D(C[SrcLen2+i], C[SrcLen2+i-1], L_Src2[SrcLen2-1]);

		//	Step 2-2 : Make C <- C-q*L_Src2
		if( bn_MulSub(C+i, SrcLen2+1, L_Src2, SrcLen2, q) ) {
			q--;
			if( bn_Add(C+i, C+i, SrcLen2+1, L_Src2, SrcLen2)==0 ) {
				q--;
				bn_Add(C+i, C+i, SrcLen2+1, L_Src2, SrcLen2);
			}
		}
		L_Dst[i] = q;
	}

	//	Step 3 : Recover L_Src2
	if( make_MSB!=0 ) {
		bn_SHR(L_Src2, L_Src2, SrcLen2, make_MSB);
		bn_SHR(C, C, SrcLen2, make_MSB);
	}

	//	
	if( L_Rem!=NULL )
		bn_Copy(L_Rem, C, SrcLen2);

	//
	for( i=0; i<c; i++)
		if( C[i]!=0 )
			return 1;
	return 0;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_Euclid(unsigned int *L_Dst, unsigned int *L_Src,
						 unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int		i, ret, make_ODD, Len_1=ModLen+1;
	unsigned int		*U1, *U2, *U3, *T1, *T2, *T3, *Temp;
	unsigned int		Value1[MaxDIGIT+2], Value2[MaxDIGIT+2], Value3[MaxDIGIT+2],
				Value4[MaxDIGIT+2], Value5[MaxDIGIT+2], Value6[MaxDIGIT+2];

	U1 = Value1;
	U2 = Value2;
	U3 = Value3;
	T1 = Value4;
	T2 = Value5;
	T3 = Value6;

	//	Step 1 : Divide both L_Src and L_Modulus by 2 as long as possible
	for ( make_ODD=0;  ; make_ODD++)
		if( CheckBitDIGIT(L_Src, make_ODD) || CheckBitDIGIT(L_Modulus, make_ODD) )
			break;
	if( make_ODD!=0 ) {
		if( make_ODD>=BitsInDIGIT ) {
			assert( 1==0 );
		}
		else {
			ret = bn_SHR(L_Src, L_Src, ModLen, make_ODD);
			assert( ret==0 );
			ret = bn_SHR(L_Modulus, L_Modulus, ModLen, make_ODD);
			assert( ret==0 );
		}
	}

	//	Initialize U1, U2, U3, V1, V2, V3, T1, T2, T3
	for( i=0; i<ModLen; i++) {
		U1[i] = U2[i] = 0;
		U3[i] = T2[i] = L_Modulus[i];
		T1[i] = T3[i] = L_Src[i];
	}
	U1[i] = U2[i] = U3[i] = T2[i] = T1[i] = T3[i] = 0;
	U1[0] = 1;
	if( T2[0]!=0 )	T2[0] -= 1;
	else			bn_Sub(T2, T2, ModLen, bn_One, 1);

	//	main part
	do {
		do {
			if( isEven0(U3) ) {
				if( isOdd0(U1) || isOdd0(U2) ) {
					bn_Add(U1, U1, Len_1, L_Src, ModLen);
					bn_Add(U2, U2, Len_1, L_Modulus, ModLen);
				}
				bn_SHR(U1, U1, Len_1, 1);
				bn_SHR(U2, U2, Len_1, 1);
				bn_SHR(U3, U3, Len_1, 1);
			}

			if( isEven0(T3) || bn_Cmp(U3, Len_1, T3, Len_1)<0 ) {
				Temp = U1;	U1 = T1;	T1 = Temp;
				Temp = U2;	U2 = T2;	T2 = Temp;
				Temp = U3;	U3 = T3;	T3 = Temp;
			}
		} while( isEven0(U3) );

		while( (bn_Cmp(U1, Len_1, T1, Len_1)<0)
			|| (bn_Cmp(U2, Len_1, T2, Len_1)<0) ) {
			bn_Add(U1, U1, Len_1, L_Src, ModLen);
			bn_Add(U2, U2, Len_1, L_Modulus, ModLen);
		}

		bn_Sub(U1, U1, Len_1, T1, Len_1);
		bn_Sub(U2, U2, Len_1, T2, Len_1);
		bn_Sub(U3, U3, Len_1, T3, Len_1);
	} while( bn_Cmp(T3, Len_1, bn_Zero, 1)>0 );

	while( (bn_Cmp(U1, Len_1, L_Src, ModLen)>=0)
		&& (bn_Cmp(U2, Len_1, L_Modulus, ModLen)>=0) ) {
		bn_Sub(U1, U1, Len_1, L_Src, ModLen);
		bn_Sub(U2, U2, Len_1, L_Modulus, ModLen);
	}

	//	Inverse of Step 1
	if( make_ODD!=0 ) {
		if( make_ODD>=BitsInDIGIT ) {
			assert( 1==0 );
		}
		else {
			ret = bn_SHL(L_Src, L_Src, ModLen, make_ODD);
			assert( ret==0 );
			ret = bn_SHL(L_Modulus, L_Modulus, ModLen, make_ODD);
			assert( ret==0 );
			ret = bn_SHL(U3, U3, ModLen, make_ODD);
			assert( ret==0 );
		}
	}

	if ( bn_Cmp(U3, ModLen, bn_One, 1)==0 ) {//	gcd(L_Dst,L_Modulus)==1
		bn_Sub(L_Dst, L_Modulus, ModLen, U2, ModLen);
											//	L_Dst <- L_Src^{-1} mod L_Modulus
		return CTR_SUCCESS;
	}
	else {									//	gcd(L_Dst,L_Modulus)>1
		for( i=0; i<ModLen; i++)
			L_Dst[i] = U3[i];				//	L_Dst <- gcd(L_Src,L_Modulus)
		return CTR_VERIFY_FAIL;
	}
}

/*************** Global Variables *****************************************/
#define Max_W_size		6
static unsigned int	Window_PreData[1<<(Max_W_size-1)][MaxDIGIT+1];
#define PP_W(x) Window_PreData[x]
static int		Add_Chain[BN_MAX_BITS/Max_W_size][2];

static unsigned int	Window_PreData2_CHK[2][MaxDIGIT]={{0,0,0,0,0},{0,0,0,0,0}};

#define FirstWindowMayBeEven	0
#define FirstWindowMustBeOdd	1


/*************** Function *************************************************
*	
*/
static unsigned int MakeAddChain(
			int		AddChain[][2],	//	결과를 넣을 메무리
			int		WindowSize,		//	
			unsigned int	*L_Exponent,	//
			unsigned int	msb,			//
			int	Type)			//	Type='FirstWindowMayBeEven'이면
									//	최초 window가 짝수일수도 있음
{
	int		i=msb, j, SubExp, idx=0;

	//
	for( i=msb; (int)i >= 0; i--)
		if( CheckBitDIGIT(L_Exponent, i) )	break;
	if( (int)i == -1 ) {
		AddChain[idx][0] = -1;
		AddChain[idx][1] = -1;
		return 0;
	}

	//
	if( Type == FirstWindowMayBeEven ) {
		j = ((int)(i-(int)WindowSize+1)>=0 ) ? i-(int)WindowSize+1 : 0;
		for( SubExp=0; (i&0xffffffff) >= (j&0xffffffff); i--) {
			SubExp = (SubExp&0xffffffff) << 1;
			if( CheckBitDIGIT(L_Exponent, i) )
				SubExp = (SubExp&0xffffffff) ^ 1;
		}
		AddChain[idx][0] = i+1;
		AddChain[idx][1] = SubExp;
		idx++;
	}

	//	main part of this function
	for(  ; (int)i >= 0;  ) {
		if( (CheckBitDIGIT(L_Exponent, i)&0xffffffff) == 0 ) {
			i--;
			continue;
		}

		//	Find LSB of the Window
		j = i - (int)WindowSize + 1;
		if( j < 0 )	j = 0;
		for(  ; (int)j <= (int)i; j++)
			if( (int)CheckBitDIGIT(L_Exponent, j) )
				break;

		//	Get the Window value = 'SubExp'
		for( SubExp=0; (int)i >= (int)j; i--) {
			SubExp = (SubExp&0xffffffff) << 1;
            
			if( (int)CheckBitDIGIT(L_Exponent, i) )
				SubExp = (SubExp&0xffffffff) ^ 1;
		}
		AddChain[idx][0] = i+1;
		AddChain[idx][1] = SubExp;
		idx++;
	}
    
	AddChain[idx][0] = -1;
	AddChain[idx][1] = -1;
	return idx;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int bn_ModExp(unsigned int *L_Dst, unsigned int *L_Base, unsigned int BaseLen,
						 unsigned int *L_Exponent, unsigned int ExpLen,
						 unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int		ret;
	unsigned int		i, j = 0, MSB=0, WindowSize;
	unsigned int		*P1, *P2, *P3;
	unsigned int (*Algorithm_REDC)(unsigned int *L_Dst, unsigned int Len_Res,
							  unsigned int *L_Modulus, unsigned int ModLen);
	unsigned int		L_Temp1[2*(MaxDIGIT+2)];
	unsigned int		L_Temp2[2*(MaxDIGIT+2)];

	//	Fine the Most-Significant-Bit of exponent L_Exponent
	i = (int)ExpLen * BitsInDIGIT - 1;
	for(  ; (int)i != (int)-1; i--)
		if( (int)CheckBitDIGIT(L_Exponent, i) )
			break;

	if( (int)i == (int)-1 ) {		//	L_Exponent[] = 0
        L_Dst[0] = 1;
		for( j=1; (int)j < (int)ModLen; j++)	L_Dst[j] = 0;
		//
		ret = CTR_SUCCESS;
		goto LABEL_END;
	}
    
	if( (int)i==0 ) {				//	L_Exponent[] = 1
        
		for( j=0; (int)j < (int)BaseLen; j++)	L_Dst[j] = L_Base[j];
		for(    ; (int)j < (int)ModLen; j++)	L_Dst[j] = 0;
		//
		ret = CTR_SUCCESS;
		goto LABEL_END;
	}

	//	Determine Window size
	if	   ( (int)i < 32 )		WindowSize = 1;
	else if( (int)i < 60 )		WindowSize = 3;
	else if( (int)i < 220 )	WindowSize = 4;
	else if( (int)i < 636 )	WindowSize = 5;
	else if( (int)i < 1758 )	WindowSize = 6;
	else				WindowSize = 7;
	if( (int)WindowSize > Max_W_size )		WindowSize = Max_W_size;
    
	//	Determine
	Algorithm_REDC = Montgomery_REDC;   //	Apply Montgomery Algorithm

	//
	for( j=0; (int)j < (int)BaseLen; j++)	L_Temp2[j] = L_Base[j];
	for(    ; (int)j < (int)ModLen; j++)	L_Temp2[j] = 0;
    
	//	initialize for ModRed depand on L_Modulus
	ret = Montgomery_Init(L_Modulus, ModLen);					GOTO_END;
    
	//	Change number system Zn to RZn : L_Temp1<-L_Base in RZn
	ret = Montgomery_Zn2RZn(L_Temp1, L_Temp2, L_Modulus, ModLen);
																GOTO_END;
    
	////	Binary method
    if( (int)WindowSize == 1 ) {
		bn_Copy(L_Dst, L_Temp1, ModLen);
		P1 = L_Temp1;
		P2 = L_Temp2;
		for( i--; (int)i != -1; i--) {
			bn_KaraSqr(P2, P1, ModLen);
			ret = Algorithm_REDC(P2, 2*ModLen, L_Modulus, ModLen);
																	GOTO_END;
			if( (int)CheckBitDIGIT(L_Exponent, i) ) {
				bn_KaraMul(P1, P2, L_Dst, ModLen);
				ret = Algorithm_REDC(P1, 2*ModLen, L_Modulus, ModLen);
																	GOTO_END;
			}
			else {
				P3 = P1;	P1 = P2;	P2 = P3;
			}
		}
	}
	
	else {	////	Window method
		//	Precompute and save in *PP_W(x)
		bn_KaraSqr(L_Temp2, L_Temp1, ModLen);	//	L_Temp2<-L_Base^2
        
		ret = Algorithm_REDC(L_Temp2, 2*ModLen, L_Modulus, ModLen);	GOTO_END;
		bn_Copy(PP_W(0), L_Temp1, ModLen);
		for( j=1; (int)j < ((unsigned int)1 << ((WindowSize-1)&0xffffffff)); j++) {
			bn_KaraMul(L_Temp1, PP_W(j-1), L_Temp2, ModLen);
			ret = Algorithm_REDC(L_Temp1, 2*ModLen, L_Modulus, ModLen);	GOTO_END;
			bn_Copy(PP_W(j), L_Temp1, ModLen);
		}

		//	Get Addition Chain
		i = MakeAddChain(Add_Chain, WindowSize, L_Exponent, i, FirstWindowMayBeEven);
		if( (int)i >= (int)(BN_MAX_BITS/Max_W_size) ) {
			ret = CTR_FATAL_ERROR;
			goto LABEL_END;
		}

		if( (int)(Add_Chain[0][1]&0xffffffff)&1 )		//	if SubExp == odd
			bn_Copy(L_Temp2, PP_W(Add_Chain[0][1]/2), ModLen);
		else {
			bn_KaraMul(L_Temp2, PP_W(0), PP_W(Add_Chain[0][1]/2-1), ModLen);
			ret = Algorithm_REDC(L_Temp2, 2*ModLen, L_Modulus, ModLen);	GOTO_END;
		}
		i = Add_Chain[0][0] - 1;
		j = 1;

		//	main part of this function
		P1 = L_Temp2;
		P2 = L_Temp1;
		for(  ; (unsigned int)i != (unsigned int)-1; i--) {
			bn_KaraSqr(P2, P1, ModLen);
			ret = Algorithm_REDC(P2, 2*ModLen, L_Modulus, ModLen);	GOTO_END;
			P3 = P1;	P1 = P2;	P2 = P3;

			if( (unsigned int)i == ((unsigned int)Add_Chain[j][0]&0xffffffff) ) {
				bn_KaraMul(P2, P1, PP_W((Add_Chain[j][1]&0xffffffff)>>1), ModLen);
				ret = Algorithm_REDC(P2, 2*ModLen, L_Modulus, ModLen);	GOTO_END;
				P3 = P1;	P1 = P2;	P2 = P3;
				j++;
			}
		}
	}
	
	if( Algorithm_REDC == Montgomery_REDC ) {
		//	Change number system RZn to Zn
		ret = Montgomery_REDC(P1, ModLen, L_Modulus, ModLen);		GOTO_END;
	}
	else if( (int)MSB ) {
		bn_SHR(L_Modulus, L_Modulus, ModLen, MSB);
		ret = Classical_REDC(P1, ModLen+1, L_Modulus, ModLen);		GOTO_END;
	}

	bn_Copy(L_Dst, P1, ModLen);

	ret = CTR_SUCCESS;
LABEL_END:
	return ret;
}

//########################################
//	BIGNUM의 지원 함수 
//########################################

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
BIGNUM	*CreateBigNum(unsigned int dMemoryLen)
{
	unsigned char		*pbTemp;
	BIGNUM		*BN_Num;

	if( dMemoryLen==0 )
		dMemoryLen = MaxDIGIT;

	pbTemp = (unsigned char *) malloc(sizeof(BIGNUM)+(dMemoryLen+1)*sizeof(unsigned int));
	if( pbTemp==NULL )	return NULL;

	BN_Num = (BIGNUM *) pbTemp;
	BN_Num->Length = 0;
	BN_Num->Space = dMemoryLen+1;
	BN_Num->pData = (unsigned int *) (pbTemp + sizeof(BIGNUM));	

	return BN_Num;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
void	DestroyBigNum(BIGNUM *BN_Src)
{
	unsigned int		i;

	if( BN_Src!=NULL ) {
		i = sizeof(BIGNUM) + BN_Src->Space * sizeof(unsigned int);

		memset((unsigned char *)BN_Src, 0, i);
		free(BN_Src);
	}
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int	BN2OS(
			BIGNUM	*BN_Src,	//	Source integer
			unsigned int	dDstLen,	//	Destination Length in BYTEs
			unsigned char	*pbDst)		//	Destination Octet string pointer
{
	unsigned int	i;

	CheckMostSignificantDIGIT(BN_Src);

	if( (DIGITSIZE*BN_Src->Length)<=dDstLen ) {
		for( i=0; i<dDstLen; i++)
			pbDst[i] = 0;
		for( i=0; (dDstLen!=0) && (i<BN_Src->Length); i++) {
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]    ) & 0xFF);
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>> 8) & 0xFF);
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>>16) & 0xFF);
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>>24) & 0xFF);
		}
	}
	else {
		i = (DIGITSIZE*BN_Src->Length) - dDstLen;
		if( i>=DIGITSIZE )
			return CTR_BUFFER_TOO_SMALL;
		else if( BN_Src->pData[BN_Src->Length-1]>>(8*(DIGITSIZE-i))  )
			return CTR_BUFFER_TOO_SMALL;

		for( i=0;  ; i++) {
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]    ) & 0xFF);
			if( dDstLen==0 )	break;
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>> 8) & 0xFF);
			if( dDstLen==0 )	break;
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>>16) & 0xFF);
			if( dDstLen==0 )	break;
			pbDst[--dDstLen] = (unsigned char)((BN_Src->pData[i]>>24) & 0xFF);
			if( dDstLen==0 )	break;
		}
	}

	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int	OS2BN(
			unsigned char	*pbSrc,		//	Source Octet string pointer
			unsigned int	dSrcLen,	//	Source Length in BYTEs
			BIGNUM	*BN_Dst)	//	Destination unsigned int array pointer
{
	unsigned int	i;
	unsigned int	ret;

	BN_Dst->Length = 0;
	BN_Dst->pData[0] = 0;

	for( i=0; (int)i<(int)dSrcLen; i++) {
		ret = BN_SHL(BN_Dst, BN_Dst, 8);	if( ret!=CTR_SUCCESS )	return ret;
		BN_Dst->pData[0] = (BN_Dst->pData[0]&0xffffffff) ^ (pbSrc[i]&0xffffffff);
		if( (int)BN_Dst->Length==0 )
			BN_Dst->Length = 1;
	}

	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_Copy(BIGNUM *BN_Dst, BIGNUM *BN_Src)
{
	unsigned int	i;

	if( BN_Dst!=BN_Src ) {
		CheckInput_MemLen(BN_Src);

		BN_Dst->Length = BN_Src->Length;
		CheckOutput_MemLen(BN_Dst);
        
		//	copy long values
        for( i=0; (int)i < (int)BN_Dst->Length; i++){
			BN_Dst->pData[i] = BN_Src->pData[i];
        }
	}

	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
int BN_Cmp(BIGNUM *BN_Src1, BIGNUM *BN_Src2)
{
	CheckInput_MemLen(BN_Src1);
	CheckInput_MemLen(BN_Src2);
	
	if( BN_Src1->Length >= BN_Src2->Length )
		return  bn_Cmp(BN_Src1->pData, BN_Src1->Length,
					   BN_Src2->pData, BN_Src2->Length);
	else
		return -bn_Cmp(BN_Src2->pData, BN_Src2->Length,
					   BN_Src1->pData, BN_Src1->Length);
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_Rand(BIGNUM *BN_Dst, unsigned int BitLen)
{
	unsigned int	i, j;
	unsigned int temp_rand;
	
	
	for( i=0; (int)i < (int)BitLen/BitsInDIGIT; i++){
		temp_rand = rand()&0xffff;
        
		BN_Dst->pData[i] = (rand()&0xffff) ^ ((temp_rand&0xffff)<<11) ^ ((temp_rand&0xffff)<<19);
	}
    
	j = (BitLen&0xffffffff)%BitsInDIGIT;
	if( (int)j ) {
		temp_rand = rand()&0xffff;
		BN_Dst->pData[i] = (rand()&0xffff) ^ ((temp_rand&0xffff)<<11) ^ ((temp_rand&0xffff)<<19);
		BN_Dst->pData[i] = (BN_Dst->pData[i]&0xffff) & ((((unsigned int)1)<<(j)) - 1);
		i++;
	}
	BN_Dst->Length = (((int)BitLen-1))/BitsInDIGIT + 1;
	CheckOutput_MemLen(BN_Dst);

	return CTR_SUCCESS;
}

//########################################
//	BIGNUM의 핵심연산 함수
//########################################

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_SHL(BIGNUM *BN_Dst, BIGNUM *BN_Src, unsigned int NumOfShift)
{
	unsigned int	i;
	unsigned int	t;

	CheckInput_MemLen(BN_Src);

	//
	if( (int)BN_Src->Length==0 ) {
		return BN_Copy(BN_Dst, &BN_Zero);
	}

	//	if ( n>=BitsInDIGIT ) then unsigned int 단위로 left shift
	t = (NumOfShift&0xffffffff) % BitsInDIGIT;
	if( (int)t ) {
		BN_Dst->Length = BN_Src->Length;
		t = bn_SHL(BN_Dst->pData, BN_Src->pData, BN_Src->Length, t);
		if( (int)t )
			BN_Dst->pData[BN_Dst->Length++] = t;
	}

	t = (NumOfShift&0xffffffff) / BitsInDIGIT;
	if( (int)t ) {
		BN_Dst->Length = BN_Src->Length + t;
		CheckOutput_MemLen(BN_Dst);
		for( i=BN_Dst->Length-t-1; (int)i!=-1; i--)
			BN_Dst->pData[t+i] = BN_Src->pData[i];
		for( i=0; (int)i<(int)t; i++)
			BN_Dst->pData[i] = 0;
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_SHR(BIGNUM *BN_Dst, BIGNUM *BN_Src, unsigned int NumOfShift)
{
	unsigned int	i;
	unsigned int	t;

	CheckInput_MemLen(BN_Src);

	//	if ( n>=BitsInDIGIT ) then unsigned int 단위로 left shift
	t = NumOfShift / BitsInDIGIT;
	if( t&0xffffffff ) {
		if( (t&0xffffffff) >= (BN_Src->Length&0xffffffff) )
			return BN_Copy(BN_Dst, &BN_Zero);

		for( i=0; i<BN_Src->Length-t; i++)
			BN_Dst->pData[i] = BN_Src->pData[i+t];
		BN_Dst->Length = BN_Src->Length - t;
		CheckMostSignificantDIGIT(BN_Dst);
	}
	else
		BN_Copy(BN_Dst, BN_Src);

	t = (NumOfShift&0xffffffff) % BitsInDIGIT;
	if( t&0xffffffff ) {
		bn_SHR(BN_Dst->pData, BN_Dst->pData, BN_Dst->Length, t);
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_Add(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2)
{
	unsigned int	tmp;
	unsigned int	carry;

	CheckInput_MemLen(BN_Src1);
	CheckInput_MemLen(BN_Src2);

	if( BN_Src1->Length==0 )	return BN_Copy(BN_Dst, BN_Src2);
	if( BN_Src2->Length==0 )	return BN_Copy(BN_Dst, BN_Src1);

	if( BN_Src1->Length>=BN_Src2->Length ) {
		tmp = BN_Src2->Length;
		BN_Dst->Length = BN_Src1->Length;
		CheckOutput_MemLen(BN_Dst);
		carry = bn_Add(BN_Dst->pData, BN_Src1->pData, BN_Src1->Length,
									 BN_Src2->pData, tmp);
	}
	else {
		tmp = BN_Src1->Length;
		BN_Dst->Length = BN_Src2->Length;
		CheckOutput_MemLen(BN_Dst);
		carry = bn_Add(BN_Dst->pData, BN_Src2->pData, BN_Src2->Length,
									 BN_Src1->pData, tmp);
	}

	if( carry ) {
		BN_Dst->pData[BN_Dst->Length++] = carry;
		CheckOutput_MemLen(BN_Dst);
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_Sub(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2)
{
	unsigned int	tmp;
	unsigned int	carry;

	CheckInput_MemLen(BN_Src1);
	CheckInput_MemLen(BN_Src2);

	if( bn_Cmp(BN_Src1->pData, BN_Src1->Length,
			   BN_Src2->pData, BN_Src2->Length)<0 )
		return CTR_BN_NEGATIVE_RESULT;

	tmp = BN_Src2->Length;
	BN_Dst->Length = BN_Src1->Length;
	CheckOutput_MemLen(BN_Dst);
	carry = bn_Sub(BN_Dst->pData, BN_Src1->pData, BN_Src1->Length,
								 BN_Src2->pData, tmp);

	if( (carry&0xffffffff) ) {
		BN_Dst->pData[BN_Dst->Length++] = carry;
		CheckOutput_MemLen(BN_Dst);
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_Mul(BIGNUM *BN_Dst, BIGNUM *BN_Multiplicand, BIGNUM *BN_Multiplier)
{
	CheckInput_MemLen(BN_Multiplicand);
	CheckInput_MemLen(BN_Multiplier);

	BN_Dst->Length = BN_Multiplicand->Length + BN_Multiplier->Length;
	CheckOutput_MemLen(BN_Dst);

	if( (BN_Multiplicand->Length==0) || (BN_Multiplier->Length==0) ) {
		BN_Dst->Length = 0;
		return CTR_SUCCESS;
	}
	else if( BN_Multiplicand->Length>BN_Multiplier->Length ) {
		bn_Mul(BN_Dst->pData,
				BN_Multiplicand->pData, BN_Multiplicand->Length,
				BN_Multiplier->pData, BN_Multiplier->Length);
	}
	else {
		bn_Mul(BN_Dst->pData,
				BN_Multiplier->pData, BN_Multiplier->Length,
				BN_Multiplicand->pData, BN_Multiplicand->Length);
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/*************** Function *************************************************
*	Long Number Division : BN_Res <- BN_Dividend div BN_Divisor
*/
unsigned int BN_Div(BIGNUM *BN_Quotient, BIGNUM *BN_Remainder,
			  BIGNUM *BN_Dividend, BIGNUM *BN_Divisor)
{
	unsigned int	tmp;
	unsigned int		bnTmp[MaxDIGIT+2];

	CheckInput_MemLen(BN_Dividend);
	CheckInput_MemLen(BN_Divisor);

	if( BN_Quotient==NULL ) {
		BN_Remainder->Length = BN_Divisor->Length;
		CheckOutput_MemLen(BN_Remainder);

		tmp = bn_Div(bnTmp, BN_Remainder->pData,
					 BN_Dividend->pData, BN_Dividend->Length,
					 BN_Divisor->pData, BN_Divisor->Length);
	}
	else if( BN_Remainder==NULL ) {
		BN_Quotient->Length = BN_Dividend->Length - BN_Divisor->Length + 1;
		CheckOutput_MemLen(BN_Quotient);

		tmp = bn_Div(BN_Quotient->pData, bnTmp,
					 BN_Dividend->pData, BN_Dividend->Length,
					 BN_Divisor->pData, BN_Divisor->Length);
	}
	else {
		BN_Quotient->Length = BN_Dividend->Length - BN_Divisor->Length + 1;
		CheckOutput_MemLen(BN_Quotient);
		BN_Remainder->Length = BN_Divisor->Length;
		CheckOutput_MemLen(BN_Remainder);

		tmp = bn_Div(BN_Quotient->pData, BN_Remainder->pData,
					 BN_Dividend->pData, BN_Dividend->Length,
					 BN_Divisor->pData, BN_Divisor->Length);
	}

	CheckMostSignificantDIGIT(BN_Quotient);
	return CTR_SUCCESS;
}

//########################################
//	BIGNUM의 Modulus 연산 함수
//########################################

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModAdd(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
				 BIGNUM *BN_Modulus)
{
	unsigned int	tmp;

	if( (BN_Cmp(BN_Src1, BN_Modulus)>=0) || (BN_Cmp(BN_Src2, BN_Modulus)>=0) )
		return ERROR_OverModulus;

	if( BN_Src1->Length>=BN_Src2->Length ) {
		BN_Dst->Length = BN_Src1->Length;
		tmp = bn_Add(BN_Dst->pData, BN_Src1->pData, BN_Src1->Length,
									 BN_Src2->pData, BN_Src2->Length);
	}
	else {
		BN_Dst->Length = BN_Src2->Length;
		tmp = bn_Add(BN_Dst->pData, BN_Src2->pData, BN_Src2->Length,
									 BN_Src1->pData, BN_Src1->Length);
	}

	if( tmp )
		BN_Dst->pData[BN_Dst->Length++] = tmp;

	if( bn_Cmp(BN_Dst->pData, BN_Dst->Length,
			   BN_Modulus->pData, BN_Modulus->Length)>=0 ) {
		bn_Sub(BN_Dst->pData, BN_Dst->pData, BN_Dst->Length,
							   BN_Modulus->pData, BN_Modulus->Length);
	}

	//
	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModSub(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
				 BIGNUM *BN_Modulus)
{
	unsigned int	tmp;

	if( (BN_Cmp(BN_Src1, BN_Modulus)>=0) || (BN_Cmp(BN_Src2, BN_Modulus)>=0) )
		return ERROR_OverModulus;

	if( bn_Cmp(BN_Src1->pData, BN_Src1->Length,
			   BN_Src2->pData, BN_Src2->Length)>=0 ) {
		BN_Dst->Length = BN_Src1->Length;
		tmp = bn_Sub(BN_Dst->pData, BN_Src1->pData, BN_Src1->Length,
									 BN_Src2->pData, BN_Src2->Length);
	}
	else {
		BN_Dst->Length = BN_Modulus->Length;
		bn_Add(BN_Dst->pData, BN_Modulus->pData, BN_Modulus->Length,
							   BN_Src1->pData, BN_Src1->Length);
		bn_Sub(BN_Dst->pData, BN_Dst->pData, BN_Dst->Length,
							   BN_Src2->pData, BN_Src2->Length);
	}

	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModRed(BIGNUM *BN_Dst, BIGNUM *BN_Src, BIGNUM *BN_Modulus)
{
	unsigned int		i;
	unsigned int		Value[2*(MaxDIGIT+2)];
	unsigned int		ret;

	if( BN_Cmp(BN_Src, BN_Modulus)<0 )
		return BN_Copy(BN_Dst, BN_Src);

	for( i=0; i<BN_Src->Length; i++)	Value[i] = BN_Src->pData[i];

	ret = Classical_REDC(Value, BN_Src->Length,
					BN_Modulus->pData, BN_Modulus->Length);
	if( ret!=CTR_SUCCESS )	return ret;

	for( i=0; i<BN_Modulus->Length; i++)	BN_Dst->pData[i] = Value[i];

	BN_Dst->Length = BN_Modulus->Length;
	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModMul(BIGNUM *BN_Dst, BIGNUM *BN_Src1, BIGNUM *BN_Src2,
				 BIGNUM *BN_Modulus)
{
	unsigned int		i;
	unsigned int		ret;
	unsigned int		Value[2*(MaxDIGIT+2)];

	//	Long Number Multiple Part
	bn_Mul(Value, BN_Src1->pData, BN_Src1->Length,
				  BN_Src2->pData, BN_Src2->Length);

	//	Long Number Reduction Part
	ret = Classical_REDC(Value, BN_Src1->Length+BN_Src2->Length,
					BN_Modulus->pData, BN_Modulus->Length);
	if( ret!=CTR_SUCCESS )	return ret;

	//	Long Number Saving Part
	BN_Dst->Length = BN_Modulus->Length;
	for( i=0; (i&0xffffffff) < (BN_Modulus->Length&0xffffffff); i++)	BN_Dst->pData[i] = Value[i];

	CheckMostSignificantDIGIT(BN_Dst);

	return CTR_SUCCESS;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModInv(BIGNUM *BN_Dst, BIGNUM *BN_Src, BIGNUM *BN_Modulus)
{
	unsigned int		i;
	unsigned int		ret;
	unsigned int		BN_Temp[MaxDIGIT+2];

	for( i=0; i<BN_Src->Length; i++)		BN_Temp[i] = BN_Src->pData[i];
	for(  ; i<BN_Modulus->Length; i++)		BN_Temp[i] = 0;

	BN_Dst->Length = BN_Modulus->Length;
	ret = bn_Euclid(BN_Dst->pData, BN_Temp,
				  BN_Modulus->pData, BN_Modulus->Length);
	CheckMostSignificantDIGIT(BN_Dst);

	return ret;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
unsigned int BN_ModExp(BIGNUM *BN_Dst, BIGNUM *BN_Base, BIGNUM *BN_Exponent,
				 BIGNUM *BN_Modulus)
{
	unsigned int	ret=CTR_SUCCESS;
	
	ret = bn_ModExp(BN_Dst->pData, BN_Base->pData, BN_Base->Length,
					BN_Exponent->pData, BN_Exponent->Length,
					BN_Modulus->pData, BN_Modulus->Length);

	if( ret != CTR_SUCCESS )	return ret;

	BN_Dst->Length = BN_Modulus->Length;
	CheckMostSignificantDIGIT(BN_Dst);
	return CTR_SUCCESS;
}

//########################################
//	기타 보조연산 함수
//########################################

/*************** Function *************************************************
*	Classical Modular Reduction Algorithm
*		L_Dst[ModLen-1..0] <- L_Dst[DstLen-1..0]
*								   mod L_Modulus[ModLen-1..0]
*	** Assume L_Dst[] has at least (DstLen+1)-DIGIT memory **
*/
unsigned int Classical_REDC(unsigned int *L_Dst, unsigned int DstLen,
					   unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int	i;
	unsigned int	MSB=0, TTTT=0, FLAG=0,
			D_Quotient,			//	Estimated quotient
			MSD_Modulus;			//	Most Significant unsigned int of L_Modulus

	//	Step 1 :
	if( (int)DstLen < (int)ModLen )
		return CTR_SUCCESS;
    
	//	Step 1.5 :
	if( (L_Dst[DstLen-1]&0xffffffff) >= (L_Modulus[ModLen-1]&0xffffffff) ) {
		FLAG++;
		TTTT = L_Dst[DstLen];
		L_Dst[DstLen++] = 0;
	}
    
	//	Step 2 : set MSB
	for( i=BitsInDIGIT-1; (int)i != -1; i--) {
		if( (L_Modulus[ModLen-1]&0xffffffff) & ((unsigned int)1 << (i&0xffffffff)) )
			break;
		MSB++;
	}
    
	if( (int)MSB ) {
		bn_SHL(L_Modulus, L_Modulus, ModLen, MSB);
		bn_SHL(L_Dst, L_Dst, DstLen, MSB);
	}
    
	//	Step 2 : main part
    
	MSD_Modulus = L_Modulus[ModLen-1];
    
	for( i=DstLen-ModLen-1; (int)i != -1; i--) {
        
		//	Step 2-1 : Estimate D_Quotient
		if( (L_Dst[ModLen+i]&0xffffffff) == (MSD_Modulus&0xffffffff) )
			D_Quotient = (unsigned int)-1;
		else
			D_Quotient = DD_Div_D(L_Dst[ModLen+i], L_Dst[ModLen+i-1], MSD_Modulus);
        
		//	Step 2-2 : Make L_Dst <- L_Dst-D_Quotient*L_Modulus
        int aa = bn_MulSub(L_Dst+i, ModLen+1, L_Modulus, ModLen, D_Quotient);
        
        if( aa ){
            if( (bn_Add(L_Dst+i, L_Dst+i, ModLen+1, L_Modulus, ModLen)&0xffffffff) ==0 ){
				bn_Add(L_Dst+i, L_Dst+i, ModLen+1, L_Modulus, ModLen);
            }
        }
	}
    
	//	Step 4 : inverse part of Step 2
	if( (int)MSB ) {
		bn_SHR(L_Modulus, L_Modulus, ModLen, MSB);
		bn_SHR(L_Dst, L_Dst, ModLen, MSB);
	}
    
	//	Step 4.5 : inverse part of Step 1.5
	if( (int)FLAG ) {
		DstLen--;
		L_Dst[DstLen] = TTTT;
	}
    
	return CTR_SUCCESS;
}

/*************** Function *************************************************
*	Initialize for Montgomery Modular Reduction
*/
static unsigned int Montgo_Inv;	//	<- L_Modulus[0]^{-1} mod (2^BitsInDIGIT)
static unsigned int Montgo_Rto2modN[MaxDIGIT+2];	//	<- R^2 mod L_Modulus[]

unsigned int Montgomery_Init(unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int		i;
	unsigned int		T[2*(MaxDIGIT+2)];

	//	Calculate N[0]^{-1} mod (b=2^BitsInDigit)
	Montgo_Inv = D_Inv( (unsigned int)(0-L_Modulus[0]) );
    
	//	Compute MEMORY_Montgo = b^{2*ModLen} (mod N)
	for( i=0; (int)i < 2*(int)ModLen; i++) 			//	T <- b^{2*ModLen}
		T[i] = 0;
	T[i] = 1;
    
	Classical_REDC(T, 2*ModLen+1, L_Modulus, ModLen);

												//	T <- T (mod N)
	bn_Copy(Montgo_Rto2modN, T, ModLen);	//	MEMORY_Montgo <- T

	return CTR_SUCCESS;
}

/*************** Function *************************************************
*	Montgomery Modular Reduction Algorithm
*		L_Dst[ModLen..0] <- L_Dst[DstLen..0] mod L_Modulus[ModLen..0]
*	** Assume L_Dst[] has at least (2*ModLen+1)-unsigned int memory **
*/
unsigned int Montgomery_REDC(unsigned int *L_Dst, unsigned int DstLen,
						unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int i;

	if( (DstLen&0xffffffff) != (ModLen&0xffffffff)+(ModLen&0xffffffff) ) {
		for( i=DstLen; (i&0xffffffff) < (ModLen&0xffffffff)+(ModLen&0xffffffff)+1; i++)
			L_Dst[i] = 0;
		DstLen = ModLen + ModLen;
	}

	L_Dst[DstLen] = 0;

	//	Secial Case :: Modulus = 64times 1 || **** || 64times 1
	if( (Montgo_Inv&0xffffffff) == 1 ) {
		unsigned int j;

		for( j=0;  ; j++)
			if( ((++L_Modulus[j])&0xffffffff) != 0 )	break;
		for( i=0; (i&0xffffffff) < (ModLen&0xffffffff); i++)
			bn_MulAdd(L_Dst+i+j, ModLen+ModLen+2-i-j,
					  L_Modulus+j, ModLen-j, L_Dst[i]);
		for(  ; (j&0xffffffff) != -1; j--)
			L_Modulus[j]--;
	}
	else
		for( i=0; (i&0xffffffff) < (ModLen&0xffffffff); i++)
			bn_MulAdd(L_Dst+i, ModLen+ModLen+2-i,
					  L_Modulus, ModLen, (unsigned int)(L_Dst[i]*Montgo_Inv));

	if( bn_Cmp(L_Dst+ModLen, ModLen+1, L_Modulus, ModLen)>=0 )
		bn_Sub(L_Dst, L_Dst+ModLen, ModLen+1, L_Modulus, ModLen);
	else
		bn_Copy(L_Dst, L_Dst+ModLen, ModLen);

	return CTR_SUCCESS;
}

/*************** Function *************************************************
*	Change number system Zn to RZn
*/
unsigned int Montgomery_Zn2RZn(unsigned int *L_Dst, unsigned int *L_Src,
						  unsigned int *L_Modulus, unsigned int ModLen)
{
	unsigned int		ret;
	unsigned int		T[2*(MaxDIGIT+2)];
		
	//	main part
    
	bn_KaraMul(T, L_Src, Montgo_Rto2modN, ModLen);
    
	ret = Montgomery_REDC(T, 2*ModLen, L_Modulus, ModLen);			GOTO_END;

	bn_Copy(L_Dst, T, ModLen);

	ret = CTR_SUCCESS;
LABEL_END:
	return ret;
}

/**************************************************************************
*
*	Function Description
*	
*	Return values:
*		- CTR_SUCCESS					함수가 성공적으로 수행됨.
*/
static unsigned int	SmallPrimes[ ]={
	0xC8E15F2A, 0x16FA4227, 0x87B81DA9, 0xDA38C071, 0xFDB17C23, 0xFE5E796B,
	0xC7E4CBF5, 0x7EB0F0B1, 0xB72EFC93, 0xF46CEE57, 0x80B2C2BB, 0x34A77199,
	0x447D1BD5, 0xEA4C7C31, 0xF046D45B, 0xFF55A7BF, 0x9B287041, 0x85663BEF,
	0x7856625B, 0,	/* 100-primes */
	0xF53CB8EF, 0x0BF8B47B, 0x302F3B45, 0xF7889105, 0xAEB9C343, 0xE4703BE3,
	0x7E15A86D, 0x8DFBFF6D, 0xE3FF5767, 0xF4DC76E3, 0xFFDEB1BB, 0xF1CCD229,
	0xAD97C169, 0x44655D23, 0xD39EFD0F, 0x39E3CD4D, 0xE049D915, 0xF9CD1761,
	0xF7B3D683, 0x5170C36F, 0xC22F6765, 0x81779DA7, 0x76EC6BF5, 0};

static unsigned int	IterNo[][2]={
	{ 100, 27},
	{ 150, 18},
	{ 200, 15},
	{ 250, 12},
	{ 500,  9},
	{ 500,  6},
	{ 600,  5},
	{ 800,  4},
	{1250,  40},
	{2048,  56},
	{3072,	 64},
	{9999,  1},
};

/*************** Function ************************************************/
unsigned int MillerRabin(
		BIGNUM		*BN_Num)
{
	unsigned int		s, i, j, NoTest, DigitLen=BN_Num->Length;
	unsigned int		tmp;
	unsigned int		ret;
	BIGNUM		*BN_Num_1=NULL, *BN_Tmp=NULL, *T=NULL, *M=NULL;

	//
	ret = CTR_VERIFY_FAIL;
	if( BN_Num->Length==0 )			goto LABEL_END; //길이가 0이면
	if( isEven0(BN_Num->pData) )	goto LABEL_END; //입력 BIGNUM이 짝수이면

	//	Trivial Division
	for( i=0; SmallPrimes[i]!=0; i++) {
		tmp = bn_ModD(BN_Num->pData, DigitLen, SmallPrimes[i]);
		tmp = D_Gcd(SmallPrimes[i], tmp);
		if( (int)tmp != 1 )	goto LABEL_END;
	}

	j = BitsInDIGIT * DigitLen; //입력의 Bit 길이
	for( i=0;  ; i++) {
		NoTest = IterNo[i][1];
		if( (int)j <= (int)(IterNo[i][0]) )	break;
	}

	ret = CTR_MEMORY_ALLOC_ERROR;
	
	if( (BN_Num_1=CreateBigNum(DigitLen+1))==NULL )	goto LABEL_END;
	if( (BN_Tmp=CreateBigNum(DigitLen+1))==NULL )	goto LABEL_END;
	if( (T=CreateBigNum(DigitLen+1))==NULL )		goto LABEL_END;
	if( (M=CreateBigNum(DigitLen+1))==NULL )		goto LABEL_END;

	ret = BN_Sub(BN_Num_1, BN_Num, &BN_One);
    
    if( ret!=CTR_SUCCESS )    goto LABEL_END;

	//	Compute s, T satisfing BN_Num-1 = T * 2^s with T odd
	ret = BN_Copy(T, BN_Num_1);
    if( ret!=CTR_SUCCESS )    goto LABEL_END;
    
	for( s=0; (int)isEven0(T->pData); s++) {
		ret = BN_SHR(T, T, 1);
        if( ret!=CTR_SUCCESS )    goto LABEL_END;
	}
    
	for( i=0; (int)i<=(int)NoTest; i++) {
		if( (int)i == 0 ) {
			ret = BN_Copy(BN_Tmp, &BN_Two);
            if( ret!=CTR_SUCCESS )    goto LABEL_END;
		}
		else {
			ret = BN_Rand(BN_Tmp, BitsInDIGIT*DigitLen-1);
            if( ret!=CTR_SUCCESS )    goto LABEL_END;
		}
        
		ret = BN_ModExp(M, BN_Tmp, T, BN_Num);
        
        if( ret!=CTR_SUCCESS )    goto LABEL_END;
        
		if( ((int)BN_Cmp(M, &BN_One) == 0) || ((int)BN_Cmp(M, BN_Num_1) == 0) )	continue;

		for( j=0; (int)j < (int)s; j++) {
			ret = BN_ModMul(M, M, M, BN_Num);
            if( ret!=CTR_SUCCESS )    goto LABEL_END;

			ret = CTR_VERIFY_FAIL;
			if( (int)BN_Cmp(M, &BN_One) == 0 )	goto LABEL_END;

			if( (int)BN_Cmp(M, BN_Num_1) == 0 )	break;
		}

		ret = CTR_VERIFY_FAIL;
		if( (int)s == (int)j )	goto LABEL_END;		//return CTR_VERIFY_FAIL;
        
	}

	ret = CTR_SUCCESS;

LABEL_END:
	if( BN_Num_1 != NULL )	DestroyBigNum(BN_Num_1);
	if( BN_Tmp != NULL )		DestroyBigNum(BN_Tmp);
	if( T != NULL )			DestroyBigNum(T);
	if( M != NULL )			DestroyBigNum(M);
	return ret;
}
