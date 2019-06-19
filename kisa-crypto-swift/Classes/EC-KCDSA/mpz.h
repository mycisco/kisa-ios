#ifndef _MPZ_H_
#define _MPZ_H_

#ifdef  __cplusplus
extern "C" {
#endif
    
#include <stdio.h>
#include <string.h>
#include "sysconf.h"
    
    typedef struct _MPZ {
        SINT    sig;    /* 1:positive,0:zero,-1:negative */
        ULONG    *dat;
        SINT    len;
    }MPZ;
    
    /* Galoi field of Char(P) is defined as MPZ */
    typedef MPZ GFP;
    
    
    /* macro constants */
    
#define MPCONST_POS_SIG        1
#define MPCONST_NEG_SIG        -1
#define MPCONST_ZERO_SIG    0
    
    /* macros */
    
    
    
    static const char bits_to_index_low[256]={
        0,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
        5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
    };
    
    
    
#if defined(_BIT32_PROCESSOR_)
    static char bits_to_index[256]={
        0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
        6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    };
#elif defined(_BIT64_PROCESSOR_)
    static char bits_to_index[512]={
        0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
        6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,
    };
#endif
    
#define MAC_NONZERO_BITS_NUM_ULONG(a, i) \
{ \
    if((a) & 0xffff0000L){ \
        if((a) & 0xff000000L) \
            (i) = bits_to_index[(a)>>24L]+24; \
        else \
            (i) = bits_to_index[(a)>>16L]+16; \
    }else{ \
        if((a) & 0xff00L) \
            (i) = bits_to_index[(a)>>8]+8; \
        else \
            (i) = bits_to_index[(a)   ]; \
    } \
}
    
#define MAC_NONZERO_BYTES_NUM(a) ((MPZ_NONZERO_BITS_NUM((a))+7)>>3)
    
#define MAC_INIT_MPZ(/* (MPZ) */x,/* (ULONG *) */y,/* SIGN */s)\
{\
    (x).dat = (y); \
    (x).len = 0; \
    (x).sig = (s); \
}
    
#define MAC_INIT_MPZ_MEM_CLR(/* (MPZ) */x,/* (ULONG *) */y,/* SIGN */s)\
{\
    (x).dat = (y); \
    (x).len = 0; \
    (x).sig = (s); \
    memset(y,0,sizeof(y));\
}

#define MAC_DIV2EXP(a,e) ((a)>>(e))
    
#define MAC_MULT2EXP(a,e) ((a)<<(e))
    
#define MAC_SWAP(a,b,t) {    (t) = (a);(a) = (b);(b) = (t); }
    
#define MAC_MAX(x,y) (((x)>=(y))? (x):(y))
    
#define MAC_IS_POSITIVE_INTEGER( /* MPZ */ x) ((x).sig == MPCONST_POS_SIG)
    
#define MAC_IS_ODD_INTEGER(/* MPZ */ x) (((x).dat[0]&0x1) == 1)
    
#define MAC_BIT_IS_SET(x,i) (( ((x).dat[(i)/LONG_BITS] & ((ULONG)1<<((i)%LONG_BITS))) > 0 ) ? 1 : 0)
    
#define MAC_MAKE_ULONG2MPZ( /* ULONG */u,/* sign */s,/* MPZ */x) { (x).sig = (s);(x).len = 1;(x).dat[0]= u; }
    
#define MPZ_ULONG_ABS(/* ULONG */x) (x>=0?(x):(-(x)))
    
#ifdef __cplusplus
    extern "C" {
#endif

        /* MPZ Basic Operations */
        SINT MPZ_shl_1bit( MPZ *a,MPZ *b);
        SINT MPZ_shl(MPZ *a, SINT n,MPZ *r);
        SINT MPZ_shr(MPZ *a, SINT n,MPZ *r);
        SINT MPZ_copy(MPZ *src,MPZ *dest);
        SINT MPZ_nonzero_bits_num(MPZ *a);
        
        /* MPZ Basic arithmetic */
        SINT MPZ_abs_comp(MPZ *a,MPZ *b);
        SINT MPZ_asym_add(MPZ *a,MPZ *b,MPZ *c);
        SINT MPZ_asym_sub(MPZ *a,MPZ *b,    MPZ *c);
        SINT MPZ_mult_ULONG(MPZ *a,ULONG b,MPZ *c);
        SINT MPZ_mult_ULONG_add(MPZ *a,ULONG b,MPZ *c);
        SINT MPZ_comp(MPZ *a,MPZ *b);
        SINT MPZ_add(MPZ *a,MPZ *b,MPZ *c);
        SINT MPZ_sub(MPZ *a,MPZ *b,    MPZ *c);
        SINT MPZ_plain_mul(MPZ *a,MPZ *b,MPZ *c);
        #define MPZ_mul(a,b,c) MPZ_plain_mul(a,b,c)
        SINT MPZ_plain_sqr(MPZ *a,MPZ *b);
        #define MPZ_sqr(a,c) MPZ_plain_sqr(a,c)
        SINT MPZ_div(MPZ *a,MPZ *b,MPZ *c,MPZ *d);
        
        /* MPZ Modular arithmetic */
        SINT MPZ_mod(MPZ *a,MPZ *m,MPZ *r);
        SINT MPZ_sub_mod(MPZ *a,MPZ *b,MPZ *m,MPZ *r);
        SINT MPZ_mul_mod(MPZ *a,MPZ *b,MPZ *m,MPZ *r);
        SINT MPZ_mul_inv_mod(MPZ *a,MPZ *m,MPZ *r);
        
        ULONG MAC_LW(ULONG x);
        ULONG MAC_HW(ULONG x);
        void MAC_MAKE_ZERO(MPZ *x);
        void MAC_MAKE_ONE(MPZ *x);
        void MAC_CLR_UPPER_ZEROBYTES(MPZ *x);
        void MAC_ULONG_MULT(ULONG *a, ULONG *b, ULONG *c, ULONG *d);
        void MAC_ULONG_MULT_ADD(ULONG *a, ULONG *b, ULONG *c, ULONG *d);
        void MAC_ULONG_SQUARE(ULONG *a, ULONG *b, ULONG *c);
        void MAC_ULONG_DIVIDE(ULONG *a, ULONG *b, ULONG *c, ULONG *d);
        SINT MAC_IS_MPZ_ONE(MPZ x);
        SINT MAC_IS_MPZ_ZERO(MPZ x);
        
#ifdef __cplusplus
    }
#endif
    
#endif _MPZ_H_
