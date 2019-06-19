#ifndef _GFP_H_
#define _GFP_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include "mpz.h"

/* GFP Modular arithmetic functions */
SINT GFP_add(GFP *a, GFP *b, GFP *m, GFP *r);
SINT GFP_sub(GFP *a, GFP *b, GFP *m, GFP *r);
SINT GFP_mul(GFP *a, GFP *b, GFP *m, GFP *r);
SINT GFP_mul_inv(GFP *a, GFP *m, GFP *r);
SINT GFP_sqr(GFP *a, GFP *m, GFP *r);

/* Use MPZ Basic Operations for GFP */
#define GFP_shl_1bit			MPZ_shl_1bit
#define GFP_shl					MPZ_shl
#define GFP_shr					MPZ_shr
#define GFP_copy				MPZ_copy
#define GFP_comp				MPZ_comp
#define MAC_INIT_GFP			MAC_INIT_MPZ

#ifdef  __cplusplus
}
#endif

#endif _GFP_H_