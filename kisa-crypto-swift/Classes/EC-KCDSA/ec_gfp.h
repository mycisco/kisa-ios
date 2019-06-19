#ifndef _EC_GFP_
#define _EC_GFP_

#include "gfp.h"


#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _GFP_EC_CTX{
	GFP		prime;
	GFP		a;
	GFP		b;
}GFP_EC_CTX;

typedef struct _GFP_EC_CTX_BUF{
	ULONG	prime_buf[MAX_GFP_BUF_LEN];
	ULONG	a_buf[MAX_GFP_BUF_LEN];
	ULONG	b_buf[MAX_GFP_BUF_LEN];
}GFP_EC_CTX_BUF;

/**********************************/
/* EC point in Affine Coordinates */
/**********************************/

typedef struct _ECPT_AC {
	unsigned char is_O; /* Is this a point at infinity? */
	GFP x;
	GFP y;
}GFP_ECPT_AC;

typedef struct _ECPT_AC_BUF {
	ULONG x_dat[MAX_GFP_BUF_LEN];
	ULONG y_dat[MAX_GFP_BUF_LEN];
}GFP_ECPT_AC_BUF;

SINT GFP_init_ECPT_AC(GFP_ECPT_AC *ecpt,GFP_ECPT_AC_BUF *ecptbuf);
SINT GFP_add_ECPT_AC(GFP_EC_CTX *ec_ctx,GFP_ECPT_AC *a,GFP_ECPT_AC *b,GFP_ECPT_AC *r);
SINT GFP_dbl_ECPT_AC(GFP_EC_CTX *ec_ctx,GFP_ECPT_AC *p1,GFP_ECPT_AC *p3);
SINT GFP_smul_ECPT_AC(GFP_EC_CTX *ec_ctx,MPZ *n,GFP_ECPT_AC *pt,GFP_ECPT_AC *r);

#ifdef  __cplusplus
}
#endif

#endif _EC_GFP_

