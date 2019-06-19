#ifndef _EC_GF2N_
#define _EC_GF2N_

#include "mpz.h"
#include "gf2n.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _GF2N_EC_CTX{
	IRR			irr;
	GF2N		a2;
	GF2N		a6;
}GF2N_EC_CTX;

/**********************************/
/* EC point in Affine Coordinates */
/**********************************/

typedef struct _GF2N_ECPT_AC {
	unsigned char is_O; /* Is this a point at infinity? */
	GF2N x;
	GF2N y;
}GF2N_ECPT_AC;

typedef struct _GF2N_ECPT_AC_BUF {
	ULONG x_dat[MAX_GF2N_BUF_LEN];
	ULONG y_dat[MAX_GF2N_BUF_LEN];
}GF2N_ECPT_AC_BUF;

SINT GF2N_init_ECPT_AC(GF2N_ECPT_AC *ecpt,GF2N_ECPT_AC_BUF *ecptbuf);
SINT GF2N_add_ECPT_AC(GF2N_EC_CTX *ec_ctx,GF2N_ECPT_AC *a,GF2N_ECPT_AC *b,GF2N_ECPT_AC *r);
SINT GF2N_dbl_ECPT_AC(GF2N_EC_CTX *ec_ctx,GF2N_ECPT_AC *p1,GF2N_ECPT_AC *p3);
SINT GF2N_smul_ECPT_AC(GF2N_EC_CTX *ec_ctx,MPZ *n,GF2N_ECPT_AC *pt,GF2N_ECPT_AC *r);

#ifdef  __cplusplus
}
#endif

#endif _EC_GF2N_

