#include "gfp.h"

/* 0 <= a < m , 0 <=b < m */
SINT
GFP_add(GFP *a,GFP *b,GFP *m,GFP *r)
{
	MPZ_add(a,b,r);
	if(MPZ_abs_comp(r,m) >= 0 ){
		MPZ_asym_sub(r,m,r);
	}
	MAC_CLR_UPPER_ZEROBYTES(r);

	return 0;
}

SINT
GFP_sub(GFP *a,GFP *b,GFP *m,GFP *r)
{
	MPZ_sub(a,b,r);
	
	if(r->sig == -1)
		MPZ_add(r,m,r);
	
	return 0;
}

SINT
GFP_mul(GFP *a,GFP *b,GFP *m,GFP *r)
{
    MPZ_plain_mul(a,b,r);
	MPZ_mod(r,m,r);
	return 0;
}

SINT
GFP_mul_inv(GFP *a,GFP *m,GFP *b)
{
	MPZ_mul_inv_mod(a,m,b);
	return 0;
}

SINT
GFP_sqr(GFP *a,GFP *m,GFP *r)
{	
	MPZ_plain_sqr(a,r);
	MPZ_mod(r,m,r);
	return 0;
}
