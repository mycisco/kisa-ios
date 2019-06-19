#include "ec_gfp.h"

SINT
GFP_init_ECPT_AC(GFP_ECPT_AC *ecpt,GFP_ECPT_AC_BUF *ecptbuf)
{
	MAC_INIT_GFP(ecpt->x,ecptbuf->x_dat,MPCONST_POS_SIG);
	MAC_INIT_GFP(ecpt->y,ecptbuf->y_dat,MPCONST_POS_SIG);
	ecpt->is_O = FALSE;

	return 0;
}

/* Elliptic Curve point addition in Homogeneous Affine coordinates    */

SINT
GFP_add_ECPT_AC(GFP_EC_CTX *ec_ctx,GFP_ECPT_AC *a,GFP_ECPT_AC *b,GFP_ECPT_AC *r)
{
	GFP *x1,*y1,*x2,*y2,*x3,*y3,*p;
	GFP lambda,tmp1,tmp2;
	ULONG lambda_dat[MAX_GFP_BUF_LEN],tmp1_dat[MAX_GFP_BUF_LEN],tmp2_dat[MAX_GFP_BUF_LEN];

	MAC_INIT_GFP(lambda,lambda_dat,MPCONST_POS_SIG);
	MAC_INIT_GFP(tmp1,tmp1_dat,MPCONST_POS_SIG);
	MAC_INIT_GFP(tmp2,tmp2_dat,MPCONST_POS_SIG);

	x1 = &a->x;
	y1 = &a->y;
	x2 = &b->x;
	y2 = &b->y;
	x3 = &r->x;
	y3 = &r->y;
	p = &ec_ctx->prime;

	/* Check if a is O. */
	if(a->is_O == TRUE ){
		MPZ_copy(x2,x3);
		MPZ_copy(y2,y3);
		r->is_O = b->is_O;
		return 0;
	}
    
	/* Check if b is O. */
	if(b->is_O == TRUE ){
		MPZ_copy(x1,x3);
		MPZ_copy(y1,y3);
		r->is_O = a->is_O;
		return 0;
	}
    
	/* Check if two points are additive invers to each other. */
    
	if(MPZ_comp(x1,x2)!=0){
		GFP_sub(x2,x1,p,&tmp1);
		GFP_sub(y2,y1,p,&tmp2);
		GFP_mul_inv(&tmp1,p,&tmp1);
		GFP_mul(&tmp2,&tmp1,p,&lambda);
		GFP_sqr(&lambda,p,&tmp1); /* tmp1 = lambda*lambda */
		GFP_sub(&tmp1,x1,p,&tmp2);
		GFP_sub(&tmp2,x2,p,&tmp1);
		GFP_sub(x1,&tmp1,p,&tmp2);
		MPZ_copy(&tmp1,x3);
        
		GFP_mul(&tmp2,&lambda,p,&tmp1);
		GFP_sub(&tmp1,y1,p,y3);
	}else{
		if(MPZ_comp(y1,y2)==0){
            
			GFP_dbl_ECPT_AC(ec_ctx,a,r);
		}else{
            
			r->is_O = TRUE;
			return 0;
		}
	}

	r->is_O = FALSE;

	return 0;
}

SINT
GFP_dbl_ECPT_AC(GFP_EC_CTX *ec_ctx,GFP_ECPT_AC *p1,GFP_ECPT_AC *p3)
{
	GFP *x1,*y1,*x3,*y3,*p,*a;
	GFP lambda,tmp1,tmp2;
	ULONG lambda_dat[MAX_GFP_BUF_LEN],tmp1_dat[MAX_GFP_BUF_LEN],tmp2_dat[MAX_GFP_BUF_LEN];

	MAC_INIT_GFP(lambda,lambda_dat,MPCONST_POS_SIG);
	MAC_INIT_GFP(tmp1,tmp1_dat,MPCONST_POS_SIG);
	MAC_INIT_GFP(tmp2,tmp2_dat,MPCONST_POS_SIG);

	x1 = &p1->x;
	y1 = &p1->y;
	x3 = &p3->x;
	y3 = &p3->y;
	p = &ec_ctx->prime;
	a = &ec_ctx->a;

	if( ( p1->is_O == TRUE ) ||(MAC_IS_MPZ_ZERO(*y1))){
		p3->is_O = TRUE;
		return 0;
	}
    
	/*	Use 3x = (a<<1) + a */
    
	GFP_sqr(x1,p,&tmp1);
    
	/*-> tmp1 = x1**2 */
	MPZ_shl_1bit(&tmp1,&tmp2);
	if(MPZ_comp(&tmp2,p)>0){
		MPZ_sub(&tmp2,p,&tmp2);
	}
	GFP_add(&tmp2,&tmp1,p,&tmp2);
	/*-> tmp2 = 3*x1**2 */
	GFP_add(&tmp2,a,p,&tmp2);
	/*-> tmp2 = 3*x1**2 + a */
	MPZ_shl_1bit(y1,&tmp1);
	if(MPZ_comp(&tmp1,p)>0){
		MPZ_sub(&tmp1,p,&tmp1);
	}
	/*-> tmp1 = 2*y1 */

	GFP_mul_inv(&tmp1,p,&tmp1);
	/*-> tmp1 = (2*y1)**(-1) */
	GFP_mul(&tmp1,&tmp2,p,&lambda);
	/*-> lambda =(3*x1**2 + a )/( 2*y1 ) */
	GFP_sqr(&lambda,p,&tmp1);
	/*-> tmp1 = lambda**2 */
	MPZ_shl_1bit(x1,&tmp2);
	if(MPZ_comp(&tmp2,p)>0){
		MPZ_sub(&tmp2,p,&tmp2);
	}
	/*-> tmp2 = 2*x1 */
	GFP_sub(&tmp1,&tmp2,p,&tmp2);
    
	/*-> tmp2 = lambda**2 - 2*x1 */
	GFP_sub(x1,&tmp2,p,&tmp1);
	
    /*-> tmp1 = x1 - (lambda**2 - 2*x1) */
	GFP_copy(&tmp2,x3);
	
	/*-> x3 = lambda**2 - 2*x1 */
	GFP_mul(&tmp1,&lambda,p,&tmp2);
    
	/*-> tmp2 = (x1 - (lambda**2 - 2*x1))*lambda */
	GFP_sub(&tmp2,y1,p,y3);
	/*-> y3 = (x1 - (lambda**2 - 2*x1))*lambda -y1 */

		p3->is_O = FALSE;
	
	return 0;
}

SINT
GFP_smul_ECPT_AC(GFP_EC_CTX *ec_ctx,MPZ *n,GFP_ECPT_AC *pt,GFP_ECPT_AC *r)
{
/*
	Modular exponentiation using Left to right binary exponentiation.
	r = x^e (mod m)
*/
    SINT n_len, n_bit;
    GFP_ECPT_AC tmp;
	GFP_ECPT_AC_BUF tmp_buf;
    ULONG *n_dat, mask;

	GFP_init_ECPT_AC(&tmp,&tmp_buf);
	n_bit = (MPZ_nonzero_bits_num(n) - 1) % LONG_BITS;
    mask = 1 << n_bit;
    n_len = n->len;
    n_dat = &((n->dat)[n_len - 1]);

	r->is_O = TRUE;
    int cnt = 0;
	while (n_len--){
        while (mask&0xffffffff){    
			GFP_dbl_ECPT_AC(ec_ctx,r,&tmp);
			if (((*n_dat)&0xffffffff) & (mask&0xffffffff)){
				GFP_add_ECPT_AC(ec_ctx,&tmp,pt,r);
		    }else{
				GFP_copy(&tmp.x,&r->x);
				GFP_copy(&tmp.y,&r->y);
				r->is_O = tmp.is_O;
			}
            mask = (mask&0xffffffff) >> 1;
        }
        mask = HIGHER_MSB_ONE;
        n_dat--;
    }
   
    MAC_CLR_UPPER_ZEROBYTES(&(r->x));
	MAC_CLR_UPPER_ZEROBYTES(&(r->y));

	if(MAC_IS_MPZ_ZERO(r->x))
		r->is_O = TRUE;
	
    return 0;
}