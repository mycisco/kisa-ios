#include "ec_gf2n.h"

SINT
GF2N_init_ECPT_AC(GF2N_ECPT_AC *ecpt,GF2N_ECPT_AC_BUF *ecpt_buf)
{
	// point의 값 부여 ,point at infinite 처리 
	ecpt->x = ecpt_buf->x_dat                  ;
	ecpt->y = ecpt_buf->y_dat                  ;
	ecpt->is_O = FALSE                         ;

	return 0;
}

/* Elliptic Curve point addition in Homogeneous Affine coordinates    */
SINT
GF2N_add_ECPT_AC(GF2N_EC_CTX *ec_ctx,GF2N_ECPT_AC *a,GF2N_ECPT_AC *b,GF2N_ECPT_AC *r)
{
	// affine addition 
	SINT i,top ;
	GF2N px,py, qx, qy, rx, ry, a2, lam,tmp,tmp1 ;
	IRR *irr ;
	ULONG lam_dat[MAX_GF2N_BUF_LEN],tmp_dat[MAX_GF2N_BUF_LEN],tmp1_dat[MAX_GF2N_BUF_LEN] ;

	px = a->x ;	
	py = a->y ;	
	qx = b->x ;	
	qy = b->y ;	
	rx = r->x ;	
	ry = r->y ;
	a2 = ec_ctx->a2    ;
	irr = &ec_ctx->irr ;
	top = irr->top     ;
	lam = lam_dat      ;
	tmp =tmp_dat       ;
	tmp1 = tmp1_dat    ;

	if( a->is_O == TRUE ){
		for( i = 0 ; i <= top ; i++ ){
			rx[i] = qx[i] ;
			ry[i] = qy[i] ;
		}
		r->is_O = FALSE ;
		return 0 ;
	}
   if(b->is_O == TRUE) {
		for( i = 0 ; i <= top ; i++ ){
			rx[i] = px[i] ;
			ry[i] = py[i] ;
		}
		r->is_O = FALSE ;
		return 0 ;
	}
	
   	i = top ; 
	while( i >= 0 ){               // x1!=x2  check
		if( (px[i]&0xffffffff) == (qx[i]&0xffffffff) ) i-- ;
		else break ;
	}
	if( i >= 0 ){
		for( i = 0 ; i <= top ; i++ ){
			lam[i] = (px[i]&0xffffffff) ^ (qx[i]&0xffffffff)  ;
			tmp1[i] = (py[i]&0xffffffff) ^ (qy[i]&0xffffffff) ;
		}
		GF2N_mul_inv(lam,irr,tmp) ;
		GF2N_mul(tmp,tmp1,irr,lam);
		GF2N_sqr(lam,irr,rx)      ;
		
		for( i = 0 ; i <= top ; i++ ){    //x
			rx[i] = (rx[i]&0xffffffff) ^ (lam[i]&0xffffffff) ^ (px[i]&0xffffffff) ^ (qx[i]&0xffffffff) ^ (a2[i]&0xffffffff);
			tmp[i] = (px[i]&0xffffffff) ^ (rx[i]&0xffffffff) ;
		}	
		GF2N_mul(lam,tmp,irr,ry)   ;      //y
		for( i = 0 ; i <= top ; i++ ){
			ry[i] = (ry[i]&0xffffffff) ^ (rx[i]&0xffffffff) ^ (py[i]&0xffffffff) ;
		}
	}
	else{
		i = top ;
		while( i >= 0 ){
			if( (py[i]&0xffffffff) == (qy[i]&0xffffffff) ) i--;
			else break ;
		}
		if( i >= 0 ){                  //  y1  !=  y2
			r->is_O = TRUE ;
			return 0 ;
		}
		else{                          //  y1  ==  y2
			GF2N_dbl_ECPT_AC(ec_ctx,a,r) ;
		}
	}
	r->is_O = FALSE ;
	
	return 0 ;
}


SINT
GF2N_dbl_ECPT_AC(GF2N_EC_CTX *ec_ctx,GF2N_ECPT_AC *p1,GF2N_ECPT_AC *p3)
{
	// affine doubling
	SINT i,top ;
	GF2N px, py, rx, ry, a2, lam,tmp,tmp1 ;
	IRR *irr ;
	ULONG lam_dat[MAX_GF2N_BUF_LEN],tmp_dat[MAX_GF2N_BUF_LEN],tmp1_dat[MAX_GF2N_BUF_LEN] ;

	px = p1->x ;	py = p1->y ;	rx = p3->x ;	ry = p3->y ;
	a2 = ec_ctx->a2 ; irr = &ec_ctx->irr ; top = irr->top ;	lam = lam_dat ;	tmp =tmp_dat ;
	tmp1 = tmp1_dat ;

	if( p1->is_O == TRUE ){
		p3->is_O = TRUE ;
		return 0 ;
	}
	i = top ;
    
	while( i >= 0 ){
		if( (px[i]&0xffffffff) == 0 ) i-- ;
		else break;
	}
    
	if( i < 0 ){          // x1 == 0 
		p3->is_O = TRUE;
		return 0;
	}
	GF2N_mul_inv(px,irr,tmp);
    
	GF2N_mul(py,tmp,irr,lam);
	for( i = 0 ; i <= top ; i++ ){
		lam[i] = (lam[i]&0xffffffff) ^ (px[i]&0xffffffff) ;
	}
	GF2N_sqr( lam,irr,tmp ) ;
	for( i = 0 ; i <= top ; i++ ){
		rx[i] = (tmp[i]&0xffffffff) ^ (lam[i]&0xffffffff) ^ (a2[i]&0xffffffff) ;
		tmp1[i] = (px[i]&0xffffffff) ^ (rx[i]&0xffffffff)  ;
	}
	GF2N_mul(lam,tmp1,irr,ry);
	for( i = 0 ; i <= top ; i++ ){
		ry[i] ^= (rx[i]&0xffffffff) ^ (py[i]&0xffffffff) ;
	}
   	p3->is_O = FALSE;

	return 0 ;
}


SINT
GF2N_smul_ECPT_AC(GF2N_EC_CTX *ec_ctx,MPZ *n,GF2N_ECPT_AC *pt,GF2N_ECPT_AC *r)
{
	GF2N rx,ry ;
	GF2N_ECPT_AC tmp ;
	GF2N_ECPT_AC_BUF tmp_buf ;
	SINT i,top ;
	ULONG bit_check,*kp,n_len ;
	
	kp = n->dat ;
	rx = r->x ;
	ry = r->y ;
	top = ec_ctx->irr.top;
	n_len = n->len ;
	GF2N_init_ECPT_AC(&tmp,&tmp_buf) ;

    while( (kp[n_len-1]&0xffffffff)==0 ) n_len--;

	r->is_O = TRUE ;	

	while( (n_len--)&0xffffffff ){
		bit_check = HIGHER_MSB_ONE ;
		while( bit_check&0xffffffff ){
            GF2N_dbl_ECPT_AC(ec_ctx,r,&tmp);
			if( (kp[n_len]&0xffffffff) & (bit_check&0xffffffff) ){
				GF2N_add_ECPT_AC(ec_ctx,pt,&tmp,r);
			}
			else{
				for( i = top ; i >= 0 ; i-- ){
					rx[i] = tmp.x[i] ;
					ry[i] = tmp.y[i] ;
				}
				r->is_O = tmp.is_O ;
			}
			bit_check = (bit_check&0xffffffff) >> 1 ;
		}
	}
    
	return 0 ;
}