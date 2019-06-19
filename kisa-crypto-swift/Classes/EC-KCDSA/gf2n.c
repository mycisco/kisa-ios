#include <stdio.h>
#include <stdlib.h>
#include "gf2n.h"
#include "mpz.h"

/* GF2N arithmeric : Polynomial basis */
static ULONG precom_sqr[] = {
 		0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015, 0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
        0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115, 0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
        0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
        0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
        0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015, 0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
        0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
        0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
        0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515, 0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
        0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
        0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
        0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
        0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
        0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
        0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115, 0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
        0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415, 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
        0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555,
}; // 8-bit precomputation //

SINT 
GF2N_mul(GF2N a,GF2N b,IRR *irr,GF2N c){
	
	SINT i=0,j,k ,BIT;
	ULONG *in_a, *in_b, *ir_f, *ou_c ;
	ULONG nnn_len,nn_len, n_len, temp,temp1;
	
	in_a = a ;
	in_b = b ;
	ir_f = irr->term ;
	ou_c = c ;

	n_len = irr->top ; 	
	nn_len = n_len + 1 ;
	nnn_len = ((n_len&0xffffffff) << 1) +1;
	
	while(  i <= (nnn_len&0xffffffff) ){
		ou_c[i] = 0 ;
		i++ ;
	}
	BIT = LONG_BITS - 1 ;

	for( i = 0 ; i <= n_len ; i++ ){
		if( (in_a[i]&0xffffffff)&LOWER_LSB_ONE ){
			for( j = 0 ; j <= (n_len&0xffffffff) ; j++ ){
				ou_c[i+j] = (ou_c[i+j]&0xffffffff) ^ (in_b[j]&0xffffffff);
			}
		}
		k = BIT ;
		while( k != 0 ){
			if( ( ((in_a[i]&0xffffffff) >> k) & LOWER_LSB_ONE ) ){
				temp = LONG_BITS-k ;
				for( j = (n_len&0xffffffff); j > 0 ; j--){
					ou_c[i+j] = (ou_c[i+j]&0xffffffff) ^ (((in_b[j]&0xffffffff)<<k)^( (in_b[j-1]&0xffffffff) >> temp ));
				}
				ou_c[i] = (ou_c[i]&0xffffffff) ^ ((in_b[0]&0xffffffff) << k) ;
				ou_c[nn_len+i] = (ou_c[nn_len+i]&0xffffffff) ^ ((in_b[n_len]&0xffffffff) >> temp) ;
			}
			k--;
		}	
	}
	
	//reduction
	for( i = (nnn_len&0xffffffff) ; i > (n_len&0xffffffff) ; i-- ){
		if( ((ou_c[i]&0xffffffff) & HIGHER_MSB_ONE)!=0 ){
			for( j = 0 ; j <= (n_len&0xffffffff) ; j++ ){
				ou_c[i-j] = (ou_c[i-j]&0xffffffff) ^ (ir_f[n_len-j]&0xffffffff) ;
			}
		}
		k = 1 ;
		while( k <= (BIT&0xffffffff) ){
			if( ( ((ou_c[i]&0xffffffff) << k) & HIGHER_MSB_ONE )!=0 ){
				temp = LONG_BITS-k ;
				for( j = 1; j <= (n_len&0xffffffff) ; j++){
					ou_c[i-j] = (ou_c[i-j]&0xffffffff) ^ (((ir_f[n_len-j]&0xffffffff)>>k)^( (ir_f[n_len-j+1]&0xffffffff) << temp ));
				}
				ou_c[i] = (ou_c[i]&0xffffffff) ^ ( ((ir_f[n_len]&0xffffffff) >> k) );
				ou_c[i-n_len-1] = (ou_c[i-n_len-1]&0xffffffff) ^ (((ir_f[0]&0xffffffff) << temp)) ;
			}
			k++;
		}	
	}
	
	temp = irr->fbits-1 ;
	if( ((ou_c[n_len]&0xffffffff) >> temp) != 0 ){
		if( ((ou_c[n_len]&0xffffffff) & HIGHER_MSB_ONE )!=0 ){
			for( i = 0 ; i <= (n_len&0xffffffff) ; i++ ){
				ou_c[i] = (ou_c[i]&0xffffffff) ^ (ir_f[i]&0xffffffff) ;
			}
		}
		for( i = 1 ; i <= ((BIT&0xffffffff)-(temp&0xffffffff)) ; i++ ){
			if( (((ou_c[n_len]&0xffffffff) << i) & HIGHER_MSB_ONE) !=0 ){
				temp1 = LONG_BITS-i ;
				for( j = 0 ; j < (n_len&0xffffffff) ; j++ ){
					ou_c[j] = (ou_c[j]&0xffffffff) ^ (( (ir_f[j]&0xffffffff) >> i ) ^ ( (ir_f[j+1]&0xffffffff) << temp1 )) ;
				}
				ou_c[n_len] = (ou_c[n_len]&0xffffffff) ^ ( (ir_f[n_len]&0xffffffff) >> i );
			}
		}
	}	

	return 0 ;
}

SINT
GF2N_sqr(GF2N a,IRR *irr,GF2N c){

	SINT i=0,j,k,BIT ;
	ULONG *in_a,*ou_c, *ir_f;
	ULONG n_len ,s,t,nn_len,nnn_len,temp,temp1;
	
	in_a = a ;
	ou_c = c ;	
	ir_f = irr->term ;

	n_len = irr->top ; 	
	nn_len = (n_len&0xffffffff) + 1 ;
	nnn_len = ((n_len&0xffffffff) << 1) +1;
	
	while(  i <= (nnn_len&0xffffffff) ){
		ou_c[i] = 0 ;
		i++ ;
	}
	BIT = LONG_BITS - 1 ;
	
	s = LONG_BITS >> 2  ;
	t = LONG_BITS - s ;

	for( i = 0 ; i <= n_len ; i++ ){
		ou_c[2*i]=precom_sqr[(((in_a[i]&0xffffffff)<<t)&0xffffffff)>>t] ^ (( precom_sqr[(((in_a[i]&0xffffffff)<<((s<<1)&0xffffffff)) &0xffffffff) >>t] << (LONG_BITS>>1)) &0xffffffff);
		ou_c[2*i+1]=precom_sqr[(((in_a[i]&0xffffffff)<<s)&0xffffffff)>>t] ^ (( precom_sqr[((in_a[i]&0xffffffff)>>t)&0xffffffff] << (LONG_BITS>>1)) &0xffffffff) &0xffffffff;
	}
    
	//  reduction
	for( i = (nnn_len&0xffffffff) ; i > (n_len&0xffffffff) ; i-- ){
		if( ((ou_c[i]&0xffffffff) & HIGHER_MSB_ONE)!=0 ){
			for( j = 0 ; j <= (n_len&0xffffffff) ; j++ ){
				ou_c[i-j] = (ou_c[i-j]&0xffffffff) ^ (ir_f[n_len-j]&0xffffffff) ;
			}
		}
		k = 1;
		while( k <= (BIT&0xffffffff) ){
			if( ( ((ou_c[i] << k)&0xffffffff) & HIGHER_MSB_ONE )!=0 ){
				temp = LONG_BITS-k ;
				for( j = 1; j <= (n_len&0xffffffff) ; j++){
					ou_c[ i-j]=(ou_c[ i-j]&0xffffffff) ^ (((ir_f[n_len-j]>>k)&0xffffffff)^( (ir_f[n_len-j+1] << (temp&0xffffffff) )));
				}
				ou_c[i] = (ou_c[i]&0xffffffff) ^ ((ir_f[n_len] >> k)&0xffffffff) ;
				ou_c[i-n_len-1] = (ou_c[i-n_len-1]&0xffffffff) ^ ((ir_f[0] << (temp&0xffffffff))&0xffffffff) ;
			}
			k++;
		}	
	}

	temp = irr->fbits-1 ;
	if( ((ou_c[n_len] >> (temp&0xffffffff))&0xffffffff) != 0 ){
		if( ((ou_c[n_len]&0xffffffff) & HIGHER_MSB_ONE )!=0 ){
			for( i = 0 ; i <= (n_len&0xffffffff) ; i++ ){
				ou_c[i] = (ou_c[i]&0xffffffff) ^ (ir_f[i]&0xffffffff) ;
			}
		}
		for( i = 1 ; i <= ((BIT&0xffffffff)-(temp&0xffffffff)) ; i++ ){
			if( (((ou_c[n_len] << i)&0xffffffff) & HIGHER_MSB_ONE) !=0 ){
				temp1 = LONG_BITS-i ;
				for( j = 0 ; j < (n_len&0xffffffff) ; j++ ){
					ou_c[j] = (ou_c[j]&0xffffffff) ^ (( (ir_f[j] >> i)&0xffffffff ) ^ ( (ir_f[j+1] << (temp1&0xffffffff))&0xffffffff )) ;
				}
				ou_c[n_len] = (ou_c[n_len]&0xffffffff) ^ ( (ir_f[n_len] >> i)&0xffffffff );
			}
		}
	}		
	return 0;
}


SINT 
GF2N_mul_inv(GF2N a,IRR *irr,GF2N r)
{
	GF2N u,v,b,c,irr_term,swap_t;
	ULONG u_dat[MAX_GFP_BUF_LEN],v_dat[MAX_GFP_BUF_LEN],
		b_dat[MAX_GFP_BUF_LEN],c_dat[MAX_GFP_BUF_LEN];
	SINT i,j,fsz,normbits,deg_u,deg_v;
	SINT shw;

	/* Initialize Variables */
	u = u_dat;
	v = v_dat;
	b = b_dat;
	c = c_dat;
	fsz = irr->top;
	irr_term = irr->term;
	normbits = 32-irr->fbits;

	/* b <- 1 , c <- 0 , u <- a , v <- irr */
	for(i = 0; i < fsz;i++){
		u[i] = a[i];
		c[i] = b[i] = 0;
		v[i] = ((irr_term[i]&0xffffffff)>>normbits)|((irr_term[i+1]&0xffffffff)<<(32-normbits));
	}
	u[fsz] = a[fsz];
	c[fsz] = b[fsz] = 0;
	b[0] = 1;
	v[fsz] = (irr_term[fsz]&0xffffffff)>>normbits;

	while(1){

		/* Find degree of u */
		for(i = fsz;i>=0;i--){
			j = 0 ;
			if((u[i]&0xffffffff) !=0){
				for( ; j < 32 ; j++){
					if((0x80000000>>j)&(u[i]&0xffffffff)) goto deg1;
				}
			}
		}
deg1:
		deg_u = (i<<5) + 32 - j ;

		/* Find degree of v */
		for(i = fsz;i>=0;i--){
			j = 0 ;
			if((v[i]&0xffffffff) != 0){
				for( j = 0 ; j < 32 ; j++){
					if((0x80000000>>j)&(v[i]&0xffffffff)) goto deg2;
				}
			}
		}
deg2:
		deg_v = (i<<5) + 32 - j ;

		if(deg_u == 0) break;
		j = deg_u - deg_v;
		if(j < 0 ){
			
			/* u <-> v */
			swap_t = u;u = v;v = swap_t;

			/* b <-> c */
			swap_t = b;b = c;c = swap_t;

			/* j = |j| */
			j = -j;
		}

		shw = j>>5;
		j = j&0x1f;
		if( j == 0 ){
			for(i = fsz-shw;i>=0;i--){
				u[i+shw] = (u[i+shw]&0xffffffff) ^ (v[i]&0xffffffff);
				b[i+shw] = (b[i+shw]&0xffffffff) ^ (c[i]&0xffffffff);
			}
		}else{
			for(i = fsz-shw;i>0;i--){
				u[i+shw] = (u[i+shw]&0xffffffff) ^ (((v[i]&0xffffffff)<<j)|((v[i-1]&0xffffffff)>>(32-j)));
			}
			u[shw] = (u[shw]&0xffffffff) ^ ((v[0]&0xffffffff)<<j);

			for(i = fsz-shw;i>0;i--){
				b[i+shw] = (b[i+shw]&0xffffffff) ^ (((c[i]&0xffffffff)<<j)|((c[i-1]&0xffffffff)>>(32-j)));
			}
			b[shw] = (b[shw]&0xffffffff) ^ ((c[0]&0xffffffff)<<j);
		}
	}

	for( i = 0; i<=fsz;i++){
		r[i] = c[i];
	}

	return 0;
}