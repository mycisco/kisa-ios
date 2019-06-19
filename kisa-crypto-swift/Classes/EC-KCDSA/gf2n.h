#ifndef _GF2N_H_
#define _GF2N_H_
#ifdef  __cplusplus
extern "C" {
#endif

#include "sysconf.h"

#define MAX_IRR_TERM_LEN (MAX_GF2N_BUF_LEN)

typedef unsigned long* GF2N;

typedef struct _IRR {
	ULONG_PTR term;
	SINT top;
	SINT fbits; /* bits to be normalized of reduced element */
	SINT basis; /* define ÇÊ¿ä */
}IRR;

/* GF2N Arithmetic : polynomial basis */
SINT GF2N_mul(GF2N a, GF2N b, IRR *irr, GF2N c);
SINT GF2N_sqr(GF2N a, IRR *irr, GF2N c);
SINT GF2N_mul_inv(GF2N a, IRR *irr, GF2N c);

#ifdef  __cplusplus
}
#endif

#endif /* _GF2N_H_ */

