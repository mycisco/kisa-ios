#ifndef _SYSCONF_H_
#define _SYSCONF_H_

#ifdef  __cplusplus
extern "C" {
#endif

#define _BIT32_PROCESSOR_ 

#define _MATHEMATICA_EXPRESS_
#define ULONG_PTR unsigned long*
	/* system independent types */
	typedef unsigned long ULONG;

	typedef signed long SLONG;
	typedef SLONG* SLONG_PTR;

	typedef unsigned short USHORT;
	typedef USHORT* USHORT_PTR;

	typedef signed short SSHORT;
	typedef SSHORT* SSHORT_PTR;

	typedef unsigned int UINT;

	typedef signed int SINT;
	typedef SINT* SINT_PTR;

	typedef unsigned char UCHAR;
	typedef UCHAR* UCHAR_PTR;

	typedef char SCHAR;
	typedef SCHAR* SCHAR_PTR;

	//typedef unsigned char BOOL;
#define TRUE	1
#define FALSE	0

/* system dependent types */

	typedef unsigned char  UINT8;
	typedef unsigned short UINT16;
	typedef unsigned int   UINT32;


	typedef struct _OSTR {
		UCHAR	*val;
		UINT	len;
	}OSTR;


#if defined(_BIT32_PROCESSOR_)

#define BITMASK_LONG        0xffffffff
#define BITMASK_HIGHER_LONG 0xffff0000 
#define BITMASK_LOWER_LONG  0x0000ffff
#define HIGHER_MSB_ONE		0x80000000
#define LOWER_MSB_ONE		0x00008000
#define HIGHER_LSB_ONE		0x00010000
#define LOWER_LSB_ONE		0x00000001
#define LOW_DEG_FIND        0x0000001f
#define LONG_BITS			32
#define HALF_LONG_BITS		16

#elif defined(_BIT64_PROCESSOR_)

#define BITMASK_LONG        0xffffffffffffffff
#define BITMASK_HIGHER_LONG 0xffffffff00000000 
#define BITMASK_LOWER_LONG  0x00000000ffffffff
#define HIGHER_MSB_ONE		0x8000000000000000
#define LOWER_MSB_ONE		0x0000000080000000
#define HIGHER_LSB_ONE		0x0000000100000000
#define LOWER_LSB_ONE		0x0000000000000001
#define LONG_BITS			64
#define HALF_LONG_BITS		32

#endif

#define MAX_MPZ_BUF_LEN (300 + 1)
#define MAX_GFP_BUF_LEN (500 + 1)
#define MAX_GF2N_BUF_LEN (500 + 1)
#define MAX_HASH_BUF_BYTES (20 + 1)

#ifdef  __cplusplus
}
#endif

#endif _SYSCONF_H_