#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"

#define MAX_HMAC_BLOCK 128
#define IPAD 0x36
#define OPAD 0x5C

typedef struct hmac_unit_structure
{
	KISA_SHA256 sha1_unit;
	KISA_SHA256 state_i;
	KISA_SHA256 state_o;
	unsigned int state_length;
	unsigned char key[128];
	int key_length;
	int hmac_status;	
} HMAC_ST;

HMAC_ST *HMAC_SHA256_new(void);
void HMAC_SHA256_clear(HMAC_ST *unit);
void HMAC_SHA256_free(HMAC_ST *unit);

int HMAC_SHA256_init(HMAC_ST *unit, unsigned char *key, int keyLen);
int HMAC_SHA256_update(HMAC_ST *unit, const unsigned char *input, int inLength);
int HMAC_SHA256_final(HMAC_ST *unit, unsigned char *output);

int HMAC_SHA256(unsigned char *key, int keyLen, const unsigned char *input, int inLength, unsigned char *output);

HMAC_ST *HMAC_SHA256_new(void)
{
	HMAC_ST *unit = (HMAC_ST*)malloc(sizeof *unit);
	
	if(unit == NULL) {
		return NULL;
	}
	
	if (unit)
		memset(unit,0,sizeof(HMAC_ST));
	return unit;
}

void HMAC_SHA256_clear(HMAC_ST *unit)
{

	if(unit->state_length != 0)
	{		
		memset(&(unit->state_i),0x00,sizeof(unit->state_i));
		memset(&(unit->state_o),0x00,sizeof(unit->state_o));						
	}
}

void HMAC_SHA256_free(HMAC_ST *unit)
{
	if (unit)
	{		
		HMAC_SHA256_clear(unit);		
		free(unit);
	}
}

int HMAC_SHA256_init(HMAC_ST *unit, unsigned char *key, int keyLen)
{
	int i,block;
	int retcode = 0;
	unsigned char pad[MAX_HMAC_BLOCK];

	int statesize = sizeof(KISA_SHA256);

	HMAC_SHA256_clear(unit);
	
	unit->hmac_status = 1;

	if ((retcode = KISA_SHA256_init(&(unit->sha1_unit))) != 1) {
		return retcode;
	}
		
	unit->state_length = statesize;

	if (key == NULL)
	{
		return 0;
	}
	block = SHA256_BLOCK_SIZE;

	if(!(block <= (int)sizeof(unit->key)))
	{
		return 0;
	}

	if (block < keyLen)
	{
		if((retcode = KISA_SHA256_update(&(unit->sha1_unit),key,keyLen)) != 1)
		{
			return retcode;
		}
		if((retcode = KISA_SHA256_final(&(unit->sha1_unit),unit->key)) != 1)
		{
			return retcode;
		}
		unit->key_length = SHA256_DIGEST_LENGTH;
		KISA_SHA256_init(&(unit->sha1_unit));
	}
	else
	{
		if(!(keyLen>=0 && keyLen<=(int)sizeof(unit->key)))
		{
			return 0;
		}
		memcpy(unit->key,key,keyLen);
		unit->key_length = keyLen;
	}

	if(unit->key_length < block)
		memset(&unit->key[unit->key_length], 0x00, block - unit->key_length);

	for (i=0; i<MAX_HMAC_BLOCK; i++) pad[i] = OPAD ^ unit->key[i];		

	if(KISA_SHA256_update(&(unit->sha1_unit), pad, SHA256_BLOCK_SIZE) != 1)
	{
		return 0;
	}
	memcpy(&(unit->state_o), &(unit->sha1_unit), statesize);

	for (i=0; i<MAX_HMAC_BLOCK; i++) pad[i] = IPAD ^ unit->key[i];

	//unit->md_unit->init(unit->md_unit->state);
	KISA_SHA256_init(&(unit->sha1_unit));

	if((retcode = KISA_SHA256_update(&(unit->sha1_unit), pad, SHA256_BLOCK_SIZE)) != 1)
	{
		return retcode;
	}

	memcpy(&(unit->state_i), &(unit->sha1_unit), statesize);

	return 1;
}

int HMAC_SHA256_update(HMAC_ST *unit, const unsigned char *input, int inLength)
{
	if(unit->hmac_status == 3)
	{
		memcpy(&(unit->sha1_unit), &(unit->state_i), sizeof(KISA_SHA256));
		unit->hmac_status = 1;
	}
	if(KISA_SHA256_update(&(unit->sha1_unit), input, inLength) != 1)
	{
		return 0;
	}
	unit->hmac_status = 2;
	return 1;
}

int HMAC_SHA256_final(HMAC_ST *unit, unsigned char *output)
{
	int i = SHA256_DIGEST_LENGTH;
	unsigned char buf[128];

	if(KISA_SHA256_final(&(unit->sha1_unit), buf) != 1)
	{
		return 0;
	}
	KISA_SHA256_init(&(unit->sha1_unit));

	memcpy(&(unit->sha1_unit), &(unit->state_o), sizeof(KISA_SHA256));

	if(KISA_SHA256_update(&(unit->sha1_unit), buf, i) != 1)
	{
		return 0;
	}

	if(KISA_SHA256_final(&(unit->sha1_unit), output) != 1)
	{
		return 0;
	}
	unit->hmac_status = 3;
	return 1;
}

int HMAC_SHA256(unsigned char *key, int keyLen, const unsigned char *input, int inLength,
			  unsigned char *output)
{
	HMAC_ST *unit = HMAC_SHA256_new();

	if(HMAC_SHA256_init(unit,key,keyLen) != 1)
	{
		HMAC_SHA256_free(unit);
		return 0;
	}

	if(HMAC_SHA256_update(unit,input,inLength) != 1)
	{
		HMAC_SHA256_free(unit);
		return 0;
	}

	if(HMAC_SHA256_final(unit,output) != 1)
	{
		HMAC_SHA256_free(unit);
		return 0;
	}

	HMAC_SHA256_free(unit);

	return 1;
}



int KISA_PBKDF2(unsigned char* password, int passwordLen, unsigned char* salt, int saltLen, int iter, unsigned char* key, int keyLen)
{
	unsigned char* salt_and_int = NULL;
	int saltIntLen;
	unsigned char U[64]; // Max Digest Size
	int ULen = SHA256_DIGEST_LENGTH;
	unsigned char T[64]; // Max Digest Size
	int l,r,hLen = SHA256_DIGEST_LENGTH, outInd = 0;
	int i,j,k, retcode = 0; 

	HMAC_ST* hmac = NULL;

	l = keyLen / hLen + (keyLen%hLen == 0 ? 0 : 1);
	r = keyLen - ((l-1)*hLen);

	if(r < 0)
		return 0;

	salt_and_int = (unsigned char*)malloc(saltLen+4); 
	
	if (salt_and_int == NULL)	goto ret;
	
	memcpy(salt_and_int,salt,saltLen);

	hmac = HMAC_SHA256_new();

	for(i=1;i <= l;i++)
	{
		saltIntLen = saltLen+4;

		salt_and_int[saltLen    ] = (i >> 24) & 0xFF;
		salt_and_int[saltLen + 1] = (i >> 16) & 0xFF;
		salt_and_int[saltLen + 2] = (i >> 8 ) & 0xFF;
		salt_and_int[saltLen + 3] = (i      ) & 0xFF;

		retcode = HMAC_SHA256_init(hmac,password,passwordLen);
		if(retcode != 1) goto ret;
		retcode = HMAC_SHA256_update(hmac,salt_and_int,saltIntLen);
		if(retcode != 1) goto ret;
		retcode = HMAC_SHA256_final(hmac,U);
		if(retcode != 1) goto ret;
		memset(T, 0x00, 64);

		for(k=0;k<ULen;k++) T[k] ^= U[k];

		for(j=1;j<iter;j++)
		{
			retcode = HMAC_SHA256_init(hmac,password,passwordLen);
			if(retcode != 1) goto ret;
			retcode = HMAC_SHA256_update(hmac,U,ULen);
			if(retcode != 1) goto ret;
			retcode = HMAC_SHA256_final(hmac,U);
			if(retcode != 1) goto ret;
			for(k=0;k<ULen;k++) T[k] ^= U[k];
		}
		memcpy(key + (outInd),T,(i == l)?r:ULen);
		outInd += (i==l)?r:ULen;
	}

	retcode = 1;

ret:
	if(salt_and_int) free(salt_and_int);
	
	if(hmac) HMAC_SHA256_free(hmac);
	
	return retcode;

}
