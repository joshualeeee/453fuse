#include "aes-crypt.h"
#include <openssl/rand.h>

#define BLOCKSIZE 1024
#define FAILURE 0
#define SUCCESS 1

// password: user input (null-terminated string)
// key: output buffer (must be at least 32 bytes)
extern int do_crypt(FILE* in, FILE* out, int action, char* key_str, unsigned char* iv_buffer){
    /* Local Vars */

    /* Buffers */
    unsigned char inbuf[BLOCKSIZE];
    int inlen;
    /* Allow enough space in output buffer for additional cipher block */
    unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    int writelen;

    /* OpenSSL libcrypto vars */
    EVP_CIPHER_CTX ctx;
    unsigned char key[32];
    int nrounds = 5;
    
    /* tmp vars */
    int i;

    /* Setup Encryption Key and Cipher Engine if in cipher mode */
    if(action >= 0){
		printf("setting up cipher engine\n");
		if(!key_str){
			/* Error */
			fprintf(stderr, "Key_str must not be NULL\n");
			return 0;
		}
		/* Build Key from String */
		i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
				(unsigned char*)key_str, strlen(key_str), nrounds, key, NULL);
		if (i != 32) {
			/* Error */
			fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
			return 0;
		}
		/* Init Engine */
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv_buffer, action);
	}
	
	
	while ((inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, in)) > 0) {
		printf("Read %d bytes from input file\n", inlen);
		////////////////////////////////////////////////////////////////////////////////////////////////
		/* If in cipher mode, perform cipher transform on block */
		if(action >= 0){
			if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
			{
				/* Error */
				EVP_CIPHER_CTX_cleanup(&ctx);
				return 0;
			}
		}
		/* If in pass-through mode. copy block as is */
		else{
			memcpy(outbuf, inbuf, inlen);
			outlen = inlen;
		}


		/* Write Block */
		writelen = fwrite(outbuf, sizeof(*outbuf), outlen, out);
		//print outbuf
		
		if(writelen != outlen){
			/* Error */
			perror("fwrite error");
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
    }
    
    /* If in cipher mode, handle necessary padding */
    if(action >= 0){
		/* Handle remaining cipher block + padding */
		if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
			{
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
			}
		/* Write remaining cipher block + padding*/
		fwrite(outbuf, sizeof(*inbuf), outlen, out);
		EVP_CIPHER_CTX_cleanup(&ctx);
    }
    
    /* Success */
    return 1;
}

extern int generate_random_iv(unsigned char *iv)
{
	if (!RAND_bytes(iv, IV_SIZE_BYTES))
	{
		fprintf(stderr, "Failed to generate random IV\n");
		return FAILURE;
	}

	/* Success */
	return SUCCESS;
}
