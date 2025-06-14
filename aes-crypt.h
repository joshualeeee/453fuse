#ifndef AES_CRYPT_H
#define AES_CRYPT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#define BLOCKSIZE 1024
#define FAILURE 0
#define SUCCESS 1
#define IV_SIZE_BYTES 16

/* int do_crypt(FILE* in, FILE* out, int action, char* key_str)
* Purpose: Perform cipher on in File* and place result in out File*
* Args: FILE* in : Input File Pointer
* FILE* out : Output File Pointer
* int action : Cipher action (1=encrypt, 0=decrypt, -1=pass-through
(copy))
* char* key_str : C-string containing passphrase from which key is derived
* Return: FAILURE on error, SUCCESS on success
*/
extern int do_crypt(FILE* in, FILE* out, int action, char* key_str, unsigned char* iv_buffer);

/* int generate_random_iv(unsigned char *iv)
* Purpose: Generate a random IV for AES-256-CBC and place result in provided IV buffer
* Args: unsigned char *iv : IV buffer (should be 16 bytes)
* Return: FAILURE on error, SUCCESS on success
*/
extern int generate_random_iv(unsigned char *iv);

#endif
