#ifndef CAVP_H
#define CAVP_H

#include <stdio.h>

// Function prototypes
static unsigned int get_random_uint(void);
static void get_random_hex_string(char* buf, int bytes);
static void Zeroize_Key_BC(unsigned int* key, unsigned int key_len);
static void Zeroize_rk_BC(unsigned int* rk, unsigned int key_len);
unsigned int Crypt_ECB(unsigned int* pOutput, const unsigned int* pInput, const unsigned int Input_length, const unsigned int* pRk, const unsigned int key_len, const unsigned char algorithm, const unsigned char sit);
int read_bc_kat_req(FILE* fp, unsigned char* key, int* keyLen, unsigned char* iv, int* ivLen, unsigned char* pt, int* ptLen, int alg, int mode);
int write_bc_kat_rsp(FILE* fp, unsigned char* key, int keyLen, unsigned char* iv, int ivLen, unsigned char* pt, int ptLen, unsigned char* ct, int ctLen, int alg, int mode);
unsigned int Encrypt_BC(unsigned int* pOutput, unsigned char* pMac, unsigned int* pInput, unsigned int Input_length, unsigned char* pIV, unsigned int IV_length, unsigned char* pAut, unsigned int* pKey, unsigned int Key_length, unsigned char Algorithm, unsigned char Mode);
void generate_LEA_KAT_files();
void Req_Rsp_file_bc_kat(int alg, int mode, int keySize);

#endif // CAVP_UTIL_H
