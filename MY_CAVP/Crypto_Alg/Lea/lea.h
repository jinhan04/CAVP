#ifndef _LEA_H_
#define _LEA_H_


#define LEA_ENC		1
#define LEA_DEC		0


unsigned int Expand_Key_LEA(unsigned int* rk, const unsigned int* key, const unsigned int key_len);
unsigned int Crypt_LEA(unsigned int* output, const unsigned int* input, const unsigned int key_len, const unsigned char sit, const unsigned int* rk);



#endif
