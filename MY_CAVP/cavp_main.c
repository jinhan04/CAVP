#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "cavp_define.h"
#include "cavp_main.h"
#include "cavp_module.h"
#include "Crypto_Alg/Lea/lea.h"

int main()
{
    // 프로그램 설명 출력

    // 사용법 출력

    // switch case

	generate_LEA_KAT_files();
    Req_Rsp_file_bc_kat(ALG_ARIA, MODE_CBC, SYMMETRIC_KEY_128_BIT_LEN);

    return 0;
}

// urandom => random uint geanerate
static unsigned int get_random_uint() {
    unsigned int random_value;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("Error opening /dev/urandom");
        exit(1);
    }
    
    if (read(fd, &random_value, sizeof(random_value)) != sizeof(random_value)) {
        perror("Error reading from /dev/urandom");
        close(fd);
        exit(1);
    }
    
    close(fd);
    return random_value;
}

// urandom => random hex string generate
static void get_random_hex_string(char* buf, int bytes) {
	
    for (int i = 0; i < bytes; i++) {
        unsigned char byte;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1) {
            perror("Error opening /dev/urandom");
            exit(1);
        }
        
        if (read(fd, &byte, 1) != 1) {
            perror("Error reading from /dev/urandom");
            close(fd);
            exit(1);
        }
        
        close(fd);
        sprintf(buf + (i * 2), "%02X", byte);
    }
    buf[bytes * 2] = '\0';
}

static void Zeroize_Key_BC(unsigned int* key, unsigned int key_len)
{
	unsigned int i;
	volatile unsigned int* rk_temp = key;

	for (i = 0; i < key_len; i++)
		rk_temp[i] = 0;

}

static void Zeroize_rk_BC(unsigned int* rk, unsigned int key_len)
{
	unsigned int i;
	volatile unsigned int* rk_temp = rk;

	for (i = 0; i < key_len; i++)
		rk_temp[i] = 0;
	
}

// BC
int read_bc_kat_req(FILE* fp, unsigned char* key, int* keyLen, unsigned char* iv, int* ivLen, unsigned char* pt, int* ptLen, int alg, int mode)
{
	char buf[BUF_SIZE] = "";

	memset(buf, 0, BUF_SIZE);
	if (fscanf(fp, "KEY = %s\n", buf) <= 0)
		return 1;

	asc_to_byte(key, buf, (int)strlen(buf));
	*keyLen = (int)(strlen(buf) >> 1);

	if (mode != MODE_ECB)
	{
		memset(buf, 0, BUF_SIZE);
		if ((alg == ALG_LEA) && (mode == MODE_CTR))
		{
			if (fscanf(fp, "CTR = %s\n", buf) <= 0)
				return 2;
		}
		else
		{
			if (fscanf(fp, "IV = %s\n", buf) <= 0)
				return 2;
		}

		asc_to_byte(iv, buf, (int)strlen(buf));
		*ivLen = (int)(strlen(buf) >> 1);
	}

	memset(buf, 0, BUF_SIZE);
	if (fscanf(fp, "PT = %s\n\n", buf) <= 0)
		return 3;

	asc_to_byte(pt, buf, (int)strlen(buf));
	*ptLen = (int)(strlen(buf) >> 1);

	return 0;
}

int write_bc_kat_rsp(FILE* fp, unsigned char* key, int keyLen, unsigned char* iv, int ivLen, unsigned char* pt, int ptLen, unsigned char* ct, int ctLen, int alg, int mode)
{
	int i = 0;

	fprintf(fp, "KEY = ");
	for (i = 0; i < keyLen; i++)
		fprintf(fp, "%02X", key[i]);
	fprintf(fp, "\n");

	if (mode != MODE_ECB)
	{
		if ((alg == ALG_LEA) && (mode == MODE_CTR))
			fprintf(fp, "CTR = ");
		else
			fprintf(fp, "IV = ");

		for (i = 0; i < ivLen; i++)
			fprintf(fp, "%02X", iv[i]);
		fprintf(fp, "\n");
	}

	fprintf(fp, "PT = ");
	for (i = 0; i < ptLen; i++)
		fprintf(fp, "%02X", pt[i]);
	fprintf(fp, "\n");

	fprintf(fp, "CT = ");
	for (i = 0; i < ctLen; i++)
		fprintf(fp, "%02X", ct[i]);
	fprintf(fp, "\n\n");

	return 0;
}

unsigned int Encrypt_BC(
	unsigned int* pOutput,
	unsigned char* pMac,
	unsigned int* pInput,
	unsigned int Input_length,
	unsigned char* pIV,
	unsigned int IV_length,
	unsigned char* pAut,
	unsigned int* pKey,
	unsigned int Key_length,
	unsigned char Algorithm,
	unsigned char Mode)
{
	unsigned int key[SYMMETRIC_KEY_256_WORD_LEN] = { 0, };
	unsigned int rk[BC_ROUNDKEY_MAXLEN] = { 0, };
	unsigned int key_len = 0;
	unsigned int i;

	// if (m_stt == INACTIVE_STATE)
	// 	return ENCRYPT_BC_INACTIVE_MODULE;

	// else if (m_stt == FATAL_ERROR_STATE) 
	// 	return ENCRYPT_BC_FATAL_ERROR_STATE;

    // Invalid 처리
	if ((Algorithm < ALG_ARIA) || (Algorithm > ALG_LEA))
		return ENCRYPT_BC_ALG_INVALID;
	else if (Algorithm == ALG_ARIA && Key_length != SYMMETRIC_KEY_128_BYTE_LEN &&
		Key_length != SYMMETRIC_KEY_192_BYTE_LEN && Key_length != SYMMETRIC_KEY_256_BYTE_LEN)
		return ENCRYPT_BC_KEY_INVALID;
	else if (Algorithm == ALG_LEA && Key_length != SYMMETRIC_KEY_128_BYTE_LEN &&
		Key_length != SYMMETRIC_KEY_192_BYTE_LEN && Key_length != SYMMETRIC_KEY_256_BYTE_LEN)
		return ENCRYPT_BC_KEY_INVALID;
	else if (pKey == NULL)
		return ENCRYPT_BC_KEY_INVALID;
    
    // Mode 분류
	if (Mode < MODE_ECB)
		return ENCRYPT_BC_ALG_INVALID;
	if ((Mode == MODE_CBC || Mode == MODE_CTR) && (pIV == NULL || IV_length <= 0 || IV_length > 16 || IV_length % BLOCK_BYTE_LEN != 0))
		return ENCRYPT_BC_IV_INVALID;
	if ((pOutput == NULL) || (pInput == NULL))
		return ENCRYPT_BC_PARAM_INVALID;
	if ((Mode == MODE_ECB))
	{
		if ((pMac != NULL) || (pIV != NULL) || (pAut != NULL))
			return ENCRYPT_BC_PARAM_INVALID;	
	}

	if ((Mode == MODE_CBC) || (Mode == MODE_CTR))
	{
		if (pMac != NULL || pAut != NULL)
			return ENCRYPT_BC_PARAM_INVALID;
	}

	if (Input_length > BLOCK_CHAR_MAX_LEN)
		return ENCRYPT_BC_PLAIN_LEN_INVALID;

	key_len = Key_length / 4;

	for (i = 0; i < key_len; i++)
		key[i] = pKey[i];

	if (Algorithm == ALG_ARIA)
		// Expand_Enckey_ARIA(rk, key, key_len);
		printf("AL_ARIA isnt finished!!!\n");
	else if (Algorithm == ALG_LEA)
		Expand_Key_LEA(rk, key, key_len);

	if (Mode == MODE_ECB)
	{
		Crypt_ECB(pOutput, pInput, Input_length / 4, rk, key_len, Algorithm, ENCRYPT);
	}
	// else if (Mode == MODE_CBC)
	// {
	// 	Crypt_CBC(pOutput, pInput, Input_length / 4, pIV, IV_length, rk, key_len, Algorithm, ENCRYPT);
	// }
	// else if (Mode == MODE_CTR)
	// {
	// 	Crypt_CTR(pOutput, pInput, Input_length / 4, pIV, rk, key_len, Algorithm);
	// }

	Zeroize_rk_BC(rk, BC_ROUNDKEY_MAXLEN);

	Zeroize_Key_BC(key, key_len);

	return ENCRYPT_BC_SUCCESS;
}

void generate_LEA_KAT_files() {
    const int keySizes[] = { 128, 192, 256 };
    const int keyCount = 3;

    char filePath[256];
    FILE* req_fp;
    FILE* sam_fp;

    for (int i = 0; i < keyCount; i++) {
        int keyLen = keySizes[i];
        int keyStrLen = keyLen / 4;  // hex 문자 길이

        for (int mode = 0; mode <= 1; mode++) {
            char pt[33] = "80000000000000000000000000000000";
            char* key = (char*)malloc(keyStrLen + 1);
            if (!key) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(1);
            }

            key[0] = '8';
            memset(key + 1, '0', keyStrLen - 1);
            key[keyStrLen] = '\0';

            int position = 0;
            const char* modeStr = (mode == 0) ? "CBC" : "CTR";

            sprintf(filePath, "./testvector/LEA-%d_(%s)_KAT.req", keyLen, modeStr);
            req_fp = fopen(filePath, "w");
            sprintf(filePath, "./testvector/LEA-%d_(%s)_KAT.sam", keyLen, modeStr);
            sam_fp = fopen(filePath, "w");

            if (!req_fp || !sam_fp) {
                fprintf(stderr, "Error creating KAT files for LEA-%d %s\n", keyLen, modeStr);
                free(key);
                continue;
            }

            while (1) {
                if (mode == 0) {
                    fprintf(req_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(req_fp, "IV = %032X\n", 0);
                    fprintf(req_fp, "PT = %s\n\n", pt);

                    fprintf(sam_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(sam_fp, "IV = %032X\n", 0);
                    fprintf(sam_fp, "PT = %s\n", pt);
                    fprintf(sam_fp, "CT = ?\n\n");
                } else {
                    fprintf(req_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(req_fp, "CTR = %s\n", pt);
                    fprintf(req_fp, "PT = %032X\n\n", 0);

                    fprintf(sam_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(sam_fp, "CTR = %s\n", pt);
                    fprintf(sam_fp, "PT = %032X\n", 0);
                    fprintf(sam_fp, "CT = ?\n\n");
                }

                if (position >= 32) break;

                if (pt[position] == '8') pt[position] = 'C';
                else if (pt[position] == 'C') pt[position] = 'E';
                else if (pt[position] == 'E') pt[position] = 'F';
                else if (pt[position] == 'F') {
                    position++;
                    if (position < 32) pt[position] = '8';
                }
            }

            memset(key, '0', keyStrLen);
            key[0] = '8';
            key[keyStrLen] = '\0';
            position = 0;

            while (1) {
                if (mode == 0) {
                    fprintf(req_fp, "KEY = %s\n", key);
                    fprintf(req_fp, "IV = %032X\n", 0);
                    fprintf(req_fp, "PT = %032X\n\n", 0);

                    fprintf(sam_fp, "KEY = %s\n", key);
                    fprintf(sam_fp, "IV = %032X\n", 0);
                    fprintf(sam_fp, "PT = %032X\n", 0);
                    fprintf(sam_fp, "CT = ?\n\n");
                } else {
                    fprintf(req_fp, "KEY = %s\n", key);
                    fprintf(req_fp, "CTR = %032X\n", 0);
                    fprintf(req_fp, "PT = %032X\n\n", 0);

                    fprintf(sam_fp, "KEY = %s\n", key);
                    fprintf(sam_fp, "CTR = %032X\n", 0);
                    fprintf(sam_fp, "PT = %032X\n", 0);
                    fprintf(sam_fp, "CT = ?\n\n");
                }

                if (position >= keyStrLen) break;

                if (key[position] == '8') key[position] = 'C';
                else if (key[position] == 'C') key[position] = 'E';
                else if (key[position] == 'E') key[position] = 'F';
                else if (key[position] == 'F') {
                    position++;
                    if (position < keyStrLen) key[position] = '8';
                }
            }

            for (int k = 0; k < 20; k++) {
                get_random_hex_string(pt, 16);
                if (mode == 0) {
                    fprintf(req_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(req_fp, "IV = %032X\n", 0);
                    fprintf(req_fp, "PT = %s\n\n", pt);

                    fprintf(sam_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(sam_fp, "IV = %032X\n", 0);
                    fprintf(sam_fp, "PT = %s\n", pt);
                    fprintf(sam_fp, "CT = ?\n\n");
                } else {
                    fprintf(req_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(req_fp, "CTR = %s\n", pt);
                    fprintf(req_fp, "PT = %032X\n\n", 0);

                    fprintf(sam_fp, "KEY = %0*X\n", keyStrLen, 0);
                    fprintf(sam_fp, "CTR = %s\n", pt);
                    fprintf(sam_fp, "PT = %032X\n", 0);
                    fprintf(sam_fp, "CT = ?\n\n");
                }
            }

            fclose(req_fp);
            fclose(sam_fp);
            free(key);
        }
    }
}

void Req_Rsp_file_bc_kat(int alg, int mode, int keySize)
{
	FILE* fp_req = NULL;
	FILE* fp_rsp = NULL;
	char testName[BUF_SIZE] = "", fileName[BUF_SIZE] = "";
	unsigned char bKey[SYMMETRIC_KEY_256_BYTE_LEN] = { 0x00 };
	unsigned char bIn[SYMMETRIC_128_BYTE_LEN] = { 0x00 };
	unsigned char bIv[SYMMETRIC_128_BYTE_LEN] = { 0x00 };
	unsigned char bOut[SYMMETRIC_128_BYTE_LEN] = { 0x00 };
	unsigned int wKey[SYMMETRIC_KEY_256_WORD_LEN] = { 0x00 };
	unsigned int wIn[SYMMETRIC_128_WORD_LEN] = { 0x00 };
	unsigned int wOut[SYMMETRIC_128_WORD_LEN] = { 0x00 };
	int keyLen = 0, inLen = 0, ivLen = 0, outLen = 0;

	// 파일 이름 설정
	switch (alg) {
	case ALG_ARIA:
		sprintf(testName, "ARIA-%03d_", keySize);
		break;
	case ALG_LEA:
		sprintf(testName, "LEA-%03d_", keySize);
		break;
	}

	switch (mode) {
    case MODE_ECB:
		strcat(testName, "(ECB)_KAT");
		break;
	case MODE_CBC:
		strcat(testName, "(CBC)_KAT");
		break;
	case MODE_CTR:
		strcat(testName, "(CTR)_KAT");
		break;
	}

	printf("%s Start\n", testName);

	sprintf(fileName, "./testvector/%s.req", testName);
	fp_req = fopen(fileName, "rt");

	sprintf(fileName, "./response_file/%s.rsp", testName);
	fp_rsp = fopen(fileName, "wt");

	if ((fp_req == NULL) || (fp_rsp == NULL)) {
		printf("testvector file open\n");
		if (fp_req) fclose(fp_req);
		if (fp_rsp) fclose(fp_rsp);
		return;
	}

	// 파일을 한 줄씩 읽어 처리
	while (!feof(fp_req))
	{
		memset(bKey, 0, SYMMETRIC_KEY_256_BYTE_LEN);
		memset(bIv, 0, SYMMETRIC_128_BYTE_LEN);
		memset(bIn, 0, SYMMETRIC_128_BYTE_LEN);
		memset(bOut, 0, SYMMETRIC_128_BYTE_LEN);

		memset(wKey, 0, SYMMETRIC_KEY_256_BYTE_LEN);
		memset(wIn, 0, SYMMETRIC_128_BYTE_LEN);
		memset(wOut, 0, SYMMETRIC_128_BYTE_LEN);

		keyLen = inLen = ivLen = outLen = 0;

		if (read_bc_kat_req(fp_req, bKey, &keyLen, bIv, &ivLen, bIn, &inLen, alg, mode) != 0)
		{
			fclose(fp_req);
			fclose(fp_rsp);

			printf("read bc kat req file\n");

			break;
		}

		byte_to_word(wKey, bKey, keyLen);
		byte_to_word(wIn, bIn, inLen);

		if ((mode == MODE_ECB))
		{
			Encrypt_BC(wOut, NULL, wIn, inLen, NULL, 0, NULL, 0, keyLen, alg, mode);
		}

		else if ((mode == MODE_CBC) || (mode == MODE_CTR))
		{
			Encrypt_BC(wOut, NULL, wIn, inLen, bIv, ivLen, NULL, 0, keyLen, alg, mode);
		}


		outLen = inLen;
		word_to_byte(bOut, wOut, outLen);
		if (write_bc_kat_rsp(fp_rsp, bKey, keyLen, bIv, ivLen, bIn, inLen, bOut, outLen, alg, mode) != 0)
		{
			fclose(fp_req);
			fclose(fp_rsp);

			printf("write bc kat rsp file\n");

			break;
		}
				}

	fclose(fp_req);
	fclose(fp_rsp);
}
