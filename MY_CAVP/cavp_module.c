#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "cavp_define.h"
#include "Crypto_Alg/Lea/lea.h"

unsigned int byte_to_word(unsigned int* dest, const unsigned char* src, const unsigned int src_length)
{
	unsigned int i = 0;
	unsigned int remain = 0;

	for (i = 0; i < src_length; i++)
	{
		remain = i % 4;

		if (remain == 0)
			dest[i / 4] = ((unsigned int)src[i] << 24);
		else if (remain == 1)
			dest[i / 4] ^= ((unsigned int)src[i] << 16);
		else if (remain == 2)
			dest[i / 4] ^= ((unsigned int)src[i] << 8);
		else
			dest[i / 4] ^= ((unsigned int)src[i] & 0x000000FF);
	}

	return 0;
}

unsigned int word_to_byte(unsigned char* dest, const unsigned int* src, const unsigned int src_length)
{
	unsigned int i = 0;
	unsigned int remain = 0;

	for (i = 0; i < src_length; i++)
	{
		remain = i % 4;

		if (remain == 0)
			dest[i] = (unsigned char)(src[i / 4] >> 24);
		else if (remain == 1)
			dest[i] = (unsigned char)(src[i / 4] >> 16);
		else if (remain == 2)
			dest[i] = (unsigned char)(src[i / 4] >> 8);
		else
			dest[i] = (unsigned char)src[i / 4];
	}

	return 0;
}

void asc_to_byte(unsigned char* hex, const char* asc, int len)
{
	unsigned char tmp;
	int i = 0;

	for (i = 0; i < len; i++)
	{
		if ((asc[i] >= '0') && (asc[i] <= '9'))
			tmp = (unsigned char)(asc[i] - '0');
		else if ((asc[i] >= 'A') && (asc[i] <= 'F'))
			tmp = (unsigned char)(asc[i] - 'A' + 10);
		else if ((asc[i] >= 'a') && (asc[i] <= 'f'))
			tmp = (unsigned char)(asc[i] - 'a' + 10);
		else
			tmp = 0;

		if (i & 1)
			hex[i >> 1] |= (tmp & 0x0F);
		else
			hex[i >> 1] = (tmp & 0x0F) << 4;
	}
}

unsigned int Crypt_ECB(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm,
	const unsigned char	sit)
{
	unsigned int i = 0, j = 0;
	unsigned int temp_0[BLOCK_WORD_LEN] = { 0, }, temp_1[BLOCK_WORD_LEN] = { 0, };

	for (j = 0; j < Input_length; j = j + BLOCK_WORD_LEN)
	{
		for (i = 0; i < BLOCK_WORD_LEN; i++)
		{
			temp_0[i] = pInput[i + j];
		}

		if (algorithm == ALG_ARIA)
			// Crypt_ARIA(temp_1, temp_0, key_len, pRk);
			printf("ARIA isn't finished!! \n");
		else if (algorithm == ALG_LEA)
			Crypt_LEA(temp_1, temp_0, key_len, sit, pRk);

		for (i = 0; i < BLOCK_WORD_LEN; i++)
		{
			pOutput[i + j] = temp_1[i];
		}
	}

	return 0;
}

unsigned int Crypt_CBC(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned char* pIV,
	const unsigned int Iv_length,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm,
	const unsigned char	sit)
{
	unsigned int i = 0, j = 0;
	unsigned int temp_0[BLOCK_WORD_LEN] = { 0, }, temp_1[BLOCK_WORD_LEN] = { 0, };

	if (sit == 1)
	{
		for (j = 0; j < Iv_length / BLOCK_WORD_LEN; j = j + BLOCK_WORD_LEN)
		{
			byte_to_word(temp_0, pIV + (j * BLOCK_WORD_LEN), BLOCK_BYTE_LEN);
			for (i = 0; i < BLOCK_WORD_LEN; i++)
				temp_0[i] ^= pInput[j + i];

			if (algorithm == ALG_LEA)
				Crypt_LEA(temp_1, temp_0, key_len, sit, pRk);

			for (i = 0; i < 4; i++)
				pOutput[j + i] = temp_1[i];
		}

		for (; j < Input_length; j = j + BLOCK_WORD_LEN)
		{
			for (i = 0; i < BLOCK_WORD_LEN; i++)
				temp_0[i] = pInput[j + i] ^ pOutput[j - (Iv_length / BLOCK_WORD_LEN) + i];

			if (algorithm == ALG_LEA)
				Crypt_LEA(temp_1, temp_0, key_len, sit, pRk);

			for (i = 0; i < BLOCK_WORD_LEN; i++)
				pOutput[j + i] = temp_1[i];
		}
	}
	else
	{
		for (j = 0; j < Iv_length / BLOCK_WORD_LEN; j = j + BLOCK_WORD_LEN)
		{
			for (i = 0; i < BLOCK_WORD_LEN; i++)
				temp_0[i] = pInput[j + i];

			if (algorithm == ALG_LEA)
				Crypt_LEA(temp_1, temp_0, key_len, sit, pRk);

			
			byte_to_word(pOutput + j, pIV + (j * BLOCK_WORD_LEN), BLOCK_BYTE_LEN);
			for (i = 0; i < BLOCK_WORD_LEN; i++)
				pOutput[j + i] ^= temp_1[i];
		}

		for (; j < Input_length; j = j + BLOCK_WORD_LEN)
		{
			for (i = 0; i < BLOCK_WORD_LEN; i++)
				temp_0[i] = pInput[j + i];

			if (algorithm == ALG_LEA)
				Crypt_LEA(temp_1, temp_0, key_len, sit, pRk);

			for (i = 0; i < BLOCK_WORD_LEN; i++)
				pOutput[j + i] = temp_1[i] ^ pInput[j - (Iv_length / BLOCK_WORD_LEN) + i];
		}
	}

	return 0;
}

unsigned int Crypt_CTR(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned char* pIV,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm)
{
	unsigned int i = 0, j;
	unsigned int temp_0[BLOCK_WORD_LEN] = { 0, }, tempIV[BLOCK_WORD_LEN] = { 0, };

	
	byte_to_word(tempIV, pIV, BLOCK_BYTE_LEN);

	for (j = 0; j < Input_length; j = j + BLOCK_WORD_LEN)
	{
        if (algorithm == ALG_LEA)
			Crypt_LEA(temp_0, tempIV, key_len, LEA_ENC, pRk);

		for (i = 0; i < BLOCK_WORD_LEN; i++)
			pOutput[j + i] = temp_0[i] ^ pInput[j + i];

		if (tempIV[3] != 0xffffffff)
		{
			tempIV[3]++;
		}
		else
		{
			if (tempIV[2] != 0xffffffff)
			{
				tempIV[2]++;
				tempIV[3] = 0;
			}
			else
			{
				if (tempIV[1] != 0xffffffff)
				{
					tempIV[1]++;
					tempIV[2] = 0;
					tempIV[3] = 0;
				}
				else
				{
					if (tempIV[0] != 0xffffffff)
					{
						tempIV[0]++;
						tempIV[1] = 0;
						tempIV[2] = 0;
						tempIV[3] = 0;
					}
					else
					{
						tempIV[0] = 0;
						tempIV[1] = 0;
						tempIV[2] = 0;
						tempIV[3] = 0;
					}
				}
			}
		}
	}

	return 0;
}
