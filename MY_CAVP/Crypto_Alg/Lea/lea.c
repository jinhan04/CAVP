#include "lea.h"


#define ROR(W,i) (((W)>>(i)) | ((W)<<(32-(i))))
#define ROL(W,i) (((W)<<(i)) | ((W)>>(32-(i))))


unsigned int Expand_Key_LEA(unsigned int* rk, const unsigned int* key, const unsigned int key_len)
{
	unsigned int delta[8] = { 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957 };
	unsigned int T[8] = { 0, };

	unsigned int i;

	for (i = 0; i < key_len; i++)
	{
		T[i] ^= ((key[i] << 24) & 0xff000000);
		T[i] ^= ((key[i] << 8) & 0x00ff0000);
		T[i] ^= ((key[i] >> 8) & 0x0000ff00);
		T[i] ^= ((key[i] >> 24) & 0x000000ff);
	}

	if (key_len == 4)
	{
		for (i = 0; i < 24; i++)
		{
			T[0] = ROL(T[0] + ROL(delta[i & 3], i), 1);
			T[1] = ROL(T[1] + ROL(delta[i & 3], i + 1), 3);
			T[2] = ROL(T[2] + ROL(delta[i & 3], i + 2), 6);
			T[3] = ROL(T[3] + ROL(delta[i & 3], i + 3), 11);

			rk[i * 6] = T[0];
			rk[i * 6 + 1] = T[1];
			rk[i * 6 + 2] = T[2];
			rk[i * 6 + 3] = T[1];
			rk[i * 6 + 4] = T[3];
			rk[i * 6 + 5] = T[1];
		}
	}
	else if (key_len == 6)
	{
		for (i = 0; i < 28; i++)
		{
			T[0] = ROL(T[0] + ROL(delta[i % 6], i & 0x1f), 1);
			T[1] = ROL(T[1] + ROL(delta[i % 6], (i + 1) & 0x1f), 3);
			T[2] = ROL(T[2] + ROL(delta[i % 6], (i + 2) & 0x1f), 6);
			T[3] = ROL(T[3] + ROL(delta[i % 6], (i + 3) & 0x1f), 11);
			T[4] = ROL(T[4] + ROL(delta[i % 6], (i + 4) & 0x1f), 13);
			T[5] = ROL(T[5] + ROL(delta[i % 6], (i + 5) & 0x1f), 17);

			rk[i * 6] = T[0];
			rk[i * 6 + 1] = T[1];
			rk[i * 6 + 2] = T[2];
			rk[i * 6 + 3] = T[3];
			rk[i * 6 + 4] = T[4];
			rk[i * 6 + 5] = T[5];
		}
	}
	else if (key_len == 8)
	{
		for (i = 0; i < 32; i++)
		{
			T[(6 * i) & 7] = ROL(T[(6 * i) & 7] + ROL(delta[i & 7], i & 0x1f), 1);
			T[(6 * i + 1) & 7] = ROL(T[(6 * i + 1) & 7] + ROL(delta[i & 7], (i + 1) & 0x1f), 3);
			T[(6 * i + 2) & 7] = ROL(T[(6 * i + 2) & 7] + ROL(delta[i & 7], (i + 2) & 0x1f), 6);
			T[(6 * i + 3) & 7] = ROL(T[(6 * i + 3) & 7] + ROL(delta[i & 7], (i + 3) & 0x1f), 11);
			T[(6 * i + 4) & 7] = ROL(T[(6 * i + 4) & 7] + ROL(delta[i & 7], (i + 4) & 0x1f), 13);
			T[(6 * i + 5) & 7] = ROL(T[(6 * i + 5) & 7] + ROL(delta[i & 7], (i + 5) & 0x1f), 17);

			rk[i * 6] = T[(6 * i) & 7];
			rk[i * 6 + 1] = T[(6 * i + 1) & 7];
			rk[i * 6 + 2] = T[(6 * i + 2) & 7];
			rk[i * 6 + 3] = T[(6 * i + 3) & 7];
			rk[i * 6 + 4] = T[(6 * i + 4) & 7];
			rk[i * 6 + 5] = T[(6 * i + 5) & 7];
		}
	}

	return 0;
}

unsigned int Crypt_LEA(unsigned int* output, const unsigned int* input, const unsigned int key_len, const unsigned char sit, const unsigned int* rk)
{
	unsigned int t[4] = { 0, }, temp = 0;
	unsigned int i = 0;
	unsigned int num_rnd = 0;

	if (key_len == 4)
		num_rnd = 24;
	else if (key_len == 6)
		num_rnd = 28;
	else if (key_len == 8)
		num_rnd = 32;

	for (i = 0; i < 4; i++)
	{
		t[i] ^= ((input[i] << 24) & 0xff000000);
		t[i] ^= ((input[i] << 8) & 0x00ff0000);
		t[i] ^= ((input[i] >> 8) & 0x0000ff00);
		t[i] ^= ((input[i] >> 24) & 0x000000ff);
	}

	if (sit == LEA_ENC)
	{
		for (i = 0; i < num_rnd; i++)
		{
			t[3] = ROR((t[2] ^ rk[i * 6 + 4]) + (t[3] ^ rk[i * 6 + 5]), 3);
			t[2] = ROR((t[1] ^ rk[i * 6 + 2]) + (t[2] ^ rk[i * 6 + 3]), 5);
			t[1] = ROL((t[0] ^ rk[i * 6]) + (t[1] ^ rk[i * 6 + 1]), 9);
			temp = t[0];

			t[0] = t[1];
			t[1] = t[2];
			t[2] = t[3];
			t[3] = temp;
		}
	}
	else
	{
		for (i = 0; i < num_rnd; i++)
		{
			temp = t[3];
			t[3] = t[2];
			t[2] = t[1];
			t[1] = t[0];
			t[0] = temp;

			t[1] = (ROR(t[1], 9) - (t[0] ^ rk[(num_rnd - 1 - i) * 6])) ^ rk[(num_rnd - 1 - i) * 6 + 1];
			t[2] = (ROL(t[2], 5) - (t[1] ^ rk[(num_rnd - 1 - i) * 6 + 2])) ^ rk[(num_rnd - 1 - i) * 6 + 3];
			t[3] = (ROL(t[3], 3) - (t[2] ^ rk[(num_rnd - 1 - i) * 6 + 4])) ^ rk[(num_rnd - 1 - i) * 6 + 5];
		}
	}

	for (i = 0; i < 4; i++)
	{
		output[i] = ((t[i] << 24) & 0xff000000);
		output[i] ^= ((t[i] << 8) & 0x00ff0000);
		output[i] ^= ((t[i] >> 8) & 0x0000ff00);
		output[i] ^= ((t[i] >> 24) & 0x000000ff);
	}

	return 0;
}
