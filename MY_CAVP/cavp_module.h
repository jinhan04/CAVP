// ASCII 문자열(hex) → 바이트 배열로 변환
void asc_to_byte(unsigned char* hex, const char* asc, int len);

// 바이트 배열 → 워드 배열로 변환
unsigned int byte_to_word(unsigned int* dest, const unsigned char* src, const unsigned int src_length);

// 워드 배열 → 바이트 배열로 변환
unsigned int word_to_byte(unsigned char* dest, const unsigned int* src, const unsigned int src_length);

// ECB 모드 암/복호화
unsigned int Crypt_ECB(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm,
	const unsigned char	sit);

// CBC 모드 암/복호화
unsigned int Crypt_CBC(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned char* pIV,
	const unsigned int Iv_length,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm,
	const unsigned char	sit);

// CTR 모드 암호화 (복호화도 동일)
unsigned int Crypt_CTR(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned char* pIV,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm);
