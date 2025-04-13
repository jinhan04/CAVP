// ASCII ���ڿ�(hex) �� ����Ʈ �迭�� ��ȯ
void asc_to_byte(unsigned char* hex, const char* asc, int len);

// ����Ʈ �迭 �� ���� �迭�� ��ȯ
unsigned int byte_to_word(unsigned int* dest, const unsigned char* src, const unsigned int src_length);

// ���� �迭 �� ����Ʈ �迭�� ��ȯ
unsigned int word_to_byte(unsigned char* dest, const unsigned int* src, const unsigned int src_length);

// ECB ��� ��/��ȣȭ
unsigned int Crypt_ECB(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm,
	const unsigned char	sit);

// CBC ��� ��/��ȣȭ
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

// CTR ��� ��ȣȭ (��ȣȭ�� ����)
unsigned int Crypt_CTR(
	unsigned int* pOutput,
	const unsigned int* pInput,
	const unsigned int Input_length,
	const unsigned char* pIV,
	const unsigned int* pRk,
	const unsigned int key_len,
	const unsigned char	algorithm);
