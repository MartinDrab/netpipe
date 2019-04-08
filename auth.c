
#include "compat-header.h"
#include "aes.h"
#include "sha2.h"
#include "auth.h"




static void _generateSalt(unsigned char Salt[16])
{
	for (size_t i = 0; i < 16; ++i)
		Salt[i] = rand();

	return;
}


static void _increment16(unsigned char Block[16])
{
	unsigned char *b = Block + 16;

	do {
		--b;
		++*b;
	} while (b != Block && *b == 0);

	return;
}



void AuthKeyGen(const char *Password, unsigned char *Salt, unsigned int SaltLen, uint32_t IterationCount, unsigned char Key[16])
{
	sha256_ctx ctx;
	unsigned char digest[256/8];

	sha256_init(&ctx);
	sha256_update(&ctx, Salt, SaltLen);
	sha256_update(&ctx, Password, (unsigned int)strlen(Password));
	for (size_t i = 0; i < IterationCount - 1; ++i) {
		sha256_final(&ctx, digest);
		sha256_init(&ctx);
		sha256_update(&ctx, Salt, SaltLen);
		sha256_update(&ctx, digest, sizeof(digest));
	}

	sha256_final(&ctx, digest);
	memcpy(Key, digest, 0x10);

	return;
}


int AuthSocket(SOCKET Socket, const char *Password)
{
	int ret = 0;
	unsigned char ourChallenge[16];
	unsigned char otherChallenge[16];
	unsigned char salt[16];
	unsigned char key[16];
	unsigned char tmp[16];
	AES_Ctx aesCtx;

	_generateSalt(ourChallenge);
	ret = send(Socket, ourChallenge, sizeof(ourChallenge), 0);
	if (ret != sizeof(ourChallenge)) {
		ret = -1;
		goto Exit;
	}

	ret = recv(Socket, otherChallenge, sizeof(otherChallenge), MSG_WAITALL);
	if (ret != sizeof(otherChallenge)) {
		ret = -1;
		goto Exit;
	}

	for (size_t i = 0; i < sizeof(salt) / sizeof(salt[0]); ++i)
		salt[0] = ourChallenge[0] ^ otherChallenge[0];

	AuthKeyGen(Password, salt, sizeof(salt), 65536, key);
		_increment16(otherChallenge);
	AES_SetupEncrypt(&aesCtx, key, sizeof(key) * 8);
	AES_Encrypt(&aesCtx, otherChallenge, sizeof(otherChallenge), tmp);
	ret = send(Socket, tmp, sizeof(tmp), 0);
	if (ret != sizeof(tmp)) {
		ret = errno;
		goto Exit;
	}

	ret = recv(Socket, tmp, sizeof(tmp), MSG_WAITALL);
	if (ret != sizeof(tmp)) {
		ret = errno;
		goto Exit;
	}
	
	AES_SetupDecrypt(&aesCtx, key, sizeof(key) * 8);
	AES_Decrypt(&aesCtx, tmp, sizeof(tmp), otherChallenge);
	_increment16(ourChallenge);
	ret = memcmp(otherChallenge, ourChallenge, sizeof(otherChallenge));
	if (ret != 0)
		ret = -1;

Exit:
	return ret;
}
