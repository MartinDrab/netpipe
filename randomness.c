
#include "compat-header.h"





int RandomBuffer(void *Buffer, uint32_t Size)
{
	int ret = 0;
	HCRYPTPROV hCryptProv = 0;

	ret = 0;
	if (CryptAcquireContextW(&hCryptProv, NULL, L"Microsoft Base Cryptographic Provider v1.0", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		if (!CryptGenRandom(hCryptProv, 16, Buffer))
			ret = GetLastError();

		CryptReleaseContext(hCryptProv, 0);
	} else ret = GetLastError();

	return ret;
}
