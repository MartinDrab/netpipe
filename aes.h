#ifndef __AES_H__
#define __AES_H__



int rijndaelSetupEncrypt(unsigned long *rk, const unsigned char *key, int keybits);
int rijndaelSetupDecrypt(unsigned long *rk, const unsigned char *key, int keybits);
void rijndaelEncrypt(const unsigned long *rk, int nrounds, const unsigned char plaintext[16], unsigned char ciphertext[16]);
void rijndaelDecrypt(const unsigned long *rk, int nrounds, const unsigned char ciphertext[16], unsigned char plaintext[16]);

#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

typedef struct _AES_Ctx {
	unsigned long RoundKeys[RKLENGTH(0x100)];
	unsigned char IV[0x10];
	int Rounds;
} AES_Ctx, *PAES_Ctx;

void AES_SetupEncrypt(PAES_Ctx Ctx,  const unsigned char *Key, int KeyBits);
void AES_SetupDecrypt(PAES_Ctx Ctx,  const unsigned char *Key, int KeyBits);
void AES_Encrypt(const AES_Ctx *Ctx, const unsigned char *Pt, size_t Length, unsigned char *Ct);
void AES_Decrypt(const AES_Ctx *Ctx, const unsigned char *Ct, size_t Length, unsigned char *Pt);
void AES_EncryptCBC(const AES_Ctx *Ctx, const unsigned char *Pt, size_t Length, unsigned char *Ct);
void AES_DecryptCBC(const AES_Ctx *Ctx, const unsigned char *Ct, size_t Length, unsigned char *Pt);
void AES_EncryptECB(const AES_Ctx *Ctx, const unsigned char *Pt, size_t Length, unsigned char *Ct);
void AES_DecryptECB(const AES_Ctx *Ctx, const unsigned char *Ct, size_t Length, unsigned char *Pt);

void AESDecryptCTS(const AES_Ctx *Ctx, const unsigned char *Ct, size_t Length, unsigned char *Pt);


#endif
 