#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include <windows.h>
#include <bcrypt.h>
#include <vector>

BCRYPT_ALG_HANDLE OpenAlgorithmProvider();
BCRYPT_KEY_HANDLE GenerateKeyPair(BCRYPT_ALG_HANDLE hAlgorithm);
std::vector<BYTE> EncryptData(BCRYPT_KEY_HANDLE hKey, const std::vector<BYTE>& data);
std::vector<BYTE> DecryptData(BCRYPT_KEY_HANDLE hKey, const std::vector<BYTE>& cipherText);
void Cleanup(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hKey);

#endif // RSA_ENCRYPTION_H
