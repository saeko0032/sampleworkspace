#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

void HandleError(const char* msg, NTSTATUS status) {
    std::cerr << msg << " Error code: " << status << std::endl;
    exit(EXIT_FAILURE);
}

BCRYPT_ALG_HANDLE OpenAlgorithmProvider() {
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to open algorithm provider", status);
    }
    return hAlgorithm;
}

BCRYPT_KEY_HANDLE GenerateKeyPair(BCRYPT_ALG_HANDLE hAlgorithm) {
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(hAlgorithm, &hKey, 2048, 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to generate key pair", status);
    }
    status = BCryptFinalizeKeyPair(hKey, 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to finalize key pair", status);
    }
    return hKey;
}

std::vector<BYTE> EncryptData(BCRYPT_KEY_HANDLE hKey, const std::vector<BYTE>& data) {
    DWORD cbCipherText = 0;
    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, nullptr, 0, nullptr, 0, &cbCipherText, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to calculate ciphertext size", status);
    }

    std::vector<BYTE> cipherText(cbCipherText);
    status = BCryptEncrypt(hKey, (PUCHAR)data.data(), data.size(), nullptr, nullptr, 0, cipherText.data(), cipherText.size(), &cbCipherText, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to encrypt data", status);
    }

    return cipherText;
}

std::vector<BYTE> DecryptData(BCRYPT_KEY_HANDLE hKey, const std::vector<BYTE>& cipherText) {
    DWORD cbPlainText = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)cipherText.data(), cipherText.size(), nullptr, nullptr, 0, nullptr, 0, &cbPlainText, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to calculate plaintext size", status);
    }

    std::vector<BYTE> plainText(cbPlainText);
    status = BCryptDecrypt(hKey, (PUCHAR)cipherText.data(), cipherText.size(), nullptr, nullptr, 0, plainText.data(), plainText.size(), &cbPlainText, BCRYPT_PAD_PKCS1);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to decrypt data", status);
    }

    return plainText;
}

void Cleanup(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hKey) {
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
}
