#include "rsa_encryption.h"
#include "key_storage.h"
#include <ntstatus.h>
#include <iostream>

int main() {
    // Open algorithm provider
    BCRYPT_ALG_HANDLE hAlgorithm = OpenAlgorithmProvider();

    // Generate RSA key pair
    BCRYPT_KEY_HANDLE hKey = GenerateKeyPair(hAlgorithm);

    // Store the RSA key securely
    std::vector<BYTE> keyData;
    DWORD keySize = 0;
    NTSTATUS status = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, nullptr, 0, &keySize, 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to calculate key size", status);
    }
    keyData.resize(keySize);
    status = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, keyData.data(), keyData.size(), &keySize, 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to export key", status);
    }
    StoreKey("rsa_key.dat", keyData);

    // Retrieve the RSA key securely
    std::vector<BYTE> retrievedKeyData = RetrieveKey("rsa_key.dat");
    BCRYPT_KEY_HANDLE hImportedKey = nullptr;
    status = BCryptImportKeyPair(hAlgorithm, nullptr, BCRYPT_RSAPRIVATE_BLOB, &hImportedKey, retrievedKeyData.data(), retrievedKeyData.size(), 0);
    if (status != STATUS_SUCCESS) {
        HandleError("Failed to import key", status);
    }

    // Encrypt an arbitrary list
    std::vector<BYTE> data = {1, 2, 3, 4, 5};
    std::vector<BYTE> encryptedData = EncryptData(hImportedKey, data);

    // Decrypt the encrypted list
    std::vector<BYTE> decryptedData = DecryptData(hImportedKey, encryptedData);

    // Print the decrypted data
    std::cout << "Decrypted data: ";
    for (BYTE byte : decryptedData) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Cleanup
    Cleanup(hAlgorithm, hImportedKey);

    return 0;
}
