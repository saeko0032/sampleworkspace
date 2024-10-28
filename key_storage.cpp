#include "key_storage.h"

#include <windows.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <fstream>

void HandleError(const char* msg, DWORD errorCode) {
    std::cerr << msg << " Error code: " << errorCode << std::endl;
    exit(EXIT_FAILURE);
}

void StoreKey(const std::string& filePath, const std::vector<BYTE>& key) {
    DATA_BLOB dataIn;
    dataIn.pbData = const_cast<BYTE*>(key.data());
    dataIn.cbData = key.size();

    DATA_BLOB dataOut;
    if (!CryptProtectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut)) {
        HandleError("Failed to protect data", GetLastError());
    }

    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
        HandleError("Failed to open file for writing", GetLastError());
    }

    outFile.write(reinterpret_cast<const char*>(dataOut.pbData), dataOut.cbData);
    outFile.close();

    LocalFree(dataOut.pbData);
}

std::vector<BYTE> RetrieveKey(const std::string& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) {
        HandleError("Failed to open file for reading", GetLastError());
    }

    std::vector<BYTE> encryptedKey((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    DATA_BLOB dataIn;
    dataIn.pbData = encryptedKey.data();
    dataIn.cbData = encryptedKey.size();

    DATA_BLOB dataOut;
    if (!CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr, 0, &dataOut)) {
        HandleError("Failed to unprotect data", GetLastError());
    }

    std::vector<BYTE> key(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);

    return key;
}
