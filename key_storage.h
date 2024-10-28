#ifndef KEY_STORAGE_H
#define KEY_STORAGE_H

#include <windows.h>
#include <dpapi.h>
#include <vector>
#include <string>

void HandleError(const char* msg, DWORD errorCode);
void StoreKey(const std::string& filePath, const std::vector<BYTE>& key);
std::vector<BYTE> RetrieveKey(const std::string& filePath);

#endif // KEY_STORAGE_H
