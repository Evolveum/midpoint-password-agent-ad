/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "registry_provider.h"
#include "../logger/logger.h"
#include "../pch.h"
#include <wincrypt.h>

namespace {

std::string CacheKey(const std::string &subPath, const std::string &valueName) {
  return subPath + "\\" + valueName;
}

std::string GetRegisterValue(const std::string &subPath, const std::string &valueName,
                             const std::string &defaultValue) {
  HKEY hKey;
  std::string path(MAX_PATH, '\0');
  auto size = static_cast<DWORD>(path.size());
  DWORD type = REG_SZ;

  LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    Logger::FileError("Could not open registry key");
    Logger::FileError(subPath);
    return defaultValue;
  }

  result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type,
                            reinterpret_cast<LPBYTE>(&path[0]), &size);
  RegCloseKey(hKey);

  if (result != ERROR_SUCCESS) {
    Logger::FileError("Could not query registry value name");
    Logger::FileError(valueName);
    return defaultValue;
  }

  path.resize(size > 0 ? size - 1 : 0);
  return path;
}

std::vector<BYTE> GetRegisterBinaryValue(const std::string &subPath, const std::string &valueName) {
  HKEY hKey;
  LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = REG_BINARY;
  DWORD size = 0;

  result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &size);
  if (result != ERROR_SUCCESS || type != REG_BINARY || size == 0) {
    RegCloseKey(hKey);
    return {};
  }

  std::vector<BYTE> data(size);
  result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, data.data(), &size);
  RegCloseKey(hKey);

  if (result != ERROR_SUCCESS) {
    return {};
  }

  return data;
}

std::vector<BYTE> DPAPIUnprotect(const std::vector<BYTE> &encrypted) {
  DATA_BLOB input;
  input.pbData = const_cast<BYTE *>(encrypted.data());
  input.cbData = static_cast<DWORD>(encrypted.size());

  DATA_BLOB output = {};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &output)) {
    return {};
  }

  std::vector<BYTE> result(output.pbData, output.pbData + output.cbData);
  LocalFree(output.pbData);
  return result;
}

} // namespace

RegistryProvider &RegistryProvider::Instance() {
  static RegistryProvider instance;
  return instance;
}

std::string RegistryProvider::GetString(const std::string &subPath,
                                        const std::string &valueName,
                                        const std::string &defaultValue) const {
  return GetRegisterValue(subPath, valueName, defaultValue);
}

std::vector<uint8_t>
RegistryProvider::GetProtectedBinary(const std::string &subPath,
                                     const std::string &valueName) {
  const auto key = CacheKey(subPath, valueName);

  {
    std::scoped_lock<std::mutex> lock(mutex_);
    auto it = protectedBinaryCache_.find(key);
    if (it != protectedBinaryCache_.end()) {
      return it->second;
    }
  }

  auto encrypted = GetRegisterBinaryValue(subPath, valueName);
  auto unprotected = DPAPIUnprotect(encrypted);
  if (unprotected.empty()) {
    return unprotected;
  }

  std::scoped_lock<std::mutex> lock(mutex_);
  protectedBinaryCache_[key] = unprotected;
  return unprotected;
}
