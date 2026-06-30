/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once

#include <cstring>
#include <string>
#include <vector>
#include "logger/logger.h"
#include "pch.h"
#include <wincrypt.h>

inline std::string GetRegisterValue(const char* subPath, const char* valueName, const char* defaultValue) {
  HKEY hKey;
  std::string path(MAX_PATH, '\0');
  auto size = static_cast<DWORD>(path.size());
  DWORD type = REG_SZ;

  LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    Logger::FileError("Could not open registry key");
    Logger::FileError(subPath);
    return defaultValue;
  }

  result = RegQueryValueExA(hKey, valueName, nullptr, &type,
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

inline std::vector<BYTE> GetRegisterBinaryValue(const char* subPath, const char* valueName) {
  HKEY hKey;
  LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = REG_BINARY;
  DWORD size = 0;

  result = RegQueryValueExA(hKey, valueName, nullptr, &type, nullptr, &size);
  if (result != ERROR_SUCCESS || type != REG_BINARY || size == 0) {
    RegCloseKey(hKey);
    return {};
  }

  std::vector<BYTE> data(size);
  result = RegQueryValueExA(hKey, valueName, nullptr, &type, data.data(), &size);
  RegCloseKey(hKey);

  if (result != ERROR_SUCCESS) {
    return {};
  }

  return data;
}

inline std::vector<BYTE> DPAPIUnprotect(const std::vector<BYTE>& encrypted) {
  DATA_BLOB input;
  input.pbData = const_cast<BYTE*>(encrypted.data());
  input.cbData = static_cast<DWORD>(encrypted.size());

  DATA_BLOB output = {};
  if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &output)) {
    return {};
  }

  std::vector<BYTE> result(output.pbData, output.pbData + output.cbData);
  LocalFree(output.pbData);
  return result;
}
