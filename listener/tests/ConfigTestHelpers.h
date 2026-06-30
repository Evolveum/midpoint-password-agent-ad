/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include <filesystem>
#include <fstream>
#include <string>
#include <windows.h>

#include "../src/Common.h"

namespace ConfigTestHelpers {

inline std::filesystem::path TempRootDir(const char *name) {
  char tmp[MAX_PATH];
  GetTempPathA(MAX_PATH, tmp);
  return std::filesystem::path(tmp) / name;
}

inline void WriteJson(const std::filesystem::path &path, const char *content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
  f.flush();
}

struct RegistryConfigScope {
  std::filesystem::path _rootPath;
  bool hadPrevious = false;
  std::string previousValue;

  RegistryConfigScope(const RegistryConfigScope &) = delete;
  RegistryConfigScope &operator=(const RegistryConfigScope &) = delete;
  RegistryConfigScope(RegistryConfigScope &&) = delete;
  RegistryConfigScope &operator=(RegistryConfigScope &&) = delete;

  explicit RegistryConfigScope(const std::filesystem::path &rootPath)
      : _rootPath(rootPath) {
    std::filesystem::create_directories(_rootPath / CONFIG_FOLDER_NAME);

    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, ADPS_REG_CONFIG, 0, nullptr, 0,
                        KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &hKey,
                        nullptr) != ERROR_SUCCESS) {
      return;
    }

    char buf[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (DWORD type = REG_SZ;
        RegQueryValueExA(hKey, REG_VAL_ROOT_PATH, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf),
                         &size) == ERROR_SUCCESS) {
      hadPrevious = true;
      previousValue = buf;
    }

    std::string rootStr = _rootPath.string();
    RegSetValueExA(hKey, REG_VAL_ROOT_PATH, 0, REG_SZ,
                   reinterpret_cast<const BYTE *>(rootStr.c_str()),
                   static_cast<DWORD>(rootStr.size() + 1));
    RegCloseKey(hKey);
  }

  ~RegistryConfigScope() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADPS_REG_CONFIG, 0, KEY_SET_VALUE,
                      &hKey) != ERROR_SUCCESS) {
      return;
    }
    if (hadPrevious) {
      RegSetValueExA(hKey, REG_VAL_ROOT_PATH, 0, REG_SZ,
                     reinterpret_cast<const BYTE *>(previousValue.c_str()),
                     static_cast<DWORD>(previousValue.size() + 1));
    } else {
      RegDeleteValueA(hKey, REG_VAL_ROOT_PATH);
    }
    RegCloseKey(hKey);

    try { std::filesystem::remove_all(_rootPath); } catch (...) {}
  }
};

} // namespace ConfigTestHelpers
