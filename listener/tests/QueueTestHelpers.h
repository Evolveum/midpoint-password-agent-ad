/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <string>
#include <vector>
#include <wincrypt.h>

#include "../src/Common.h"
#include "../src/crypto/crypto.h"
#include "../src/queue/queue_writer.h"

namespace QueueTestHelpers {

inline constexpr const char *TEST_KEY_VERSION = "v1";

inline std::string TestQueueDir() {
  std::string tmp(MAX_PATH, '\0');
  tmp.resize(GetTempPathA(MAX_PATH, tmp.data()));
  return tmp + "ADPSQueueWriterTests";
}

inline void DeleteDirTree(const std::string &dir) {
  std::string pattern = dir + "\\*";
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }
  do {
    if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
      continue;
    }
    std::string child = dir + "\\" + fd.cFileName;
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      DeleteDirTree(child);
      RemoveDirectoryA(child.c_str());
    } else {
      DeleteFileA(child.c_str());
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  RemoveDirectoryA(dir.c_str());
}

inline std::vector<std::string> ListFiles(const std::string &dir,
                                          const std::string &ext) {
  std::vector<std::string> files;
  std::string pattern = dir + "\\*" + ext;
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) {
    return files;
  }
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
      files.push_back(dir + "\\" + fd.cFileName);
    }
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  return files;
}

inline std::vector<uint8_t> ReadBinaryFile(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

// Generates a fresh AES-256 key, DPAPI-protects it, and writes it to the
// registry so FileQueue::Write can find it during tests.
inline bool SetupTestRegistry() {
  uint8_t rawKey[Crypto::KEY_BYTES];
  NTSTATUS status =
      BCryptGenRandom(nullptr, rawKey, static_cast<ULONG>(sizeof(rawKey)),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (!BCRYPT_SUCCESS(status)) {
    return false;
  }

  DATA_BLOB plainBlob = {static_cast<DWORD>(sizeof(rawKey)), rawKey};
  DATA_BLOB cipherBlob = {};
  bool ok = CryptProtectData(&plainBlob, nullptr, nullptr, nullptr, nullptr,
                             CRYPTPROTECT_LOCAL_MACHINE, &cipherBlob) != 0;
  SecureZeroMemory(rawKey, sizeof(rawKey));
  if (!ok) {
    return false;
  }

  HKEY hKey;
  LONG r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, ADPS_REG_KEY_CONFIG, 0, nullptr,
                           0, KEY_SET_VALUE, nullptr, &hKey, nullptr);
  if (r != ERROR_SUCCESS) {
    LocalFree(cipherBlob.pbData);
    return false;
  }

  RegSetValueExA(hKey, TEST_KEY_VERSION, 0, REG_BINARY, cipherBlob.pbData,
                 cipherBlob.cbData);
  RegSetValueExA(hKey, REG_VAL_LATEST_KEY_PATH, 0, REG_SZ,
                 reinterpret_cast<const BYTE *>(TEST_KEY_VERSION),
                 static_cast<DWORD>(strlen(TEST_KEY_VERSION) + 1));
  RegCloseKey(hKey);
  LocalFree(cipherBlob.pbData);
  return true;
}

inline std::string PrepareQueueDir() {
  auto dir = TestQueueDir();
  DeleteDirTree(dir);

  FileQueue::Init(dir);

  return dir;
}

inline void CleanupTestRegistry() {
  RegDeleteKeyA(HKEY_LOCAL_MACHINE, ADPS_REG_KEY_CONFIG);
}

} // namespace QueueTestHelpers
