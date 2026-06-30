/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "queue_writer.h"
#include "../Common.h"
#include "../WindowsRegisterHelpers.h"
#include "../crypto/crypto.h"
#include "../logger/logger.h"
#include "../pch.h"
#include "../string_helper.h"
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4702) // cppcodec: unreachable code in stream_codec.hpp
#endif
#include <cppcodec/base64_rfc4648.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>
#include <filesystem>

static const std::filesystem::path* queueDirPath = nullptr;


void to_json(nlohmann::json &j, const PasswordEvent &e) {
  j = nlohmann::json{{"username", e.username},
                     {"domain", e.domain},
                     {"password", cppcodec::base64_rfc4648::encode(e.password)}};
}

// File name format `YYYYMMDD_HHmmss_<uuid>_<keyVersion>.event`
static std::string GenerateFileName(const std::string &keyVersion) {
  SYSTEMTIME st;
  GetSystemTime(&st);

  UUID uuid;
  UuidCreate(&uuid);

  char name[128];
  snprintf(name, sizeof(name),
           "%04u%02u%02u_%02u%02u%02u_%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X_%s.event",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
           static_cast<unsigned>(uuid.Data1), uuid.Data2, uuid.Data3, uuid.Data4[0], uuid.Data4[1],
           uuid.Data4[2], uuid.Data4[3], uuid.Data4[4], uuid.Data4[5],
           uuid.Data4[6], uuid.Data4[7], keyVersion.c_str());
  return name;
}

static bool EnsureDir(const std::wstring &path) {
  if (!CreateDirectoryW(path.c_str(), nullptr)) {
    return GetLastError() == ERROR_ALREADY_EXISTS;
  }

  return true;
}

namespace FileQueue {

void Init(const std::filesystem::path &queueDir) {
  static const std::filesystem::path path = queueDir;
  queueDirPath = &path;
  EnsureDir(path.wstring());
  EnsureDir((path / STAGING_FOLDER_NAME).wstring());
}

bool Write(const PasswordEvent& event) {
  if (!queueDirPath) {
    Logger::FileError("Queue directory path variable is empty");
    return false;
  }

  if (event.password.empty()) {
    Logger::FileError("Event has no encrypted password — aborting queue write");
    return false;
  }

  std::string fileName = GenerateFileName(event.keyVersion);
  Logger::FileInfo(fmt::format("Generated new file name '{}'", fileName));
  std::filesystem::path fileNamePath(fileName);
  std::filesystem::path stagingPath = *queueDirPath / STAGING_FOLDER_NAME / fileNamePath;
  std::filesystem::path finalPath = *queueDirPath / fileNamePath;

  std::string payload = nlohmann::json(event).dump();

  HANDLE hFile = CreateFileW(stagingPath.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    Logger::FileError("Creating queue staging file failed");
    return false;
  }
  Logger::FileInfo("Creating queue staging file succeeded");

  DWORD written = 0;
  bool ok = WriteFile(hFile, payload.data(), static_cast<DWORD>(payload.size()),
                      &written, nullptr) &&
            written == static_cast<DWORD>(payload.size());
  CloseHandle(hFile);

  if (!ok) {
    DeleteFileW(stagingPath.c_str());
    Logger::FileError("Write to queue staging file failed");
    return false;
  }

  Logger::FileInfo("Write to queue staging file succeeded");

  if (!MoveFileExW(stagingPath.c_str(), finalPath.c_str(),
                   MOVEFILE_REPLACE_EXISTING)) {
    DeleteFileW(stagingPath.c_str());
    Logger::FileError("Move queue staging file to final destination failed");
    return false;
  }
  Logger::FileInfo("Move queue staging file to final destination succeeded");

  return true;
}

} // namespace FileQueue
