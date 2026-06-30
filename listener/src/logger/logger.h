/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "../pch.h"
#include <spdlog/spdlog.h>
#include <string>
#include <filesystem>

namespace Logger {
  
static constexpr std::size_t MAX_FILE_SIZE =
    static_cast<long long>(5 * 1024) * 1024; // 5 MB per file
static constexpr std::size_t MAX_FILES = 3;

/// Initialize spdlog with a rotating file sink.
/// Call from DllMain on DLL_PROCESS_ATTACH.
void Init(const std::filesystem::path &logDirPath);

/// Flush and shut down spdlog.
/// Call from DllMain on DLL_PROCESS_DETACH.
void Uninit();

/// Update the active log level at runtime.
void SetLevel(spdlog::level::level_enum level);
void SetMaxFileSize(std::size_t maxFileSize);
void SetMaxFiles(std::size_t maxFiles);

template <typename T> inline void FileInfo(const T &msg) { spdlog::info(msg); }
template <typename T> inline void FileError(const T &msg) {
  spdlog::error(msg);
}

void EventInfo(LPCWSTR message);
void EventError(LPCWSTR message);

} // namespace Logger
