/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "../logger/logger.h"
#include <nlohmann/json_fwd.hpp>
#include <spdlog/spdlog.h>
#include <string>
#include <filesystem>

enum class FilteringFileMode {
  EXACT,
  REGEX,
};

inline std::string to_string(FilteringFileMode mode) {
  switch (mode) {
    case FilteringFileMode::EXACT: return "EXACT";
    case FilteringFileMode::REGEX: return "REGEX";
  }
  return "UNKNOWN";
}

struct ListenerFileConfig {
    spdlog::level::level_enum logLevel = spdlog::level::info;
    std::size_t logMaxFileSize = Logger::MAX_FILE_SIZE;
    std::size_t logMaxFiles = Logger::MAX_FILES;
    std::string filteringFilePath;
    FilteringFileMode filteringFileMode = FilteringFileMode::EXACT;
};

void from_json(const nlohmann::json& j, ListenerFileConfig& c);

// Holds Listener configuration from `config.json` file
class AppConfig {
public:
    AppConfig();

    std::filesystem::path rootPath;
    std::filesystem::path logDirPath;
    std::filesystem::path queueDirPath;
    std::filesystem::path configFilePath;

    spdlog::level::level_enum logLevel = spdlog::level::info;
    std::size_t logMaxFileSize = Logger::MAX_FILE_SIZE;
    std::size_t logMaxFiles = Logger::MAX_FILES;

    std::filesystem::path filteringFilePath;
    FilteringFileMode filteringFileMode;

    bool operator==(const AppConfig& other) const;
    std::string ToString() const;
};
