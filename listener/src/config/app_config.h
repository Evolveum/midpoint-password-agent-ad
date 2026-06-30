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

struct ListenerFileConfig {
    spdlog::level::level_enum logLevel = spdlog::level::info;
    std::size_t logMaxFileSize = Logger::MAX_FILE_SIZE;
    std::size_t logMaxFiles = Logger::MAX_FILES;
};

void from_json(const nlohmann::json& j, ListenerFileConfig& c);

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

    bool operator==(const AppConfig& other) const;
    std::string ToString() const;
};
