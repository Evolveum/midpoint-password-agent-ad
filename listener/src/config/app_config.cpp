/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "app_config.h"
#include "../Common.h"
#include "../WindowsRegisterHelpers.h"
#include "../logger/logger.h"
#include <fmt/format.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <filesystem>

void from_json(const nlohmann::json& j, ListenerFileConfig& c) {
  c.logLevel = spdlog::level::from_str(j.value("LogLevel", "info"));
  c.logMaxFileSize = j.value("LogFileSizeLimitBytes", Logger::MAX_FILE_SIZE);
  c.logMaxFiles = j.value("LogRetainedFileCountLimit", Logger::MAX_FILES);
}

AppConfig::AppConfig() {
  this->rootPath = GetRegisterValue(ADPS_REG_CONFIG, REG_VAL_ROOT_PATH, DEFAULT_ROOT_PATH);
  this->logDirPath = this->rootPath / LOGS_FOLDER_NAME;
  this->queueDirPath = this->rootPath / DATA_FOLDER_NAME / QUEUE_FOLDER_NAME;
  this->configFilePath = this->rootPath / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;

  std::ifstream f(configFilePath);
  if (!f.is_open()) {
    return;
  }

  Logger::FileInfo("Preparing to read from config file");

  try {
    auto j = nlohmann::json::parse(f);
    auto listener = j.value("Listener", nlohmann::json::object()).get<ListenerFileConfig>();
    this->logLevel = listener.logLevel;
    this->logMaxFiles = listener.logMaxFiles;
    this->logMaxFileSize = listener.logMaxFileSize;

    Logger::FileInfo(fmt::format("Successfull read of config file and 'Listener' value -> {}", this->ToString()));
  } catch (...) {
    Logger::FileError("Failed during loading config");
  }
}

std::string AppConfig::ToString() const {
  return fmt::format("logDirPath={}, queueDirPath={}, configFilePath={}, logLevel={}, logMaxFileSize={}, logMaxFiles={}",
                     logDirPath.string(), queueDirPath.string(), configFilePath.string(),
                     spdlog::level::to_string_view(logLevel),
                     logMaxFileSize, logMaxFiles);
}

bool AppConfig::operator==(const AppConfig &other) const {
  return logDirPath == other.logDirPath && queueDirPath == other.queueDirPath &&
         configFilePath == other.configFilePath && logLevel == other.logLevel && 
         logMaxFiles == other.logMaxFiles && logMaxFileSize == other.logMaxFileSize;
}
