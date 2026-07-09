/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "app_config.h"
#include "../Common.h"
#include "../logger/logger.h"
#include "../registry/registry_provider.h"
#include <fmt/format.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <share.h>

NLOHMANN_JSON_SERIALIZE_ENUM(FilteringFileMode, {
  {FilteringFileMode::EXACT, "EXACT"},
  {FilteringFileMode::REGEX, "REGEX"},
})

void from_json(const nlohmann::json& j, ListenerFileConfig& c) {
  c.logLevel = spdlog::level::from_str(j.value("LogLevel", "info"));
  c.logMaxFileSize = j.value("LogFileSizeLimitBytes", Logger::MAX_FILE_SIZE);
  c.logMaxFiles = j.value("LogRetainedFileCountLimit", Logger::MAX_FILES);
  c.filteringFilePath = j.value("FilteringFilePath", "");
  c.filteringFileMode = j.value("FilteringFileMode", FilteringFileMode::EXACT);
}

AppConfig::AppConfig() {
  this->rootPath = RegistryProvider::Instance().GetString(ADPS_REG_CONFIG, REG_VAL_ROOT_PATH, DEFAULT_ROOT_PATH);
  this->logDirPath = this->rootPath / LOGS_FOLDER_NAME;
  this->queueDirPath = this->rootPath / DATA_FOLDER_NAME / QUEUE_FOLDER_NAME;
  this->configFilePath = this->rootPath / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;

  FILE* fp = _wfsopen(configFilePath.wstring().c_str(), L"rb", _SH_DENYNO);
  if (!fp) {
    return;
  }

  std::string content;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    content.append(buf, n);
  }
  fclose(fp);

  if (content.empty()) {
    return;
  }

  Logger::FileInfo("Preparing to read from config file");

  try {
    auto j = nlohmann::json::parse(content);
    auto listener = j.value("Listener", nlohmann::json::object()).get<ListenerFileConfig>();
    this->logLevel = listener.logLevel;
    this->logMaxFiles = listener.logMaxFiles;
    this->logMaxFileSize = listener.logMaxFileSize;
    this->filteringFilePath = listener.filteringFilePath;
    this->filteringFileMode = listener.filteringFileMode;

    Logger::FileInfo(fmt::format("Successfull read of config file and 'Listener' value -> {}", this->ToString()));
  } catch (...) {
    Logger::FileError("Failed during loading config");
  }
}

std::string AppConfig::ToString() const {
  return fmt::format("logDirPath={}, queueDirPath={}, configFilePath={}, logLevel={}, logMaxFileSize={}, logMaxFiles={}, filteringFilePath={}, filteringFileMode={}",
                     logDirPath.string(), queueDirPath.string(), configFilePath.string(),
                     spdlog::level::to_string_view(logLevel),
                     logMaxFileSize, logMaxFiles, filteringFilePath.string(), to_string(filteringFileMode));
}

bool AppConfig::operator==(const AppConfig &other) const {
  return logDirPath == other.logDirPath && queueDirPath == other.queueDirPath &&
         configFilePath == other.configFilePath && logLevel == other.logLevel && 
         logMaxFiles == other.logMaxFiles && logMaxFileSize == other.logMaxFileSize &&
         filteringFilePath == other.filteringFilePath && filteringFileMode == other.filteringFileMode;
}
