/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "config_watcher.h"
#include "../logger/logger.h"
#include "../pch.h"
#include <filesystem>
#include <fmt/format.h>

ConfigWatcher::ConfigWatcher(std::function<void(const AppConfig &)> onChanged)
    : _onChanged(std::move(onChanged)) {}

ConfigWatcher::~ConfigWatcher() { Stop(); }

void ConfigWatcher::Start(const AppConfig &initialConfig) {
  _lastConfig = initialConfig;
  _configFilePath = initialConfig.configFilePath;
  _thread = std::thread(&ConfigWatcher::WatchLoop, this);
}

void ConfigWatcher::Stop() {
  _stop = true;
  if (_thread.joinable()) {
    _thread.join();
  }
}

void ConfigWatcher::WatchLoop() {
  std::filesystem::path dir = _configFilePath.parent_path();
  std::string dirString = dir.string();
  std::string configFileString = _configFilePath.string();

  Logger::FileInfo(
      fmt::format("ConfigWatcher: watching directory: {}", dirString));
  Logger::FileInfo(
      fmt::format("ConfigWatcher: watching config file: {}", configFileString));

  HANDLE hChange = FindFirstChangeNotificationA(
      dirString.c_str(), FALSE,
      FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
  if (hChange == INVALID_HANDLE_VALUE) {
    Logger::FileError(fmt::format(
        "ConfigWatcher: FindFirstChangeNotificationA failed, error: {}",
        GetLastError()));
    return;
  }

  FILETIME lastWriteTime = {};
  if (WIN32_FILE_ATTRIBUTE_DATA fileInfo; GetFileAttributesExA(
          configFileString.c_str(), GetFileExInfoStandard, &fileInfo)) {
    lastWriteTime = fileInfo.ftLastWriteTime;
    Logger::FileInfo("ConfigWatcher: initial config file write time captured");
  } else {
    Logger::FileInfo(
        "ConfigWatcher: config file does not exist yet, will detect creation");
  }

  while (!_stop) {
    DWORD wait = WaitForSingleObject(hChange, 1000);

    if (_stop) {
      break;
    }

    if (wait != WAIT_OBJECT_0) {
      continue;
    }

    Logger::FileInfo("ConfigWatcher: directory change notification received");

    if (WIN32_FILE_ATTRIBUTE_DATA newInfo;
        GetFileAttributesExA(configFileString.c_str(), GetFileExInfoStandard,
                             &newInfo) &&
        CompareFileTime(&newInfo.ftLastWriteTime, &lastWriteTime) != 0) {
      lastWriteTime = newInfo.ftLastWriteTime;
      Logger::FileInfo(
          "ConfigWatcher: config file write time changed, reloading");
      AppConfig newConfig;
      if (!(newConfig == _lastConfig)) {
        _lastConfig = newConfig;
        _onChanged(newConfig);
      } else {
        Logger::FileInfo(
            "ConfigWatcher: config unchanged after reload, skipping callback");
      }
    } else {
      Logger::FileInfo("ConfigWatcher: directory changed but config file write "
                       "time unchanged, ignoring");
    }

    FindNextChangeNotification(hChange);
  }

  Logger::FileInfo("ConfigWatcher: watch loop stopped");
  FindCloseChangeNotification(hChange);
}
