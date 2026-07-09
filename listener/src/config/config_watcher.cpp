/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "config_watcher.h"
#include "../logger/logger.h"

ConfigWatcher::ConfigWatcher(std::function<void(const AppConfig &)> onChanged)
    : _onChanged(std::move(onChanged)) {}

ConfigWatcher::~ConfigWatcher() { Stop(); }

void ConfigWatcher::Start(const AppConfig &initialConfig) {
  _lastConfig = initialConfig;
  _fileWatcher = std::make_unique<FileWatcher>(
      initialConfig.configFilePath, [this] { OnFileChanged(); });
  _fileWatcher->Start();
}

void ConfigWatcher::Stop() {
  if (_fileWatcher) {
    _fileWatcher->Stop();
  }
}

void ConfigWatcher::OnFileChanged() {
  Logger::FileInfo("ConfigWatcher: config file changed, reloading");
  AppConfig newConfig;
  if (!(newConfig == _lastConfig)) {
    _lastConfig = newConfig;
    _onChanged(newConfig);
  } else {
    Logger::FileInfo(
        "ConfigWatcher: config unchanged after reload, skipping callback");
  }
}
