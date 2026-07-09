/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "app_config.h"
#include "file_watcher.h"
#include <functional>
#include <memory>

// Creates watcher on `config.json` file. On change it recreates new AppConfig instance
class ConfigWatcher {
public:
    explicit ConfigWatcher(std::function<void(const AppConfig&)> onChanged);
    ~ConfigWatcher();

    void Start(const AppConfig& initialConfig);
    void Stop();

private:
    void OnFileChanged();

    std::function<void(const AppConfig&)> _onChanged;
    AppConfig _lastConfig;
    std::unique_ptr<FileWatcher> _fileWatcher;
};
