/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "app_config.h"
#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <filesystem>

class ConfigWatcher {
public:
    explicit ConfigWatcher(std::function<void(const AppConfig&)> onChanged);
    ~ConfigWatcher();

    void Start(const AppConfig& initialConfig);
    void Stop();

private:
    void WatchLoop();

    std::filesystem::path _configFilePath;
    std::function<void(const AppConfig&)> _onChanged;
    AppConfig _lastConfig;
    std::atomic<bool> _stop{false};
    std::thread _thread;
};
