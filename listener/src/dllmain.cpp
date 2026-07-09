/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "pch.h"
#include "queue/queue_writer.h"
#include "config/app_config.h"
#include "logger/logger.h"
#include "config/config_watcher.h"
#include "config/file_watcher.h"
#include "filtering/account_filter.h"
#include <fmt/format.h>
#include <memory>

namespace {

// Function-local static instead of a namespace-scope global: same lifetime
// (constructed once, lives for the process), but only reachable through
// this accessor rather than sitting as mutable global state.
std::unique_ptr<ConfigWatcher>& ConfigWatcherInstance() {
    static std::unique_ptr<ConfigWatcher> instance;
    return instance;
}

std::unique_ptr<FileWatcher>& FilteringFileWatcherInstance() {
    static std::unique_ptr<FileWatcher> instance;
    return instance;
}

// Reloads the filter and (re)starts a watcher on filteringFilePath, so edits to it take effect without a config.json change.
void ApplyFilteringFileConfig(const std::filesystem::path& filteringFilePath, FilteringFileMode filteringFileMode) {
    AccountFiltering::Reload(filteringFilePath, filteringFileMode);

    if (filteringFilePath.empty()) {
        FilteringFileWatcherInstance().reset();
        return;
    }

    FilteringFileWatcherInstance() = std::make_unique<FileWatcher>(
        filteringFilePath,
        [filteringFilePath, filteringFileMode] {
            Logger::FileInfo(fmt::format("Filtering file changed: {}", filteringFilePath.string()));
            AccountFiltering::Reload(filteringFilePath, filteringFileMode);
        });
    FilteringFileWatcherInstance()->Start();
}

} // namespace

// Main entry of DLL application
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        AppConfig config;
        Logger::Init(config.logDirPath);
        FileQueue::Init(config.queueDirPath);
        Logger::SetLevel(config.logLevel);

        ConfigWatcherInstance() = std::make_unique<ConfigWatcher>([](const AppConfig& cfg) {
            Logger::SetLevel(cfg.logLevel);
            Logger::SetMaxFileSize(cfg.logMaxFileSize);
            Logger::SetMaxFiles(cfg.logMaxFiles);

            Logger::FileInfo(fmt::format("Configuration reloaded: {}", cfg.ToString()));

            ApplyFilteringFileConfig(cfg.filteringFilePath, cfg.filteringFileMode);
        });

        ConfigWatcherInstance()->Start(config);

        ApplyFilteringFileConfig(config.filteringFilePath, config.filteringFileMode);
    } else if (reason == DLL_PROCESS_DETACH) {
        FilteringFileWatcherInstance().reset();
        ConfigWatcherInstance().reset();
        Logger::Uninit();
    }

    return TRUE;
}
