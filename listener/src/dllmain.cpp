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
#include <fmt/format.h>
#include <memory>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    static std::unique_ptr<ConfigWatcher> g_configWatcher;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        AppConfig config;
        Logger::Init(config.logDirPath);
        FileQueue::Init(config.queueDirPath);
        Logger::SetLevel(config.logLevel);

        g_configWatcher = std::make_unique<ConfigWatcher>([](const AppConfig& cfg) {
            Logger::SetLevel(cfg.logLevel);
            Logger::SetMaxFileSize(cfg.logMaxFileSize);
            Logger::SetMaxFiles(cfg.logMaxFiles);

            Logger::FileInfo(fmt::format("Configuration reloaded: {}", cfg.ToString()));
        });

        g_configWatcher->Start(config);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_configWatcher.reset();
        Logger::Uninit();
    }

    return TRUE;
}
