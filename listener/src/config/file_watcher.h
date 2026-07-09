/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include <atomic>
#include <functional>
#include <filesystem>
#include <thread>

class FileWatcher {
public:
    FileWatcher(std::filesystem::path filePath, std::function<void()> onChanged);
    ~FileWatcher();

    void Start();
    void Stop();

private:
    void WatchLoop() const;

    std::filesystem::path _filePath;
    std::function<void()> _onChanged;
    std::atomic<bool> _stop{false};
    std::thread _thread;
};
