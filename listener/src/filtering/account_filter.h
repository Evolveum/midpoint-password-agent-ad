/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "../config/app_config.h"
#include <filesystem>
#include <regex>
#include <string>
#include <vector>

// Deny-list: accounts matching an entry are excluded from syncing.
// A missing or empty filtering file matches nothing, so all accounts pass.
class AccountFilter {
public:
    AccountFilter() = default;
    AccountFilter(const std::filesystem::path& filePath, FilteringFileMode mode);

    bool IsAllowed(const std::string& accountName) const;

private:
    void LoadExact(const std::filesystem::path& filePath);
    void LoadRegex(const std::filesystem::path& filePath);

    FilteringFileMode _mode = FilteringFileMode::EXACT;
    std::vector<std::string> _exactEntries;
    std::vector<std::regex> _regexEntries;
};

// Holds the currently active AccountFilter and allows it to be swapped
// out safely while IsAllowed() is being called concurrently from other threads.
namespace AccountFiltering {
void Reload(const std::filesystem::path& filePath, FilteringFileMode mode);
bool IsAllowed(const std::string& accountName);
}
