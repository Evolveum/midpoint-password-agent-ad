/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "account_filter.h"
#include "../logger/logger.h"
#include <algorithm>
#include <cctype>
#include <fmt/format.h>
#include <fstream>
#include <mutex>

namespace {

std::string Trim(std::string_view s) {
  auto begin = std::find_if(s.begin(), s.end(), [](unsigned char c) { return !std::isspace(c); });
  auto end = std::find_if(s.rbegin(), s.rend(), [](unsigned char c) { return !std::isspace(c); }).base();
  return begin < end ? std::string(begin, end) : std::string();
}

std::string ToLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

}

AccountFilter::AccountFilter(const std::filesystem::path& filePath, FilteringFileMode mode)
    : _mode(mode) {
  if (_mode == FilteringFileMode::EXACT) {
    LoadExact(filePath);
  } else {
    LoadRegex(filePath);
  }
}

void AccountFilter::LoadExact(const std::filesystem::path& filePath) {
  std::ifstream file(filePath);
  if (!file) {
    Logger::FileInfo(fmt::format("AccountFilter: filtering file not found: {}", filePath.string()));
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    std::string entry = Trim(line);
    if (!entry.empty()) {
      _exactEntries.push_back(ToLower(entry));
    }
  }

  Logger::FileInfo(fmt::format("AccountFilter: loaded {} exact entries from {}", _exactEntries.size(), filePath.string()));
}

void AccountFilter::LoadRegex(const std::filesystem::path& filePath) {
  std::ifstream file(filePath);
  if (!file) {
    Logger::FileInfo(fmt::format("AccountFilter: filtering file not found: {}", filePath.string()));
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    std::string pattern = Trim(line);
    if (pattern.empty()) {
      continue;
    }

    try {
      _regexEntries.emplace_back(pattern, std::regex::icase);
    } catch (const std::regex_error& e) {
      Logger::FileError(fmt::format("AccountFilter: invalid regex pattern '{}': {}", pattern, e.what()));
    }
  }

  Logger::FileInfo(fmt::format("AccountFilter: loaded {} regex entries from {}",
                               _regexEntries.size(), filePath.string()));
}

bool AccountFilter::IsAllowed(const std::string& accountName) const {
  if (_mode == FilteringFileMode::EXACT) {
    if (_exactEntries.empty()) {
      return true;
    }
    return std::find(_exactEntries.begin(), _exactEntries.end(), ToLower(accountName)) == _exactEntries.end();
  }

  return std::none_of(_regexEntries.begin(), _regexEntries.end(),
                      [&accountName](const std::regex& re) {
                        return std::regex_match(accountName, re);
                      });
}

namespace AccountFiltering {

namespace {

// Function-local statics instead of namespace-scope globals: same lifetime
// (constructed once, lives for the process), but only reachable through
// these accessors rather than sitting as mutable global state.
std::mutex& Mutex() {
  static std::mutex mutex;
  return mutex;
}

AccountFilter& Current() {
  static AccountFilter current;
  return current;
}

}

// lock_guard (not explicit lock()/unlock(), unlocked in destructor) so the mutex still gets released if
// AccountFilter's assignment or IsAllowed() ever throws, avoiding a deadlock
void Reload(const std::filesystem::path& filePath, FilteringFileMode mode) {
  AccountFilter filter(filePath, mode);
  std::scoped_lock<std::mutex> lock(Mutex());
  Current() = std::move(filter);
}

bool IsAllowed(const std::string& accountName) {
  std::scoped_lock<std::mutex> lock(Mutex());
  return Current().IsAllowed(accountName);
}

}
