/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

/// Windows registry value provider with value caching
class RegistryProvider {
public:
  static RegistryProvider &Instance();

  RegistryProvider(const RegistryProvider &) = delete;
  RegistryProvider &operator=(const RegistryProvider &) = delete;

  /// Reads a REG_SZ value
  std::string GetString(const std::string &subPath,
                         const std::string &valueName,
                         const std::string &defaultValue = "") const;

  /// Reads a REG_BINARY value and DPAPI-unprotected
  /// Cached after the first successful read.
  std::vector<uint8_t> GetProtectedBinary(const std::string &subPath,
                                           const std::string &valueName);

private:
  RegistryProvider() = default;

  std::mutex mutex_;
  std::unordered_map<std::string, std::vector<uint8_t>> protectedBinaryCache_;
};
