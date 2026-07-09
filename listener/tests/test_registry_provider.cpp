/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <string>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

#include "../src/registry/registry_provider.h"

namespace {

// Same HKLM subkey the production code uses for encryption keys — created
// (if missing) and left in place, mirroring RegistryConfigScope in
// ConfigTestHelpers.h.
constexpr const char *kSubPath = "SOFTWARE\\Evolveum\\MidPointPasswordAgent\\Keys";

std::vector<BYTE> DPAPIProtect(const std::string &plain) {
  DATA_BLOB input;
  input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(plain.data()));
  input.cbData = static_cast<DWORD>(plain.size());

  DATA_BLOB output = {};
  if (!CryptProtectData(&input, nullptr, nullptr, nullptr, nullptr,
                        CRYPTPROTECT_LOCAL_MACHINE, &output)) {
    return {};
  }

  std::vector<BYTE> result(output.pbData, output.pbData + output.cbData);
  LocalFree(output.pbData);
  return result;
}

// Sets a single registry value under kSubPath for the lifetime of the
// scope, and removes it (and only it) on destruction.
struct RegistryValueScope {
  std::string valueName;

  RegistryValueScope(const RegistryValueScope &) = delete;
  RegistryValueScope &operator=(const RegistryValueScope &) = delete;

  RegistryValueScope(std::string name, DWORD type, const BYTE *data, DWORD size)
      : valueName(std::move(name)) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, kSubPath, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
      return;
    }
    RegSetValueExA(hKey, valueName.c_str(), 0, type, data, size);
    RegCloseKey(hKey);
  }

  ~RegistryValueScope() { Remove(); }

  // Deletes the underlying registry value early, while the scope object
  // (and any provider cache entry keyed on it) stays alive — used to prove
  // that a cached read no longer touches the registry.
  void Remove() const {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kSubPath, 0, KEY_SET_VALUE, &hKey) !=
        ERROR_SUCCESS) {
      return;
    }
    RegDeleteValueA(hKey, valueName.c_str());
    RegCloseKey(hKey);
  }
};

} // namespace

// ---------------------------------------------------------------------------
// GetString — always reads fresh, never cached
// ---------------------------------------------------------------------------

TEST_CASE("GetString returns the default value when the value is missing",
          "[registry]") {
  auto value = RegistryProvider::Instance().GetString(
      kSubPath, "unittest_missing_string", "fallback");
  CHECK(value == "fallback");
}

TEST_CASE("GetString reflects a value change immediately (not cached)",
          "[registry]") {
  RegistryValueScope scope("unittest_latest_key", REG_SZ,
                           reinterpret_cast<const BYTE *>("v1"), 3);

  CHECK(RegistryProvider::Instance().GetString(kSubPath, "unittest_latest_key",
                                               "") == "v1");

  HKEY hKey = nullptr;
  REQUIRE(RegOpenKeyExA(HKEY_LOCAL_MACHINE, kSubPath, 0, KEY_SET_VALUE,
                        &hKey) == ERROR_SUCCESS);
  RegSetValueExA(hKey, "unittest_latest_key", 0, REG_SZ,
                reinterpret_cast<const BYTE *>("v2"), 3);
  RegCloseKey(hKey);

  CHECK(RegistryProvider::Instance().GetString(kSubPath, "unittest_latest_key",
                                               "") == "v2");
}

// ---------------------------------------------------------------------------
// GetProtectedBinary — DPAPI-unprotects and caches
// ---------------------------------------------------------------------------

TEST_CASE("GetProtectedBinary returns empty vector when the value is missing",
          "[registry]") {
  auto value = RegistryProvider::Instance().GetProtectedBinary(
      kSubPath, "unittest_missing_key");
  CHECK(value.empty());
}

TEST_CASE("GetProtectedBinary unprotects the DPAPI-protected key bytes",
          "[registry]") {
  const std::string rawKey(32, '\x42');
  auto protectedBytes = DPAPIProtect(rawKey);
  REQUIRE_FALSE(protectedBytes.empty());

  RegistryValueScope scope("unittest_key_v_decrypt", REG_BINARY,
                           protectedBytes.data(),
                           static_cast<DWORD>(protectedBytes.size()));

  auto keyBytes = RegistryProvider::Instance().GetProtectedBinary(
      kSubPath, "unittest_key_v_decrypt");

  REQUIRE(keyBytes.size() == rawKey.size());
  CHECK(std::equal(keyBytes.begin(), keyBytes.end(), rawKey.begin()));
}

TEST_CASE("GetProtectedBinary caches the result after the registry value is deleted",
          "[registry]") {
  const std::string rawKey(32, '\x7A');
  auto protectedBytes = DPAPIProtect(rawKey);
  REQUIRE_FALSE(protectedBytes.empty());

  RegistryValueScope scope("unittest_key_v_cached", REG_BINARY,
                           protectedBytes.data(),
                           static_cast<DWORD>(protectedBytes.size()));

  auto firstRead = RegistryProvider::Instance().GetProtectedBinary(
      kSubPath, "unittest_key_v_cached");
  REQUIRE(firstRead.size() == rawKey.size());

  // Value no longer exists in the registry — a fresh read would now fail.
  scope.Remove();

  auto secondRead = RegistryProvider::Instance().GetProtectedBinary(
      kSubPath, "unittest_key_v_cached");
  CHECK(secondRead == firstRead);
}
