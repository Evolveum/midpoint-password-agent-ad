/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include <catch2/catch_test_macros.hpp>

#include "../src/Common.h"
#include "../src/config/app_config.h"
#include "ConfigTestHelpers.h"

using namespace ConfigTestHelpers;

// ---------------------------------------------------------------------------
// operator== tests — no registry/file I/O needed
// ---------------------------------------------------------------------------

TEST_CASE("AppConfig operator== - identical instances are equal",
          "[appconfig]") {
  AppConfig a;
  AppConfig b;
  CHECK(a == b);
}

TEST_CASE("AppConfig operator== - different logLevel is not equal",
          "[appconfig]") {
  AppConfig a;
  AppConfig b;
  a.logLevel = spdlog::level::debug;
  b.logLevel = spdlog::level::warn;
  CHECK_FALSE(a == b);
}

TEST_CASE("AppConfig operator== - different logDirPath is not equal",
          "[appconfig]") {
  AppConfig a;
  AppConfig b;
  a.logDirPath = "C:\\logs\\a";
  b.logDirPath = "C:\\logs\\b";
  CHECK_FALSE(a == b);
}

// ---------------------------------------------------------------------------
// JSON parsing tests — requires writing a temp file and registry setup
// ---------------------------------------------------------------------------

TEST_CASE("AppConfig uses default logLevel when JSON file is missing",
          "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_missing");
  RegistryConfigScope scope(rootDir);
  // config file intentionally not written

  AppConfig config;
  CHECK(config.logLevel == spdlog::level::info);
}

TEST_CASE("AppConfig reads LogLevel debug from JSON", "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_debug");
  RegistryConfigScope scope(rootDir);
  WriteJson(rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME,
            R"({"Listener":{"LogLevel":"debug"}})");

  AppConfig config;
  CHECK(config.logLevel == spdlog::level::debug);
}

TEST_CASE("AppConfig reads LogLevel warn from JSON", "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_warn");
  RegistryConfigScope scope(rootDir);
  WriteJson(rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME,
            R"({"Listener":{"LogLevel":"warn"}})");

  AppConfig config;
  CHECK(config.logLevel == spdlog::level::warn);
}

TEST_CASE("AppConfig defaults logLevel to info when key is absent from JSON",
          "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_nokey");
  RegistryConfigScope scope(rootDir);
  WriteJson(rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME,
            R"({"Listener":{}})");

  AppConfig config;
  CHECK(config.logLevel == spdlog::level::info);
}

TEST_CASE("AppConfig does not crash on malformed JSON", "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_malformed");
  RegistryConfigScope scope(rootDir);
  WriteJson(rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME,
            "{ this is not valid json !!!");

  AppConfig config;
  CHECK(config.logLevel == spdlog::level::info);
}

TEST_CASE("AppConfig stores configFilePath from registry", "[appconfig]") {
  auto rootDir = TempRootDir("adps_test_path");
  RegistryConfigScope scope(rootDir);
  WriteJson(rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME, "{}");

  AppConfig config;
  CHECK(config.configFilePath == rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME);
}
