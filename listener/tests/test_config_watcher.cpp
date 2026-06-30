/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include <atomic>
#include <catch2/catch_test_macros.hpp>

#include "../src/Common.h"
#include "../src/config/app_config.h"
#include "../src/config/config_watcher.h"
#include "ConfigTestHelpers.h"

using namespace ConfigTestHelpers;

namespace {

bool WaitFor(const std::atomic<bool> &flag, DWORD timeoutMs = 3000) {
  DWORD start = GetTickCount();
  while (!flag && (GetTickCount() - start) < timeoutMs) {
    Sleep(100);
  }
  return flag.load();
}

} // namespace

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("ConfigWatcher fires callback when LogLevel changes",
          "[configwatcher]") {
  auto rootDir = TempRootDir("adps_watcher_test");
  auto configFile = rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;
  RegistryConfigScope scope(rootDir);
  WriteJson(configFile, R"({"Listener":{"LogLevel":"info"}})");

  AppConfig initial;
  REQUIRE(initial.configFilePath == configFile);

  std::atomic<bool> called{false};
  spdlog::level::level_enum received = spdlog::level::info;

  ConfigWatcher watcher([&called, &received](const AppConfig &cfg) {
    received = cfg.logLevel;
    called = true;
  });
  watcher.Start(initial);

  Sleep(300); // let the watcher thread settle and capture initial write time

  WriteJson(configFile, R"({"Listener":{"LogLevel":"debug"}})");

  bool fired = WaitFor(called);

  CHECK(fired);
  CHECK(received == spdlog::level::debug);
}

TEST_CASE("ConfigWatcher does not fire callback when LogLevel is unchanged",
          "[configwatcher]") {
  auto rootDir = TempRootDir("adps_watcher_nochange_test");
  auto configFile = rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;
  RegistryConfigScope scope(rootDir);
  WriteJson(configFile, R"({"Listener":{"LogLevel":"warn"}})");

  AppConfig initial;
  REQUIRE(initial.configFilePath == configFile);

  std::atomic<bool> called{false};

  ConfigWatcher watcher([&called](const AppConfig &) { called = true; });
  watcher.Start(initial);

  Sleep(300);

  // Rewrite exact same content — file timestamp changes but config is identical
  WriteJson(configFile, R"({"Listener":{"LogLevel":"warn"}})");

  Sleep(2000); // wait long enough that a spurious callback would have arrived

  CHECK_FALSE(called);
}

TEST_CASE("ConfigWatcher fires callback when LogFileSizeLimitBytes changes",
          "[configwatcher]") {
  auto rootDir = TempRootDir("adps_watcher_maxsize_test");
  auto configFile = rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;
  RegistryConfigScope scope(rootDir);
  WriteJson(configFile, R"({"Listener":{"LogFileSizeLimitBytes":1024}})");

  AppConfig initial;
  REQUIRE(initial.configFilePath == configFile);
  CHECK(initial.logMaxFileSize == 1024);

  std::atomic<bool> called{false};
  std::size_t received = 1024;

  ConfigWatcher watcher([&called, &received](const AppConfig &cfg) {
    received = cfg.logMaxFileSize;
    called = true;
  });
  watcher.Start(initial);

  Sleep(300); // let the watcher thread settle and capture initial write time

  WriteJson(configFile, R"({"Listener":{"LogFileSizeLimitBytes":2048}})");

  bool fired = WaitFor(called);

  CHECK(fired);
  CHECK(received == 2048);
}

TEST_CASE("ConfigWatcher fires callback when LogRetainedFileCountLimit changes",
          "[configwatcher]") {
  auto rootDir = TempRootDir("adps_watcher_maxfiles_test");
  auto configFile = rootDir / CONFIG_FOLDER_NAME / CONFIG_FILE_NAME;
  RegistryConfigScope scope(rootDir);
  WriteJson(configFile, R"({"Listener":{"LogRetainedFileCountLimit":3}})");

  AppConfig initial;
  REQUIRE(initial.configFilePath == configFile);
  CHECK(initial.logMaxFiles == 3);

  std::atomic<bool> called{false};
  std::size_t received = 3;

  ConfigWatcher watcher([&called, &received](const AppConfig &cfg) {
    received = cfg.logMaxFiles;
    called = true;
  });
  watcher.Start(initial);

  Sleep(300); // let the watcher thread settle and capture initial write time

  WriteJson(configFile, R"({"Listener":{"LogRetainedFileCountLimit":5}})");

  bool fired = WaitFor(called);

  CHECK(fired);
  CHECK(received == 5);
}
