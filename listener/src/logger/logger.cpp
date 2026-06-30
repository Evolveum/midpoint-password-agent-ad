/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "logger.h"
#include "../Common.h"
#include "../WindowsRegisterHelpers.h"
#include <fmt/format.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>

namespace Logger {

void Init(const std::filesystem::path &logDirPath) {
  try {
    auto logPath = logDirPath / LOGS_FILE_NAME;
    auto logger = spdlog::rotating_logger_mt("listener", logPath.string(), MAX_FILE_SIZE, MAX_FILES);
    spdlog::set_default_logger(logger);

    std::string jsonpattern = {"{\"time\": \"%Y-%m-%dT%H:%M:%S.%f%z\", "
                               "\"level\": \"%^%l%$\", \"message\": \"%v\"},"};
    spdlog::set_pattern(jsonpattern);
    spdlog::set_level(spdlog::level::info);
    spdlog::flush_on(spdlog::level::info);

    FileInfo(fmt::format("Initialized logger with log files path {}", logDirPath.string()).c_str());
  } catch (...) {
    EventError(L"MidPointPasswordAgentListener: failed to initialize file logger");
  }
}

void SetLevel(spdlog::level::level_enum level) {
  spdlog::set_level(level);
  spdlog::flush_on(level);
}

void SetMaxFileSize(std::size_t maxFileSize) {
  auto default_logger = spdlog::default_logger();
  auto &sinks = default_logger->sinks();
  auto rotating_sink = std::dynamic_pointer_cast<spdlog::sinks::rotating_file_sink_mt>(
      sinks[0]);

  if (rotating_sink) {
    rotating_sink->set_max_size(maxFileSize);
  }
}

void SetMaxFiles(std::size_t maxFiles) {
  auto default_logger = spdlog::default_logger();
  auto &sinks = default_logger->sinks();
  auto rotating_sink = std::dynamic_pointer_cast<spdlog::sinks::rotating_file_sink_mt>(
      sinks[0]);

  if (rotating_sink) {
    rotating_sink->set_max_files(maxFiles);
  }
}

void Uninit() {
  try {
    spdlog::info("MidPointPasswordAgentListener unloading");
    spdlog::shutdown();
  } catch (...) {
    EventError(L"MidPointPasswordAgentListener: failed to uninitialize file logger");
  }
}

void EventError(LPCWSTR message) {
  HANDLE hEventLog = RegisterEventSourceW(nullptr, SERVICE_NAME);
  if (hEventLog) {
    LPCWSTR strings[] = {message};
    ReportEventW(hEventLog, EVENTLOG_ERROR_TYPE,
                 0,    // category
                 1,    // event id
                 nullptr, // user SID
                 1,    // num strings
                 0,    // raw data size
                 strings, nullptr);
    DeregisterEventSource(hEventLog);
  }
}

void EventInfo(LPCWSTR message) {
  HANDLE hEventLog = RegisterEventSourceW(nullptr, SERVICE_NAME);
  if (hEventLog) {
    LPCWSTR strings[] = {message};
    ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE,
                 0,    // category
                 1,    // event id
                 nullptr, // user SID
                 1,    // num strings
                 0,    // raw data size
                 strings, nullptr);
    DeregisterEventSource(hEventLog);
  }
}

} // namespace Logger
