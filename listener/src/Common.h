/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "pch.h"
#include <string>

// Registry key for all MidPointPasswordAgent configuration (HKLM)
constexpr const char *ADPS_REG_CONFIG = "SOFTWARE\\Evolveum\\MidPointPasswordAgent";
constexpr const char *ADPS_REG_KEY_CONFIG =
    "SOFTWARE\\Evolveum\\MidPointPasswordAgent\\Keys";

// Registry value names
constexpr const char *REG_VAL_ROOT_PATH = "RootPath";
constexpr const char *REG_VAL_LOG_PATH = "LogPath";
constexpr const char *REG_VAL_QUEUE_PATH = "QueuePath";
constexpr const char *REG_VAL_CONFIG_PATH = "ConfigPath";
constexpr const char *REG_VAL_KEY_PATH = "Keys";
constexpr const char *REG_VAL_LATEST_KEY_PATH = "LatestKey";

// FileSystem folder and file names
constexpr const char *CONFIG_FILE_NAME = "config.json";
constexpr const char *CONFIG_FOLDER_NAME = "Config";
constexpr const char *QUEUE_FOLDER_NAME = "Queue";
constexpr const char *DATA_FOLDER_NAME = "Data";
constexpr const char *LOGS_FOLDER_NAME = "Logs";
constexpr const char *LOGS_FILE_NAME = "listener.json";
constexpr const wchar_t *STAGING_FOLDER_NAME = L"staging";

// Default paths
constexpr const char *DEFAULT_ROOT_PATH = "C:\\ProgramData\\MidPoint Password Agent for Active Directory";

// Event log source — wide because RegisterEventSourceW requires LPCWSTR
constexpr const wchar_t *SERVICE_NAME = L"MidPointPasswordAgentListener";

// ---------------------------------------------------------------------------
// SEH portability
// MSVC supports native Windows SEH (__try/__except).
// MinGW/GCC does not expose __try/__except syntax, so we fall back to a
// C++ try/catch(...) which catches C++ exceptions but not hardware faults
// (e.g. access violations).  For a cross-compiled development build this
// is acceptable; the production build must use MSVC.
// ---------------------------------------------------------------------------
#ifdef _MSC_VER
#define ADPL_TRY __try
#define ADPL_EXCEPT __except (EXCEPTION_EXECUTE_HANDLER)
#else
#define ADPL_TRY try
#define ADPL_EXCEPT catch (...)
#endif
