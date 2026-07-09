/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "file_watcher.h"
#include "../logger/logger.h"
#include "../pch.h"
#include <fmt/format.h>

FileWatcher::FileWatcher(std::filesystem::path filePath, std::function<void()> onChanged)
    : _filePath(std::move(filePath)), _onChanged(std::move(onChanged)) {}

FileWatcher::~FileWatcher() { Stop(); }

void FileWatcher::Start() {
  _thread = std::thread(&FileWatcher::WatchLoop, this);
}

void FileWatcher::Stop() {
  _stop = true;
  if (_thread.joinable()) {
    _thread.join();
  }
}

void FileWatcher::WatchLoop() const {
  std::string dirString = _filePath.parent_path().string();
  std::string fileString = _filePath.string();

  Logger::FileInfo(fmt::format("FileWatcher: watching directory: {}", dirString));
  Logger::FileInfo(fmt::format("FileWatcher: watching file: {}", fileString));

  HANDLE hChange = FindFirstChangeNotificationA(
      dirString.c_str(), FALSE,
      FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
  if (hChange == INVALID_HANDLE_VALUE) {
    Logger::FileError(fmt::format(
        "FileWatcher: FindFirstChangeNotificationA failed, error: {}",
        GetLastError()));
    return;
  }

  FILETIME lastWriteTime = {};
  if (WIN32_FILE_ATTRIBUTE_DATA fileInfo; GetFileAttributesExA(
          fileString.c_str(), GetFileExInfoStandard, &fileInfo)) {
    lastWriteTime = fileInfo.ftLastWriteTime;
    Logger::FileInfo("FileWatcher: initial file write time captured");
  } else {
    Logger::FileInfo("FileWatcher: file does not exist yet, will detect creation");
  }

  while (!_stop) {
    DWORD wait = WaitForSingleObject(hChange, 1000);

    if (_stop) {
      break;
    }

    if (wait != WAIT_OBJECT_0) {
      continue;
    }

    Logger::FileInfo("FileWatcher: directory change notification received");

    if (WIN32_FILE_ATTRIBUTE_DATA newInfo;
        GetFileAttributesExA(fileString.c_str(), GetFileExInfoStandard, &newInfo) &&
        CompareFileTime(&newInfo.ftLastWriteTime, &lastWriteTime) != 0) {
      lastWriteTime = newInfo.ftLastWriteTime;
      Logger::FileInfo("FileWatcher: file write time changed, notifying");
      _onChanged();
    } else {
      Logger::FileInfo(
          "FileWatcher: directory changed but file write time unchanged, ignoring");
    }

    FindNextChangeNotification(hChange);
  }

  Logger::FileInfo("FileWatcher: watch loop stopped");
  FindCloseChangeNotification(hChange);
}
