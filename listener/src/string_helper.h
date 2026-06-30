/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include <string>

inline std::string WideToUtf8(const wchar_t *wide) {
  if (!wide) {
    return "";
  }
  int len =
      WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
  if (len <= 0) {
    return "";
  }
  std::string result(len - 1, '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], len, nullptr, nullptr);
  return result;
}

inline std::wstring Utf8ToWide(const std::string &str) {
  if (str.empty()) {
    return L"";
  }
  int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
  if (len <= 0) {
    return L"";
  }
  std::wstring result(len - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
  return result;
}
