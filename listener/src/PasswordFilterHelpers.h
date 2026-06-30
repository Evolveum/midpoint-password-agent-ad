/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "pch.h"

/// Copy a UNICODE_STRING into a null-terminated heap buffer.
/// Caller must HeapFree the returned pointer (and SecureZeroMemory it first
/// when it holds a password).
/// Returns nullptr on failure or empty input.
inline wchar_t* DupUnicodeString(PUNICODE_STRING const us) {
  if (!us || !us->Buffer || us->Length == 0) {
    return nullptr;
  }
  USHORT charCount = us->Length / sizeof(WCHAR);
  auto buf = static_cast<wchar_t*>(
    HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
              (charCount + 1) * sizeof(wchar_t)));
  if (!buf) {
    return nullptr;
  }
  memcpy(buf, us->Buffer, us->Length);
  return buf;
}
