/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "PasswordFilter.h"
#include "logger/logger.h"
#include "pch.h"
#include "Common.h"
#include "PasswordFilterHelpers.h"
#include "queue/queue_writer.h"
#include "string_helper.h"
#include <fmt/format.h>
#include <spdlog/spdlog.h>

BOOLEAN NTAPI InitializeChangeNotify(void) {
  return TRUE;
}

BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName,
                             PUNICODE_STRING FullName, PUNICODE_STRING Password,
                             BOOLEAN SetOperation) {
  // This filter does not impose any complexity requirements.
  // Always approve so that we never block a legitimate password change.
  UNREFERENCED_PARAMETER(AccountName);
  UNREFERENCED_PARAMETER(FullName);
  UNREFERENCED_PARAMETER(Password);
  UNREFERENCED_PARAMETER(SetOperation);
  return TRUE;
}

static void HandlePasswordChange(PUNICODE_STRING UserName,
                                 PUNICODE_STRING NewPassword) {
  if (!UserName || !NewPassword) { return; }

  wchar_t *username = DupUnicodeString(UserName);
  wchar_t *password = DupUnicodeString(NewPassword);

  if (username && password) {
    wchar_t domain[256] = {};
    DWORD domainLen = _countof(domain);
    if (!GetComputerNameExW(ComputerNameDnsDomain, domain, &domainLen)) {
      domain[0] = L'\0';
    }

    std::string usernameUtf8 = WideToUtf8(username);
    std::string domainUtf8 = WideToUtf8(domain);

    Logger::FileInfo(fmt::format("PasswordChangeNotify: user={} domain={}", usernameUtf8, domainUtf8));

    PasswordEvent event{usernameUtf8, domainUtf8, WideToUtf8(password)};
    if (!FileQueue::Write(event)) {
      Logger::EventError(L"MidPointPasswordAgentListener: failed to write event to queue.");
    }
  } else {
    Logger::EventError(L"MidPointPasswordAgentListener: memory allocation failed in "
                       L"PasswordChangeNotify.");
  }

  // Zero password from local heap copy before freeing.
  if (password) {
    USHORT pwLen = NewPassword->Length / sizeof(WCHAR);
    SecureZeroMemory(password, (pwLen + 1) * sizeof(wchar_t));
    HeapFree(GetProcessHeap(), 0, password);
  }
  if (username) {
    HeapFree(GetProcessHeap(), 0, username);
  }
}

NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId,
                                    PUNICODE_STRING NewPassword) {
  UNREFERENCED_PARAMETER(RelativeId);

  // Wrap everything in SEH: a crash in this function would crash lsass.exe
  // and trigger an immediate domain controller reboot.
  ADPL_TRY {
    HandlePasswordChange(UserName, NewPassword);
  }
  ADPL_EXCEPT {
    // Never let an exception escape into LSA.
    Logger::EventError(L"MidPointPasswordAgentListener: unhandled exception in "
                       L"PasswordChangeNotify – event dropped.");
  }

  // Always return STATUS_SUCCESS. Returning an error here would cause
  // the password change to fail from the user's perspective.
  return STATUS_SUCCESS;
}
