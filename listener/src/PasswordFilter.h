/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "pch.h"

#ifdef __cplusplus
extern "C" {
#endif

// The three entry points required by the LSA Password Notification Filter contract.
// All three must be exported by name (see PasswordFilter.def).

BOOLEAN NTAPI InitializeChangeNotify(void);

BOOLEAN NTAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN         SetOperation);

NTSTATUS NTAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG           RelativeId,
    PUNICODE_STRING NewPassword);

#ifdef __cplusplus
}
#endif
