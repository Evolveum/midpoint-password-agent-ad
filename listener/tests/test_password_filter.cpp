/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
// Tests for the listener password filter.
//
// Note: PasswordChangeNotify attempts to write to the Windows Application
// Event Log. Tests will still pass without admin rights because the function
// always returns STATUS_SUCCESS regardless of logging outcome.

#include <catch2/catch_test_macros.hpp>
#include <string>

#include "../src/PasswordFilter.h"
#include "../src/PasswordFilterHelpers.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a UNICODE_STRING from a wide-string literal. The Length field holds
/// the byte count of the characters (not counting the null terminator), which
/// matches how LSA populates the struct.
static UNICODE_STRING MakeUnicodeString(wchar_t* buf) {
    UNICODE_STRING us;
    us.Buffer        = buf;
    us.Length        = static_cast<USHORT>(wcslen(buf) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    return us;
}

// ---------------------------------------------------------------------------
// DupUnicodeString
// ---------------------------------------------------------------------------

TEST_CASE("DupUnicodeString - null pointer returns nullptr", "[dup]") {
    CHECK(static_cast<void*>(DupUnicodeString(nullptr)) == nullptr);
}

TEST_CASE("DupUnicodeString - null Buffer returns nullptr", "[dup]") {
    UNICODE_STRING us{0, 0, nullptr};
    CHECK(static_cast<void*>(DupUnicodeString(&us)) == nullptr);
}

TEST_CASE("DupUnicodeString - zero Length returns nullptr", "[dup]") {
    wchar_t buf[] = L"hello";
    UNICODE_STRING us{0, static_cast<USHORT>(sizeof(buf)), buf};
    CHECK(static_cast<void*>(DupUnicodeString(&us)) == nullptr);
}

TEST_CASE("DupUnicodeString - copies string content correctly", "[dup]") {
    wchar_t src[] = L"TestUser";
    UNICODE_STRING us = MakeUnicodeString(src);

    wchar_t* copy = DupUnicodeString(&us);
    REQUIRE(static_cast<void*>(copy) != nullptr);
    CHECK(std::wstring(copy) == L"TestUser");
    CHECK(static_cast<void*>(copy) != static_cast<void*>(src)); // must be a distinct allocation

    HeapFree(GetProcessHeap(), 0, copy);
}

TEST_CASE("DupUnicodeString - result is null-terminated", "[dup]") {
    wchar_t src[] = L"Abc";
    UNICODE_STRING us = MakeUnicodeString(src);

    wchar_t* copy = DupUnicodeString(&us);
    REQUIRE(static_cast<void*>(copy) != nullptr);
    CHECK(copy[wcslen(src)] == L'\0');

    HeapFree(GetProcessHeap(), 0, copy);
}

TEST_CASE("DupUnicodeString - handles single character", "[dup]") {
    wchar_t src[] = L"X";
    UNICODE_STRING us = MakeUnicodeString(src);

    wchar_t* copy = DupUnicodeString(&us);
    REQUIRE(static_cast<void*>(copy) != nullptr);
    CHECK(copy[0] == L'X');
    CHECK(copy[1] == L'\0');

    HeapFree(GetProcessHeap(), 0, copy);
}

TEST_CASE("DupUnicodeString - handles string with special characters", "[dup]") {
    wchar_t src[] = L"user@domain.com";
    UNICODE_STRING us = MakeUnicodeString(src);

    wchar_t* copy = DupUnicodeString(&us);
    REQUIRE(static_cast<void*>(copy) != nullptr);
    CHECK(std::wstring(copy) == L"user@domain.com");

    HeapFree(GetProcessHeap(), 0, copy);
}

// ---------------------------------------------------------------------------
// LSA entry points
// ---------------------------------------------------------------------------

TEST_CASE("InitializeChangeNotify returns TRUE", "[lsa]") {
    CHECK(InitializeChangeNotify() == TRUE);
}

TEST_CASE("PasswordFilter always returns TRUE (never blocks)", "[lsa]") {
    wchar_t acct[] = L"jdoe";
    wchar_t full[] = L"John Doe";
    wchar_t pw[]   = L"P@ssw0rd!";

    UNICODE_STRING usAcct = MakeUnicodeString(acct);
    UNICODE_STRING usFull = MakeUnicodeString(full);
    UNICODE_STRING usPw   = MakeUnicodeString(pw);

    CHECK(PasswordFilter(&usAcct, &usFull, &usPw, TRUE)  == TRUE);
    CHECK(PasswordFilter(&usAcct, &usFull, &usPw, FALSE) == TRUE);
}

TEST_CASE("PasswordFilter returns TRUE for null inputs", "[lsa]") {
    CHECK(PasswordFilter(nullptr, nullptr, nullptr, FALSE) == TRUE);
}

TEST_CASE("PasswordChangeNotify returns STATUS_SUCCESS with valid input", "[lsa]") {
    wchar_t user[] = L"jdoe";
    wchar_t pw[]   = L"NewP@ss1!";

    UNICODE_STRING usUser = MakeUnicodeString(user);
    UNICODE_STRING usPw   = MakeUnicodeString(pw);

    NTSTATUS result = PasswordChangeNotify(&usUser, 1001, &usPw);
    CHECK(result == STATUS_SUCCESS);
}

TEST_CASE("PasswordChangeNotify returns STATUS_SUCCESS with null inputs", "[lsa]") {
    CHECK(PasswordChangeNotify(nullptr, 0, nullptr) == STATUS_SUCCESS);
}

TEST_CASE("PasswordChangeNotify returns STATUS_SUCCESS with null password", "[lsa]") {
    wchar_t user[] = L"jdoe";
    UNICODE_STRING usUser = MakeUnicodeString(user);

    CHECK(PasswordChangeNotify(&usUser, 42, nullptr) == STATUS_SUCCESS);
}
