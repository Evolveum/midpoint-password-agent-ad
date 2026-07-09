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
#include "../src/filtering/account_filter.h"
#include "ConfigTestHelpers.h"
#include "QueueTestHelpers.h"

using namespace ConfigTestHelpers;
using namespace QueueTestHelpers;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a UNICODE_STRING from a mutable wide string. The Length field holds
/// the byte count of the characters (not counting the null terminator), which
/// matches how LSA populates the struct. `buf` must outlive the returned
/// UNICODE_STRING since Buffer just points into it.
static UNICODE_STRING MakeUnicodeString(std::wstring& buf) {
    UNICODE_STRING us;
    us.Buffer        = buf.data();
    us.Length        = static_cast<USHORT>(buf.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    return us;
}

static NTSTATUS InvokePasswordChangeNotify(std::wstring& user, std::wstring& password) {
    UNICODE_STRING usUser = MakeUnicodeString(user);
    UNICODE_STRING usPw   = MakeUnicodeString(password);
    return PasswordChangeNotify(&usUser, 1001, &usPw);
}

namespace {

// Owns a DupUnicodeString() result and frees it on scope exit.
struct HeapWString {
    wchar_t* ptr;

    explicit HeapWString(wchar_t* p) : ptr(p) {}
    HeapWString(const HeapWString&) = delete;
    HeapWString& operator=(const HeapWString&) = delete;

    ~HeapWString() {
        if (ptr) {
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }

    wchar_t* get() const { return ptr; }
};

} // namespace

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
    std::wstring buf = L"hello";
    UNICODE_STRING us{0, static_cast<USHORT>((buf.size() + 1) * sizeof(wchar_t)), buf.data()};
    CHECK(static_cast<void*>(DupUnicodeString(&us)) == nullptr);
}

TEST_CASE("DupUnicodeString - copies string content correctly", "[dup]") {
    std::wstring src = L"TestUser";
    UNICODE_STRING us = MakeUnicodeString(src);

    HeapWString copy(DupUnicodeString(&us));
    REQUIRE(copy.get() != nullptr);
    CHECK(std::wstring(copy.get()) == L"TestUser");
    CHECK(static_cast<void*>(copy.get()) != static_cast<void*>(src.data())); // must be a distinct allocation
}

TEST_CASE("DupUnicodeString - result is null-terminated", "[dup]") {
    std::wstring src = L"Abc";
    UNICODE_STRING us = MakeUnicodeString(src);

    HeapWString copy(DupUnicodeString(&us));
    REQUIRE(copy.get() != nullptr);
    CHECK(copy.get()[src.size()] == L'\0');
}

TEST_CASE("DupUnicodeString - handles single character", "[dup]") {
    std::wstring src = L"X";
    UNICODE_STRING us = MakeUnicodeString(src);

    HeapWString copy(DupUnicodeString(&us));
    REQUIRE(copy.get() != nullptr);
    CHECK(copy.get()[0] == L'X');
    CHECK(copy.get()[1] == L'\0');
}

TEST_CASE("DupUnicodeString - handles string with special characters", "[dup]") {
    std::wstring src = L"user@domain.com";
    UNICODE_STRING us = MakeUnicodeString(src);

    HeapWString copy(DupUnicodeString(&us));
    REQUIRE(copy.get() != nullptr);
    CHECK(std::wstring(copy.get()) == L"user@domain.com");
}

// ---------------------------------------------------------------------------
// LSA entry points
// ---------------------------------------------------------------------------

TEST_CASE("InitializeChangeNotify returns TRUE", "[lsa]") {
    CHECK(InitializeChangeNotify() == TRUE);
}

TEST_CASE("PasswordFilter always returns TRUE (never blocks)", "[lsa]") {
    std::wstring acct = L"jdoe";
    std::wstring full = L"John Doe";
    std::wstring pw   = L"P@ssw0rd!";

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
    std::wstring user = L"jdoe";
    std::wstring pw   = L"NewP@ss1!";

    CHECK(InvokePasswordChangeNotify(user, pw) == STATUS_SUCCESS);
}

TEST_CASE("PasswordChangeNotify returns STATUS_SUCCESS with null inputs", "[lsa]") {
    CHECK(PasswordChangeNotify(nullptr, 0, nullptr) == STATUS_SUCCESS);
}

TEST_CASE("PasswordChangeNotify returns STATUS_SUCCESS with null password", "[lsa]") {
    std::wstring user = L"jdoe";
    UNICODE_STRING usUser = MakeUnicodeString(user);

    CHECK(PasswordChangeNotify(&usUser, 42, nullptr) == STATUS_SUCCESS);
}

// ---------------------------------------------------------------------------
// Integration: AccountFiltering gates whether PasswordChangeNotify writes to
// the queue. AccountFiltering holds process-wide state, so each test resets
// it to fail-open on the way in and out to stay isolated from other tests.
// ---------------------------------------------------------------------------

namespace {

struct AccountFilteringResetScope {
    AccountFilteringResetScope() { AccountFiltering::Reload("", FilteringFileMode::EXACT); }
    ~AccountFilteringResetScope() { AccountFiltering::Reload("", FilteringFileMode::EXACT); }
};

// Owns a temp queue directory plus the DPAPI registry key FileQueue::Write
// needs, and tears both down on scope exit.
struct QueueScope {
    std::string dir = PrepareQueueDir();

    ~QueueScope() {
        DeleteDirTree(dir);
        CleanupTestRegistry();
    }
};

} // namespace

TEST_CASE("PasswordChangeNotify skips queue write when AccountFiltering denies the account",
          "[lsa][accountfilter]") {
    AccountFilteringResetScope resetScope;
    REQUIRE(SetupTestRegistry());
    QueueScope queue;

    TempFilterFile filterFile("adps_pwfilter_deny_test", "jdoe\n");
    AccountFiltering::Reload(filterFile.path, FilteringFileMode::EXACT);

    std::wstring user = L"jdoe";
    std::wstring pw   = L"NewP@ss1!";

    CHECK(InvokePasswordChangeNotify(user, pw) == STATUS_SUCCESS);
    CHECK(ListFiles(queue.dir, ".event").empty());
}

TEST_CASE("PasswordChangeNotify writes to queue when AccountFiltering allows the account",
          "[lsa][accountfilter]") {
    AccountFilteringResetScope resetScope;
    REQUIRE(SetupTestRegistry());
    QueueScope queue;

    TempFilterFile filterFile("adps_pwfilter_allow_test", "someoneelse\n");
    AccountFiltering::Reload(filterFile.path, FilteringFileMode::EXACT);

    std::wstring user = L"jdoe";
    std::wstring pw   = L"NewP@ss1!";

    CHECK(InvokePasswordChangeNotify(user, pw) == STATUS_SUCCESS);
    CHECK(ListFiles(queue.dir, ".event").size() == 1);
}
