/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include <catch2/catch_test_macros.hpp>

#include "../src/filtering/account_filter.h"
#include "ConfigTestHelpers.h"

using namespace ConfigTestHelpers;

TEST_CASE("AccountFilter EXACT mode denies listed accounts case-insensitively",
          "[accountfilter]") {
  TempFilterFile file("adps_filter_exact_test", "alice\nbob\n");
  AccountFilter filter(file.path, FilteringFileMode::EXACT);

  CHECK_FALSE(filter.IsAllowed("alice"));
  CHECK_FALSE(filter.IsAllowed("bob"));
  CHECK_FALSE(filter.IsAllowed("ALICE"));
  CHECK(filter.IsAllowed("carol"));
}

TEST_CASE("AccountFilter REGEX mode denies accounts ending in 'admin', case-insensitively",
          "[accountfilter]") {
  TempFilterFile file("adps_filter_regex_test", ".*admin$\n");
  AccountFilter filter(file.path, FilteringFileMode::REGEX);

  CHECK_FALSE(filter.IsAllowed("sysadmin"));
  CHECK_FALSE(filter.IsAllowed("admin"));
  CHECK_FALSE(filter.IsAllowed("SYSADMIN"));
  CHECK(filter.IsAllowed("adminx"));
  CHECK(filter.IsAllowed("alice"));
}

TEST_CASE("AccountFilter REGEX mode skips invalid patterns without throwing",
          "[accountfilter]") {
  TempFilterFile file("adps_filter_regex_invalid_test", "[unclosed\n^svc_.*$\n");
  AccountFilter filter(file.path, FilteringFileMode::REGEX);

  CHECK_FALSE(filter.IsAllowed("svc_backup"));
  CHECK(filter.IsAllowed("alice"));
}

TEST_CASE("AccountFilter allows everything when the filtering file is missing",
          "[accountfilter]") {
  auto path = TempRootDir("adps_filter_missing_test") / "does_not_exist.txt";

  AccountFilter filter(path, FilteringFileMode::EXACT);

  CHECK(filter.IsAllowed("alice"));
  CHECK(filter.IsAllowed("anyone"));
}

TEST_CASE("AccountFilter allows everything when the filtering file is empty",
          "[accountfilter]") {
  TempFilterFile file("adps_filter_empty_test", "");
  AccountFilter filter(file.path, FilteringFileMode::EXACT);

  CHECK(filter.IsAllowed("alice"));
}
