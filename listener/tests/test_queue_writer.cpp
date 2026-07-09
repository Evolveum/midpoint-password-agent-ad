/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include <windows.h>
#include <catch2/catch_test_macros.hpp>
#include <string>

#include <nlohmann/json.hpp>

#include "../src/crypto/crypto.h"
#include "../src/queue/queue_writer.h"
#include "QueueTestHelpers.h"

using namespace QueueTestHelpers;

// ---------------------------------------------------------------------------
// Tests — no registry required
// ---------------------------------------------------------------------------

TEST_CASE("FileQueue::Write returns false when not initialized", "[queue]") {
  FileQueue::Init("");
  CHECK_FALSE(FileQueue::Write({"user", "domain.com", "pass"}));
}

TEST_CASE("FileQueue::Init creates queue and staging directories", "[queue]") {
  auto dir = PrepareQueueDir();

  CHECK(GetFileAttributesA(dir.c_str()) != INVALID_FILE_ATTRIBUTES);
  CHECK(GetFileAttributesA((dir + "\\staging").c_str()) !=
        INVALID_FILE_ATTRIBUTES);

  DeleteDirTree(dir);
}

// ---------------------------------------------------------------------------
// Tests — require registry key with DPAPI-protected AES key
// ---------------------------------------------------------------------------

TEST_CASE("FileQueue::Write writes exactly one event file", "[queue]") {
  REQUIRE(SetupTestRegistry());
  auto dir = PrepareQueueDir();

  CHECK(FileQueue::Write({"jdoe", "example.com", "P@ss"}));
  CHECK(ListFiles(dir, ".event").size() == 1);

  DeleteDirTree(dir);
  CleanupTestRegistry();
}

TEST_CASE("FileQueue::Write leaves no staging file behind", "[queue]") {
  REQUIRE(SetupTestRegistry());
  auto dir = PrepareQueueDir();

  FileQueue::Write({"jdoe", "example.com", "P@ss"});

  CHECK(ListFiles(dir + "\\staging", ".*").empty());

  DeleteDirTree(dir);
  CleanupTestRegistry();
}

TEST_CASE("FileQueue::Write event file has JSON structure with encrypted password field",
          "[queue]") {
  REQUIRE(SetupTestRegistry());
  auto dir = PrepareQueueDir();

  FileQueue::Write({"jdoe", "example.com", "secret"});

  auto files = ListFiles(dir, ".event");
  REQUIRE(files.size() == 1);

  auto raw = ReadBinaryFile(files[0]);
  auto json = nlohmann::json::parse(raw.begin(), raw.end());
  CHECK(json["username"] == "jdoe");
  CHECK(json["domain"] == "example.com");

  // password field holds a base64-encoded encrypted blob: nonce(12)|tag(16)|ciphertext(N)
  std::string b64 = json["password"].get<std::string>();
  DWORD decodedLen = 0;
  CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr,
                       &decodedLen, nullptr, nullptr);
  CHECK(decodedLen > Crypto::NONCE_BYTES + Crypto::TAG_BYTES);

  DeleteDirTree(dir);
  CleanupTestRegistry();
}

TEST_CASE("FileQueue::Write handles special characters in credentials",
          "[queue]") {
  REQUIRE(SetupTestRegistry());
  auto dir = PrepareQueueDir();

  CHECK(FileQueue::Write({"user", "domain.com", "p\"a\\ss!@#$%"}));

  CHECK(ListFiles(dir, ".event").size() == 1);

  DeleteDirTree(dir);
  CleanupTestRegistry();
}

TEST_CASE("FileQueue::Write accumulates multiple event files", "[queue]") {
  REQUIRE(SetupTestRegistry());
  auto dir = PrepareQueueDir();

  FileQueue::Write({"user1", "domain.com", "pass1"});
  FileQueue::Write({"user2", "domain.com", "pass2"});
  FileQueue::Write({"user3", "domain.com", "pass3"});

  CHECK(ListFiles(dir, ".event").size() == 3);

  DeleteDirTree(dir);
  CleanupTestRegistry();
}
