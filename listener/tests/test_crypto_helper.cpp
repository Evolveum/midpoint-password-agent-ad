/* Copyright (C) 2010-2026 Evolveum and contributors
 * Licensed under the EUPL-1.2 or later. */

#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <string>
#include <vector>

#include "../src/crypto/crypto.h"

using namespace Crypto;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

std::array<uint8_t, KEY_BYTES> MakeKey(uint8_t fill = 0x42) {
  std::array<uint8_t, KEY_BYTES> k{};
  k.fill(fill);
  return k;
}

std::array<uint8_t, NONCE_BYTES> MakeNonce(uint8_t fill = 0x01) {
  std::array<uint8_t, NONCE_BYTES> n{};
  n.fill(fill);
  return n;
}

struct EncryptResult {
  std::vector<uint8_t> ciphertext;
  std::array<uint8_t, TAG_BYTES> tag{};
};

EncryptResult Encrypt(const std::array<uint8_t, KEY_BYTES> &key,
                      const std::array<uint8_t, NONCE_BYTES> &nonce,
                      const std::string &plaintext) {
  EncryptResult r;
  r.ciphertext.resize(plaintext.size());
  EncryptGCM(key.data(), nonce.data(),
             reinterpret_cast<const uint8_t *>(plaintext.data()),
             plaintext.size(), r.ciphertext.data(), r.tag.data());
  return r;
}

template <typename Container>
bool AllZero(const Container &c) {
  return std::all_of(c.begin(), c.end(), [](uint8_t b) { return b == 0; });
}

} // namespace

// ---------------------------------------------------------------------------
// GenerateRandom
// ---------------------------------------------------------------------------

TEST_CASE("GenerateRandom returns true and fills the buffer", "[crypto]") {
  std::array<uint8_t, 32> buf{};
  CHECK(GenerateRandom(buf.data(), buf.size()));
  CHECK_FALSE(AllZero(buf));
}

TEST_CASE("GenerateRandom produces different output on successive calls",
          "[crypto]") {
  std::array<uint8_t, NONCE_BYTES> a{}, b{};
  GenerateRandom(a.data(), a.size());
  GenerateRandom(b.data(), b.size());
  CHECK(a != b);
}

// ---------------------------------------------------------------------------
// EncryptGCM
// ---------------------------------------------------------------------------

TEST_CASE("EncryptGCM succeeds with valid inputs", "[crypto]") {
  auto key = MakeKey();
  auto nonce = MakeNonce();
  const std::string plaintext = "hello world";

  std::vector<uint8_t> ciphertext(plaintext.size());
  std::array<uint8_t, TAG_BYTES> tag{};

  bool ok = EncryptGCM(key.data(), nonce.data(),
                       reinterpret_cast<const uint8_t *>(plaintext.data()),
                       plaintext.size(), ciphertext.data(), tag.data());
  CHECK(ok);
}

TEST_CASE("EncryptGCM ciphertext differs from plaintext", "[crypto]") {
  auto r = Encrypt(MakeKey(), MakeNonce(), "sensitive password data");
  const std::string plaintext = "sensitive password data";

  CHECK(std::memcmp(r.ciphertext.data(), plaintext.data(), plaintext.size()) != 0);
}

TEST_CASE("EncryptGCM different nonces produce different ciphertext",
          "[crypto]") {
  auto key = MakeKey();
  auto r1 = Encrypt(key, MakeNonce(0x01), "same plaintext");
  auto r2 = Encrypt(key, MakeNonce(0x02), "same plaintext");

  CHECK(r1.ciphertext != r2.ciphertext);
}

TEST_CASE("EncryptGCM different keys produce different ciphertext",
          "[crypto]") {
  auto nonce = MakeNonce();
  auto r1 = Encrypt(MakeKey(0xAA), nonce, "same plaintext");
  auto r2 = Encrypt(MakeKey(0xBB), nonce, "same plaintext");

  CHECK(r1.ciphertext != r2.ciphertext);
  CHECK(r1.tag != r2.tag);
}

TEST_CASE("EncryptGCM same keys produce same ciphertext", "[crypto]") {
  auto nonce = MakeNonce();
  auto r1 = Encrypt(MakeKey(), nonce, "same plaintext");
  auto r2 = Encrypt(MakeKey(), nonce, "same plaintext");

  CHECK(r1.ciphertext == r2.ciphertext);
  CHECK(r1.tag == r2.tag);
}

TEST_CASE("EncryptGCM different plaintexts produce different tags",
          "[crypto]") {
  auto key = MakeKey();
  auto nonce = MakeNonce();
  auto r1 = Encrypt(key, nonce, "password1");
  auto r2 = Encrypt(key, nonce, "password2");

  CHECK(r1.tag != r2.tag);
}

// ---------------------------------------------------------------------------
// SecureZero
// ---------------------------------------------------------------------------

TEST_CASE("SecureZero zeroes the buffer", "[crypto]") {
  std::array<uint8_t, KEY_BYTES> buf{};
  buf.fill(0xFF);

  SecureZero(buf.data(), buf.size());

  CHECK(AllZero(buf));
}
