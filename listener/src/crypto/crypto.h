/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "../Common.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Crypto {

constexpr size_t KEY_BYTES = 32;
constexpr size_t NONCE_BYTES = 12;
constexpr size_t TAG_BYTES = 16;

/// AES-256-GCM encryption using Windows BCrypt.
/// key   – KEY_BYTES bytes
/// nonce – NONCE_BYTES bytes (randomly generated per message)
/// outCiphertext – caller-allocated, same length as plaintext
/// outTag        – caller-allocated, TAG_BYTES bytes
/// Returns true on success.
bool EncryptGCM(const uint8_t *key, const uint8_t *nonce,
                const uint8_t *plaintext, size_t plaintextLen,
                uint8_t *outCiphertext, uint8_t *outTag);

/// Generates a random nonce, encrypts plaintext with AES-256-GCM, zeros the
/// key, and returns a blob of the form: nonce (12) | tag (16) | ciphertext (N).
/// Returns an empty vector on any failure.
std::vector<uint8_t> EncryptToBlob(std::vector<uint8_t> &key,
                                    const uint8_t *plaintext,
                                    size_t plaintextLen);

/// Fill buffer with cryptographically random bytes via BCryptGenRandom.
bool GenerateRandom(uint8_t *buf, size_t len);

/// Guaranteed-not-optimised-away zeroing (wraps SecureZeroMemory).
inline void SecureZero(void *p, size_t n) { SecureZeroMemory(p, n); }

} // namespace Crypto
