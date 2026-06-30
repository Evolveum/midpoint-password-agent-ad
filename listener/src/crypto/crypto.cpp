/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "crypto.h"
#include "../pch.h"
#include <bcrypt.h>

namespace Crypto {

bool EncryptGCM(const uint8_t *key, const uint8_t *nonce,
                const uint8_t *plaintext, size_t plaintextLen,
                uint8_t *outCiphertext, uint8_t *outTag) {
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_KEY_HANDLE hKey = nullptr;

  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
  if (!BCRYPT_SUCCESS(status)) {
    return false;
  }

  status = BCryptSetProperty(
      hAlg, BCRYPT_CHAINING_MODE,
      reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (!BCRYPT_SUCCESS(status)) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return false;
  }

  status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                      const_cast<PUCHAR>(key),
                                      static_cast<ULONG>(KEY_BYTES), 0);
  if (!BCRYPT_SUCCESS(status)) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return false;
  }

  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
  BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
  authInfo.pbNonce = const_cast<PUCHAR>(nonce);
  authInfo.cbNonce = static_cast<ULONG>(NONCE_BYTES);
  authInfo.pbTag = outTag;
  authInfo.cbTag = static_cast<ULONG>(TAG_BYTES);

  ULONG bytesEncrypted = 0;
  status = BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext),
                         static_cast<ULONG>(plaintextLen), &authInfo, nullptr,
                         0, outCiphertext, static_cast<ULONG>(plaintextLen),
                         &bytesEncrypted, 0);

  BCryptDestroyKey(hKey);
  BCryptCloseAlgorithmProvider(hAlg, 0);

  return BCRYPT_SUCCESS(status) &&
         bytesEncrypted == static_cast<ULONG>(plaintextLen);
}

std::vector<uint8_t> EncryptToBlob(std::vector<uint8_t> &key,
                                    const uint8_t *plaintext,
                                    size_t plaintextLen) {
  std::vector<uint8_t> nonce(NONCE_BYTES);
  if (!GenerateRandom(nonce.data(), nonce.size())) {
    SecureZero(key.data(), key.size());
    return {};
  }

  std::vector<uint8_t> ciphertext(plaintextLen);
  std::vector<uint8_t> tag(TAG_BYTES);
  bool ok = EncryptGCM(key.data(), nonce.data(), plaintext, plaintextLen,
                       ciphertext.data(), tag.data());
  SecureZero(key.data(), key.size());

  if (!ok) {
    return {};
  }

  std::vector<uint8_t> blob;
  blob.reserve(NONCE_BYTES + TAG_BYTES + plaintextLen);
  blob.insert(blob.end(), nonce.begin(), nonce.end());
  blob.insert(blob.end(), tag.begin(), tag.end());
  blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
  return blob;
}

bool GenerateRandom(uint8_t *buf, size_t len) {
  NTSTATUS status =
      BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(buf),
                      static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return BCRYPT_SUCCESS(status);
}

} // namespace Crypto
