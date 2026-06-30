/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#include "password_event.h"
#include "../Common.h"
#include "../WindowsRegisterHelpers.h"
#include "../crypto/crypto.h"
#include "../logger/logger.h"
#include "../pch.h"

PasswordEvent::PasswordEvent(const std::string& u, const std::string& d,
                             const std::string& plainPassword)
    : username(u), domain(d) {
  keyVersion =
      GetRegisterValue(ADPS_REG_KEY_CONFIG, REG_VAL_LATEST_KEY_PATH, "");

  auto encryptedKey =
      GetRegisterBinaryValue(ADPS_REG_KEY_CONFIG, keyVersion.c_str());
  auto keyBytes = DPAPIUnprotect(encryptedKey);

  if (keyBytes.size() != Crypto::KEY_BYTES) {
    Logger::FileError(
        "AES key unavailable or wrong size => aborting password encryption");
    return;
  }
  Logger::FileInfo("AES key loaded and unprotected with DPAPI");

  password = Crypto::EncryptToBlob(
      keyBytes, reinterpret_cast<const uint8_t*>(plainPassword.data()),
      plainPassword.size());
}
