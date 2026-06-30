/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct PasswordEvent {
    std::string username;
    std::string domain;
    std::string keyVersion;
    std::vector<uint8_t> password;

    PasswordEvent(const std::string& username, const std::string& domain,
                  const std::string& password);
};
