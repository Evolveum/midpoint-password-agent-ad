/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
#pragma once
#include "password_event.h"
#include <nlohmann/json_fwd.hpp>
#include <string>
#include <filesystem>

void to_json(nlohmann::json& j, const PasswordEvent& e);

namespace FileQueue {

void Init(const std::filesystem::path &queueDir);

bool Write(const PasswordEvent& event);

} // namespace FileQueue
