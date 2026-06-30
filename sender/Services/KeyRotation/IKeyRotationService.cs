/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

namespace Sender.KeyRotation;

public interface IKeyRotationService
{
    Task CleanupExpiredKeysAsync();
    Task RotateAsync();
}
