/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
namespace Sender.WindowsRegistry
{
    public interface IWindowsRegistryProvider
    {
        string? GetProtectedString(string valueName);
        string? GetString(string valueName);
        string GetRequiredProtectedString(string valueName);
        string GetRequiredString(string valueName);
    }
}
