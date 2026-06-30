/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using Sender.Exceptions;

namespace Sender.WindowsRegistry
{
    [SupportedOSPlatform("windows")]
    public class WindowsRegistryProvider() : IWindowsRegistryProvider
    {
        public string? GetString(string valueName)
        {
            var value = Registry.GetValue(Constants.Registry.FullPath, valueName, null) as string;
            return string.IsNullOrEmpty(value) ? null : value;
        }

        public string GetRequiredString(string valueName)
            => GetString(valueName) ?? throw new MissingRegistryValueException(valueName);

        public string? GetProtectedString(string valueName)
        {
            using var key = Registry.LocalMachine.OpenSubKey(Constants.Registry.SubKeyPath);
            if (key?.GetValue(valueName) is not byte[] protectedBytes) return null;
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine));
        }

        public string GetRequiredProtectedString(string valueName)
            => GetProtectedString(valueName) ?? throw new MissingRegistryValueException(valueName);
    }
}
