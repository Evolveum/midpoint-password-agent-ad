/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32;
using Sender.Configuration;
using Sender.Logger;

namespace Sender.Crypto;

[SupportedOSPlatform("windows")]
public class WindowsKeyProvider(SenderConfigurationProvider configuration, AppLogger appLogger) : IKeyProvider
{
    private readonly Dictionary<string, byte[]> _keyCache = new();

    public byte[] GenerateNewKey()
    {
        var newRawKey = new byte[Constants.Crypto.KeyBytes];
        RandomNumberGenerator.Fill(newRawKey);
        return newRawKey;
    }

    public void GenerateFirstKey()
    {
        var oldKeyVersion = GetLatestKeyVersion();
        if (oldKeyVersion != null && oldKeyVersion.Any())
        {
            appLogger.ToAll("Key already exists, skipping generation");
            return;
        }

        var newKeyVersion = Constants.Crypto.InitialKeyVersion;
        var newRawKey = GenerateNewKey();
        StoreKey(newKeyVersion, newRawKey);
        SetLatestKeyVersion(newKeyVersion);
    }

    public byte[]? GetKey(string keyVersion)
    {
        if (_keyCache.TryGetValue(keyVersion, out var cached))
            return cached;

        using var regKey = Registry.LocalMachine.OpenSubKey(configuration.KeyRegistryPath);
        if (regKey is null)
            return null;

        var protectedBytes = regKey.GetValue(keyVersion) as byte[];
        if (protectedBytes is null)
            return null;

        var key = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        _keyCache[keyVersion] = key;
        return key;
    }

    public byte[]? GetLatestKey()
    {
        var latestKeyVersion = GetLatestKeyVersion();
        if (latestKeyVersion is null)
            return null;

        return GetKey(latestKeyVersion);
    }

    public string? GetLatestKeyVersion()
    {
        using var regKey = Registry.LocalMachine.OpenSubKey(configuration.KeyRegistryPath);
        if (regKey is null)
            return null;

        return regKey.GetValue(configuration.LatestKeyRegistryName) as string;
    }

    public void StoreKey(string keyVersion, byte[] rawKey)
    {
        var protectedKey = ProtectedData.Protect(rawKey, null, DataProtectionScope.LocalMachine);
        using var regKey = Registry.LocalMachine.CreateSubKey(configuration.KeyRegistryPath, writable: true);
        regKey.SetValue(keyVersion, protectedKey, RegistryValueKind.Binary);
        _keyCache[keyVersion] = rawKey;
    }

    public void SetLatestKeyVersion(string keyVersion)
    {
        using var regKey = Registry.LocalMachine.CreateSubKey(configuration.KeyRegistryPath, writable: true);
        regKey.SetValue(configuration.LatestKeyRegistryName, keyVersion, RegistryValueKind.String);
    }

    public void DeleteKey(string keyVersion)
    {
        using var regKey = Registry.LocalMachine.OpenSubKey(configuration.KeyRegistryPath, writable: true);
        regKey?.DeleteValue(keyVersion, throwOnMissingValue: false);
        regKey?.DeleteValue($"{keyVersion}_expires", throwOnMissingValue: false);

        if (keyVersion == GetLatestKeyVersion())
        {
            regKey?.SetValue(configuration.LatestKeyRegistryName, new byte[0], RegistryValueKind.None);
        }

        _keyCache.Remove(keyVersion);
    }

    public string? IncrementKeyVersion(string version)
    {
        if (version.StartsWith('v') && int.TryParse(version[1..], out var n))
            return $"v{n + 1}";
        return null;
    }

    public IEnumerable<string> GetAllKeyVersions()
    {
        using var regKey = Registry.LocalMachine.OpenSubKey(configuration.KeyRegistryPath);

        if (regKey is null)
            return [];

        return regKey.GetValueNames()
            .Where(name => name.StartsWith('v') && int.TryParse(name[1..], out _))
            .ToList();
    }

    public void SetKeyExpiry(string keyVersion, DateTime expiresAt)
    {
        using var regKey = Registry.LocalMachine.CreateSubKey(configuration.KeyRegistryPath, writable: true);
        regKey.SetValue($"{keyVersion}_expires", expiresAt.ToString("O"), RegistryValueKind.String);
    }

    public DateTime? GetKeyExpiry(string keyVersion)
    {
        using var regKey = Registry.LocalMachine.OpenSubKey(configuration.KeyRegistryPath);
        if (regKey?.GetValue($"{keyVersion}_expires") is not string value) return null;
        return DateTime.TryParse(value, new CultureInfo("sk-SK"), DateTimeStyles.RoundtripKind, out var dt) ? dt : null;
    }
}
