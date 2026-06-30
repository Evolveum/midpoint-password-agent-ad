/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Security.Cryptography;
using Sender.Crypto;
using Sender.Logger;

namespace Sender.MultiPlatform;

public class InMemoryKeyProvider(AppLogger appLogger) : IKeyProvider
{
    private readonly Dictionary<string, DateTime> _expiries = new();
    private readonly Dictionary<string, byte[]> _keys = new();

    private string? _latestKey = null;

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
        appLogger.ToAll(string.Format("Created first key with version {0}", newKeyVersion));
    }

    public byte[]? GetKey(string keyVersion)
        => _keys.TryGetValue(keyVersion, out var key) ? key : null;

    public byte[]? GetLatestKey()
    {
        return _latestKey is not null ? _keys[_latestKey] : null;
    }

    public string? GetLatestKeyVersion()
    {
        return _latestKey;
    }

    public void StoreKey(string keyVersion, byte[] rawKey)
    {
        _keys[keyVersion] = rawKey;
    }

    public void SetLatestKeyVersion(string? keyVersion)
    {
        _latestKey = keyVersion;
    }

    public void DeleteKey(string keyVersion)
    {
        _keys.Remove(keyVersion);
        _expiries.Remove(keyVersion);
        if (keyVersion == _latestKey)
            _latestKey = null;
    }

    public string? IncrementKeyVersion(string version)
    {
        if (version.StartsWith('v') && int.TryParse(version[1..], out var n))
            return $"v{n + 1}";
        return null;
    }

    public IEnumerable<string> GetAllKeyVersions() => _keys.Keys.ToList();

    public void SetKeyExpiry(string keyVersion, DateTime expiresAt) => _expiries[keyVersion] = expiresAt;

    public DateTime? GetKeyExpiry(string keyVersion) =>
        _expiries.TryGetValue(keyVersion, out var dt) ? dt : null;
}
