/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

namespace Sender.Crypto;

public interface IKeyProvider
{
    byte[] GenerateNewKey();
    void GenerateFirstKey();
    byte[]? GetKey(string keyVersion);
    byte[]? GetLatestKey();
    string? GetLatestKeyVersion();
    void StoreKey(string keyVersion, byte[] rawKey);
    void SetLatestKeyVersion(string keyVersion);
    void DeleteKey(string keyVersion);
    string? IncrementKeyVersion(string version);
    IEnumerable<string> GetAllKeyVersions();
    void SetKeyExpiry(string keyVersion, DateTime expiresAt);
    DateTime? GetKeyExpiry(string keyVersion);
}
