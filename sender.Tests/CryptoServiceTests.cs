/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Sender.Configuration;
using Sender.Crypto;
using Sender.Logger;
using Sender.MultiPlatform;
using Sender.Queue;

namespace Sender.Tests;

public class CryptoServiceTests : IDisposable
{
    private readonly CryptoService _cryptoService;
    private readonly IKeyProvider _keyProvider;
    private readonly byte[] _aesKey;
    private readonly SenderConfigurationProvider _configurationProvider;

    private const string TestKeyVersion = "v1";

    public CryptoServiceTests()
    {
        var _queueDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_queueDir);

        _aesKey = new byte[32];
        RandomNumberGenerator.Fill(_aesKey);

        _configurationProvider = new SenderConfigurationProvider(new SenderConfiguration
        {
            QueueDirectory = _queueDir,
            PollInterval = TimeSpan.FromMilliseconds(10),
            KeyRegistryPath = $@"SOFTWARE\Evolveum\MidPointPasswordAgent\Keys\Tests\{Guid.NewGuid():N}"
        }
        );

        SetupKeyRegistries();

        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        if (OperatingSystem.IsWindows())
        {
            _keyProvider = new WindowsKeyProvider(_configurationProvider, appLogger);
        }
        else
        {
            var inMemoryKeyProvider = new InMemoryKeyProvider(appLogger);
            inMemoryKeyProvider.StoreKey(TestKeyVersion, _aesKey);
            _keyProvider = inMemoryKeyProvider;
        }

        _cryptoService = new CryptoService(appLogger, _keyProvider);
    }

    public void Dispose()
    {
        if (Directory.Exists(_configurationProvider.QueueDirectory))
            Directory.Delete(_configurationProvider.QueueDirectory, recursive: true);

        CleanupRegistry();
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private void SetupKeyRegistries()
    {
        if (OperatingSystem.IsWindows())
        {
            var protectedKey = ProtectedData.Protect(_aesKey, null, DataProtectionScope.LocalMachine);
            using var key = Registry.LocalMachine.CreateSubKey(_configurationProvider.KeyRegistryPath, writable: true);
            key.SetValue(TestKeyVersion, protectedKey, RegistryValueKind.Binary);
            key.SetValue(_configurationProvider.LatestKeyRegistryName, TestKeyVersion, RegistryValueKind.String);
        }
    }

    private void CleanupRegistry()
    {
        if (OperatingSystem.IsWindows())
            Registry.LocalMachine.DeleteSubKeyTree(_configurationProvider.KeyRegistryPath, throwOnMissingSubKey: false);
    }

    private PasswordChangeEvent CreateEncryptedEvent(string password, string keyVersion = TestKeyVersion)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(password);
        var nonce = new byte[12];
        var tag = new byte[16];
        var ciphertext = new byte[plaintextBytes.Length];

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_aesKey, tagSizeInBytes: 16);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        var blob = nonce.Concat(tag).Concat(ciphertext).ToArray();

        return new PasswordChangeEvent("testuser", "example.com", Convert.ToBase64String(blob))
        {
            FilePath = $"/tmp/test_{keyVersion}.event"
        };
    }

    // ---------------------------------------------------------------------------
    // DecryptPassword tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void DecryptEventFile_ReturnsCorrectPayload()
    {
        var changeEvent = CreateEncryptedEvent("secret");

        var result = _cryptoService.DecryptPassword(changeEvent);

        Assert.Equal("secret", result.Password);
    }

    [Fact]
    public void DecryptEventFile_ReturnsNullWhenBlobTooSmall()
    {
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", Convert.ToBase64String(new byte[5]))
        {
            FilePath = $"/tmp/test_{TestKeyVersion}.event"
        };

        Assert.ThrowsAny<Exception>(() => _cryptoService.DecryptPassword(changeEvent));
    }

    [Fact]
    public void DecryptEventFile_ReturnsNullWhenKeyVersionNotFound()
    {
        var changeEvent = CreateEncryptedEvent("payload", keyVersion: "nonexistent-key");

        Assert.ThrowsAny<Exception>(() => _cryptoService.DecryptPassword(changeEvent));
    }

    [Fact]
    public void DecryptEventFile_ReturnsNullWhenBlobIsCorrupted()
    {
        var changeEvent = CreateEncryptedEvent("payload");
        var blob = Convert.FromBase64String(changeEvent.Password);
        blob[28] ^= 0xFF;
        changeEvent.Password = Convert.ToBase64String(blob);

        Assert.ThrowsAny<Exception>(() => _cryptoService.DecryptPassword(changeEvent));
    }

    [Fact]
    public void DecryptEventFile_HandlesSpecialCharactersInPayload()
    {
        var changeEvent = CreateEncryptedEvent(@"p@$$w0rd!\n");

        var result = _cryptoService.DecryptPassword(changeEvent);

        Assert.Equal(@"p@$$w0rd!\n", result.Password);
    }

    // ---------------------------------------------------------------------------
    // EncryptPassword tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void EncryptPassword_PasswordIsReplacedWithBase64Blob()
    {
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", "secret");

        var result = _cryptoService.EncryptPassword(changeEvent, TestKeyVersion);

        var blob = Convert.FromBase64String(result.Password);
        Assert.True(blob.Length > Constants.Crypto.NonceSize + Constants.Crypto.TagSize);
    }

    [Fact]
    public void EncryptPassword_EncryptedValueDiffersFromPlaintext()
    {
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", "secret");

        var result = _cryptoService.EncryptPassword(changeEvent, TestKeyVersion);

        Assert.NotEqual("secret", result.Password);
    }

    [Fact]
    public void EncryptPassword_RoundTrip_RecovesOriginalPassword()
    {
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", "secret");

        var encrypted = _cryptoService.EncryptPassword(changeEvent, TestKeyVersion);
        encrypted.FilePath = $"/tmp/test_{TestKeyVersion}.event";
        var decrypted = _cryptoService.DecryptPassword(encrypted);

        Assert.Equal("secret", decrypted.Password);
    }

    [Fact]
    public void EncryptPassword_TwoCallsProduceDifferentCiphertext()
    {
        var first = _cryptoService.EncryptPassword(new PasswordChangeEvent("testuser", "example.com", "secret"), TestKeyVersion);
        var second = _cryptoService.EncryptPassword(new PasswordChangeEvent("testuser", "example.com", "secret"), TestKeyVersion);

        Assert.NotEqual(first.Password, second.Password);
    }

    [Fact]
    public void EncryptPassword_ThrowsWhenKeyVersionNotFound()
    {
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", "secret");

        Assert.ThrowsAny<Exception>(() => _cryptoService.EncryptPassword(changeEvent, "nonexistent-key"));
    }

    [Fact]
    public void EncryptPassword_ThrowsWhenNoLatestKeyVersion()
    {
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var emptyProvider = new InMemoryKeyProvider(appLogger);
        var cryptoService = new CryptoService(appLogger, emptyProvider);
        var changeEvent = new PasswordChangeEvent("testuser", "example.com", "secret");

        Assert.ThrowsAny<Exception>(() => cryptoService.EncryptPassword(changeEvent));
    }
}
