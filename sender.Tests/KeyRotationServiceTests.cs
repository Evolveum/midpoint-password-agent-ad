/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Sender.Configuration;
using Sender.Crypto;
using Sender.KeyRotation;
using Sender.Logger;
using Sender.MultiPlatform;
using Sender.Queue;

namespace Sender.Tests;

public class KeyRotationServiceTests : IDisposable
{
    private readonly SenderConfigurationProvider _configurationProvider;
    private readonly AppLogger _appLogger;

    public KeyRotationServiceTests()
    {
        var queueDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

        _configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                QueueDirectory = queueDir,
                PollInterval = TimeSpan.FromMilliseconds(10),
                KeyRotationGracePeriod = TimeSpan.FromHours(12),
                KeyReencryptionTimeout = TimeSpan.Zero,
                KeyRegistryPath = $@"SOFTWARE\Evolveum\MidPointPasswordAgent\Keys\Tests\{Guid.NewGuid():N}",
            }
        );

        _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_configurationProvider.QueueDirectory))
            Directory.Delete(_configurationProvider.QueueDirectory, recursive: true);

        if (OperatingSystem.IsWindows())
            Registry.LocalMachine.DeleteSubKeyTree(_configurationProvider.KeyRegistryPath, throwOnMissingSubKey: false);
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private string CreateEncryptedEventFile(string directory, string keyVersion, byte[] rawKey, string content = "test payload")
    {
        Directory.CreateDirectory(directory);
        var blob = CryptoService.EncryptToBlob(rawKey, content);
        var base64Password = Convert.ToBase64String(blob);
        var fileName = $"{Guid.NewGuid():N}_{keyVersion}.event";
        var path = Path.Combine(directory, fileName);
        File.WriteAllText(path, $@"{{""username"":""user"",""domain"":""domain"",""password"":""{base64Password}""}}");
        return path;
    }

    private IKeyProvider CreateKeyProvider(SenderConfigurationProvider configProvider)
    {
        return OperatingSystem.IsWindows() ? new WindowsKeyProvider(configProvider, _appLogger) : new InMemoryKeyProvider(_appLogger);
    }

    private (CryptoService cryptoService, KeyRotationService keyRotationService, IKeyProvider keyProvider, QueueService queueService) CreateDependantService(SenderConfigurationProvider? configProvider = null)
    {
        var usedConfigProvider = configProvider ?? _configurationProvider;
        var keyProvider = CreateKeyProvider(usedConfigProvider);
        var cryptoService = new CryptoService(_appLogger, keyProvider);
        var queueService = new QueueService(_appLogger, usedConfigProvider);
        var keyRotationService = new KeyRotationService(_appLogger, usedConfigProvider, keyProvider, queueService, cryptoService);

        return (cryptoService, keyRotationService, keyProvider, queueService);
    }

    // ---------------------------------------------------------------------------
    // Key rotation tests
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task RotateAsync_WhenNoLatestKeyVersion_DoesNotStoreNewKey()
    {
        var services = CreateDependantService();
        await services.keyRotationService.RotateAsync();

        Assert.Null(services.keyProvider.GetLatestKeyVersion());
    }

    [Fact]
    public async Task RotateAsync_WhenVersionCannotBeIncremented_DoesNotStoreNewKey()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var invalidKeyName = "cannot_increment";
        services.keyProvider.StoreKey(invalidKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(invalidKeyName);

        await services.keyRotationService.RotateAsync();

        Assert.Equal(invalidKeyName, services.keyProvider.GetLatestKeyVersion());

        services.keyProvider.DeleteKey(invalidKeyName);
    }

    [Fact]
    public async Task RotateAsync_StoresNewKeyAndSetsItAsLatest()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var keyName = "v1";
        services.keyProvider.StoreKey(keyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(keyName);

        await services.keyRotationService.RotateAsync();

        var newKeyName = "v2";

        Assert.Equal(newKeyName, services.keyProvider.GetLatestKeyVersion());
        Assert.NotNull(services.keyProvider.GetKey(newKeyName));

        services.keyProvider.DeleteKey(newKeyName);
    }

    [Fact]
    public async Task RotateAsync_NewKeyIsDifferentFromOldKey()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v1";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        var newKeyName = "v2";

        await services.keyRotationService.RotateAsync();

        var newKey = services.keyProvider.GetKey(newKeyName);
        Assert.NotNull(newKey);
        Assert.False(oldKey.SequenceEqual(newKey));

        services.keyProvider.DeleteKey(newKeyName);
    }

    [Fact]
    public async Task RotateAsync_NoQueueFiles_SetsExpiryOnOldKey()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v1";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        await services.keyRotationService.RotateAsync();

        Assert.NotNull(services.keyProvider.GetKeyExpiry(oldKeyName));
        Assert.NotNull(services.keyProvider.GetKey(oldKeyName));
        Assert.NotEqual(oldKeyName, services.keyProvider.GetLatestKeyVersion());
    }

    [Fact]
    public async Task RotateAsync_ReEncryptsQueueFilesWithNewKey()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v2";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        var filePayload = "secret payload";

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyName, oldKey, filePayload);

        await services.keyRotationService.RotateAsync();

        var newKeyName = "v3";

        var newFiles = Directory.GetFiles(_configurationProvider.QueueDirectory, $"*{newKeyName}.event");
        Assert.Single(newFiles);

        var newKey = services.keyProvider.GetKey(newKeyName)!;
        var json = File.ReadAllText(newFiles[0]);
        using var doc = JsonDocument.Parse(json);
        var blob = Convert.FromBase64String(doc.RootElement.GetProperty("password").GetString()!);
        var plaintext = CryptoService.DecryptBlob(newKey, blob);

        Assert.NotNull(plaintext);
        Assert.Equal(filePayload, plaintext);

        services.keyProvider.DeleteKey(newKeyName);
    }

    [Fact]
    public async Task RotateAsync_OldVersionFileIsRemovedFromQueue()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v2";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyName, oldKey);

        await services.keyRotationService.RotateAsync();

        var oldFiles = Directory.GetFiles(_configurationProvider.QueueDirectory, $"*{oldKeyName}.event");
        Assert.Empty(oldFiles);

        services.keyProvider.DeleteKey(oldKeyName);
    }

    [Fact]
    public async Task RotateAsync_SetsExpiryOnOldKeyAfterReEncryption()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v1";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyName, oldKey);

        var before = DateTime.UtcNow;
        await services.keyRotationService.RotateAsync();

        var expiry = services.keyProvider.GetKeyExpiry(oldKeyName);
        Assert.NotNull(expiry);
        Assert.True(expiry > before);
        Assert.NotNull(services.keyProvider.GetKey(oldKeyName));
    }

    [Fact]
    public async Task RotateAsync_MultipleFailedQueueFiles_AllReEncrypted()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v1";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        var newKeyName = "v2";

        for (var i = 1; i <= 5; i++)
            CreateEncryptedEventFile(_configurationProvider.FailedQueueDirectory, oldKeyName, oldKey, $"payload {i}");

        await services.keyRotationService.RotateAsync();

        Assert.Empty(Directory.GetFiles(_configurationProvider.FailedQueueDirectory, $"*_{oldKeyName}.event"));
        Assert.Equal(5, Directory.GetFiles(_configurationProvider.FailedQueueDirectory, $"*_{newKeyName}.event").Length);

        services.keyProvider.DeleteKey(newKeyName);
    }

    [Fact]
    public async Task RotateAsync_FilesWithOtherVersions_AreNotTouched()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyName = "v1";
        services.keyProvider.StoreKey(oldKeyName, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyName);

        var otherEncryptedBlob = CryptoService.EncryptToBlob(oldKey, "other payload");
        var otherBase64 = Convert.ToBase64String(otherEncryptedBlob);
        var otherFile = Path.Combine(_configurationProvider.QueueDirectory, $"20260501_120000_AABB_v9.event");
        Directory.CreateDirectory(_configurationProvider.QueueDirectory);
        File.WriteAllText(otherFile, $@"{{""username"":""user"",""domain"":""domain"",""password"":""{otherBase64}""}}");

        Assert.True(File.Exists(otherFile));

        await services.keyRotationService.RotateAsync();

        Assert.True(File.Exists(otherFile));

        services.keyProvider.DeleteKey(oldKeyName);
    }

    // ---------------------------------------------------------------------------
    // Rollback tests
    // ---------------------------------------------------------------------------

    private string CreateCorruptedEventFile(string directory, string keyVersion)
    {
        Directory.CreateDirectory(directory);
        var fileName = $"{Guid.NewGuid():N}_{keyVersion}.event";
        var path = Path.Combine(directory, fileName);
        var tooShortBase64 = Convert.ToBase64String(new byte[5]); // too small for AES-GCM (< NONCE_BYTES + TAG_BYTES = 28)
        var json = $@"{{""username"":""user"",""domain"":""domain"",""password"":""{tooShortBase64}""}}";
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public async Task RotateAsync_WhenReEncryptionFails_LatestKeyIsRestoredToOldVersion()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        await services.keyRotationService.RotateAsync();

        Assert.Equal(oldKeyVersion, services.keyProvider.GetLatestKeyVersion());

        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenReEncryptionFails_NoNewKeyFilesRemain()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        var newKeyVersion = "v2";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion, oldKey);
        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        await services.keyRotationService.RotateAsync();

        Assert.Empty(Directory.GetFiles(_configurationProvider.QueueDirectory, $"*_{newKeyVersion}.event", SearchOption.AllDirectories));
        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenReEncryptionFails_OldKeyIsPreserved()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        await services.keyRotationService.RotateAsync();

        Assert.NotNull(services.keyProvider.GetKey(oldKeyVersion));
        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenReEncryptionFails_NoFilesRemainInStaging()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        await services.keyRotationService.RotateAsync();

        Assert.Empty(Directory.GetFiles(_configurationProvider.StagingDirectory, "*.event"));
        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenReEncryptionFails_FailedFileIsRestoredToOriginalLocation()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        var corruptedFilePath = CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        await services.keyRotationService.RotateAsync();

        Assert.True(File.Exists(corruptedFilePath));
        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_RollbackOfLatestKeyVersion()
    {
        var settings = new SenderConfiguration
        {
            QueueDirectory = _configurationProvider.QueueDirectory,
            KeyRotationGracePeriod = TimeSpan.FromSeconds(2),
            KeyRegistryPath = $@"SOFTWARE\Evolveum\MidPointPasswordAgent\Keys\Tests\{Guid.NewGuid():N}"
        };

        var services = CreateDependantService(new SenderConfigurationProvider(settings));
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion);

        var rotateTask = services.keyRotationService.RotateAsync();

        await Task.Delay(TimeSpan.FromMilliseconds(50));

        Assert.Equal("v2", services.keyProvider.GetLatestKeyVersion());

        await rotateTask;

        Assert.Equal("v1", services.keyProvider.GetLatestKeyVersion());

        Assert.Null(services.keyProvider.GetKey("v2"));

        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenStagingDirectoryMissing_LatestKeyIsRestoredToOldVersion()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion, oldKey);
        Directory.Delete(_configurationProvider.StagingDirectory, recursive: true);

        await services.keyRotationService.RotateAsync();

        Assert.Equal(oldKeyVersion, services.keyProvider.GetLatestKeyVersion());
    }

    [Fact]
    public async Task RotateAsync_WhenStagingDirectoryMissing_OldKeyIsPreserved()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion, oldKey);
        Directory.Delete(_configurationProvider.StagingDirectory, recursive: true);

        await services.keyRotationService.RotateAsync();

        Assert.NotNull(services.keyProvider.GetKey(oldKeyVersion));

        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenStagingIsFile_LatestKeyIsRestoredToOldVersion()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion, oldKey);

        Directory.Delete(_configurationProvider.StagingDirectory, recursive: true);
        File.WriteAllText(_configurationProvider.StagingDirectory, string.Empty);

        await services.keyRotationService.RotateAsync();

        Assert.Equal(oldKeyVersion, services.keyProvider.GetLatestKeyVersion());

        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    [Fact]
    public async Task RotateAsync_WhenStagingIsFile_QueueFileIsPreserved()
    {
        var services = CreateDependantService();
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(oldKey);

        var oldKeyVersion = "v1";
        services.keyProvider.StoreKey(oldKeyVersion, oldKey);
        services.keyProvider.SetLatestKeyVersion(oldKeyVersion);

        var filePath = CreateEncryptedEventFile(_configurationProvider.QueueDirectory, oldKeyVersion, oldKey);

        Directory.Delete(_configurationProvider.StagingDirectory, recursive: true);
        File.WriteAllText(_configurationProvider.StagingDirectory, string.Empty);

        await services.keyRotationService.RotateAsync();

        Assert.True(File.Exists(filePath));

        services.keyProvider.DeleteKey(oldKeyVersion);
    }

    // ---------------------------------------------------------------------------
    // CleanupExpiredKeysAsync tests
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task CleanupAsync_WhenKeyNotYetExpired_KeyIsPreserved()
    {
        var services = CreateDependantService();
        var latestKey = new byte[32];
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(latestKey);
        RandomNumberGenerator.Fill(oldKey);

        services.keyProvider.StoreKey("v1", oldKey);
        services.keyProvider.StoreKey("v2", latestKey);
        services.keyProvider.SetLatestKeyVersion("v2");
        services.keyProvider.SetKeyExpiry("v1", DateTime.UtcNow.AddDays(1));

        await services.keyRotationService.CleanupExpiredKeysAsync();

        Assert.NotNull(services.keyProvider.GetKey("v1"));
    }

    [Fact]
    public async Task CleanupAsync_WhenKeyExpired_DeletesKey()
    {
        var services = CreateDependantService();
        var latestKey = new byte[32];
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(latestKey);
        RandomNumberGenerator.Fill(oldKey);

        services.keyProvider.StoreKey("v1", oldKey);
        services.keyProvider.StoreKey("v2", latestKey);
        services.keyProvider.SetLatestKeyVersion("v2");
        services.keyProvider.SetKeyExpiry("v1", DateTime.UtcNow.AddDays(-1));

        await services.keyRotationService.CleanupExpiredKeysAsync();

        Assert.Null(services.keyProvider.GetKey("v1"));
    }

    [Fact]
    public async Task CleanupAsync_WhenKeyExpired_ReEncryptsRemainingFilesWithLatestKey()
    {
        var services = CreateDependantService();
        var latestKey = new byte[32];
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(latestKey);
        RandomNumberGenerator.Fill(oldKey);

        services.keyProvider.StoreKey("v1", oldKey);
        services.keyProvider.StoreKey("v2", latestKey);
        services.keyProvider.SetLatestKeyVersion("v2");
        services.keyProvider.SetKeyExpiry("v1", DateTime.UtcNow.AddDays(-1));

        var payload = "secret payload";
        CreateEncryptedEventFile(_configurationProvider.QueueDirectory, "v1", oldKey, payload);

        await services.keyRotationService.CleanupExpiredKeysAsync();

        var reEncryptedFiles = Directory.GetFiles(_configurationProvider.QueueDirectory, "*_v2.event", SearchOption.AllDirectories);
        Assert.Single(reEncryptedFiles);

        var json = File.ReadAllText(reEncryptedFiles[0]);
        using var doc = JsonDocument.Parse(json);
        var blob = Convert.FromBase64String(doc.RootElement.GetProperty("password").GetString()!);
        // decrypted with "new" latest key
        var plaintext = CryptoService.DecryptBlob(latestKey, blob);
        Assert.Equal(payload, plaintext);
    }

    [Fact]
    public async Task CleanupAsync_WhenReEncryptionFails_KeyIsNotDeleted()
    {
        var services = CreateDependantService();
        var latestKey = new byte[32];
        var oldKey = new byte[32];
        RandomNumberGenerator.Fill(latestKey);
        RandomNumberGenerator.Fill(oldKey);

        services.keyProvider.StoreKey("v1", oldKey);
        services.keyProvider.StoreKey("v2", latestKey);
        services.keyProvider.SetLatestKeyVersion("v2");
        services.keyProvider.SetKeyExpiry("v1", DateTime.UtcNow.AddDays(-1));

        CreateCorruptedEventFile(_configurationProvider.QueueDirectory, "v1");

        await services.keyRotationService.CleanupExpiredKeysAsync();

        Assert.NotNull(services.keyProvider.GetKey("v1"));
        Assert.Equal("v2", services.keyProvider.GetLatestKeyVersion());
    }
}
