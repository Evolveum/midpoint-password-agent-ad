/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Security.Cryptography;
using System.Text.Json;
using Sender.Configuration;
using Sender.Crypto;
using Sender.Logger;
using Sender.Queue;

namespace Sender.KeyRotation;

public class KeyRotationService : IKeyRotationService
{
    private readonly AppLogger appLogger;
    private readonly SenderConfigurationProvider configuration;
    private readonly IKeyProvider keyProvider;
    private readonly QueueService queueService;
    private readonly CryptoService cryptoService;

    public KeyRotationService(
        AppLogger appLogger,
        SenderConfigurationProvider configuration,
        IKeyProvider keyProvider,
        QueueService queueService,
        CryptoService cryptoService)
    {
        this.appLogger = appLogger;
        this.configuration = configuration;
        this.keyProvider = keyProvider;
        this.queueService = queueService;
        this.cryptoService = cryptoService;

        this.queueService.InitDirectoryStructure();
    }

    public async Task RotateAsync()
    {
        appLogger.ToFile("Starting key rotation");

        var oldKeyVersion = keyProvider.GetLatestKeyVersion();
        if (oldKeyVersion is null)
        {
            appLogger.ToAll("No LatestKey found in registry — cannot rotate", LogLevel.Error);
            return;
        }

        var newKeyVersion = keyProvider.IncrementKeyVersion(oldKeyVersion);
        if (newKeyVersion is null)
        {
            appLogger.ToAll($"Could not increment key version of '{oldKeyVersion}'", LogLevel.Error);
            return;
        }

        appLogger.ToFile($"Rotating key: {oldKeyVersion} -> {newKeyVersion}");

        var newRawKey = keyProvider.GenerateNewKey();

        keyProvider.StoreKey(newKeyVersion, newRawKey);
        keyProvider.SetLatestKeyVersion(newKeyVersion);
        appLogger.ToFile($"New key '{newKeyVersion}' stored and set as LatestKey");

        // Wait before re-encrypting old files
        // (because Listener module can be in process of creating .event file with "old" key version)
        await Task.Delay(configuration.KeyReencryptionTimeout);

        try
        {
            await ReEncryptQueueFilesAsync(oldKeyVersion, newKeyVersion);
        }
        catch (Exception ex)
        {
            appLogger.ToAll($"Error during re-encrypting queue files of oldKeyVersion {oldKeyVersion} to newKeyVersion {newKeyVersion}: {ex.Message}", LogLevel.Error);
            appLogger.ToFile($"Rolling back key rotation");
            await RollbackKeyRotation(oldKeyVersion, newKeyVersion);

            return;
        }

        var expiresAt = DateTime.UtcNow + configuration.KeyRotationGracePeriod;
        keyProvider.SetKeyExpiry(oldKeyVersion, expiresAt);
        appLogger.ToFile($"Old key '{oldKeyVersion}' kept until {expiresAt:O} for in-flight decryption");
        appLogger.ToFile("Key rotation complete");
    }

    public async Task CleanupExpiredKeysAsync()
    {
        appLogger.ToFile("Starting expired key cleanup");

        var latestKeyVersion = keyProvider.GetLatestKeyVersion();
        if (latestKeyVersion is null)
        {
            appLogger.ToFile("No latest key — skipping cleanup");
            return;
        }

        var expiredVersions = keyProvider.GetAllKeyVersions()
            .Where(v => v != latestKeyVersion)
            .Where(v => keyProvider.GetKeyExpiry(v) is { } exp && exp <= DateTime.UtcNow)
            .ToList();

        appLogger.ToFile($"Found {expiredVersions.Count} expired key(s) to clean up");

        foreach (var version in expiredVersions)
        {
            try
            {
                await ReEncryptQueueFilesAsync(version, latestKeyVersion);
            }
            catch (Exception ex)
            {
                appLogger.ToAll($"Failed to re-encrypt remaining files for expired key '{version}': {ex.Message}", LogLevel.Error);
                continue;
            }

            keyProvider.DeleteKey(version);
            appLogger.ToFile($"Expired key '{version}' deleted");
        }

        appLogger.ToFile("Expired key cleanup complete");
    }

    private async Task ReEncryptQueueFilesAsync(string oldKeyVersion, string newKeyVersion)
    {
        var eventFiles = queueService.GetEvenFilesByKeyVersion(oldKeyVersion);

        appLogger.ToFile($"Found {eventFiles.Count} file(s) to re-encrypt");

        var oldKey = keyProvider.GetKey(oldKeyVersion);
        if (oldKey is null)
        {
            appLogger.ToAll($"Old key '{oldKeyVersion}' not found — cannot re-encrypt files for re-encryption", LogLevel.Error);
            throw new Exception($"Could not find oldKeyVersion {oldKeyVersion} key inside keyProvider");
        }

        foreach (var eventFilePath in eventFiles)
        {
            var fileName = Path.GetFileName(eventFilePath);
            var sourceDirectory = Path.GetDirectoryName(eventFilePath);
            if (sourceDirectory is null || fileName is null)
            {
                continue;
            }

            var stagingPath = Path.Combine(configuration.StagingDirectory, fileName);
            File.Move(eventFilePath, stagingPath, overwrite: true);
            appLogger.ToFile($"Moved {fileName} to staging");

            try
            {
                var jsonContent = await File.ReadAllTextAsync(stagingPath);
                var deserializedEvent = JsonSerializer.Deserialize(jsonContent, SenderJsonContext.Default.PasswordChangeEvent)
                    ?? throw new InvalidDataException($"Could not deserialize event file {fileName}");
                var changeEvent = deserializedEvent with { FilePath = stagingPath };

                var decryptedEvent = cryptoService.DecryptPassword(changeEvent);
                var encryptedEvent = cryptoService.EncryptPassword(decryptedEvent, newKeyVersion);
                var newJsonContent = JsonSerializer.Serialize(encryptedEvent);

                var newFileName = GetNewEventFileName(fileName, oldKeyVersion, newKeyVersion);
                await File.WriteAllTextAsync(Path.Combine(sourceDirectory, newFileName), newJsonContent);
                File.Delete(stagingPath);
                appLogger.ToFile($"Re-encrypted {fileName} -> {newFileName}");
            }
            catch (Exception)
            {
                if (File.Exists(stagingPath))
                {
                    // Rollback event file back to its original location
                    File.Move(stagingPath, eventFilePath);
                }

                throw;
            }
        }
    }

    private static string GetNewEventFileName(string oldFileName, string oldKeyVersion, string newKeyVersion)
    {
        return oldFileName[..^QueueService.GetEventFileKeyVersionSuffix(oldKeyVersion).Length] + QueueService.GetEventFileKeyVersionSuffix(newKeyVersion);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S2234:Arguments should be passed in the same order as the method parameters", Justification = "Makes no sense")]
    private async Task RollbackKeyRotation(string oldKeyVersion, string newKeyVersion)
    {
        keyProvider.SetLatestKeyVersion(oldKeyVersion);
        var oldKey = keyProvider.GetKey(oldKeyVersion);
        if (oldKey is null)
        {
            appLogger.ToAll($"Rollback of old key {oldKeyVersion} failed, key does not exists anymore", LogLevel.Error);
            return;
        }

        try
        {
            await ReEncryptQueueFilesAsync(
                oldKeyVersion: newKeyVersion,
                newKeyVersion: oldKeyVersion);
        }
        catch (Exception ex)
        {
            appLogger.ToAll($"Rollback of old key {oldKeyVersion} failed during re-encryption: {ex.Message}", LogLevel.Error);
            return;
        }

        keyProvider.DeleteKey(newKeyVersion);
        appLogger.ToFile($"Deleted newKeyVersion {newKeyVersion} from keyProvider");
    }
}
