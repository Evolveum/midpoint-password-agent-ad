/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Sender.Configuration;
using Sender.KeyRotation;
using Sender.Logger;
using Sender.State;

namespace Sender.Worker;

public class KeyRotationWorker(
    SenderConfigurationProvider configuration,
    AppLogger appLogger,
    IKeyRotationService keyRotationService,
    IApplicationStateProvider stateProvider) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        appLogger.ToFile($"Key rotation worker started, interval: {configuration.KeyRotationInterval}");

        while (!stoppingToken.IsCancellationRequested)
        {
            if (stateProvider.IsKeyRotationRequired())
            {
                try
                {
                    await keyRotationService.RotateAsync();
                    await stateProvider.UpdateLastRotationTimeStampAsync();
                }
                catch (Exception ex)
                {
                    appLogger.ToAll($"Unhandled error during key rotation: {ex.Message}", LogLevel.Error);
                }
            }
            else
            {
                appLogger.ToFile(
                    $"Skipping rotation, last rotation at {stateProvider.CurrentState.LastKeyRotationTimeStamp}"
                );
            }

            var delayMs = (int)configuration.LongTermPollInterval.TotalMilliseconds;
            await Task.Delay(delayMs, stoppingToken);
        }

        appLogger.ToFile("Key rotation worker stopped", LogLevel.Warning);
    }
}
