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

public class KeyCleanupWorker(
    SenderConfigurationProvider configuration,
    AppLogger appLogger,
    IKeyRotationService keyRotationService,
    IApplicationStateProvider stateProvider) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        appLogger.ToFile($"Key cleanup worker started, interval: {configuration.KeyCleanupInterval}");

        while (!stoppingToken.IsCancellationRequested)
        {
            if (stateProvider.IsKeyCleanupRequired())
            {
                try
                {
                    await keyRotationService.CleanupExpiredKeysAsync();
                    await stateProvider.UpdateLastCleanupTimeStampAsync();
                }
                catch (Exception ex)
                {
                    appLogger.ToAll($"Unhandled error during key cleanup: {ex.Message}", LogLevel.Error);
                }
            }
            else
            {
                appLogger.ToFile($"Skipping cleanup, last cleanup at {stateProvider.CurrentState.LastKeyCleanupTimestamp}");
            }

            var delayMs = (int)configuration.LongTermPollInterval.TotalMilliseconds;
            await Task.Delay(delayMs, stoppingToken);
        }

        appLogger.ToFile("Key cleanup worker stopped", LogLevel.Warning);
    }
}
