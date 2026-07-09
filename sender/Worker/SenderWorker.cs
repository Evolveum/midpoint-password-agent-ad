/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using Sender.Configuration;
using Sender.Crypto;
using Sender.Logger;
using Sender.MidPoint;
using Sender.Queue;

namespace Sender.Worker
{
    /// <summary>
    /// Basic worker responsible for detecting creation of `.event` file and sending that password change to MidPoint
    /// </summary>
    public class SenderWorker(AppLogger appLogger, SenderConfigurationProvider configuration, QueueService queueService, MidPointService midPointService, CryptoService cryptoService, MidPointRateLimiter rateLimiter) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            appLogger.ToFile($"Worker started, polling queue: {configuration.QueueDirectory}");
            appLogger.ToFile($"KeyRotationInterval: {configuration.KeyRotationInterval}, MaxRetryCount: {configuration.MaxRetryCount}, RetryBaseDelay: {configuration.RetryBaseDelay}");
            appLogger.ToFile($"MaxQueueDepth: {configuration.MaxQueueDepth} concurrent event(s) in-processing");
            if (configuration.MaxRequestsPerMinute > 0)
                appLogger.ToFile($"Rate limit: {configuration.MaxRequestsPerMinute} requests/minute");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var passwordChangeEvents = queueService.GetPasswordChangeEvents();

                    var parallelOptions = new ParallelOptions
                    {
                        MaxDegreeOfParallelism = configuration.MaxQueueDepth > 0 ? configuration.MaxQueueDepth : -1,
                        CancellationToken = stoppingToken
                    };

                    await Parallel.ForEachAsync(passwordChangeEvents, parallelOptions, ProcessEventAsync);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    appLogger.ToAll($"Unhandled error during queue processing: {ex.Message}", LogLevel.Error);
                }

                await Task.Delay(configuration.PollInterval, stoppingToken);
            }

            appLogger.ToFile("Worker stopped");
        }

        private async ValueTask ProcessEventAsync(string changeEventPath, CancellationToken stoppingToken)
        {
            var acquiredLimit = await rateLimiter.WaitAsync(stoppingToken);
            if (!acquiredLimit)
            {
                // if rateLimiter returns false, that means that limiter was disposed (config reload) and we will process event in next loop
                return;
            }

            PasswordChangeEvent? changeEvent = queueService.ParseEventFile(changeEventPath);
            if (changeEvent is null) return;

            var decryptedEvent = cryptoService.DecryptPassword(changeEvent);
            var (sent, lastError) = await midPointService.SendPasswordChange(decryptedEvent, stoppingToken);
            if (sent)
            {
                queueService.RemoveEvent(changeEvent);
            }
            else if ((changeEvent.Metadata?.RetryCount ?? 0) >= configuration.MaxRetryCount)
            {
                queueService.MoveToDlq(changeEvent);
            }
            else
            {
                var nextRetryAt = DateTimeOffset.Now + CalculateRetryDelay((changeEvent.Metadata?.RetryCount ?? 0) + 1);
                queueService.MarkEventForRetry(changeEvent, nextRetryAt, lastError);
            }
        }

        private TimeSpan CalculateRetryDelay(int retryNumber)
        {
            var seconds = configuration.RetryBaseDelay.TotalSeconds * Math.Pow(2, retryNumber - 1);
            return TimeSpan.FromSeconds(Math.Min(seconds, configuration.RetryMaxDelay.TotalSeconds));
        }
    }
}
