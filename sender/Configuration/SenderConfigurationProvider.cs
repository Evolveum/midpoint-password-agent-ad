/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Sender.Logger;
using Sender.MidPoint;
using Sender.Services.MidPoint;

namespace Sender.Configuration;

public class SenderConfigurationProvider
{
    private volatile SenderConfiguration _current;

    public SenderConfigurationProvider(
        IMidpointConfigurationBuilder midPointBuilder,
        AppLogger appLogger,
        StartupConfig startupConfig,
        IConfiguration configProvider)
    {
        _current = SenderConfigurationFactory.Build(
             startupConfig.QueueDirectory,
             startupConfig.RootPath,
             configProvider,
             midPointBuilder,
             appLogger
         );
    }

    public SenderConfigurationProvider(SenderConfiguration initConfig)
    {
        _current = initConfig;
    }

    public event Action? Changed;

    internal bool Update(SenderConfiguration config)
    {
        if (config.Equals(_current))
            return false;

        _current = config;
        Changed?.Invoke();
        return true;
    }

    public string QueueDirectory => _current.QueueDirectory;
    public string ProcessingQueueDirectory => _current.ProcessingQueueDirectory;
    public string FailedQueueDirectory => _current.FailedQueueDirectory;
    public string StagingDirectory => _current.StagingDirectory;
    public string DeadLetterQueueDirectory => _current.DeadLetterQueueDirectory;

    public TimeSpan PollInterval => _current.PollInterval;

    public TimeSpan LongTermPollInterval => _current.LongTermPollInterval;
    public TimeSpan KeyRotationInterval => _current.KeyRotationInterval;
    public TimeSpan KeyReencryptionTimeout => _current.KeyReencryptionTimeout;
    public TimeSpan KeyRotationGracePeriod => _current.KeyRotationGracePeriod;
    public TimeSpan KeyCleanupInterval => _current.KeyCleanupInterval;

    public string KeyRegistryPath => _current.KeyRegistryPath;
    public string LatestKeyRegistryName => _current.LatestKeyRegistryName;

    public int MaxRetryCount => _current.MaxRetryCount;
    public TimeSpan RetryBaseDelay => _current.RetryBaseDelay;
    public TimeSpan RetryMaxDelay => _current.RetryMaxDelay;

    public string SaveFilePath => _current.SaveFilePath;

    public long LogFileSizeLimitBytes => _current.LogFileSizeLimitBytes;
    public int LogRetainedFileCountLimit => _current.LogRetainedFileCountLimit;
    public MidPointClientConfiguration MidPoint => _current.MidPoint;

    public int MaxRequestsPerMinute => _current.MaxRequestsPerMinute;
}
