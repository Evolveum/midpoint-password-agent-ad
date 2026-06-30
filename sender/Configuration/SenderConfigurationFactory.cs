/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Sender.Logger;
using Sender.MidPoint;
using Sender.Services.MidPoint;

namespace Sender.Configuration;

public static class SenderConfigurationFactory
{
    public static SenderConfiguration Build(
        string queueDirectory,
        string rootPath,
        IConfiguration configuration,
        IMidpointConfigurationBuilder midpointConfigBuilder,
        AppLogger appLogger)
    {
        var jsonConfig = configuration.GetSection("Sender").Get<SenderJsonConfiguration>() ?? new SenderJsonConfiguration();
        var midPointJsonConfig = configuration.GetSection("MidPoint").Get<MidPointJsonConfiguration>() ?? new MidPointJsonConfiguration();


        MidPointClientConfiguration midPointConfig;
        try
        {
            midPointConfig = midpointConfigBuilder.Build(midPointJsonConfig);
        }
        catch (Exception e)
        {
            appLogger.ToAll(string.Format("Loading midpoint configuration failed, {0}", e.Message), LogLevel.Error);
            midPointConfig = new MidPointClientConfiguration();
        }

        return new SenderConfiguration
        {
            RootPath = rootPath,
            QueueDirectory = queueDirectory,
            KeyRotationInterval = jsonConfig.KeyRotationInterval,
            KeyRotationGracePeriod = jsonConfig.KeyRotationGracePeriod,
            KeyCleanupInterval = jsonConfig.KeyCleanupInterval,
            LogLevel = jsonConfig.LogLevel,
            LogFileSizeLimitBytes = jsonConfig.LogFileSizeLimitBytes,
            LogRetainedFileCountLimit = jsonConfig.LogRetainedFileCountLimit,
            MidPoint = midPointConfig,
        };
    }
}
