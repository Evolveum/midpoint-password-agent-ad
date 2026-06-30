/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Sender.Configuration;
using Sender.Logger;
using Sender.MultiPlatform;
using Serilog.Events;

namespace Sender.Tests;

public class SenderConfigurationFactoryTests : IDisposable
{
    private readonly List<string> _tempFiles = [];
    private AppLogger _appLogger;

    public SenderConfigurationFactoryTests()
    {
        _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
    }
    public void Dispose()
    {
        foreach (var file in _tempFiles)
            if (File.Exists(file)) File.Delete(file);
    }

    private string WriteTempJson(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.json");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
    }

    private static SenderConfiguration Build(string queueDirectory, string? jsonPath = null, string? appRoot = null)
    {
        var _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var builder = new ConfigurationBuilder();
        if (jsonPath is not null)
            builder.AddJsonFile(jsonPath, optional: false);
        return SenderConfigurationFactory.Build(
            queueDirectory,
            appRoot ?? "",
            builder.Build(),
            new SimpleMidpointConfigurationBuilder(),
            _appLogger);
    }

    [Fact]
    public void EqualsTrue_For_SameValue()
    {
        var oldConfig = new SenderConfiguration
        {
            RootPath = "testFolder",
            QueueDirectory = "testFolder/queue",
            KeyRotationInterval = TimeSpan.FromDays(20),
            KeyRotationGracePeriod = TimeSpan.FromHours(2),
            KeyCleanupInterval = TimeSpan.FromMinutes(15),
        };

        var newConfig = new SenderConfiguration
        {
            RootPath = "testFolder",
            QueueDirectory = "testFolder/queue",
            KeyRotationInterval = TimeSpan.FromDays(20),
            KeyRotationGracePeriod = TimeSpan.FromHours(2),
            KeyCleanupInterval = TimeSpan.FromMinutes(15),
        };

        Assert.True(oldConfig.Equals(newConfig));
    }

    [Fact]
    public void EqualsFalse_For_ChangedValue()
    {
        var oldConfig = new SenderConfiguration
        {
            RootPath = "testFolder",
            QueueDirectory = "testFolder/queue",
            KeyRotationInterval = TimeSpan.FromDays(20),
            KeyRotationGracePeriod = TimeSpan.FromHours(2),
            KeyCleanupInterval = TimeSpan.FromMinutes(15),
        };

        var newConfig = new SenderConfiguration
        {
            RootPath = "testFolder",
            QueueDirectory = "testFolder/queue",
            KeyRotationInterval = TimeSpan.FromDays(10),
            KeyRotationGracePeriod = TimeSpan.FromHours(1),
            KeyCleanupInterval = TimeSpan.FromMinutes(10),
        };

        Assert.False(oldConfig.Equals(newConfig));
    }

    [Fact]
    public void QueueDirectory_IsAlwaysFromCaller()
    {
        var config = Build("/expected/queue");

        Assert.Equal("/expected/queue", config.QueueDirectory);
    }

    [Fact]
    public void QueueDirectory_CannotBeOverriddenByJson()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "QueueDirectory": "/json/queue"
              }
            }
            """);

        var config = Build("/registry/queue", path);

        Assert.Equal("/registry/queue", config.QueueDirectory);
    }

    [Fact]
    public void WithNoJsonFile_DefaultsAreUsed()
    {
        var config = Build("/queue");

        Assert.Equal(TimeSpan.FromMilliseconds(300), config.PollInterval);
        Assert.Equal(TimeSpan.FromDays(20), config.KeyRotationInterval);
        Assert.Equal(TimeSpan.FromSeconds(2), config.KeyReencryptionTimeout);
        Assert.Equal(TimeSpan.FromDays(3), config.KeyRotationGracePeriod);
        Assert.Equal(TimeSpan.FromDays(1), config.KeyCleanupInterval);
    }

    [Fact]
    public void WithJsonFile_AllValuesAreApplied()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "KeyRotationInterval": "90.00:00:00",
                "KeyRotationGracePeriod": "7.00:00:00",
                "KeyCleanupInterval": "2.00:00:00"
              }
            }
            """);

        var config = Build("/queue", path);

        Assert.Equal(TimeSpan.FromDays(90), config.KeyRotationInterval);
        Assert.Equal(TimeSpan.FromDays(7), config.KeyRotationGracePeriod);
        Assert.Equal(TimeSpan.FromDays(2), config.KeyCleanupInterval);
    }

    [Fact]
    public void WithPartialJsonFile_MissingValuesUseDefaults()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "KeyRotationInterval": "45.00:00:00"
              }
            }
            """);

        var config = Build("/queue", path);

        Assert.Equal(TimeSpan.FromDays(45), config.KeyRotationInterval);
        Assert.Equal(TimeSpan.FromMilliseconds(300), config.PollInterval);
        Assert.Equal(TimeSpan.FromDays(3), config.KeyRotationGracePeriod);
    }

    [Fact]
    public void DerivedPaths_AreBasedOnQueueDirectory()
    {
        var queuePath = $"{Path.PathSeparator}my{Path.PathSeparator}queue";
        var config = Build(queuePath);

        Assert.Equal(Path.Combine(queuePath, "processing"), config.ProcessingQueueDirectory);
        Assert.Equal(Path.Combine(queuePath, "failed"), config.FailedQueueDirectory);
        Assert.Equal(Path.Combine(queuePath, "staging"), config.StagingDirectory);
    }

    [Fact]
    public void WithNoJsonFile_LogLevelDefaultsToInformation()
    {
        var config = Build("/queue");

        Assert.Equal(LogEventLevel.Information, config.LogLevel);
    }

    [Fact]
    public void WithJsonFile_LogLevelIsApplied()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "LogLevel": "Warning"
              }
            }
            """);

        var config = Build("/queue", path);

        Assert.Equal(LogEventLevel.Warning, config.LogLevel);
    }

    [Fact]
    public void WithNoJsonFile_LogRotation_DefaultsAreUsed()
    {
        var config = Build("/queue");

        Assert.Equal(5 * 1024 * 1024, config.LogFileSizeLimitBytes);
        Assert.Equal(3, config.LogRetainedFileCountLimit);
    }

    [Fact]
    public void WithJsonFile_LogRotation_ValuesAreApplied()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "LogFileSizeLimitBytes": 10485760,
                "LogRetainedFileCountLimit": 5
              }
            }
            """);

        var config = Build("/queue", path);

        Assert.Equal(10 * 1024 * 1024, config.LogFileSizeLimitBytes);
        Assert.Equal(5, config.LogRetainedFileCountLimit);
    }

    [Fact]
    public void WithPartialJsonFile_LogRotation_MissingValuesUseDefaults()
    {
        var path = WriteTempJson("""
            {
              "Sender": {
                "LogFileSizeLimitBytes": 2097152
              }
            }
            """);

        var config = Build("/queue", path);

        Assert.Equal(2 * 1024 * 1024, config.LogFileSizeLimitBytes);
        Assert.Equal(3, config.LogRetainedFileCountLimit);
    }

    [Fact]
    public void FullPipeline_RegistryConfigPath_LoadsJsonSettings()
    {
        if (!OperatingSystem.IsWindows()) return;

        const string RegistryHive = @"HKEY_LOCAL_MACHINE\SOFTWARE\Evolveum\MidPointPasswordAgent";
        const string ValueName = "ConfigPath";

        var previousValue = Registry.GetValue(RegistryHive, ValueName, null) as string;
        var jsonPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.json");

        try
        {

            var configPath = Registry.GetValue(RegistryHive, ValueName, "config.json") as string ?? "config.json";
            var configuration = new ConfigurationBuilder()
                .AddJsonFile(configPath, optional: true, reloadOnChange: true)
                .Build();
            var settings = SenderConfigurationFactory.Build(
                @"C:\queue",
                @"C:\data",
                configuration,
                new SimpleMidpointConfigurationBuilder(),
                _appLogger);

            Assert.Equal(TimeSpan.FromMilliseconds(300), settings.PollInterval);

            File.WriteAllText(jsonPath, """
                {
                  "Sender": {
                    "KeyRotationInterval": "45.00:00:00",
                    "KeyRotationGracePeriod": "5.00:00:00"
                  }
                }
                """);

            Registry.SetValue(RegistryHive, ValueName, jsonPath, RegistryValueKind.String);

            // Replicate exactly what Program.cs does
            configPath = Registry.GetValue(RegistryHive, ValueName, "config.json") as string ?? "config.json";
            configuration = new ConfigurationBuilder()
                .AddJsonFile(configPath, optional: true, reloadOnChange: true)
                .Build();
            settings = SenderConfigurationFactory.Build(
                @"C:\queue",
                @"C:\data",
                configuration,
                new SimpleMidpointConfigurationBuilder(),
                _appLogger);

            Assert.Equal(jsonPath, configPath);
            Assert.Equal(TimeSpan.FromDays(45), settings.KeyRotationInterval);
            Assert.Equal(TimeSpan.FromDays(5), settings.KeyRotationGracePeriod);
            Assert.Equal(TimeSpan.FromDays(1), settings.KeyCleanupInterval); // default
        }
        finally
        {
            if (File.Exists(jsonPath)) File.Delete(jsonPath);

            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Evolveum\MidPointPasswordAgent", writable: true);
            if (previousValue is null)
                key?.DeleteValue(ValueName, throwOnMissingValue: false);
            else
                key?.SetValue(ValueName, previousValue, RegistryValueKind.String);
        }
    }
}
