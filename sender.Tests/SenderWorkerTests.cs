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
using Sender.Logger;
using Sender.MidPoint;
using Sender.MultiPlatform;
using Sender.Queue;
using Sender.Worker;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Sender.Tests;

public class SenderWorkerTests : IDisposable
{
    private readonly SenderConfigurationProvider _configurationProvider;
    private readonly AppLogger _appLogger;
    private readonly QueueService _queueService;
    private readonly CryptoService _cryptoService;
    private readonly byte[] _aesKey;
    private const string TestKeyVersion = "v1";
    private readonly IKeyProvider _keyProvider;
    private readonly WireMockServer _server;
    private readonly MidPointService _midPointService;
    private const string NotifyChangePath = "/ws/rest/notifyChange";

    public SenderWorkerTests()
    {
        var _queueDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(_queueDir);
        _server = WireMockServer.Start();
        _server.Given(Request.Create().WithPath(NotifyChangePath).UsingPost())
               .RespondWith(Response.Create().WithStatusCode(200));

        _configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration {
                QueueDirectory = _queueDir,
                PollInterval = TimeSpan.FromMilliseconds(10),
                KeyRegistryPath = $@"SOFTWARE\Evolveum\MidPointPasswordAgent\Keys\Tests\{Guid.NewGuid():N}",
                MidPoint = new MidPointClientConfiguration
                {
                    BaseUrl = _server.Urls[0],
                    Username = "",
                    Password = Convert.ToBase64String(""u8.ToArray())
                }
            }
        );
        _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);

        _aesKey = new byte[32];
        RandomNumberGenerator.Fill(_aesKey);

        SetupKeyRegistries();

        if (OperatingSystem.IsWindows())
        {
            _keyProvider = new WindowsKeyProvider(_configurationProvider, _appLogger);
        }
        else
        {
            var inMemoryKeyProvider = new InMemoryKeyProvider(_appLogger);
            inMemoryKeyProvider.StoreKey(TestKeyVersion, _aesKey);
            _keyProvider = inMemoryKeyProvider;
        }

        _cryptoService = new CryptoService(_appLogger, _keyProvider);
        _queueService = new QueueService(_appLogger, _configurationProvider);
        _midPointService = new MidPointService(_appLogger, _configurationProvider, new BasicAuthHandler(_configurationProvider));
    }

    public void Dispose()
    {
        if (Directory.Exists(_configurationProvider.QueueDirectory))
            Directory.Delete(_configurationProvider.QueueDirectory, recursive: true);

        CleanupRegistry();
        _server.Stop();
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    public SenderWorker CreateSenderWorker()
    {
        return new SenderWorker(_appLogger, _configurationProvider, _queueService, _midPointService, _cryptoService, new MidPointRateLimiter(_configurationProvider));
    }

    private SenderWorker CreateWorkerWithMaxRetryCount(int maxRetryCount)
    {
        var config = new SenderConfigurationProvider(new SenderConfiguration
        {
            QueueDirectory = _configurationProvider.QueueDirectory,
            PollInterval = TimeSpan.FromMilliseconds(10),
            KeyRegistryPath = _configurationProvider.KeyRegistryPath,
            MaxRetryCount = maxRetryCount
        });
        var qs = new QueueService(_appLogger, config);
        return new SenderWorker(_appLogger, config, qs, _midPointService, _cryptoService, new MidPointRateLimiter(config));
    }

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

    private void WriteEventFile(string path, PasswordChangeEvent changeEvent, string password)
    {
        var keyVersion = CryptoService.ExtractKeyVersion(path);
        var encrypted = _cryptoService.EncryptPassword(new PasswordChangeEvent(changeEvent.Username, changeEvent.Domain, password), keyVersion);
        File.WriteAllText(path, JsonSerializer.Serialize(encrypted));
    }

    private async Task RunWorkerBriefly(SenderWorker worker, TimeSpan duration)
    {
        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(duration);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void RetryEventRoundTripPreservesEvent()
    {
        Directory.CreateDirectory(_configurationProvider.ProcessingQueueDirectory);
        var fileName = $"roundtrip_{TestKeyVersion}.event";
        var processingPath = Path.Combine(_configurationProvider.ProcessingQueueDirectory, fileName);
        var failedPath = Path.Combine(_configurationProvider.FailedQueueDirectory, fileName);

        var original = new PasswordChangeEvent("Jon Doe", "EvilCorp", string.Empty) { FilePath = processingPath };
        WriteEventFile(processingPath, original, "secret");
        var toRetry = _queueService.ParseEventFile(processingPath);
        Assert.NotNull(toRetry);

        _queueService.MarkEventForRetry(toRetry, DateTimeOffset.UtcNow.AddMinutes(1));

        Assert.False(File.Exists(processingPath));
        Assert.True(File.Exists(failedPath));

        var parsed = _queueService.ParseEventFile(failedPath);
        Assert.NotNull(parsed);
        Assert.Equal(1, parsed.Metadata?.RetryCount);
        Assert.Equal("Jon Doe", parsed.Username);
        Assert.Equal("secret", _cryptoService.DecryptPassword(parsed).Password);
    }

    [Fact]
    public async Task DirectoriesAreCreatedOnStart()
    {
        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(50));

        Assert.True(Directory.Exists(_configurationProvider.ProcessingQueueDirectory));
        Assert.True(Directory.Exists(_configurationProvider.FailedQueueDirectory));
    }

    [Fact]
    public async Task EventFileInQueueIsMovedToProcessingDirectory()
    {
        var changeEvent = new PasswordChangeEvent("Jon Doe", "EvilCorp", string.Empty);
        var eventFile = Path.Combine(_configurationProvider.QueueDirectory, $"test_{TestKeyVersion}.event");
        WriteEventFile(eventFile, changeEvent, "secret");

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(50));

        Assert.False(File.Exists(eventFile), "File should have been moved out of queue directory");
    }

    [Fact]
    public async Task EventFileIsDeletedAfterSuccessfulProcessing()
    {
        var changeEvent = new PasswordChangeEvent("Jon Doe", "EvilCorp", string.Empty);
        var fileName = $"test_{TestKeyVersion}.event";
        WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, fileName), changeEvent, "secret");

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(800));

        Assert.False(File.Exists(Path.Combine(_configurationProvider.QueueDirectory, fileName)));
        Assert.False(File.Exists(Path.Combine(_configurationProvider.ProcessingQueueDirectory, fileName)));
        Assert.False(File.Exists(Path.Combine(_configurationProvider.FailedQueueDirectory, fileName)));
    }

    [Fact]
    public async Task MultipleEventFilesAreAllProcessed()
    {
        for (int i = 1; i <= 100; i++)
        {
            var changeEvent = new PasswordChangeEvent { Username = $"Jon Doe{i}", Domain = "EvilCorp", Password = string.Empty };
            WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, $"event{i}_{TestKeyVersion}.event"), changeEvent, "secret");
        }

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(2000));

        Assert.Empty(Directory.EnumerateFiles(_configurationProvider.QueueDirectory, "*.event"));
        Assert.Empty(Directory.EnumerateFiles(_configurationProvider.ProcessingQueueDirectory, "*.event"));
        Assert.Empty(Directory.EnumerateFiles(_configurationProvider.FailedQueueDirectory, "*.event"));
    }

    [Fact]
    public async Task NotEncodedFileShouldMovedToFailedDirectory()
    {
        var fileName = $"not_encoded_{TestKeyVersion}.event";
        var eventFile = Path.Combine(_configurationProvider.QueueDirectory, fileName);
        File.WriteAllText(eventFile, "{}");

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(800));

        Assert.False(File.Exists(eventFile), "File should have been moved out of queue directory");
        Assert.False(File.Exists(Path.Combine(_configurationProvider.ProcessingQueueDirectory, fileName)));
        Assert.True(File.Exists(Path.Combine(_configurationProvider.FailedQueueDirectory, fileName)),
            "File was not encoded and should be moved to failure directory");
    }

    [Fact]
    public async Task EmptyQueueDoesNotCauseErrors()
    {
        var exception = await Record.ExceptionAsync(() => RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(100)));

        Assert.Null(exception);
    }

    [Fact]
    public async Task NonEventFilesInQueueAreIgnored()
    {
        File.WriteAllText(Path.Combine(_configurationProvider.QueueDirectory, "readme.txt"), "some text");

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(200));

        Assert.True(File.Exists(Path.Combine(_configurationProvider.QueueDirectory, "readme.txt")), "Non-.event file should remain untouched");
    }

    [Fact]
    public async Task EventFileIsMovedToFailedAndScheduledForRetryOnMidPointRejection()
    {
        _server.Reset();
        _server.Given(Request.Create().WithPath(NotifyChangePath).UsingPost())
               .RespondWith(Response.Create().WithStatusCode(500));

        var changeEvent = new PasswordChangeEvent("Jon Doe", "EvilCorp", string.Empty);
        var fileName = $"rejected_{TestKeyVersion}.event";
        WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, fileName), changeEvent, "secret");

        await RunWorkerBriefly(CreateSenderWorker(), TimeSpan.FromMilliseconds(800));

        var failedPath = Path.Combine(_configurationProvider.FailedQueueDirectory, fileName);
        Assert.False(File.Exists(Path.Combine(_configurationProvider.ProcessingQueueDirectory, fileName)));
        Assert.True(File.Exists(failedPath), "File should be in failed directory scheduled for retry");
        Assert.False(File.Exists(Path.Combine(_configurationProvider.DeadLetterQueueDirectory, fileName)));

        var parsed = JsonSerializer.Deserialize<PasswordChangeEvent>(File.ReadAllText(failedPath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        Assert.NotNull(parsed);
        Assert.Equal(1, parsed.Metadata?.RetryCount);
        Assert.True(parsed.Metadata?.NextRetryAt > DateTimeOffset.UtcNow);
        Assert.NotNull(parsed.Metadata?.LastError);
        Assert.Contains("500", parsed.Metadata?.LastError);
        Assert.Equal(TimeZoneInfo.Local.GetUtcOffset(DateTime.Now), parsed.Metadata?.NextRetryAt?.Offset);
    }

    [Fact]
    public async Task EventFileIsMovedToDlqAfterExhaustedRetries()
    {
        _server.Reset();
        _server.Given(Request.Create().WithPath(NotifyChangePath).UsingPost())
               .RespondWith(Response.Create().WithStatusCode(500));

        var changeEvent = new PasswordChangeEvent("Jon Doe", "EvilCorp", string.Empty);
        var fileName = $"dlq_test_{TestKeyVersion}.event";
        WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, fileName), changeEvent, "secret");

        await RunWorkerBriefly(CreateWorkerWithMaxRetryCount(0), TimeSpan.FromMilliseconds(800));

        Assert.False(File.Exists(Path.Combine(_configurationProvider.ProcessingQueueDirectory, fileName)));
        Assert.False(File.Exists(Path.Combine(_configurationProvider.FailedQueueDirectory, fileName)));
        Assert.True(File.Exists(Path.Combine(_configurationProvider.DeadLetterQueueDirectory, fileName)),
            "File should be moved to DLQ after exhausting all retries");
    }

    [Fact]
    public async Task RateLimitThrottlesSendsBeyondLimit()
    {
        for (int i = 1; i <= 3; i++)
        {
            var changeEvent = new PasswordChangeEvent($"User{i}", "EvilCorp", "secret");
            WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, $"rate{i}_{TestKeyVersion}.event"), changeEvent, "secret");
        }

        using var worker = CreateSenderWorkerWithRateLimit(1);
        await RunWorkerBriefly(worker, TimeSpan.FromMilliseconds(500));

        Assert.Empty(Directory.GetFiles(_configurationProvider.QueueDirectory, "*.event"));
        Assert.Equal(2, Directory.GetFiles(_configurationProvider.ProcessingQueueDirectory, "*.event").Length);
        Assert.Empty(Directory.GetFiles(_configurationProvider.FailedQueueDirectory, "*.event"));
    }

    [Fact]
    public async Task RequestsBelowRateLimitProcessNormally()
    {
        for (int i = 1; i <= 3; i++)
        {
            var changeEvent = new PasswordChangeEvent($"User{i}", "EvilCorp", "secret");
            WriteEventFile(Path.Combine(_configurationProvider.QueueDirectory, $"rate{i}_{TestKeyVersion}.event"), changeEvent, "secret");
        }

        using var worker = CreateSenderWorkerWithRateLimit(10);
        await RunWorkerBriefly(worker, TimeSpan.FromMilliseconds(800));

        Assert.Empty(Directory.GetFiles(_configurationProvider.QueueDirectory, "*.event"));
        Assert.Empty(Directory.GetFiles(_configurationProvider.ProcessingQueueDirectory, "*.event"));
        Assert.Empty(Directory.GetFiles(_configurationProvider.FailedQueueDirectory, "*.event"));
    }

    private SenderWorker CreateSenderWorkerWithRateLimit(int maxRequestsPerMinute)
    {
        var rateLimitedConfig = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                QueueDirectory = _configurationProvider.QueueDirectory,
                PollInterval = TimeSpan.FromMilliseconds(10),
                MaxRequestsPerMinute = maxRequestsPerMinute,
            }
        );
        return new SenderWorker(_appLogger, rateLimitedConfig, _queueService, _midPointService, _cryptoService, new MidPointRateLimiter(rateLimitedConfig));
    }

}
