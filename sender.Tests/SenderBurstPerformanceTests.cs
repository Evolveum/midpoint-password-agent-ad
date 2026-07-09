/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
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

public class SenderBurstPerformanceTests
{
    private const int EventCount = 100;

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(20)]
    public async Task ReportsBurstThroughput(int maxQueueDepth)
    {
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var keyProvider = new InMemoryKeyProvider(appLogger);
        keyProvider.StoreKey("v1", RandomNumberGenerator.GetBytes(32));
        var cryptoService = new CryptoService(appLogger, keyProvider);

        using var server = WireMockServer.Start();
        server.Given(Request.Create().WithPath("/ws/rest/notifyChange").UsingPost())
              .RespondWith(Response.Create().WithStatusCode(200).WithDelay(TimeSpan.FromMilliseconds(25)));

        var queueDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        var config = new SenderConfigurationProvider(new SenderConfiguration
        {
            QueueDirectory = queueDir,
            PollInterval = TimeSpan.FromMilliseconds(10),
            MaxQueueDepth = maxQueueDepth,
            MidPoint = new MidPointClientConfiguration { BaseUrl = server.Urls[0] }
        });
        var queueService = new QueueService(appLogger, config);
        var midPointService = new MidPointService(appLogger, config, new BasicAuthHandler(config));
        using var worker = new SenderWorker(appLogger, config, queueService, midPointService, cryptoService, new MidPointRateLimiter(config, appLogger));

        for (int i = 1; i <= EventCount; i++)
        {
            var encrypted = cryptoService.EncryptPassword(new PasswordChangeEvent($"User{i}", "EvilCorp", "secret"), "v1");
            File.WriteAllText(Path.Combine(queueDir, $"event{i}_v1.event"), JsonSerializer.Serialize(encrypted));
        }

        bool Drained() => !Directory.EnumerateFiles(queueDir, "*.event", SearchOption.AllDirectories).Any();

        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        while (!Drained() && sw.Elapsed < TimeSpan.FromSeconds(30))
            await Task.Delay(20);
        sw.Stop();
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        Console.WriteLine(
            $"[MaxQueueDepth={maxQueueDepth,2}] {EventCount} events in {sw.ElapsedMilliseconds}ms " +
            $"= {EventCount / sw.Elapsed.TotalSeconds:N1} events/sec (requests seen: {server.LogEntries.Count()})");

        Assert.True(Drained(), $"Burst of {EventCount} events did not fully drain within 30s at MaxQueueDepth={maxQueueDepth}");
        Assert.Equal(EventCount, server.LogEntries.Count());

        Directory.Delete(queueDir, recursive: true);
    }
}
