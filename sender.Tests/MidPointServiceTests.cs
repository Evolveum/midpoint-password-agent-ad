/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using Microsoft.Extensions.Logging.Abstractions;
using Sender.Configuration;
using Sender.Logger;
using Sender.MidPoint;
using Sender.Queue;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Sender.Tests;

public class MidPointServiceTests : IDisposable
{
    private readonly WireMockServer _server;
    private readonly MidPointService _service;
    private const string NotifyChangePath = "/midpoint/ws/rest/notifyChange";
    private readonly PasswordChangeEvent _testEvent = new("Jon Doe", "EvilCorp", "secret");

    public MidPointServiceTests()
    {
        _server = WireMockServer.Start();
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var configProvider = new SenderConfigurationProvider(new SenderConfiguration
        {
            MidPoint = new MidPointClientConfiguration
            {
                BaseUrl = _server.Urls[0] + "/midpoint",
                Username = "admin",
                Password = Convert.ToBase64String("secret"u8.ToArray())
            }
        });
        _service = new MidPointService(appLogger, configProvider, new BasicAuthHandler(configProvider));
    }

    public void Dispose() => _server.Stop();

    private void SetupResponse(int statusCode) =>
        _server.Given(Request.Create().WithPath(NotifyChangePath).UsingPost())
               .RespondWith(Response.Create().WithStatusCode(statusCode));

    // ---------------------------------------------------------------------------
    // Success
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData(200)]
    [InlineData(240)]
    [InlineData(250)]
    public async Task ReturnsTrueOnSuccessResponse(int statusCode)
    {
        SetupResponse(statusCode);

        var (sent, lastError) = await _service.SendPasswordChange(_testEvent);

        Assert.True(sent);
        Assert.Null(lastError);
    }

    [Fact]
    public async Task PostsToCorrectEndpoint()
    {
        SetupResponse(200);

        await _service.SendPasswordChange(_testEvent);

        Assert.Single(_server.LogEntries, e => e.RequestMessage?.Path == NotifyChangePath);
    }

    [Fact]
    public async Task SetsBasicAuthorizationHeader()
    {
        SetupResponse(200);

        await _service.SendPasswordChange(_testEvent);

        var entry = _server.LogEntries.Single();
        var headers = entry.RequestMessage?.Headers;
        Assert.NotNull(headers);
        Assert.True(headers.ContainsKey("Authorization"));
        Assert.StartsWith("Basic ", headers["Authorization"].First());
    }

    // ---------------------------------------------------------------------------
    // Failure — single attempt, move to failed
    // ---------------------------------------------------------------------------

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    [InlineData(503)]
    public async Task ReturnsFalseOnNonSuccessResponse(int statusCode)
    {
        SetupResponse(statusCode);

        var (sent, lastError) = await _service.SendPasswordChange(_testEvent);

        Assert.False(sent);
        Assert.NotNull(lastError);
        Assert.Single(_server.LogEntries);
    }

    // ---------------------------------------------------------------------------
    // Cancellation
    // ---------------------------------------------------------------------------

    [Fact]
    public async Task ThrowsWhenCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _service.SendPasswordChange(_testEvent, cts.Token));
    }
}
