using Microsoft.Extensions.Logging.Abstractions;
using Sender.Configuration;
using Sender.Logger;
using Sender.State;
using Sender.Worker;

public sealed class KeyCleanupWorkerTests : IDisposable
{
    const int ROTATION_INTERVAL = 2;
    const int POLL_INTERVAL = 1;
    private SenderConfigurationProvider _configurationProvider;
    private readonly AppLogger _appLogger;
    private readonly ApplicationStateProvider _stateProvider;

    public KeyCleanupWorkerTests()
    {
        _configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                LongTermPollInterval = TimeSpan.FromSeconds(POLL_INTERVAL),
                KeyCleanupInterval = TimeSpan.FromSeconds(ROTATION_INTERVAL),
                RootPath = "../",
                SaveFileName = "cleanupState.json"
            }
        );
        _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        _stateProvider = new ApplicationStateProvider(_appLogger, _configurationProvider);
    }

    [Fact]
    public async Task ShouldCorrectlyUpdateTimestamp()
    {
        var worker = new KeyCleanupWorker(
            _configurationProvider, _appLogger,
            new KeyRotationServiceMock(),
            _stateProvider);

        var stopToken = new CancellationTokenSource();
        _ = worker.StartAsync(stopToken.Token);

        // TODO: might be better to replace with fake timer
        await Task.Delay(TimeSpan.FromSeconds(3 * ROTATION_INTERVAL));

        Assert.True(DateTime.UtcNow - _stateProvider.CurrentState.LastKeyCleanupTimestamp < TimeSpan.FromSeconds(ROTATION_INTERVAL));

        stopToken.Cancel();
    }

    public void Dispose()
    {
        if (File.Exists("../cleanupState.json"))
        {
            File.Delete("../cleanupState.json");
        }
    }
}
