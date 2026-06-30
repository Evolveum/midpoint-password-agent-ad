using Microsoft.Extensions.Logging.Abstractions;
using Sender.Configuration;
using Sender.Logger;
using Sender.State;
using Sender.Worker;

public sealed class KeyRotationWorkerTests : IDisposable
{
    const int ROTATION_INTERVAL = 2;
    const int POLL_INTERVAL = 1;

    private SenderConfigurationProvider _configurationProvider;
    private readonly AppLogger _appLogger;
    private readonly ApplicationStateProvider _stateProvider;

    public KeyRotationWorkerTests()
    {
        _configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                LongTermPollInterval = TimeSpan.FromSeconds(POLL_INTERVAL),
                KeyRotationInterval = TimeSpan.FromSeconds(ROTATION_INTERVAL),
                RootPath = "../",
                SaveFileName = "rotationState.json"
            }
        );
        _appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        _stateProvider = new ApplicationStateProvider(_appLogger, _configurationProvider);
    }
    [Fact]
    public async Task ShouldCorrectlyUpdateTimestamp()
    {
        var worker = new KeyRotationWorker(
            _configurationProvider, _appLogger,
            new KeyRotationServiceMock(),
            _stateProvider);

        var stopToken = new CancellationTokenSource();
        _ = worker.StartAsync(stopToken.Token);

        // TODO: might be better to replace with fake timer
        await Task.Delay(TimeSpan.FromSeconds(3 * ROTATION_INTERVAL));

        Assert.True(DateTime.UtcNow - _stateProvider.CurrentState.LastKeyRotationTimeStamp < TimeSpan.FromSeconds(ROTATION_INTERVAL));

        stopToken.Cancel();
    }

    public void Dispose()
    {
        if (File.Exists("../rotationState.json"))
        {
            File.Delete("../rotationState.json");
        }
    }
}
