using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json;
using Sender.Configuration;
using Sender.Logger;
using Sender.State;

public sealed class ApplicationStateTests : IDisposable
{
    const string VALID_STATE_FILE = "test-valid.json";
    const string INVALID_STATE_FILE = "test-invalid.json";
    const string TEST_STATE_FILE = "test-state.json";

    [Fact]
    public void InitCleanAppState()
    {
        if (File.Exists("dummy.json"))
        {
            File.Delete("dummy.json");
        }
        var configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                RootPath = "./",
                SaveFileName = "dummy.json"
            }
        );
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var stateProvider = new ApplicationStateProvider(appLogger, configurationProvider);

        Assert.Null(stateProvider.CurrentState.LastKeyCleanupTimestamp);
        Assert.Null(stateProvider.CurrentState.LastKeyRotationTimeStamp);
    }

    [Fact]
    public async Task InitAppStateFromFile()
    {
        var testState = new ApplicationState
        {
            LastKeyCleanupTimestamp = DateTime.Parse("2026-01-01"),
            LastKeyRotationTimeStamp = DateTime.Parse("2026-03-03"),
        };

        var configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                RootPath = "./",
                SaveFileName = VALID_STATE_FILE
            }
        );
        Directory.CreateDirectory(Path.GetDirectoryName(configurationProvider.SaveFilePath)!);
        await File.WriteAllTextAsync(configurationProvider.SaveFilePath, JsonConvert.SerializeObject(testState));
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var stateProvider = new ApplicationStateProvider(appLogger, configurationProvider);

        Assert.Equal(
            testState.LastKeyCleanupTimestamp,
            stateProvider.CurrentState.LastKeyCleanupTimestamp
        );
        Assert.Equal(
            testState.LastKeyRotationTimeStamp,
            stateProvider.CurrentState.LastKeyRotationTimeStamp
        );
    }

    [Fact]
    public async Task InitAppStateFromMalformedFile()
    {
        await File.WriteAllTextAsync(INVALID_STATE_FILE, "incorrect JSON");

        var configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                RootPath = "./",
                SaveFileName = INVALID_STATE_FILE
            }
        );
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var stateProvider = new ApplicationStateProvider(appLogger, configurationProvider);

        Assert.Null(stateProvider.CurrentState.LastKeyCleanupTimestamp);
        Assert.Null(stateProvider.CurrentState.LastKeyRotationTimeStamp);
    }

    [Fact]
    public async Task SaveAppStateToFile()
    {
        var configurationProvider = new SenderConfigurationProvider(
            new SenderConfiguration
            {
                RootPath = "./",
                SaveFileName = TEST_STATE_FILE
            }
        );
        var appLogger = new AppLogger(NullLogger<AppLogger>.Instance);
        var stateProvider = new ApplicationStateProvider(appLogger, configurationProvider);

        await stateProvider.UpdateLastCleanupTimeStampAsync();
        await stateProvider.UpdateLastRotationTimeStampAsync();

        var restoredState = JsonConvert.DeserializeObject<ApplicationState>(
            File.ReadAllText(configurationProvider.SaveFilePath)
        );

        Assert.Equal(restoredState.LastKeyCleanupTimestamp, stateProvider.CurrentState.LastKeyCleanupTimestamp);
        Assert.Equal(restoredState.LastKeyRotationTimeStamp, stateProvider.CurrentState.LastKeyRotationTimeStamp);
    }

    public void Dispose()
    {
        // Delete all files inside Data folder
        var dataDir = Path.Combine("./", Sender.Constants.Service.DataFolderName);
        if (Directory.Exists(dataDir))
            Directory.Delete(dataDir, recursive: true);
    }
}
