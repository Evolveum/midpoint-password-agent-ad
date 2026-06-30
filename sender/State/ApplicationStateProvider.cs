using System.Text.Json;
using Sender.Configuration;
using Sender.Logger;
using Sender.Queue;

namespace Sender.State;

public class ApplicationStateProvider : IApplicationStateProvider
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly AppLogger appLogger;
    private readonly SenderConfigurationProvider configurationProvider;

    public ApplicationState CurrentState
    {
        get;
        private set;
    }

    public ApplicationStateProvider(
        AppLogger appLogger,
        SenderConfigurationProvider configurationProvider)
    {
        this.appLogger = appLogger;
        this.configurationProvider = configurationProvider;

        CurrentState = LoadLastState();
    }

    private ApplicationState LoadLastState()
    {
        try
        {
            if (File.Exists(configurationProvider.SaveFilePath))
            {
                var savedJson = File.ReadAllText(configurationProvider.SaveFilePath);

                var restoredState = JsonSerializer.Deserialize(savedJson, SenderJsonContext.Default.NullableApplicationState);
                if (!restoredState.HasValue)
                {
                    appLogger.ToFile("No previous state found.");
                    return default;
                }

                appLogger.ToFile("Resumed from previous state.");
                return restoredState.Value;
            }

            appLogger.ToFile("No previous state found.");
            return default;
        }
        catch
        {
            appLogger.ToFile("Error loading previous state");
            return default;
        }
    }

    private Task PersistCurrentState()
    {
        var jsonString = JsonSerializer.Serialize(CurrentState, SenderJsonContext.Default.ApplicationState);
        var dir = Path.GetDirectoryName(configurationProvider.SaveFilePath);
        if (dir != null)
            Directory.CreateDirectory(dir);
        return File.WriteAllTextAsync(configurationProvider.SaveFilePath, jsonString);
    }

    private async Task UpdateCurrentState(Func<ApplicationState, ApplicationState> updateFn)
    {
        await _lock.WaitAsync();
        try
        {
            var nextState = updateFn(CurrentState);
            CurrentState = nextState;
            await PersistCurrentState();
        }
        finally
        {
            _lock.Release();
        }
    }

    public Task UpdateLastRotationTimeStampAsync() =>
        UpdateCurrentState(_state => CurrentState with { LastKeyRotationTimeStamp = DateTime.UtcNow });

    public Task UpdateLastCleanupTimeStampAsync() =>
        UpdateCurrentState(_state => CurrentState with { LastKeyCleanupTimestamp = DateTime.UtcNow });

    public bool IsKeyRotationRequired()
    {
        var lastUpdateSpan = DateTime.UtcNow - CurrentState.LastKeyRotationTimeStamp;
        return !lastUpdateSpan.HasValue || lastUpdateSpan >= configurationProvider.KeyRotationInterval;
    }

    public bool IsKeyCleanupRequired()
    {
        var lastUpdateSpan = DateTime.UtcNow - CurrentState.LastKeyCleanupTimestamp;
        return !lastUpdateSpan.HasValue || lastUpdateSpan >= configurationProvider.KeyCleanupInterval;
    }
}
