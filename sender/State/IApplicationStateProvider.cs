namespace Sender.State
{
    public interface IApplicationStateProvider
    {
        ApplicationState CurrentState { get; }

        bool IsKeyRotationRequired();
        Task UpdateLastRotationTimeStampAsync();

        bool IsKeyCleanupRequired();
        Task UpdateLastCleanupTimeStampAsync();
    }
}
