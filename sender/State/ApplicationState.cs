namespace Sender.State
{
    public struct ApplicationState
    {
        public DateTime? LastKeyRotationTimeStamp { get; init; }
        public DateTime? LastKeyCleanupTimestamp { get; init; }
    }
}
