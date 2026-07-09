namespace Sender.State
{
    // State of application
    public struct ApplicationState
    {
        // When was last key rotation done
        public DateTime? LastKeyRotationTimeStamp { get; init; }
        // When was last key cleanup done
        public DateTime? LastKeyCleanupTimestamp { get; init; }
    }
}
