
using Sender.KeyRotation;

internal class KeyRotationServiceMock : IKeyRotationService
{
    public Task CleanupExpiredKeysAsync()
    {
        return Task.CompletedTask;
    }

    public Task RotateAsync()
    {
        return Task.CompletedTask;
    }
}
