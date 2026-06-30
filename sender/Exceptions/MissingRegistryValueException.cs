namespace Sender.Exceptions
{
    public class MissingRegistryValueException : Exception
    {
        public string MissingKey { get; }

        public MissingRegistryValueException(string missingKey) : base($"{missingKey} is not configured in the Windows registry.")
        {
            MissingKey = missingKey;
        }

        public MissingRegistryValueException(string missingKey, Exception? innerException) : base($"{missingKey} is not configured in the Windows registry.", innerException)
        {
            MissingKey = missingKey;
        }
    }
}