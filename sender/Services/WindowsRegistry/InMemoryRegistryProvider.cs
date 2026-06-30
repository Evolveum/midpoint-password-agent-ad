namespace Sender.WindowsRegistry;

internal class InMemoryRegistryProvider(Dictionary<string, string> initialValues) : IWindowsRegistryProvider
{
    private readonly Dictionary<string, string> inMemoryRegistry = initialValues;

    public string? GetProtectedString(string valueName)
    {
        if (inMemoryRegistry.TryGetValue(valueName, out var result))
            return result;
        return "";
    }

    public string GetRequiredProtectedString(string valueName)
    {
        return inMemoryRegistry[valueName];
    }

    public string GetRequiredString(string valueName)
    {
        return GetRequiredProtectedString(valueName);
    }

    public string? GetString(string valueName)
    {
        return GetProtectedString(valueName);
    }
}