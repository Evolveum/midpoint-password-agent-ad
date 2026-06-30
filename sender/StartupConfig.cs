/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Sender.WindowsRegistry;

namespace Sender;

public class StartupConfig
{
    public string LogDirectory { get; init; }
    public string LogPath {get; init; }
    public string ConfigPath { get; init; }
    public string QueueDirectory { get; init; }
    public string RootPath { get; init; }

    public StartupConfig(IWindowsRegistryProvider registryProvider)
    {
        RootPath = registryProvider.GetRequiredString(Constants.Registry.RootPath);
        LogDirectory = Path.Combine(RootPath, Constants.Logger.LoggerFolderName);
        LogPath = Path.Combine(LogDirectory, Constants.Logger.LoggerFileName);
        ConfigPath = Path.Combine(RootPath, Constants.Config.ConfigFolderName, Constants.Config.ConfigFileName);
        QueueDirectory = Path.Combine(RootPath, Constants.Service.DataFolderName, Constants.Queue.QueueFolderName);
    }
}
