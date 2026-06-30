/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

namespace Sender;

public static class Constants
{
    public static class Registry
    {
        public const string SubKeyPath = @"SOFTWARE\Evolveum\MidPointPasswordAgent";
        public const string FullPath = @"HKEY_LOCAL_MACHINE\" + SubKeyPath;

        public const string LogPath = "LogPath";
        public const string ConfigPath = "ConfigPath";
        public const string QueuePath = "QueuePath";
        public const string RootPath = "RootPath";
    }

    public static class Logger
    {
        public const string LoggerFolderName = "Logs";
        public const string LoggerFileName = "sender.json";
    }

    public static class Config
    {
        public const string ConfigFolderName = "Config";
        public const string ConfigFileName = "config.json";
    }

    public static class Crypto
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;
        public const int KeyBytes = 32;

        public const string InitialKeyVersion = "v1";
    }

    public static class Queue
    {
        public const string FileExtension = ".event";
        public const string QueueFolderName = "Queue";
        public const string ProcessingFolderName = "processing";
        public const string FailedFolderName = "failed";
        public const string StagingFolderName = "staging";
        public const string DeadLetterQueueFolderName = "dlq";
    }

    public static class Service
    {
        public const string Name = "MidPointPasswordAgentSender";
        public const string DataFolderName = "Data";
    }
}
