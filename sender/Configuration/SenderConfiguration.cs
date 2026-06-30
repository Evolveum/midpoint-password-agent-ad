/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using Sender.MidPoint;

namespace Sender.Configuration
{
    public record class SenderConfiguration : SenderJsonConfiguration
    {
        public string RootPath { get; init; } = string.Empty;
        public string QueueDirectory { get; init; } = string.Empty;
        public MidPointClientConfiguration MidPoint { get; init; } = new();
        public string ProcessingQueueDirectory => Path.Combine(QueueDirectory, Constants.Queue.ProcessingFolderName);
        public string FailedQueueDirectory => Path.Combine(QueueDirectory, Constants.Queue.FailedFolderName);
        public string StagingDirectory => Path.Combine(QueueDirectory, Constants.Queue.StagingFolderName);
        public string DeadLetterQueueDirectory => Path.Combine(QueueDirectory, Constants.Queue.DeadLetterQueueFolderName);

        public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(300);

        /* used in KeyRotation and KeyCleanup */
        public TimeSpan LongTermPollInterval { get; init; } = TimeSpan.FromHours(1);

        public TimeSpan KeyReencryptionTimeout { get; init; } = TimeSpan.FromSeconds(2);

        public string KeyRegistryPath { get; init; } = @"SOFTWARE\Evolveum\MidPointPasswordAgent\Keys";
        public string LatestKeyRegistryName { get; init; } = "LatestKey";

        public string SaveFileName { get; init; } = "state.json";
        public string SaveFilePath => Path.Combine(RootPath, Constants.Service.DataFolderName, SaveFileName);
    }
}
