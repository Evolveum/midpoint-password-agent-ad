/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Text.Json;
using Sender.Configuration;
using Sender.Logger;

namespace Sender.Queue
{
    public class QueueService
    {

        private readonly AppLogger appLogger;
        private readonly SenderConfigurationProvider configuration;

        public QueueService(AppLogger appLogger, SenderConfigurationProvider configuration)
        {
            this.appLogger = appLogger;
            this.configuration = configuration;

            this.InitDirectoryStructure();
        }

        public void InitDirectoryStructure()
        {
            // Create used directories inside queue directory
            Directory.CreateDirectory(configuration.QueueDirectory);
            Directory.CreateDirectory(configuration.ProcessingQueueDirectory);
            Directory.CreateDirectory(configuration.FailedQueueDirectory);
            Directory.CreateDirectory(configuration.StagingDirectory);
            Directory.CreateDirectory(configuration.DeadLetterQueueDirectory);
        }

        public List<PasswordChangeEvent> GetPasswordChangeEvents()
        {
            foreach (var eventFile in Directory.EnumerateFiles(configuration.QueueDirectory, $"*{Constants.Queue.FileExtension}"))
            {
                var fileName = Path.GetFileName(eventFile);
                var dest = Path.Combine(configuration.ProcessingQueueDirectory, fileName);
                appLogger.ToFile($"Found {fileName} event file in queue directory");

                File.Move(eventFile, dest, overwrite: true);
                appLogger.ToFile($"Moved {fileName} event file to processing directory");
            }

            foreach (var eventFile in Directory.EnumerateFiles(configuration.FailedQueueDirectory, $"*{Constants.Queue.FileExtension}"))
            {
                var retryEvent = TryParseEventFile(eventFile);
                if (retryEvent is null) continue;
                if (retryEvent.Metadata?.NextRetryAt > DateTimeOffset.UtcNow) continue;

                var fileName = Path.GetFileName(eventFile);
                var dest = Path.Combine(configuration.ProcessingQueueDirectory, fileName);
                File.Move(eventFile, dest, overwrite: true);
                appLogger.ToFile($"Moved {fileName} from failed to processing for retry #{retryEvent.Metadata?.RetryCount}");
            }

            // Always try to load files for processing
            var filesToProcess = Directory.EnumerateFiles(configuration.ProcessingQueueDirectory, $"*{Constants.Queue.FileExtension}").ToList();
            if (filesToProcess.Count == 0)
            {
                return new List<PasswordChangeEvent>();
            }

            appLogger.ToFile($"Found {filesToProcess.Count} event file(s) to process");
            List<PasswordChangeEvent> parsedEvents = new List<PasswordChangeEvent>();
            foreach (var eventFile in filesToProcess)
            {
                var passwordEvent = ParseEventFile(eventFile);
                if (passwordEvent is null) continue;

                parsedEvents.Add(passwordEvent);
                appLogger.ToFile($"Processed: {Path.GetFileName(eventFile)}");
            }

            return parsedEvents;
        }

        public bool RemoveEvent(PasswordChangeEvent changeEvent)
        {
            if (changeEvent.FilePath != null)
            {
                File.Delete(changeEvent.FilePath);
                appLogger.ToFile($"Deleted file {changeEvent.FilePath}");
                return true;
            }

            return false;
        }

        public bool MoveToDlq(PasswordChangeEvent changeEvent)
        {
            if (changeEvent.FilePath == null) return false;

            var fileName = Path.GetFileName(changeEvent.FilePath);
            var dlqPath = Path.Combine(configuration.DeadLetterQueueDirectory, fileName);
            File.Move(changeEvent.FilePath, dlqPath, overwrite: true);
            appLogger.ToAll(
                $"Password change event for {changeEvent.Username}@{changeEvent.Domain} exhausted all {changeEvent.Metadata?.RetryCount ?? 0} retries and was moved to DLQ: {fileName}",
                LogLevel.Error);
            return true;
        }

        public void MarkEventForRetry(PasswordChangeEvent changeEvent, DateTimeOffset nextRetryAt, string? lastError = null)
        {
            if (changeEvent.FilePath == null) return;

            changeEvent.Metadata = new PasswordChangeEvent.EventMetadata
            {
                RetryCount = (changeEvent.Metadata?.RetryCount ?? 0) + 1,
                NextRetryAt = nextRetryAt,
                LastError = lastError
            };

            var fileName = Path.GetFileName(changeEvent.FilePath);
            var dest = Path.Combine(configuration.FailedQueueDirectory, fileName);

            File.WriteAllText(dest, JsonSerializer.Serialize(changeEvent, SenderJsonContext.Default.PasswordChangeEvent));

            if (changeEvent.FilePath != dest)
                File.Delete(changeEvent.FilePath);

            changeEvent.FilePath = dest;
            appLogger.ToFile($"Scheduled retry #{changeEvent.Metadata.RetryCount} for {changeEvent.Username}@{changeEvent.Domain} at {nextRetryAt:O}");
        }

        public PasswordChangeEvent? ParseEventFile(string filePath)
        {
            var fileName = Path.GetFileName(filePath);
            var passwordEvent = TryParseEventFile(filePath);
            if (passwordEvent != null)
            {
                appLogger.ToFile($"Parsed: {fileName} user={passwordEvent.Username} domain={passwordEvent.Domain} retryCount={passwordEvent.Metadata?.RetryCount ?? 0}");
                return passwordEvent;
            }

            appLogger.ToFile($"Failed to parse {fileName}", LogLevel.Error);
            File.Move(filePath, Path.Combine(configuration.FailedQueueDirectory, fileName), overwrite: true);
            appLogger.ToFile($"Moved {fileName} to failed directory", LogLevel.Error);
            return null;
        }

        private PasswordChangeEvent? TryParseEventFile(string filePath)
        {
            try
            {
                var json = File.ReadAllText(filePath);
                var passwordEvent = JsonSerializer.Deserialize(json, SenderJsonContext.Default.PasswordChangeEvent);
                if (string.IsNullOrEmpty(passwordEvent?.Password))
                    return null;

                passwordEvent.FilePath = filePath;
                return passwordEvent;
            }
            catch (Exception ex)
            {
                appLogger.ToFile($"TryParseEventFile failed for {Path.GetFileName(filePath)}: {ex.Message}", LogLevel.Error);
                return null;
            }
        }

        public static string GetEventFileKeyVersionSuffix(string keyVersion)
        {
            return $"{keyVersion}.event";
        }

        public List<string> GetEvenFilesByKeyVersion(string keyVersion)
        {
            return Directory.EnumerateFiles(configuration.QueueDirectory, $"*{Constants.Queue.FileExtension}", SearchOption.AllDirectories)
                       .Where(f => f.EndsWith(GetEventFileKeyVersionSuffix(keyVersion), StringComparison.OrdinalIgnoreCase))
                       .ToList();
        }
    }
}
