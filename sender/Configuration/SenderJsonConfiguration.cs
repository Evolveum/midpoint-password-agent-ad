/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Serilog.Events;

namespace Sender.Configuration;

public record class SenderJsonConfiguration
{
    public TimeSpan KeyRotationInterval { get; set; } = TimeSpan.FromDays(20);
    public TimeSpan KeyRotationGracePeriod { get; set; } = TimeSpan.FromDays(3);
    public TimeSpan KeyCleanupInterval { get; set; } = TimeSpan.FromDays(1);
    public LogEventLevel LogLevel { get; set; } = LogEventLevel.Information;
    public long LogFileSizeLimitBytes { get; set; } = 5 * 1024 * 1024;
    public int LogRetainedFileCountLimit { get; set; } = 3;

    public int MaxRequestsPerMinute { get; set; } = 0;
    public int MaxRetryCount { get; set; } = 5;
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMinutes(1);
    public TimeSpan RetryMaxDelay { get; set; } = TimeSpan.FromHours(1);
}
