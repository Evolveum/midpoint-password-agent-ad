/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Serilog;
using Sender.Logger;

namespace Sender.Tests;

public class LogRotationTests : IDisposable
{
    private readonly string _logDir;

    public LogRotationTests()
    {
        _logDir = Path.Combine(Path.GetTempPath(), $"sender-log-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_logDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_logDir))
            Directory.Delete(_logDir, recursive: true);
    }

    private Serilog.Core.Logger BuildLogger(long fileSizeLimitBytes, int retainedFileCountLimit) =>
        new LoggerConfiguration()
            .WriteTo.File(
                new JsonLogFormatter(),
                Path.Combine(_logDir, "sender.json"),
                fileSizeLimitBytes: fileSizeLimitBytes,
                rollOnFileSizeLimit: true,
                retainedFileCountLimit: retainedFileCountLimit)
            .CreateLogger();

    private void WriteEnoughToRoll(Serilog.Core.Logger logger, int entryCount)
    {
        for (int i = 0; i < entryCount; i++)
            logger.Information("Log rotation test entry number {Number}", i);
    }

    [Fact]
    public void FilesExceedingRetainedLimit_AreDeleted()
    {
        using (var logger = BuildLogger(fileSizeLimitBytes: 150, retainedFileCountLimit: 2))
            WriteEnoughToRoll(logger, 30);

        Assert.Equal(2, Directory.GetFiles(_logDir, "*.json").Length);
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public void RetainedFileCount_MatchesConfiguredLimit(int retainedLimit)
    {
        using (var logger = BuildLogger(fileSizeLimitBytes: 150, retainedFileCountLimit: retainedLimit))
            WriteEnoughToRoll(logger, 50);

        Assert.Equal(retainedLimit, Directory.GetFiles(_logDir, "*.json").Length);
    }
}
