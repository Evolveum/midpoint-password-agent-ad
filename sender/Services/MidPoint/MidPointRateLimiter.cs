/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Threading.RateLimiting;
using Sender.Configuration;
using Sender.Logger;

namespace Sender.MidPoint;

/// <summary>
/// MidPoint request rate limitter
/// </summary>
public class MidPointRateLimiter : IDisposable
{
    private RateLimiter? _limiter;
    private readonly AppLogger _logger;

    public MidPointRateLimiter(SenderConfigurationProvider configuration, AppLogger logger)
    {
        this._logger = logger;
        var max = configuration.MaxRequestsPerMinute;
        if (max <= 0) return;

        _limiter = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            TokensPerPeriod = max,
            TokenLimit = max,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = int.MaxValue,
            AutoReplenishment = true,
        });
    }

    public async ValueTask<bool> WaitAsync(CancellationToken cancellationToken)
    {
        var limiter = _limiter;
        if (limiter != null)
        {
            var lease = await limiter.AcquireAsync(1, cancellationToken);
            return lease.IsAcquired;
        }

        return true;
    }

    public void Dispose() => _limiter?.Dispose();

    public void Update(SenderConfigurationProvider configuration)
    {
        var max = configuration.MaxRequestsPerMinute;
        var newLimiter = max <= 0
            ? null
            : new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
            {
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                TokensPerPeriod = max,
                TokenLimit = max,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = int.MaxValue,
                AutoReplenishment = true,
            });
        var oldLimiter = Interlocked.Exchange(ref _limiter, newLimiter);
        oldLimiter?.Dispose();

        _logger.ToFile($"Rate limiter reloaded, new limit: {max}");
    }
}
