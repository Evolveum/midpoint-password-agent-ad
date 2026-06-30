/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using System.Threading.RateLimiting;
using Sender.Configuration;

namespace Sender.MidPoint;

public class MidPointRateLimiter : IDisposable
{
    private readonly RateLimiter? _limiter;

    public MidPointRateLimiter(SenderConfigurationProvider configuration)
    {
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

    public async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        if (_limiter != null)
            await _limiter.AcquireAsync(1, cancellationToken);
    }

    public void Dispose() => _limiter?.Dispose();
}
