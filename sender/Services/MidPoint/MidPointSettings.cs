/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
namespace Sender.MidPoint
{
    public record MidPointJsonConfiguration
    {
        public string BaseUrl { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ResourceOid { get; set; } = string.Empty;

        public override string ToString()
        {
            return $"BaseUrl={BaseUrl}, Username={Username}, ResourceOid={ResourceOid}";
        }
    }

    public record MidPointClientConfiguration
    {
        public string BaseUrl { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ResourceOid { get; set; } = string.Empty;

        public override string ToString()
        {
            return $"BaseUrl={BaseUrl}, Username={Username}, ResourceOid={ResourceOid}";
        }
    }
}
