/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Text.Json.Serialization;

namespace Sender.Queue
{
    public record PasswordChangeEvent(string Username, string Domain, string Password)
    {
        [JsonConstructor]
        public PasswordChangeEvent() : this(string.Empty, string.Empty, string.Empty) { }

        [JsonPropertyName("username")]
        public string Username { get; set; } = Username;

        [JsonPropertyName("domain")]
        public string Domain { get; set; } = Domain;

        [JsonPropertyName("password")]
        public string Password { get; set; } = Password;

        [JsonPropertyName("metadata")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public EventMetadata? Metadata { get; set; }

        [JsonIgnore]
        public string? FilePath { get; set; }

        public class EventMetadata
        {
            [JsonPropertyName("retryCount")]
            public int RetryCount { get; set; }

            [JsonPropertyName("nextRetryAt")]
            public DateTimeOffset? NextRetryAt { get; set; }

            [JsonPropertyName("lastError")]
            public string? LastError { get; set; }
        }
    }
}
