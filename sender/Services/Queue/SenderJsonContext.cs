/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Text.Json.Serialization;
using Sender.State;

namespace Sender.Queue
{
    [JsonSerializable(typeof(PasswordChangeEvent))]
    [JsonSerializable(typeof(ApplicationState))]
    [JsonSerializable(typeof(ApplicationState?))]
    internal partial class SenderJsonContext : JsonSerializerContext { }
}
