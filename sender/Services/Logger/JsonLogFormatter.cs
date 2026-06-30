/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Serilog.Events;
using Serilog.Formatting;

namespace Sender.Logger
{
    public class JsonLogFormatter : ITextFormatter
    {
        private static string ToShortLevel(LogEventLevel level) => level switch
        {
            LogEventLevel.Verbose => "trace",
            LogEventLevel.Debug => "debug",
            LogEventLevel.Information => "info",
            LogEventLevel.Warning => "warn",
            LogEventLevel.Error => "error",
            LogEventLevel.Fatal => "fatal",
            _ => level.ToString().ToLowerInvariant()
        };

        public void Format(LogEvent logEvent, TextWriter output)
        {
            using var buffer = new MemoryStream();
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            {
                writer.WriteStartObject();
                writer.WriteString("time", logEvent.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.ffffffzzz"));
                writer.WriteString("level", ToShortLevel(logEvent.Level));
                writer.WriteString("message", logEvent.RenderMessage());
                writer.WriteEndObject();
            }

            output.WriteLine(Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length));
        }
    }
}
