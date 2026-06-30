/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using Serilog.Context;

namespace Sender.Logger
{
  public class AppLogger
  {
      private readonly ILogger<AppLogger> _logger;

      public AppLogger(ILogger<AppLogger> logger) => _logger = logger;

      public void ToFile(string message, LogLevel level = LogLevel.Information)
      {
          using (LogContext.PushProperty("WriteToFile", true))
              _logger.Log(level, message);
      }

      public void ToEventLog(string message, LogLevel level = LogLevel.Information)
      {
          using (LogContext.PushProperty("WriteToEventLog", true))
              _logger.Log(level, message);
      }

      public void ToConsole(string message, LogLevel level = LogLevel.Information)
      {
          using (LogContext.PushProperty("WriteToConsole", true))
              _logger.Log(level, message);
      }

      public void ToAll(string message, LogLevel level = LogLevel.Information)
      {
          using (LogContext.PushProperty("WriteToEventLog", true))
          using (LogContext.PushProperty("WriteToConsole", true))
          using (LogContext.PushProperty("WriteToFile", true))
              _logger.Log(level, message);
      }
  }
}
