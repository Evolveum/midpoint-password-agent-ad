/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */

using Microsoft.Extensions.Primitives;
using Sender;
using Sender.Configuration;
using Sender.Crypto;
using Sender.KeyRotation;
using Sender.Logger;
using Sender.MidPoint;
using Sender.MultiPlatform;
using Sender.Queue;
using Sender.Services.MidPoint;
using Sender.State;
using Sender.WindowsRegistry;
using Sender.Worker;
using Serilog;
using Serilog.Core;

static IWindowsRegistryProvider GetWindowsRegistryProvider()
{
#if DEBUG
    return OperatingSystem.IsWindows()
            ? new WindowsRegistryProvider()
            : new InMemoryRegistryProvider(new Dictionary<string, string>
            {
                { "LogPath", "~/MidPoint Password Agent for Active Directory/logs" },
                { "ConfigPath", "~/MidPoint Password Agent for Active Directory/config.json" },
                { "QueuePath", "~/MidPoint Password Agent for Active Directory/queue" },
                { "RootPath", "~/MidPoint Password Agent for Active Directory/" },
            });
#else
    return new WindowsRegistryProvider();
#endif
}

static void RegisterKeyService(HostApplicationBuilder builder)
{
#if DEBUG
    if (OperatingSystem.IsWindows())
    {
        builder.Services.AddSingleton<IKeyProvider, WindowsKeyProvider>();
    }
    else
    {
        builder.Services.AddSingleton<IKeyProvider, InMemoryKeyProvider>();
    }
#else
        builder.Services.AddSingleton<IKeyProvider, WindowsKeyProvider>();
#endif
}

static IMidpointConfigurationBuilder GetMidpointConfigBuilder()
{
#if DEBUG
    if (OperatingSystem.IsWindows())
    {
        return new MidpointConfigurationBuilder();
    }
    else
    {
        return new SimpleMidpointConfigurationBuilder();
    }
#else
        return new MidpointConfigurationBuilder();
#endif
}

static async Task StartServiceAsync(string[] args)
{
    HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

    IWindowsRegistryProvider registryProvider = GetWindowsRegistryProvider();
    builder.Services.AddSingleton(registryProvider);
    var startupConfig = new StartupConfig(registryProvider);
    builder.Services.AddSingleton(startupConfig);
    builder.Configuration.AddJsonFile(startupConfig.ConfigPath, optional: true, reloadOnChange: true);

    var startupSenderConfig = builder.Configuration.GetSection("Sender").Get<SenderJsonConfiguration>() ?? new SenderJsonConfiguration();

    var levelSwitch = new LoggingLevelSwitch(startupSenderConfig.LogLevel);

    Logger CreateSerilogLogger(SenderJsonConfiguration config) =>
        new LoggerConfiguration()
            .MinimumLevel.ControlledBy(levelSwitch)
            .Enrich.FromLogContext()
            .WriteTo.Logger(lc => lc
                .Filter.ByIncludingOnly(e => e.Properties.ContainsKey("WriteToConsole"))
                .WriteTo.Console()
            )
            .WriteTo.Logger(lc => lc
                .Filter.ByIncludingOnly(e => e.Properties.ContainsKey("WriteToFile"))
                .WriteTo.File(
                    new JsonLogFormatter(),
                    Path.Combine(startupConfig.LogDirectory, "sender.json"),
                    fileSizeLimitBytes: config.LogFileSizeLimitBytes,
                    rollOnFileSizeLimit: true,
                    retainedFileCountLimit: config.LogRetainedFileCountLimit)
            )
            .WriteTo.Logger(lc =>
            {
                if (OperatingSystem.IsWindows())
                {
                    lc.Filter.ByIncludingOnly(e => e.Properties.ContainsKey("WriteToEventLog"))
                    .WriteTo.EventLog(Sender.Constants.Service.Name, manageEventSource: false);
                }
            })
            .CreateLogger();

    Log.Logger = CreateSerilogLogger(startupSenderConfig);

    builder.Logging.ClearProviders();
    builder.Logging.AddSerilog();

    builder.Services.Configure<SenderJsonConfiguration>(builder.Configuration.GetSection("Sender"));
    builder.Services.AddHostedService<SenderWorker>();
    builder.Services.AddHostedService<KeyRotationWorker>();
    builder.Services.AddHostedService<KeyCleanupWorker>();
    builder.Services.AddSingleton<IKeyRotationService, KeyRotationService>();
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = Sender.Constants.Service.Name;
    });
    builder.Services.AddSingleton<AppLogger>();
    builder.Services.AddSingleton<QueueService>();
    builder.Services.AddSingleton<CryptoService>();
    builder.Services.AddSingleton<IApplicationStateProvider, ApplicationStateProvider>();

    RegisterKeyService(builder);

    builder.Services.AddSingleton<IMidPointAuthHandler, BasicAuthHandler>();
    builder.Services.AddSingleton<MidPointService>();
    builder.Services.AddSingleton<MidPointRateLimiter>();
    builder.Services.AddSingleton(GetMidpointConfigBuilder());
    builder.Services.AddSingleton<SenderConfigurationProvider>();

    var host = builder.Build();

    var appLogger = host.Services.GetRequiredService<AppLogger>();
    var configuration = host.Services.GetRequiredService<IConfiguration>();
    var configProvider = host.Services.GetRequiredService<SenderConfigurationProvider>();

    appLogger.ToFile($"Initial configuration: KeyRotationInterval={configProvider.KeyRotationInterval}, KeyRotationGracePeriod={configProvider.KeyRotationGracePeriod}, KeyCleanupInterval={configProvider.KeyCleanupInterval}, Midpoint={configProvider.MidPoint.ToString()}");

    using var debounceTimer = new Timer(
        _ =>
        {
            var midPointCofigProvider = host.Services.GetRequiredService<IMidpointConfigurationBuilder>();
            var newConfig = SenderConfigurationFactory.Build(
                startupConfig.QueueDirectory,
                startupConfig.RootPath,
                builder.Configuration,
                midPointCofigProvider,
                appLogger);

            levelSwitch.MinimumLevel = newConfig.LogLevel;

            if (newConfig.LogFileSizeLimitBytes != configProvider.LogFileSizeLimitBytes ||
                newConfig.LogRetainedFileCountLimit != configProvider.LogRetainedFileCountLimit)
            {
                var oldLogger = Log.Logger;
                Log.Logger = CreateSerilogLogger(newConfig);
                (oldLogger as IDisposable)?.Dispose();
            }

            if (configProvider.Update(newConfig))
                appLogger.ToFile($"Configuration reloaded: KeyRotationInterval={configProvider.KeyRotationInterval}, KeyRotationGracePeriod={configProvider.KeyRotationGracePeriod}, KeyCleanupInterval={configProvider.KeyCleanupInterval}, LogLevel={levelSwitch.MinimumLevel}, LogFileSizeLimitBytes={newConfig.LogFileSizeLimitBytes}, LogRetainedFileCountLimit={newConfig.LogRetainedFileCountLimit}, Midpoint={configProvider.MidPoint.ToString()}");
        },
        null,
        Timeout.Infinite,
        Timeout.Infinite
    );

    ChangeToken.OnChange(
        () => configuration.GetReloadToken(),
        () => debounceTimer.Change(TimeSpan.FromMilliseconds(500), Timeout.InfiniteTimeSpan));

    try
    {
        await host.RunAsync();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[FATAL] Host failed: {ex}");
        throw;
    }
}

static void Install(string[] args)
{
    HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
    Logger CreateSerilogLogger() => new LoggerConfiguration().WriteTo.Console().CreateLogger();

    Log.Logger = CreateSerilogLogger();
    builder.Logging.ClearProviders();
    builder.Logging.AddSerilog();
    builder.Services.AddSingleton<AppLogger>();

    var startupConfig = new StartupConfig(GetWindowsRegistryProvider());
    builder.Services.AddSingleton(startupConfig);
    builder.Services.AddSingleton(GetMidpointConfigBuilder());
    builder.Services.AddSingleton<SenderConfigurationProvider>();

    RegisterKeyService(builder);
    var host = builder.Build();

    var keyProvider = host.Services.GetRequiredService<IKeyProvider>();
    keyProvider.GenerateFirstKey();
}

if (args.Any(a => a is "-i" or "--install"))
{
    Install(args);
}
else
{
    await StartServiceAsync(args);
}
