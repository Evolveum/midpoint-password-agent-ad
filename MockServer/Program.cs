using Newtonsoft.Json;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using System;
using CommandLine;
using MockServer;

static void SetupServerReponse(CommandLineOptions opts, WireMockServer server)
{
    const string midpointPath = "/midpoint/ws/rest/notifyChange";
    switch (opts.Strategy)
    {
        case ResponseStrategy.SuccessEach:
            server.Given(
                Request.Create()
                    .UsingPost()
                    .WithPath(midpointPath)
                )
                .RespondWith(Response.Create().WithStatusCode(200).WithBody("Correct"));
            return;

        case ResponseStrategy.SuccessValid:
            server.Given(
                Request.Create()
                    .UsingPost()
                    .WithPath(midpointPath)
                    .WithBody(new JsonPathMatcher("$.resourceObjectShadowChangeDescription[?(@.objectDelta != null)]"))
                )
                .RespondWith(Response.Create().WithStatusCode(200).WithBody("Correct"));
            return;

        case ResponseStrategy.ErrorEach:
            server.Given(
                Request.Create()
                    .UsingPost()
                    .WithPath(midpointPath)
                )
                .RespondWith(Response.Create().WithStatusCode(400).WithBody("Error"));
            return;

        case ResponseStrategy.SuccessNth:
            var responseHandler = new ResponderWithCounter(opts.NthSuccess, server);
            server.Given(
                Request.Create()
                    .UsingPost()
                    .WithPath(midpointPath)
                )
                .RespondWith(
                    Response.Create()
                            .WithCallback(req => responseHandler.ServeRequest(req)));
            return;
        default:
            Console.WriteLine("No response configured for strategy {0}", opts.Strategy);
            return;
    }
}
static void StartServer(CommandLineOptions opts)
{
    var server = WireMockServer.Start(opts.Port);
    Console.WriteLine("WireMockServer running at {0}", string.Join(",", server.Ports));
    Console.WriteLine("Using strategy {0}", opts.Strategy);
    SetupServerReponse(opts, server);

    Console.WriteLine("Press any key to stop the server");
    Console.ReadKey();

    Console.WriteLine("Displaying all requests");
    var allRequests = server.LogEntries;
    Console.WriteLine(JsonConvert.SerializeObject(allRequests, Formatting.Indented));

    Console.WriteLine("Press any key to quit");
    Console.ReadKey();
}

CommandLine.Parser.Default.ParseArguments<CommandLineOptions>(args)
  .WithParsed(StartServer);
