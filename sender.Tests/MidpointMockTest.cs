using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Sender.Tests;

public class MockServerTests : IDisposable
{
    private WireMockServer _server;

    public MockServerTests()
    {
        _server = WireMockServer.Start();
    }

    public void Dispose()
    {
        _server.Stop();
    }

    [Fact]
    public async Task Should_respond_to_request()
    {
        _server
          .Given(Request.Create().WithPath("/foo").UsingGet())
          .RespondWith(
            Response.Create()
              .WithStatusCode(200)
              .WithBody(@"{ ""msg"": ""Hello world!"" }")
          );

        var response = await new HttpClient().GetAsync($"{_server.Urls[0]}/foo");
        Assert.Equal(200, (int)response.StatusCode);
    }
}