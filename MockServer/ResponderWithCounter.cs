using WireMock.Server;
using WireMock;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Types;
using WireMock.Util;

namespace MockServer;

public class ResponderWithCounter(int nthSuccess, WireMockServer server)
{
    private long requestsServed = 0;
    private readonly long nthSuccess = nthSuccess;

    private readonly WireMockServer server = server;

    public ResponseMessage ServeRequest(WireMock.IRequestMessage req)
    {
        var bodyType = Enum.Parse<BodyType>(req.DetectedBodyType ?? "");

        requestsServed++;

        if (requestsServed % nthSuccess == 0)
        {
            return new ResponseMessage
            {
                StatusCode = 200,
                BodyData = new BodyData
                {
                    DetectedBodyType = bodyType,
                    BodyAsString = "Correct"
                }
            };
        }

        return new ResponseMessage
        {
            StatusCode = 400,
            BodyData = new BodyData
            {
                DetectedBodyType = bodyType,
                BodyAsString = "Error"
            }
        };


    }
}