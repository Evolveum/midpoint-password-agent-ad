using Sender.MidPoint;
using Sender.Services.MidPoint;

namespace Sender.MultiPlatform
{
    public class SimpleMidpointConfigurationBuilder : IMidpointConfigurationBuilder
    {
        public MidPointClientConfiguration Build(MidPointJsonConfiguration jsonConfig)
        {
            return new MidPointClientConfiguration
            {
                BaseUrl = jsonConfig.BaseUrl,
                Username = jsonConfig.Username,
                ResourceOid = jsonConfig.ResourceOid,
                Password = jsonConfig.Password
            };
        }
    }
}