using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Sender.MidPoint;

namespace Sender.Services.MidPoint
{
    public interface IMidpointConfigurationBuilder
    {
        MidPointClientConfiguration Build(MidPointJsonConfiguration jsonConfig);
    }

    [SupportedOSPlatform("windows")]
    public class MidpointConfigurationBuilder : IMidpointConfigurationBuilder
    {
        public MidPointClientConfiguration Build(MidPointJsonConfiguration jsonConfig)
        {
            return new MidPointClientConfiguration
            {
                BaseUrl = jsonConfig.BaseUrl,
                Username = jsonConfig.Username,
                ResourceOid = jsonConfig.ResourceOid,
                Password = Encoding.ASCII.GetString(
                    ProtectedData.Unprotect(
                        Convert.FromBase64String(jsonConfig.Password),
                        null,
                        DataProtectionScope.LocalMachine))
            };
        }
    }
}