/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Text.Json.Nodes;
using Sender.Configuration;
using Sender.Logger;
using Sender.Queue;

namespace Sender.MidPoint
{
    public class MidPointService(AppLogger appLogger, SenderConfigurationProvider configProvider, IMidPointAuthHandler authHandler) : IDisposable
    {
        private const string NotifyChangePath = "ws/rest/notifyChange";

        private readonly HttpClient httpClient = new(new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.None
            }
        });

        public async Task<(bool sent, string? lastError)> SendPasswordChange(PasswordChangeEvent changeEvent, CancellationToken cancellationToken = default)
        {
            try
            {
                var request = BuildRequest(changeEvent);
                authHandler.Authenticate(request);

                var response = await httpClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    appLogger.ToFile($"Password change forwarded for {changeEvent.Username}@{changeEvent.Domain}");
                    return (true, null);
                }

                var error = $"MidPoint rejected password change for {changeEvent.Username}@{changeEvent.Domain}: HTTP {(int)response.StatusCode}";
                appLogger.ToAll(error, LogLevel.Error);
                return (false, error);
            }
            catch (HttpRequestException ex)
            {
                var error = $"Failed to reach midPoint for {changeEvent.Username}@{changeEvent.Domain}: {ex.Message}";
                appLogger.ToAll(error, LogLevel.Error);
                return (false, error);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
                httpClient.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private HttpRequestMessage BuildRequest(PasswordChangeEvent changeEvent)
        {
            var settings = configProvider.MidPoint;
            var body = new JsonObject
            {
                ["resourceObjectShadowChangeDescription"] = new JsonObject
                {
                    ["oldShadow"] = new JsonObject
                    {
                        ["resourceRef"] = new JsonObject
                        {
                            ["oid"] = settings.ResourceOid,
                            ["type"] = "c:ResourceType"
                        },
                        ["objectClass"] = "ri:user",
                        ["attributes"] = new JsonObject
                        {
                            ["ri:sAMAccountName"] = changeEvent.Username
                        }
                    },
                    ["objectDelta"] = new JsonObject
                    {
                        ["@ns"] = "http://prism.evolveum.com/xml/ns/public/types-3",
                        ["changeType"] = "modify",
                        ["objectType"] = "ShadowType",
                        ["itemDelta"] = new JsonObject
                        {
                            ["modificationType"] = "replace",
                            ["path"] = "credentials/password/value",
                            ["value"] = changeEvent.Password
                        }
                    }
                }
            };

            var builder = new UriBuilder(settings.BaseUrl);
            if (!builder.Path.EndsWith('/')) builder.Path += '/';
            var url = new Uri(builder.Uri, NotifyChangePath).ToString();

            return new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
            };
        }
    }
}
