/*
 * Copyright (C) 2010-2026 Evolveum and contributors
 *
 * Licensed under the EUPL-1.2 or later.
 */
using System.Net.Http.Headers;
using System.Text;
using Sender.Configuration;

namespace Sender.MidPoint
{
    public class BasicAuthHandler(SenderConfigurationProvider configProvider) : IMidPointAuthHandler
    {
        public void Authenticate(HttpRequestMessage request)
        {
            var settings = configProvider.MidPoint;
            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{settings.Username}:{settings.Password}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        }
    }
}
