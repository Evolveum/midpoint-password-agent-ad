/**
 *
 * Copyright (c) 2013 Salford Software Ltd All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;

// Author Matthew Wright
namespace PasswordFilterProcessor
{
    public class ClientInspector : IClientMessageInspector
    {
        public MessageHeader[] Headers { get; set; }

        public ClientInspector(params MessageHeader[] headers)
        {
            Headers = headers;
        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            if (Headers != null)
            {
                for (int i = Headers.Length - 1; i >= 0; i--)
                {
                    request.Headers.Insert(0, Headers[i]);
                }
            }

            return request;
        }

        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
        }
    }
}
