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

using System;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

// Author Matthew Wright
namespace PasswordFilterProcessor
{
    public class InspectorBehavior : IEndpointBehavior
    {
        public ClientInspector ClientInspector { get; set; }

        public InspectorBehavior(ClientInspector clientInspector)            
        {             
            ClientInspector = clientInspector;             
        }

        public void Validate(ServiceEndpoint endpoint)            
        {
        }

        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)            
        {             
        }
        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)            
        {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)            
        {             
            if (this.ClientInspector == null)
            {
                throw new InvalidOperationException("Caller must supply ClientInspector.");
            }
            
            clientRuntime.MessageInspectors.Add(ClientInspector);             
        }             
    }
}
