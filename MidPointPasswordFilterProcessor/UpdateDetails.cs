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
using System.IO;

// Author Matthew Wright
namespace PasswordFilterProcessor
{
    class UpdateDetails
    {
        // Private properties
        private string filename;
        private string username;
        private string password;
        private DateTime timestamp;
        private bool processed;

        // Accessor methods
        public string FileName { get { return filename; } }
        public string UserName { get { return username; } }
        public string Password { get { return password; } }
        public DateTime TimeStamp { get { return timestamp;} }

        // Accessor/Mutator methods to indicate if the details have been processed
        public bool IsProcessed { 
            get { return processed; } 
            set { processed = value; } 
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="fileName">Name of the file containing update details.</param>
        /// <param name="userName">Username in the file.</param>
        /// <param name="newPassword">New (Encrypted) password value in the file.</param>
        /// <param name="timeStamp">The recorded time stamp in the file.</param>
        public UpdateDetails(string fileName, string userName, string newPassword, DateTime timeStamp)
        {
            if (File.Exists(fileName))
            {
                if (!String.IsNullOrWhiteSpace(userName) && !String.IsNullOrWhiteSpace(newPassword))
                {
                    filename = fileName;
                    username = userName;
                    password = newPassword;
                    timestamp = timeStamp;
                    processed = false;
                }
                else
                {
                    throw new ArgumentException("Error: cannot create UpdateDetails object if credentials are blank. Username: " + userName);
                }
            }
            else
            {
                throw new ArgumentException("Error: cannot create UpdateDetails object for a non-existent file. Filename: " + fileName);
            }
        }
    }
}
