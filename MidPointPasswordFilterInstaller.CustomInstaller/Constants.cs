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

// Author: Matthew Wright
namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    /// <summary>
    /// Constants for the file paths - don't want to maintain them in multiple places.
    /// </summary>
    class Constants
    {
        /// <summary>
        /// The path to encryptor exe in application folder.
        /// </summary>
        public const string encryptorPath = @"C:\Program Files\Evolveum\MidPoint Password Filter\MidPointPasswordFilterEncryptor.exe";
        /// <summary>
        /// The path to processor exe in application folder.
        /// </summary>
        public const string processorPath = @"C:\Program Files\Evolveum\MidPoint Password Filter\MidPointPasswordFilterProcessor.exe";
        /// <summary>
        /// The path to processor config in application folder.
        /// </summary>
        public const string configPath = @"C:\Program Files\Evolveum\MidPoint Password Filter\MidPointPasswordFilterProcessor.exe.config";
        /// <summary>
        /// The path to filter dll in system32 folder. This is in system32 so that registry can find it on system start up.
        /// </summary>
        public const string filterPath = @"C:\Windows\system32\MidPointPasswordFilter.dll";
    }
}
