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
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

//Author: Matthew Wright
namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    /// <summary>
    /// Manually editing the registry. The installer allows this to be done automatically but
    /// cannot handle multi string values correctly.
    /// </summary>
    public static class RegistryEditor
    {
        #region Constants

        /// <summary>
        /// The root registry key.
        /// </summary>
        const string keyRoot = "HKEY_LOCAL_MACHINE\\";
        /// <summary>
        /// The path to registry value inside root.
        /// Needs to be separate from root for the delete command which can only be performed
        /// from a registry root key object.
        /// </summary>
        const string keyPath = "System\\CurrentControlSet\\Control\\Lsa\\";
        /// <summary>
        /// The registry value. Should be a multi string value.
        /// </summary>
        const string valueName = "Notification Packages";
        /// <summary>
        /// The name of filter dll to add/remove from registry value.
        /// </summary>
        const string filterValue = "MidPointPasswordFilter";
        /// <summary>
        /// The return value when registry seach fails - use a string array rather than a string
        /// since the value is a multi string.
        /// </summary>
        static string[] notFoundMessage = new string[] { "Value Not Found" };

        #endregion

        /// <summary>
        /// Set the registry value for the password filter dll.
        /// </summary>
        public static void SetRegistryKey()
        {
            const string keyName = keyRoot + keyPath;
            
            string[] curValues = (string[])Registry.GetValue(keyName, valueName, notFoundMessage);

            if (curValues == null || curValues[0] == notFoundMessage[0])
            {
                // Create new multi string value
                string[] newValues = new string[] { filterValue };
                Registry.SetValue(keyName, valueName, newValues);
            }
            else
            {
                string[] newValues = new string[curValues.Length + 1];
                // Copy current values
                for (int i = 0; i < curValues.Length; i++)
                {
                    newValues[i] = curValues[i];
                }
                // Append new value to array
                newValues[curValues.Length] = filterValue;

                Registry.SetValue(keyName, valueName, newValues);
            }
        }

        /// <summary>
        /// Remove the password filter dll entry from the registry value.
        /// </summary>
        public static void DeleteRegistryKey()
        {
            const string keyName = keyRoot + keyPath;

            string[] curValues = (string[])Registry.GetValue(keyName, valueName, notFoundMessage);

            if (curValues != null || curValues[0] != notFoundMessage[0])
            {
                List<string> valuesList = new List<string>();
                valuesList.AddRange(curValues);
                
                // Remove password filter value
                valuesList.RemoveAll(x => x == filterValue);

                if (valuesList.Count > 0)
                {
                    string[] newValues = valuesList.ToArray();
                    Registry.SetValue(keyName, valueName, newValues);
                }
                else
                {
                    // Empty value so delete it
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath, true);
                    key.DeleteValue(valueName);
                }
            }
        }
    }
}
