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
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;
using System.IO;
using System.Xml;

namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    [RunInstaller(true)]
    public partial class MidPointPasswordFilterInstaller : System.Configuration.Install.Installer
    {
        #region Constants

        /// <summary>
        /// The relative path to model wsdl in Midpoint. Should be appended to server URL.
        /// </summary>
        private const string modelWsdlPath = "/midpoint/model/model-1";
        /// <summary>
        /// The query string for wsdl in Midpoint. Should be appended to default endpoint address URL.
        /// </summary>
        private const string wsdlQuery = "?wsdl";

        #endregion

        #region Constructor

        public MidPointPasswordFilterInstaller()
        {
            InitializeComponent();
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// When overridden in a derived class, performs the installation.
        /// </summary>
        /// <param name="stateSaver">An <see cref="T:System.Collections.IDictionary"/> used to save information needed to perform a commit, rollback, or uninstall operation.</param>
        /// <exception cref="T:System.ArgumentException">The <paramref name="stateSaver"/> parameter is null. </exception>
        /// <exception cref="T:System.Exception">An exception occurred in the <see cref="E:System.Configuration.Install.Installer.BeforeInstall"/> event handler of one of the installers in the collection.-or- An exception occurred in the <see cref="E:System.Configuration.Install.Installer.AfterInstall"/> event handler of one of the installers in the collection. </exception>
        [System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityAction.Demand)]
        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);
        }

        /// <summary>
        /// When overridden in a derived class, completes the install transaction.
        /// </summary>
        /// <param name="savedState">An <see cref="T:System.Collections.IDictionary"/> that contains the state of the computer after all the installers in the collection have run.</param>
        /// <exception cref="T:System.ArgumentException">The <paramref name="savedState"/> parameter is null.-or- The saved-state <see cref="T:System.Collections.IDictionary"/> might have been corrupted. </exception>
        /// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred during the <see cref="M:System.Configuration.Install.Installer.Commit(System.Collections.IDictionary)"/> phase of the installation. This exception is ignored and the installation continues. However, the application might not function correctly after the installation is complete. </exception>
        [System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityAction.Demand)]
        public override void Commit(IDictionary savedState)
        {
            base.Commit(savedState);
            try
            {
                XmlDocument xmldoc = new XmlDocument();
                xmldoc.Load(Constants.configPath);
                XmlNode node = xmldoc.DocumentElement;

                string EndpointURL = Context.Parameters["DEFAULTENDPOINT"];
                string UserName = Context.Parameters["ADMINUSERNAME"];
                string Password = Context.Parameters["ADMINPASSWORD"];

                // Need to trim trailing slashes as the wsdlPath starts with one
                string bindingURL = EndpointURL.Trim().TrimEnd(new char[] { '\\', '/' }) + modelWsdlPath;
                string fullURL = bindingURL + wsdlQuery;

                foreach (XmlNode rootNode in node.ChildNodes)
                {
                    foreach (XmlNode childNode in rootNode.ChildNodes)
                    {
                        if (rootNode.Name == "appSettings" && childNode.Name == "add")
                        {
                            switch (childNode.Attributes.GetNamedItem("key").Value)
                            {
                                case "DefaultEndpoint":
                                    childNode.Attributes.GetNamedItem("value").Value = string.IsNullOrEmpty(fullURL) ? "" : fullURL;
                                    break;
                                case "AdminUserName":
                                    childNode.Attributes.GetNamedItem("value").Value = string.IsNullOrEmpty(UserName.Trim()) ? "null" : Encryptor.Encrypt(UserName);
                                    break;
                                case "AdminPassword":
                                    childNode.Attributes.GetNamedItem("value").Value = string.IsNullOrEmpty(Password.Trim()) ? "null" : Encryptor.Encrypt(Password);
                                    break;
                                default:
                                    break;
                            }
                        }

                        if (rootNode.Name == "system.serviceModel" && childNode.Name == "client")
                        {
                            foreach (XmlNode grandChildNode in childNode.ChildNodes)
                            {
                                if (grandChildNode.Name == "endpoint" && !string.IsNullOrEmpty(bindingURL))
                                {
                                    grandChildNode.Attributes.GetNamedItem("address").Value = modelWsdlPath;
                                }
                            }
                        }
                    }
                }

                xmldoc.Save(Constants.configPath);

                try
                {
                    // Add the password filter dll to registry
                    RegistryEditor.SetRegistryKey();

                    try
                    {
                        // Create scheduled task for processor
                        ScheduledTask.CreateScheduledTask();
                    }
                    catch (Exception ex)
                    {
                        throw new InstallException("Unable to create scheduled task: '" + ex.Message + "'");
                    }
                }
                catch (Exception ex)
                {
                    throw new InstallException("Unable to modify registry: '" + ex.Message + "'");
                }
            }
            catch (Exception ex)
            {
                throw new InstallException("Unable to modify configuration file: '" + ex.Message + "'");
            }
        }

        /// <summary>
        /// When overridden in a derived class, rolls back an installation.
        /// </summary>
        /// <param name="savedState">An <see cref="T:System.Collections.IDictionary"/> that contains the state of the computer after the installation was complete.</param>
        /// <exception cref="T:System.ArgumentException">The saved-state <see cref="T:System.Collections.IDictionary"/> might have been corrupted. </exception>
        /// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred while uninstalling. This exception is ignored and the uninstall continues. However, the application might not be fully uninstalled after the uninstallation completes. </exception>
        [System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityAction.Demand)]
        public override void Rollback(IDictionary savedState)
        {
            base.Rollback(savedState);

            try
            {
                // Remove the password filter dll from registry
                RegistryEditor.DeleteRegistryKey();

                // Remove the scheduled task
                ScheduledTask.DeleteScheduledTask();

                // Delete dlls and exes from system32
                FileInfo encryptorFile = new FileInfo(Constants.encryptorPath);
                if (!encryptorFile.Exists)
                {
                    File.Delete(encryptorFile.FullName);
                }

                FileInfo processorFile = new FileInfo(Constants.processorPath);
                if (!processorFile.Exists)
                {
                    File.Delete(processorFile.FullName);
                }

                FileInfo configFile = new FileInfo(Constants.configPath);
                if (!configFile.Exists)
                {
                    File.Delete(configFile.FullName);
                }

                FileInfo filterFile = new FileInfo(Constants.filterPath);
                if (!filterFile.Exists)
                {
                    File.Delete(filterFile.FullName);
                }
            }
            catch (Exception ex)
            {
                throw new InstallException("Error uninstalling application: " + ex.Message);
            }
        }

        /// <summary>
        /// When overridden in a derived class, removes an installation.
        /// </summary>
        /// <param name="savedState">An <see cref="T:System.Collections.IDictionary"/> that contains the state of the computer after the installation was complete.</param>
        /// <exception cref="T:System.ArgumentException">The saved-state <see cref="T:System.Collections.IDictionary"/> might have been corrupted. </exception>
        /// <exception cref="T:System.Configuration.Install.InstallException">An exception occurred while uninstalling. This exception is ignored and the uninstall continues. However, the application might not be fully uninstalled after the uninstallation completes. </exception>
        [System.Security.Permissions.SecurityPermission(System.Security.Permissions.SecurityAction.Demand)]
        public override void Uninstall(IDictionary savedState)
        {
            base.Uninstall(savedState);

            try
            {
                // Remove the password filter dll from registry
                RegistryEditor.DeleteRegistryKey();

                // Remove the scheduled task
                ScheduledTask.DeleteScheduledTask();

                // Delete dlls and exes from system32
                FileInfo encryptorFile = new FileInfo(Constants.encryptorPath);
                if (!encryptorFile.Exists)
                {
                    File.Delete(encryptorFile.FullName);
                }

                FileInfo processorFile = new FileInfo(Constants.processorPath);
                if (!processorFile.Exists)
                {
                    File.Delete(processorFile.FullName);
                }

                FileInfo configFile = new FileInfo(Constants.configPath);
                if (!configFile.Exists)
                {
                    File.Delete(configFile.FullName);
                }

                FileInfo filterFile = new FileInfo(Constants.filterPath);
                if (!filterFile.Exists)
                {
                    File.Delete(filterFile.FullName);
                }
            }
            catch (Exception ex)
            {
                throw new InstallException("Error uninstalling application: " + ex.Message);
            }
        }

        #endregion
    }
}
