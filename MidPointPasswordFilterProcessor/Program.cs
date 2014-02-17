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
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using PasswordFilterProcessor.MidpointModelWebService;

// Author Matthew Wright
namespace PasswordFilterProcessor
{
    class Program
    {
        #region Constants

        /// <summary>
        /// The location of the files contain password update details.
        /// Will be C:\Documents and Settings\All Users\Application Data for 2K3
        /// and C:\ProgramData for newer variants
        /// </summary>
        static readonly string passwordFilePath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) + @"\MidPointPasswordFilter\";
        /// <summary>
        /// The format of file names to find in the password file directory.
        /// Only searching for txt files. The log file as a .log extension and this should be avoided.
        /// </summary>
        const string searchPattern = "*.txt";
        /// <summary>
        /// The file path to the log file for the password filter processor.
        /// Should log to the common application data directory where the password changes files reside.
        /// </summary>
        static readonly string logFile = passwordFilePath + "MidPointPasswordFilterProcessor.log";
        /// <summary>
        /// The name of System Account - for setting log file permissions.
        /// </summary>
        const string SystemAccount = @"NT AUTHORITY\SYSTEM";
        /// <summary>
        /// The name of Builtin Administrators group - for setting log file permissions.
        /// </summary>
        const string BuiltinAdministrators = @"BUILTIN\Administrators";
        /// <summary>
        /// The expected first character of password files.
        /// </summary>
        const char firstChar = '[';
        /// <summary>
        /// The expected separator for date elements of timestamp in password files.
        /// </summary>
        const char dateSeparator = '/';
        /// <summary>
        /// The expected separator between the date and time elements of timestamp in password files.
        /// </summary>
        const char dateTimeSeparator = ' ';
        /// <summary>
        /// The expected separator for time elements of timestamp in password files.
        /// </summary>
        const char timeSeparator = ':';
        /// <summary>
        /// The expected close bracket to indicate end of timestamp in password files.
        /// Matching the open bracket that should be first character.
        /// </summary>
        const char lastChar = ']';
        /// <summary>
        /// The character to indicate start of username string in the password files.
        /// </summary>
        const char usernameStartSeparator = ':';
        /// <summary>
        /// The separator between username and encrypted password strings in the password files.
        /// The end of encrypted password is indicated by end of the line.
        /// </summary>
        const string usernameEndSeparator = ", ";

        #endregion
        
        static void Main(string[] args)
        {
            try
            {
                List<UpdateDetails> updateDetails = new List<UpdateDetails> { };
                
                // Parse each file in folder (except the log file)
                string[] files = Directory.GetFiles(passwordFilePath, searchPattern, SearchOption.TopDirectoryOnly);
                foreach (string file in files)
                {
                    try
                    {
                        UpdateDetails newUpdate = ParseUpdateDetailsFile(file);
                        // Mark any stale updates as processed so they are deleted and not processed again
                        foreach (UpdateDetails update in updateDetails)
                        {
                            if (update.UserName == newUpdate.UserName)
                            {
                                if (update.TimeStamp > newUpdate.TimeStamp)
                                {
                                    // This is a stale update
                                    newUpdate.IsProcessed = true;
                                    break;
                                }
                                else if (update.TimeStamp < newUpdate.TimeStamp)
                                {
                                    // The previous update precedes new update
                                    update.IsProcessed = true;
                                }
                                else
                                {
                                    // Timestamps are exactly equal - big problem - shouldn't happen
                                    // Don't know which is newer
                                    update.IsProcessed = true;
                                    newUpdate.IsProcessed = true;
                                }
                            }
                        }

                        // Add update to list
                        updateDetails.Add(newUpdate);
                    }
                    catch (Exception ex)
                    {
                        // If the file cannot be correctly processed, log the exception and delete it.
                        // Users should not have permissions to the files so it is important to clean them up.
                        DeleteFile(file, ex);
                    }
                }

                // Process the updates
                foreach (UpdateDetails update in updateDetails)
                {
                    try
                    {
                        // Only processed unprocessed items - if already processed then they are stale changes
                        if (!update.IsProcessed)
                        {
                            string newPassword = Encryptor.Decrypt(update.Password);
                            modelPortType modelPort = ChangePassword.createModelPort(args);
                            UserType user = ChangePassword.searchUserByName(modelPort, update.UserName);
                            ChangePassword.changeUserPassword(modelPort, user.oid, newPassword);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogError("Error processing file: " + ex.Message);
                    }
                    finally
                    {
                        // Mark file as processed so it can be deleted
                        update.IsProcessed = true;
                    }
                }

                // Delete any files that were successfully processed
                foreach (UpdateDetails update in updateDetails)
                {
                    if (update.IsProcessed)
                    {
                        DeleteFile(update.FileName, null);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError(ex.Message);
            }
        }

        /// <summary>
        /// Parses the given update details file and returns a corresponding UpdateDetails object.
        /// A file should be in the following format:
        /// [2013/07/31 16:10:34:567]:username, encryptedPassword
        /// </summary>
        /// <param name="file">The filename of file to parse.</param>
        /// <returns>The update details from the file</returns>
        private static UpdateDetails ParseUpdateDetailsFile(string file)
        {
            const string exceptionMessage = "Error malformed password file.";

            byte[] bytes = File.ReadAllBytes(file);
            string line = "";
            // Skip to every second byte because Java inserts spaces between each char
            for (int i = 0; i < bytes.Length; i += 2)
            {
                line += (char)bytes[i];
            }

            if (line[0] == firstChar)
            {
                // Parse the line to get timestamp
                int curIndex = 1;
                DateTime timeStamp = ParseDate(line, ref curIndex);

                if (line[curIndex] == usernameStartSeparator)
                {
                    int startIndex = curIndex + 1;
                    int endIndex = line.IndexOf(usernameEndSeparator, startIndex);
                    string userName = line.Substring(startIndex, endIndex - startIndex);

                    // Username end separator is a string not a char so may have to move forward multiple chars
                    string password = line.Substring(endIndex + usernameEndSeparator.Length).Split(new char[] {'\r', '\n'})[0];

                    return new UpdateDetails(file, userName, password, timeStamp);
                }
                else
                {
                    throw new IOException(exceptionMessage);
                }
            }
            else
            {
                throw new IOException(exceptionMessage);
            }
        }

        /// <summary>
        /// Parse the date from the given line and return as a datetime object.
        /// Also maintains the curIndex as a ref parameter. Assuming an error is not
        /// thrown, it will end on the index following the end timestamp character.
        /// Will throw an IOException if the date time cannot be parsed correctly.
        /// </summary>
        /// <param name="line">The line to parse.</param>
        /// <param name="curIndex">The index to begin parsing at. Should be the 
        /// first character of the timestamp year.</param>
        /// <returns>The timestamp as a datetime object.</returns>
        private static DateTime ParseDate(string line, ref int curIndex)
        {
            const string exceptionMessage = "Error parsing the timestamp.";

            // Find year
            int endIndex = line.IndexOf(dateSeparator, 1);

            int year;
            if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out year))
            {
                // Find month
                curIndex = endIndex + 1;
                endIndex = line.IndexOf(dateSeparator, curIndex);

                int month;
                if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out month))
                {
                    // Find day
                    curIndex = endIndex + 1;
                    endIndex = line.IndexOf(dateTimeSeparator, curIndex);

                    int day;
                    if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out day))
                    {
                        // Find hour
                        curIndex = endIndex + 1;
                        endIndex = line.IndexOf(timeSeparator, 1);

                        int hour;
                        if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out hour))
                        {
                            // Find minute
                            curIndex = endIndex + 1;
                            endIndex = line.IndexOf(timeSeparator, curIndex);

                            int minute;
                            if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out minute))
                            {
                                // Find second
                                curIndex = endIndex + 1;
                                endIndex = line.IndexOf(timeSeparator, curIndex);

                                int second;
                                if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out second))
                                {
                                    // Find millisecond
                                    curIndex = endIndex + 1;
                                    endIndex = line.IndexOf(lastChar, curIndex);

                                    int millisecond;
                                    if (int.TryParse(line.Substring(curIndex, endIndex - curIndex), out millisecond))
                                    {
                                        // Set curIndex to next char so that next section can be parsed by calling method
                                        curIndex = endIndex + 1;
                                        return new DateTime(year, month, day, hour, minute, second, millisecond);
                                    }
                                    else
                                    {
                                        throw new IOException(exceptionMessage);
                                    }
                                }
                                else
                                {
                                    throw new IOException(exceptionMessage);
                                }
                            }
                            else
                            {
                                throw new IOException(exceptionMessage);
                            }
                        }
                        else
                        {
                            throw new IOException(exceptionMessage);
                        }
                    }
                    else
                    {
                        throw new IOException(exceptionMessage);
                    }
                }
                else
                {
                    throw new IOException(exceptionMessage);
                }
            }
            else
            {
                throw new IOException(exceptionMessage);
            }
        }

        /// <summary>
        /// Deletes the file with given filepath. If it fails to delete the file then errors will be recorded in the
        /// PasswordFilterProcessor log. If an exception is provided then this is logged too.
        /// </summary>
        /// <param name="fileToDelete">The file to delete.</param>
        /// <param name="exception">Null if just deleting a successfully processed file.
        ///                         Otherwise, provide the exception encountered while attempting to process file.</param>
        private static void DeleteFile(string fileToDelete, Exception exception)
        {
            try
            {
                if (exception != null)
                {
                    LogError("Error processing file: " + fileToDelete + ". " + exception);
                }

                File.Delete(fileToDelete);
                if (exception != null)
                {
                    LogError("Deleted the file: " + fileToDelete);
                }
            }
            catch (Exception ex)
            {
                LogError("Error deleting file: " + fileToDelete + ". " + ex);
            }
        }

        /// <summary>
        /// Logs the given error message to the log file.
        /// Will create a new log file if one does not exist.
        /// When a new log file is created - the permissions for will be set here.
        /// </summary>
        /// <param name="error">The error message to log.</param>
        private static void LogError(string error)
        {
            StreamWriter sw = null;
            bool logExists = false;
            bool writeSuccess = false;
            try
            {
                // Check if log already exists - will have to set permissions for the new log file if not
                logExists = File.Exists(logFile) ? true : false;
                sw = new StreamWriter(logFile, true);
                sw.WriteLine(CreateErrorMessage(error));
                writeSuccess = true;
            }
            finally
            {
                if (sw != null)
                {
                    sw.Close();
                }
            }

            // Only set permissions if the log has just been SUCCESSFULLY created.
            // Don't want to call SetPermissions if creating log failed since it
            // would then fail to set permissions and attempt to log back to the 
            // non-existent log file. This would result in an infinite loop.
            if (!logExists && writeSuccess)
            {
                SetLogFilePermissions();
            }
        }

        /// <summary>
        /// Sets the permissions for the log file.
        /// Gives Full Control to NT AUTHORITY\SYSTEM and Modify to BUILTIN\Administrators.
        /// Removes all inherited rules and any other permissions.
        /// </summary>
        private static void SetLogFilePermissions()
        {
            try
            {
                // Get a FileSecurity object that represents the current security settings for the file.
                FileInfo FileInfo = new FileInfo(logFile);
                FileSecurity fSecurity = FileInfo.GetAccessControl();

                // Set NT AUTHORITY\SYSTEM with Full Control
                fSecurity.SetAccessRule(new FileSystemAccessRule(SystemAccount, FileSystemRights.FullControl, AccessControlType.Allow));
                FileInfo.SetAccessControl(fSecurity);

                // Set BUILTIN\Administrators with Modify (everything except change permissions)
                fSecurity.SetAccessRule(new FileSystemAccessRule(BuiltinAdministrators, FileSystemRights.Modify, AccessControlType.Allow));
                FileInfo.SetAccessControl(fSecurity);

                // Wipe inherited rules - must add the new rules first to ensure that there is are some access rules.
                fSecurity.SetAccessRuleProtection(true, false);
                FileInfo.SetAccessControl(fSecurity);

                // Remove all other permissions
                foreach (FileSystemAccessRule ar in fSecurity.GetAccessRules(true, true, typeof(NTAccount)))
                {
                    if (ar.IdentityReference.Value != SystemAccount && ar.IdentityReference.Value != BuiltinAdministrators)
                    {
                        // Purge AccessRules for the identity from the security settings. 
                        fSecurity.PurgeAccessRules(ar.IdentityReference);
                        FileInfo.SetAccessControl(fSecurity);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error setting log file permissions: " + ex.Message);
            }
        }

        /// <summary>
        /// Prepends the appropriate timestamp to the front of the given error message.
        /// </summary>
        /// <param name="error">The error to report.</param>
        /// <returns>The full error string to print.</returns>
        private static string CreateErrorMessage(string error)
        {
            return "[" + DateTime.Now.ToString() + "]: " + error;
        }
    }
}