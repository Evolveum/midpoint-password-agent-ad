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
using System.Diagnostics;

// Author: Matthew Wright
namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    static class Encryptor
    {
        /// <summary>
        /// This tag marks the start of the encrypted password string in encryptor stdout.
        /// </summary>
        const string startEncryptionTag = "START ENCRYPTION";
        /// <summary>
        /// This tag marks the end of the encrypted password string in encryptor stdout.
        /// </summary>
        const string endEncryptionTag = "END ENCRYPTION";
        /// <summary>
        /// This tag marks the start of the decrypted password string in encryptor stdout.
        /// </summary>
        const string startDecryptionTag = "START DECRYPTION";
        /// <summary>
        /// This tag marks the end of the decrypted password string in encryptor stdout.
        /// </summary>
        const string endDecryptionTag = "END DECRYPTION";

        /// <summary>
        /// Encrypts the plaintexts and returns the ciphertext
        /// </summary>
        /// <param name="plaintext">Plaintext to encrypt.</param>
        /// <returns>The associated ciphertext.</returns>
        public static string Encrypt(string plaintext)
        {
            Console.WriteLine("run encrypt: '" + plaintext + "'");
            return RunEncryptorFile(true, plaintext);
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext.
        /// </summary>
        /// <param name="ciphertext">Ciphertext to decrypt.</param>
        /// <returns>The associated plaintext string.</returns>
        public static string Decrypt(string ciphertext)
        {
            return RunEncryptorFile(false, ciphertext);
        }


        private static string RunEncryptorFile(bool encrypting, string inputString)
        {
            string startTag = (encrypting) ? startEncryptionTag : startEncryptionTag;
            string endTag = (encrypting) ? endEncryptionTag : endEncryptionTag;

            //Set mode - must have space after e/d to separate from next argument
            string mode = (encrypting) ? "e " : "d ";
            string newPassword = "";

            var psi = new ProcessStartInfo
            {
                FileName = Constants.encryptorPath,
                Arguments = mode + inputString,
                UseShellExecute = false,
                RedirectStandardOutput = true,
            };

            var process = Process.Start(psi);
            if (process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds))
            {
                var result = process.StandardOutput.ReadToEnd();

                // Strip the start and end tags from decrypted password string
                string[] stringLines = result.Split(new char[] { '\n' });
                bool start = false;
                foreach (string line in stringLines)
                {
                    string trimmedLine = line.TrimEnd(new char[] { '\r', '\n' });

                    if (start)
                    {
                        if (trimmedLine == endTag)
                        {
                            // Found end tag - stop parsing decrypted string
                            // Don't want to add end tag to decrypted string
                            Console.WriteLine("endtag");
                            break;
                        }
                        else
                        {
                            // If the line is between start and end tags then append it to decrypted string
                            newPassword += trimmedLine;
                            Console.WriteLine("running encrypt: '" + newPassword + "'");
                        }
                    }
                    else if (trimmedLine == startTag)
                    {
                        // Found start tag - must check this AFTER attempting to add to decrypted string 
                        // Otherwise the start tag would be added to the decrypted string
                        start = true;
                        Console.WriteLine("start tag");
                    }
                }
            }
            Console.WriteLine("return encrypt: '" + newPassword + "'");

            return newPassword;
        }
    }
}
