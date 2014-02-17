/**
 *
 * Copyright (c) 2009 Mauri Marco All rights reserved.
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
 *
 * Portions Copyright 2013 Salford Software Ltd
**/

#include "stdafx.h"
#include <stdexcept>
#include <shlobj.h>
#include <string>
#include <iostream>
#include <vcclr.h>
#include <fstream>

#using <System.dll>

using namespace System;
using namespace System::IO;
using namespace System::Diagnostics;

#ifndef STATUS_SUCCESS
  #define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
  #define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
  #define STATUS_INVALID_SID              ((NTSTATUS)0xC0000078L)
#endif

// Function prototypes
BOOLEAN NTAPI InitializeChangeNotify();
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING,ULONG,PUNICODE_STRING);
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,BOOLEAN);

// check if file exists
// Must open with mode r to read only and fail if the file doesn't exist
// Do not want to create the file if it doesn't exist as this defies the 
// purpose of the function.
bool fileExists(wchar_t *filename)
{
	FILE* file = _wfopen(filename, L"r");
	if (file != NULL)
	{
        fclose(file);
        return true;
    }
	else
	{
        return false;
    }
}

// initialise the log file permissions
BOOLEAN NTAPI InitializeChangeNotify()
{   
	// Set the permissions for the log file
	wchar_t systempath[MAX_PATH + 1];
	if (SUCCEEDED(SHGetFolderPath(NULL,CSIDL_COMMON_APPDATA|CSIDL_FLAG_CREATE, NULL, 0, systempath)))
	{
		wchar_t *totalpath = lstrcat(systempath, CHANGE_FILE_FOLDER);
		CreateDirectory(totalpath, NULL);
		totalpath = lstrcat(totalpath, LOG_FILE_NAME);

		// If file already exists then call would break
		// since it tries to create the file and set permissions
		if (!fileExists(totalpath))
		{
			setLogFilePermissions(totalpath);
		}
	}

	writeLog(L"Starting MidPointPasswordFilter", false);

	return true;
}

//the event: password has changed successfully
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName,ULONG RelativeId,PUNICODE_STRING NewPassword)
{
	writeLog(L"Starting Password Change Notify", false);
	int nLen=0;
	
	//copy username
	int userLength = UserName->Length/ sizeof(wchar_t);
	wchar_t* username = (wchar_t*)malloc((userLength + 1) * sizeof(wchar_t));
	wchar_t* z = wcsncpy(username,UserName->Buffer,userLength);
	//set the last character to null
	username[userLength] = NULL;

	//convert the password from widechar to utf-8
	int passwordLength = NewPassword->Length/ sizeof(wchar_t);
	nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer, passwordLength, 0, 0, 0, 0);
	char* password = (char*)malloc((nLen + 1) * sizeof(char));
	nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer,passwordLength, password, nLen, 0, 0);
	//set the last character to null
	password[nLen] = NULL;

	//Encrypt the password
	StreamReader^ myStreamReader;
	Process^ myProcess;
	try
	{
		String^ encArgs = gcnew String(password);
		encArgs = "e " + encArgs;

		myProcess = gcnew Process;
		myProcess->StartInfo->FileName = "C:\\Program Files\\Evolveum\\MidPoint Password Filter\\MidPointPasswordFilterEncryptor.exe";
		myProcess->StartInfo->Arguments = encArgs;
		myProcess->StartInfo->UseShellExecute = false;
		myProcess->StartInfo->RedirectStandardOutput = true;
		myProcess->Start();

		// Read the standard output of the spawned process.
		myStreamReader = myProcess->StandardOutput;
		String^ line;
		String^ encryptedString;
		bool start = false;
		bool end = false;
		while (!end && (line = myStreamReader->ReadLine()) )
        {
			if (start)
			{
				if (line == "END ENCRYPTION")
				{
					// Found end tag - stop parsing encryptedString
					// Don't want to add end tag to encryptedString
					end = true;
				}
				else
				{
					// If the line is between start and end tags then append it to encryptedString
					encryptedString += line;
				}
			}

			if (line == "START ENCRYPTION")
			{
				// Found start tag - must check this AFTER attempting to add to encryptedString 
				// Otherwise the start tag would be added to the encryptedString
				start = true;
			}
        }

		myProcess->WaitForExit();

		//write the password change out to a file
		//need to record timestamp, username and hashed password to update other systems
		pin_ptr<const wchar_t> encPwd = PtrToStringChars(encryptedString);
		size_t convertedChars = 0;
		size_t  sizeInBytes = ((encryptedString->Length + 1) * 2);
		errno_t err = 0;
		char *cEncPwd = (char *)malloc(sizeInBytes);

		err = wcstombs_s(&convertedChars, cEncPwd, sizeInBytes, encPwd, sizeInBytes);
		if (err == 0)
		{
			size_t encPwdSize = strlen(cEncPwd) + 1;
			wchar_t* wEncPwd = new wchar_t[encPwdSize];
			mbstowcs(wEncPwd, cEncPwd, encPwdSize);
			std::wstring message(username);
			message.append(L", ");
			message += wEncPwd;	

			if (writeLog(const_cast<wchar_t*>(message.c_str()), true))
			{
				writeMessageToLog(CHANGE_PASSWORD_MESSAGE,username);
			}
			else
			{
				writeLog(L"Error writing the credentials to file", false);
			}
		}
		else
		{
			writeLog(L"Error processing the password", false);
		}
	}
	catch(Exception^ e)
	{
		writeLog(L"Error Encrypting Password", false);
	}
	finally
	{
		// Tidy up the stream reader and the child process
		if ( myStreamReader )
		{
            delete (IDisposable^)myStreamReader;
		}

		if ( myProcess != nullptr )
		{
			myProcess->Close();
		}
	}

	//zero the password
	SecureZeroMemory(password,nLen);
	//free the memory
	//free(message);
	//free(z);
	free(username);
	free(password);
    
    //can I return something else in case of error?
	return STATUS_SUCCESS;
}

//don't apply any password policy
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName,PUNICODE_STRING FullName,PUNICODE_STRING Password,BOOLEAN SetOperation)
{
    return TRUE;
}
