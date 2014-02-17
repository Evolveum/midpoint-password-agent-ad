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
**/

#include "stdafx.h"
#include <shlobj.h>
#include <aclapi.h>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

wchar_t logFileName[]=LOG_FILE_NAME;
wchar_t changeFileFolder[]=CHANGE_FILE_FOLDER;

void setLogFilePermissions(wchar_t *logFile)
{
	wchar_t returnMessage [256]= {0};
	DWORD dwRes;
	PSID pSystemSID = NULL, pAdminSID = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea[2];
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	SECURITY_ATTRIBUTES sa;
	
	// Create a SID for the LOCAL SYSTEM account.
    if(!AllocateAndInitializeSid(&SIDAuthNT, 1,
                     SECURITY_LOCAL_SYSTEM_RID,
                     0, 0, 0, 0, 0, 0, 0,
                     &pSystemSID))
    {
		wsprintf (returnMessage, L"AllocateAndInitializeSid Error: %u", GetLastError());
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow Everyone read access to the key.
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
    ea[0].grfAccessPermissions = TRUSTEE_ACCESS_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance= NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName  = (LPTSTR) pSystemSID;

    // Create a SID for the BUILTIN\Administrators group.
    if(! AllocateAndInitializeSid(&SIDAuthNT, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     &pAdminSID))
    {
		wsprintf (returnMessage, L"AllocateAndInitializeSid Error: %u", GetLastError());
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the Administrators group full access to
    // the key.
    ea[1].grfAccessPermissions = TRUSTEE_ACCESS_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance= NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName  = (LPTSTR) pAdminSID;

    // Create a new ACL that contains the new ACEs.
    dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes)
    {
		wsprintf (returnMessage, L"SetEntriesInAcl Error: %u", GetLastError());
        goto Cleanup;
    }

    // Initialize a security descriptor.
    pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (NULL == pSD)
    {
		wsprintf (returnMessage, L"LocalAlloc Error: %u", GetLastError());
        goto Cleanup;
    }
 
    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
    {
		wsprintf (returnMessage, L"InitializeSecurityDescriptor Error: %u", GetLastError());
        goto Cleanup;
    }
 
    // Add the ACL to the security descriptor.
    if (!SetSecurityDescriptorDacl(pSD, 
            TRUE,     // bDaclPresent flag
            pACL,
            FALSE))   // not a default DACL
    {
		wsprintf (returnMessage, L"SetSecurityDescriptorDacl Error: %u", GetLastError());
        goto Cleanup;
    }

    // Initialize a security attributes structure.
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

	HANDLE hFile = CreateFile(logFile, FILE_APPEND_DATA , FILE_SHARE_WRITE, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wsprintf (returnMessage, L"CreateFile Error: %u", GetLastError());
	}
	else
	{
		wsprintf (returnMessage, L"Set file permissions successfully: %s", logFile);
	}

	// Must close file handle after use
	CloseHandle(hFile);

Cleanup:
    if (pSystemSID) 
        FreeSid(pSystemSID);
    if (pAdminSID) 
        FreeSid(pAdminSID);
    if (pACL) 
        LocalFree(pACL);
    if (pSD) 
        LocalFree(pSD);

	writeLog(returnMessage, false);
}

// Set bool to true to record a password change to change file
// Set bool to false to record a message/error to log file
bool writeLog(wchar_t *message, bool pwdChange)
{
	bool writeSucceeded = false;
	//get the system path
	wchar_t systempath[MAX_PATH + 1];
    if(SUCCEEDED(SHGetFolderPath(NULL,CSIDL_COMMON_APPDATA|CSIDL_FLAG_CREATE, NULL, 0, systempath)))
	{
		wchar_t *totalpath = lstrcat(systempath,changeFileFolder);
		bool res = CreateDirectory(totalpath, NULL);
		if (res || GetLastError() == ERROR_ALREADY_EXISTS)
		{
			if (pwdChange)
			{
				// Create a new uuid
				UUID uuid;
				RPC_STATUS ret_val = ::UuidCreate(&uuid);

				if (ret_val == RPC_S_OK)
				{
					// convert UUID to LPWSTR
					WCHAR* wszUuid = NULL;
					::UuidToStringW(&uuid, (RPC_WSTR*)&wszUuid);

					if (wszUuid != NULL)
					{
						wchar_t *fileName;
						fileName = lstrcat(wszUuid, L".txt");
						totalpath = lstrcat(totalpath,fileName);

						// free up the allocated string
						::RpcStringFree((RPC_WSTR*)&wszUuid);
						wszUuid = NULL;

						// Set file permissions for the password change file
						setLogFilePermissions(totalpath);
					}
					else
					{
						// couldn't convert the GUID to string (a result of not enough free memory)
						totalpath = NULL;
						writeLog(L"Error couldn't convert the GUID to string", false);
					}
				}
				else
				{
					// couldn't create the GUID
					totalpath = NULL;
					writeLog(L"Error couldn't create the GUID", false);
				}
			}
			else
			{
				totalpath = lstrcat(totalpath,logFileName);
			}

			if (totalpath != NULL)
			{
				SYSTEMTIME timestamp;
				GetLocalTime(&timestamp);
        
				unsigned int year=timestamp.wYear;
				unsigned int month=timestamp.wMonth;
				unsigned int day=timestamp.wDay;

				unsigned int hour=timestamp.wHour;
				unsigned int minute=timestamp.wMinute;
				unsigned int second=timestamp.wSecond;
				unsigned int milliseconds=timestamp.wMilliseconds;

				FILE* logFile=_wfopen( totalpath, L"a+b" );
				if (logFile != NULL)
				{
					fwprintf(logFile,L"[%04u/%02u/%02u %02u:%02u:%02u:%03u]:%s\r\n",year,month,day,hour,minute,second,milliseconds,message);
					fclose(logFile);
					writeSucceeded = true;
				}
			}
		}
	}

	return writeSucceeded;
}

bool writeMessageToLog(wchar_t* format, ...)
{
    va_list args;

    va_start( args, format );
    int len = _vscwprintf(format,args) + 1;
    wchar_t* buffer = (wchar_t*)malloc(len * sizeof(wchar_t));
    vswprintf(buffer,len,format,args);
    bool result = writeLog(buffer, false);
    free(buffer);
    return result;
}