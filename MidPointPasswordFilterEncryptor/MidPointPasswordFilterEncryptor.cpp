// MidPointPasswordFilterEncryptor.cpp : Defines the entry point for the console application.

/**
 *
 * Licensed under the Microsoft Public License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *		http://opensource.org/licenses/MS-PL
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

#include "stdafx.h"
#include "Rijndael.h"
#include <iostream>
#include <string>

#if defined(UNICODE)
    #define _tcout std::wcout
#else
    #define _tcout std::cout
#endif

const char *key = "kealtihzearbient";
const char *IV = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const int blocksize = 16;
const int keylength = 16;

//Function to convert unsigned char to string of length 2
void Char2Hex(unsigned char ch, char* szHex)
{
	unsigned char byte[2];
	byte[0] = ch/16;
	byte[1] = ch%16;
	for(int i=0; i<2; i++)
	{
		if(byte[i] >= 0 && byte[i] <= 9)
			szHex[i] = '0' + byte[i];
		else
			szHex[i] = 'A' + byte[i] - 10;
	}
	szHex[2] = 0;
}

//Function to convert string of unsigned chars to string of chars
void CharStr2HexStr(unsigned char const* pucCharStr, char* pszHexStr, size_t iSize)
{
	int i;
	char szHex[3];
	pszHexStr[0] = 0;
	for(i=0; i<iSize; i++)
	{
		Char2Hex(pucCharStr[i], szHex);
		strcat(pszHexStr, szHex);
	}
}

//Function to convert string of length 2 to unsigned char
void Hex2Char(char const* szHex, unsigned char& rch)
{
	rch = 0;
	for(int i=0; i<2; i++)
	{
		if(*(szHex + i) >='0' && *(szHex + i) <= '9')
			rch = (rch << 4) + (*(szHex + i) - '0');
		else if(*(szHex + i) >='A' && *(szHex + i) <= 'F')
			rch = (rch << 4) + (*(szHex + i) - 'A' + 10);
		else
			break;
	}
} 

//Function to convert string of chars to string of unsigned chars
void HexStr2CharStr(char const* pszHexStr, unsigned char* pucCharStr, size_t iSize)
{
	int i;
	unsigned char ch;
	for(i=0; i<iSize; i++)
	{
		Hex2Char(pszHexStr+2*i, ch);
		pucCharStr[i] = ch;
	}
}

// Main function - entry point
int _tmain(int argc, _TCHAR* argv[])
{
	// Check the value of argc. If not enough parameters have been passed, inform user and exit.
	if (argc != 3)
	{ 
        _tcout << "Usage is [e|d] <message>\n"; // Inform the user of how to use the program
    }
	else
	{
		if (wcscmp(argv[1], _T("e")) == 0)
		{
			// Encrypt the password
			try
			{
				// Convert args from TCHAR* to char*
				errno_t err = 0;
				size_t convertedChars = 0;
				size_t passwordLen = ((wcslen(argv[2]) + 1) * 2);
				char *password = (char *)malloc(passwordLen);
				err = wcstombs_s(&convertedChars, password, passwordLen, argv[2], passwordLen);
				if (err == 0)
				{
					// Add padding up to a multiple of block size
					int numPadChars = blocksize - (passwordLen % blocksize);
					size_t bufferSize = (numPadChars == blocksize) ? passwordLen : passwordLen + numPadChars;
					char *szHex = new char[(bufferSize*2) + 1];

					// Populate Data Out char array with nulls
					char *szDataOut = new char[bufferSize];
					std::fill(szDataOut, szDataOut + bufferSize + 1, '\0');

					// Create Key
					CRijndael oRijndael;
					oRijndael.MakeKey(key, IV, keylength, blocksize);

					// Do Encryption with CBC (mode 1)
					oRijndael.Encrypt(password, szDataOut, bufferSize, 1);

					// Convert to Hex representation
					CharStr2HexStr((unsigned char*)szDataOut, szHex, bufferSize);

					// Print Hex representation to be picked up by caller
					_tcout << "START ENCRYPTION\n" << szHex << "\nEND ENCRYPTION";

					// Free multibyte char buffers after use
					if (password) free(password);
					if (szDataOut) free(szDataOut);
					if (szHex) free(szHex);
				}
				else
				{
					_tcout << "Error parsing password. Error code: " << err << endl;
				}
			}
			catch(exception& roException)
			{
				_tcout << roException.what() << endl;
			}
		}
		else if (wcscmp(argv[1], _T("d")) == 0)
		{
			// Decrypt the password
			try
			{
				// Convert args from TCHAR* to char*
				errno_t err = 0;
				size_t convertedChars = 0;
				size_t argLen = ((wcslen(argv[2]) + 1) * 2);
				char *passwordArg = (char *)malloc(argLen);
				err = wcstombs_s(&convertedChars, passwordArg, argLen, argv[2], argLen);
				if (err == 0)
				{
					// Convert from Hex representation
					size_t bufferSize = (strlen(passwordArg) / 2);
					unsigned char* encPassword = new unsigned char[bufferSize];
					HexStr2CharStr(passwordArg, encPassword, bufferSize);

					// Populate Data Out char array with nulls
					char *szDataOut = new char[bufferSize + 1];
					std::fill(szDataOut, szDataOut + bufferSize + 1, '\0');

					// Create Key
					CRijndael oRijndael;
					oRijndael.MakeKey(key, IV, keylength, blocksize);

					// Do Decryption with CBC (mode 1)
					oRijndael.Decrypt(reinterpret_cast<char *>(encPassword), szDataOut, bufferSize, 1);

					// Print decrypted string to be picked up by caller
					_tcout << "START DECRYPTION\n" << szDataOut << "\nEND DECRYPTION";

					// Free multibyte char buffers after use
					if (passwordArg) free(passwordArg);
					if (encPassword) free(encPassword);
					if (szDataOut) free(szDataOut);
				}
				else
				{
					_tcout << "Error parsing password. Error code: " << err << endl;
				}
			}
			catch(exception& roException)
			{
				_tcout << roException.what() << endl;
			}
		}
		else
		{
			_tcout  << "Usage is [e|d] <message>\n"; // Inform the user of how to use the program
		}
	}

	return 0;
}

