# MidPoint Password Agent for Active Directory (Deprecated)

This project contains a code of Active Directory agent that captures password change events and sents them to midPoint.

**This code is DEPRECATED and it is not supported.** This code was donated to the midPoint project long time age. This code was no longer maintained by the original author. And as it turned out, there was not enough market incentive for Evolveum to maintain that code either. Maybe part of the reason is that the overall idea of a password agent may be questionable (see [Initial Password Management Discussion](https://wiki.evolveum.com/display/midPoint/Initial+Password+Management+Discussion)).

In case that you need AD password agent, [midPointADPasswordAgent maintained by Identicum](https://github.com/Identicum/midPointADPasswordAgent) may be a viable alternative.

# Original Description

~~~~
This application filters password changes from a local active directory server to a text file.
The text file can then be parsed and transitted to Midpoint to syncronise accounts with changes in AD.

Prerequisites:
	Microsoft Visual C++ 2010 [x86|x64] Redistributable must be installed (select x86 or x64 according to platform)
	Microsoft .NET Framework 4
		1) This is installed by default on Windows Server 2012
		2) Need to install Windows Imaging Component on Windows Server 2003

Permissions:
	After deploying the PasswordFilter dll and exe files, you should edit the file permissions
	to only include the SYSTEM account and Administrators group.
	This is particularly true for the encryptor, since user could run it to discover plaintext/ciphertext pairs.

Running the application:
	Once deployed you can test the filter as follows:
		• Activate the option "User must change password at next logon" for all the accounts to sync
		• Restart the machine
		• Login with one of the users marked for changing password at next login and change the password when requested
		• Check the filter log:
			On W2K3 servers:	C:\Documents and Settings\All Users\Application Data\MidPointPasswordFilter\MidPointPasswordFilter.log
			On W2K8/12 servers:	C:\Program Data\MidPointPasswordFilter\MidPointPasswordFilter.log
			There should also be a file for each updated user, containing the encrypted password.
	Once this is done you can transmit changes:
		• Run (as administrator) MidPointPasswordFilterProcessor which is in the "C:\Program Files\Evolveum\MidPoint Password Filter" folder
		  (this is also run as a scheduled task)
		• Login to Midpoint with the new credentials
~~~~
