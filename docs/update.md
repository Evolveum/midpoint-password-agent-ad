# Updating

Application can be updated with running "new" `.msi` installer on Windows Server where this application is already installed.

It is required to increment application version inside [`Package.wxs`](../Package.wxs). Increment <Package> tag's `Version` attribute.

Update does not touch:
- encryption keys
- root path folder of application
- config.json


Only Listener DLL and Sender exe binaries are updated.
