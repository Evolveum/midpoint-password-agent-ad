## Troubleshooting ##

### Retry mechanism ###
Application has configurable retry count (default 5). Interval between retries is increasing for each next retry (see [configuration](configuration.md)).

After last retry attempt fails, files are moved to `Data/Queue/DLQ` folder. If admin wants application to process them again (e.g. problem on external API was resolved), he needs to move files from `Data/Queue/DLQ` to `Data/Queue/` folder, and application automatically picks them for reprocessing (retry count is reset to 0).

Before Admin is able to move files from DLQ folder, he needs to add his user into `MidPoint Password Agent Managers user` group (see [permissions](permissions.md) for more info).

### Reading processing error ###
Last processing error is saved to .event file, section metadata. Example of failed .event file:
```
{
  "username": "example.name",
  "domain": "EXAMPLE",
  "password": "<base64-encoded AES-GCM ciphertext>",
  "metadata": {
    "retryCount": 2,
    "nextRetryAt": "2026-06-09T14:30:00+00:00",
    "lastError": "Endpoint responded with 404"
  }
}
```

### Logs ###
Application is storing logs to folder `Logs`. Logs are split to 2 sections:
- sender 
- listener

Application is also logging errors to `Windows Event File`.