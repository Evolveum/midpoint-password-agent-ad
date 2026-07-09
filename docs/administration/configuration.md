## Configuration of Midpoint Password Agent for Active Directory

Configuration is done using file [AppRoot]\Config\config.json.
Configuration has 3 sections.

### Listener (Windows LSA Password Notification Filter)
```
"Listener": {
    "LogLevel": "info",
    "LogFileSizeLimitBytes": 532480,
    "LogRetainedFileCountLimit": 3,
    "FilteringFilePath": "C:\\ProgramData\\MidPoint Password Agent for Active Directory\\Config\\filtering.txt",
    "FilteringFileMode": "EXACT"
}
```
`LogLevel` - Logging level [`trace`, `debug`, `info`, `warn`, `err`, `critical`, `off`]. Default: `info`

`LogFileSizeLimitBytes` - Max size of log file in bytes. Default: `5242880` (5 MB)

`LogRetainedFileCountLimit` - Max number or last log files to keep. Default: `3`

`FilteringFilePath` - Path to a text file listing accounts to exclude from syncing (a deny-list, one account name/pattern per line). Leave empty or unset to sync every account. Default: not set

`FilteringFileMode` - Interpretation mode of filtering file: `EXACT` (literal account name) or `REGEX` (regular expression matched against the whole account name). Both are **case-insensitive**. Default: `EXACT`

**All fields are optional, if not set in config, defaults are used.**
### Sender (Windows service that sends password updates to MidPoint)
```
"Sender": {
    "KeyRotationInterval": "10.00:00:00",
    "KeyRotationGracePeriod": "6.00:00:00",
    "KeyCleanupInterval": "2.00:00:00",
    "LogLevel": "Information",
    "LogFileSizeLimitBytes": 5242880,
    "LogRetainedFileCountLimit": 3,
    "MaxRetryCount": 5,
    "RetryBaseDelay": "00:01:00",
    "RetryMaxDelay": "01:00:00",
    "MaxRequestsPerMinute": 60,
    "MaxQueueDepth": 10
}
```
`KeyRotationInterval` - Interval of key rotation (how often is new key created). Default `20.00:00:00` (20 days).

`KeyRotationGracePeriod` - Grace period of "old" key after key rotation (how long old key is kept). Default `3.00:00:00` (3 days)

`KeyCleanupInterval` - Interval of "old" key cleanup (how often we check for "old" key deletion). Default `1.00:00:00` (1 day)

`LogLevel` - Minimum log level written to the log file (`Verbose`, `Debug`, `Information`, `Warning`, `Error`, `Fatal`). Default: `Information`

`LogFileSizeLimitBytes` - Maximum size of a single log file in bytes before it is rolled over and a new file is created. Default: `5242880` (5 MB)

`LogRetainedFileCountLimit` - Maximum number of log files to keep on disk. When exceeded, the oldest file is deleted. Default: `3`

`MaxQueueDepth` - Maximum number of password change events sent to MidPoint concurrently. Under burst loads, events queue up on disk and are processed by up to this many worker threads at once instead of one at a time. Default `10`.

`MaxRetryCount` — Number of retry attempts before the event is moved to the dead-letter queue.

`RetryBaseDelay` — Base delay for the first retry. Default `00:01:00` (1 minute).

`RetryMaxDelay` — Maximum delay between retries. Default `01:00:00` (1 hour).

Delay is calculated as `RetryBaseDelay × 2^(retryNumber − 1)`, capped at `RetryMaxDelay`.

`MaxRequestsPerMinute` - Maximum number of send request to MidPoint per minute. Default `0` => no limitation


**All fields are optional, if not set in config, defaults are used.**

### Midpoint (API configuration)

```
    "MidPoint": {
        "BaseUrl": "http://localhost:8080/midpoint",
        "Username": "administrator",
        "Password": "<DPAPI protected password>",
        "ResourceOid": "baaad572-97d0-491e-9b4a-024633533778"
    }
```
Midpoint password is protected using Windows DPAPI. For easy update, application is shipped with script `updateMidpointPassword.ps1`. Script can be found in installation folder of application (`Program Files\Evolveum\Midpoint Password Agent for Active Directory\updateMidpointPassword.ps1` by default) .

**For correct behaviour of application, all Midpoint fields are required.**

### Example of full config:
```
{
    "Listener": {
        "LogLevel": "info",
        "LogFileSizeLimitBytes": 532480,
        "LogRetainedFileCountLimit": 3,
        "FilteringFilePath": "C:\\ProgramData\\MidPoint Password Agent for Active Directory\\Config\\filtering.txt",
        "FilteringFileMode": "EXACT"
    },
    "MidPoint": {
        "BaseUrl": "http://localhost:8080/",
        "Username": "administrator",
        "Password": "<DPAPI protected password>",
        "ResourceOid": "baaad572-97d0-491e-9b4a-024633533778"
    },
    "Sender": {
        "KeyRotationInterval": "10.00:00:00",
        "KeyRotationGracePeriod": "6.00:00:00",
        "KeyCleanupInterval": "2.00:00:00",
        "LogLevel": "Information",
        "LogFileSizeLimitBytes": 5242880,
        "LogRetainedFileCountLimit": 3,
        "MaxRetryCount": 5,
        "RetryBaseDelay": "00:01:00",
        "RetryMaxDelay": "01:00:00",
        "MaxQueueDepth": 10
    }
}
```

Application is watching for changes in config file and automatically loads new configuration, without any action from administrator.
