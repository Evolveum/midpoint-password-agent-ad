# MidPoint Password Agent for Active Directory Sender

## Overview

The sender is a .NET 10 Windows Service that picks up password-change events written by the [listener](../listener/README.md) and forwards them to the midPoint REST API.

It runs on the same Domain Controller as the listener, polls the local queue directory, and deletes each event file after a successful delivery.

---

## Prerequisites

- .NET SDK 10 — [download](https://dotnet.microsoft.com/download)
- just - command runner ([installation](https://just.systems/man/en/packages.html))

---

## Run locally

Only possible on Windows, because of Win dependencies.

```bash
cd sender
dotnet run
```

or simply run published `sender.exe` with

```bash
just sender-publish

# In Windows

just sender-run-locally
```

---

## Testing

Tests are implemented in `sender.Tests` folder. And can be run with `just sender-test` on all platforms with dotnet installed.

Mocked midpoint server is implemented using WireMock (.NET port) can be started by command `just server-mock {args}`

---

## Logging

Sender application logs are divided into 2 categories:

- Application state logs - Windows EventLog (can be traces with Event Viewer Windows app)
- Application operations - stored in `sender.log` file path as `[APPROOT]/Logs/`. Logged with C# library `Serilog`

Log files use size-based rotation: once a file reaches the configured size limit a new file is created. Old files beyond the configured retention count are deleted automatically. Both limits are configurable — see the `Configuration` section below.

---

## MidPoint Configuration

The Sender authenticates to MidPoint using HTTP Basic Authentication. Credentials and the base URL are configured in `config.json` under the `MidPoint` section:

```json
{
    "MidPoint": {
        "BaseUrl": "http://localhost:8080/midpoint",
        "Username": "administrator",
        "Password": "<DPAPI protected password>",
        "ResourceOid": "baaad572-97d0-491e-9b4a-024633533778"
    }
}
```

---

## File decryption

Sender module has to read content of `.event` files. So it needs to first parse JSON file. Filename holds also key name that was used for its encryption. By reading used key from Windows registry is Sender able to decrypt `password` field of JSON content.

---

## Retry mechanism

When a password change event cannot be delivered to midPoint, the sender retries using exponential backoff before permanently discarding the event.

1. Sender reads a `.event` file from the queue and attempts to send it to midPoint.
2. On failure, the file is moved to the `failed/` directory and its metadata is updated with the new retry count and the scheduled time for the next attempt.
3. On each poll cycle, files in `failed/` whose retry time has passed are moved back to `processing/` for another attempt.
4. After `MaxRetryCount` failed attempts, the file is moved to `queue/dlq/` and an error is written to the Windows Event Log.

Delay is calculated as `RetryBaseDelay × 2^(retryNumber − 1)`, capped at `RetryMaxDelay`.

With the default values (`RetryBaseDelay = 1 min`, `RetryMaxDelay = 1 h`):

| Retry | Delay  |
|-------|--------|
| 1     | 1 min  |
| 2     | 2 min  |
| 3     | 4 min  |
| 4     | 8 min  |
| 5     | 16 min |
| 6     | 60 min |

After the first failure the `.event` file is rewritten as JSON with only the password field encrypted. All other fields are plaintext.

```json
{
  "username": "example.name",
  "domain": "EXAMPLE",
  "password": "<base64-encoded AES-GCM ciphertext>",
  "metadata": {
    "retryCount": 2,
    "nextRetryAt": "2026-06-09T14:30:00+00:00",
    "lastError": null
  }
}
```

This beviour can be configured in following way

```json
{
  "Sender": {
    "MaxRetryCount": 5,
    "RetryBaseDelay": "00:01:00",
    "RetryMaxDelay": "01:00:00"
  }
}
```

`MaxRetryCount` — number of retry attempts before the event is moved to the dead-letter queue.
`RetryBaseDelay` — base delay for the first retry.
`RetryMaxDelay` — maximum delay between retries.

---

## Burst load handling

Mass events can drop a large number of `.event` files into the queue at the same time. Instead of sending them one at a time, the sender processes up to `MaxQueueDepth` events concurrently.

```json
{
  "Sender": {
    "MaxQueueDepth": 10
  }
}
```

`MaxQueueDepth` — maximum number of events processed concurrently. Default `10`.

---

## Key rotation

Sender module is responsible for rotation of encryption/decryption keys. In configured intervals it creates new key and removes unused one.

Process of key rotation:
1. Create new key with incremented version name (`v1` -> `v2`)
2. Set new key as a `LatestKey` (so each module will start to use it)
3. Wait few seconds (2-3) so listener can finish writing `.event` files with old key
3. Search Queue folder for `.event` files that have old key in filename
4. Move those files into staging folder
5. Decrypt `password` field of `.event` files with old key and encrypt with new key (file name has to change)
6. Move `.event` file back to its original place
7. If there are no `.event` files encrypted with old key, we can delete it


---

## Configuration

Sender service is configurable with `config.json` file. Its location is read from Windows Registry `"HKLM:SOFTWARE\Evolveum\MidPointPasswordAgent\ConfigPath"`. If configuration file does not exists or cannot be read defaults are used that are defined inside [`SenderJsonConfiguration`](../../sender/Configuration/SenderJsonConfiguration.cs)

Example of `config.json`
```json
{
    "MidPoint": {
        "BaseUrl": "http://localhost:8080/midpoint",
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
        "MaxRequestsPerMinute": 60,
        "MaxQueueDepth": 10
    }
}
```

`KeyRotationInterval` - Interval of key rotation (how often is new key created)
`KeyRotationGracePeriod` - Grace period of "old" key after key rotation (how long old key is kept)
`KeyCleanupInterval` - Interval of "old" key cleanup (how often we check for "old" key deletion)
`LogLevel` - Minimum log level written to the log file (`Verbose`, `Debug`, `Information`, `Warning`, `Error`, `Fatal`). Default: `Information`
`LogFileSizeLimitBytes` - Maximum size of a single log file in bytes before it is rolled over and a new file is created. Default: `5242880` (5 MB)
`LogRetainedFileCountLimit` - Maximum number of log files to keep on disk. When exceeded, the oldest file is deleted. Default: `3`
`MaxRetryCount` — Number of retry attempts before the event is moved to the dead-letter queue.
`RetryBaseDelay` — Base delay for the first retry. Default `00:01:00` (1 minute).
`RetryMaxDelay` — Maximum delay between retries. Default `01:00:00` (1 hour).
`MaxRequestsPerMinute` - Maximum number of send request to MidPoint per minute. Default `0` => no limitation
`MaxQueueDepth` - Maximum number of password change events sent to MidPoint concurrently. Default: `10`

To change configuration of MidPoint password, user needs to call script scripts/updateMidpointPassword.ps1 (will be part of installation folder). To avoid passing password as plaintext parameter, script expects interactive user input.


## Performance testing
For performance testing, we can use script `scripts/batchPasswordChangeTest.ps1`. Script generates multiple accounts (configurable number) in AD then changes password to each of them.
