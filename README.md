# MidPoint Password Agent for Active Directory

Captures Active Directory password changes on Domain Controllers and forwards them to a configurable midPoint REST endpoint in real time.

## Administrator's Guide

Please see [`docs/administration/README.md`](docs/administration/README.md) for installation and configuration instructions.

Alternatively, you can see a sample installation of the agent and midPoint in [`sample-installation/pwd-agent-test-env`](sample-installation/README.adoc).

## Architecture

The solution runs on every Domain Controller and consists of two decoupled components:

| Component | Language | Role | Docs |
|---|---|---|---|
| **Listener** | C++ | LSA Password Notification Filter. Captures the cleartext password at change time and writes it to a local filesystem queue. | [`docs/development/listener/README.md`](docs/development/listener/README.md) |
| **Sender** | C# | Windows service that reads the queue and forwards events to the target REST API. | [`docs/development/sender/README.md`](docs/development/sender/README.md) |

## Repository Layout

```
.
├── installation/            # Listener + Sender instalation scripts (.ps1)
├── docs/                    # Documentation
├── sample-installation/     # Sample installation of the agent and midPoint
├── listener/                # C++ LSA filter DLL
│   ├── CMakeLists.txt
│   ├── PasswordFilter.def   # Linker exports
│   └── src/                 # Listener source files
│   └── tests/               # Listener tests
├── sender/                  # C# Windows service app
│   ├── Program.cs           # Application builder
│   ├── sender.csproj        # C# app definition
├── sender.Tests/            # C# Windows service app Tests
└── justfile                 # Just recipes
└── README.md
```

## Developer's Guide

Please see [`docs/development/`](docs/development/) for development instructions.
